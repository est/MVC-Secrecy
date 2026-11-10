# MVC + S（Capability）原型与设计报告

> 目录：`<repo>/mvc-secrecy/`
>
> 环境：Node 22 / Chrome/Edge 157 / Safari 26.2（WebRTC 部分另见上一份报告）
>
> 目标：验证“把每个可能 spam 的用户操作绑定到一张一次性、带 scope、绑定设备的证书；XSS 可以用掉当前一张，但老证书失效、不能无限续杯”的设计，并给出一个面向开发者的 API。

---

## 0. 一句话结论

**这个方向成立，而且已经有一个可运行的原型。**

- 没有主流 MVC 框架直接提供“视图上下文 → 每动作一次性、带 scope、绑定设备的 capability”这一层；它是 **object-capability / Sandstorm Powerbox / TBAC / OWASP transaction authorization / PSD2 dynamic linking / DPoP / WebAuthn / macaroons-Biscuit-UCAN** 的交集。详见 `RESEARCH.md`。
- 原型 v2.1 的核心结论：
  - 业务代码只调用 `secrecy.execute(action, { scope, body })`，不碰 crypto/token。
  - 每个动作一张一次性 capability，绑定 device + action + view + scope + body。
  - 高危动作需要带外 presence（demo 用 server console 6 位码；生产应换 WebAuthn UV）。
  - 服务端 ACL 在 **issue 和 use 两次**都检查。
  - 并发双花、presence 绕过、scope 替换、JWK 重编码绕过吊销、PoP 并发重放都已修复并有回归测试。
- 测试结果：
  - `node src/test/smoke.mjs`：**11/11**
  - `node src/test/security.mjs`：**19/19**
  - Playwright 浏览器矩阵：**18/18**
  - Playwright 对抗矩阵：**5/5**

---

## 1. 有没有人这么搞过？

### 1.1 直接答案

没有完全相同的“MVC + S”框架，但每一块都有成熟先例：

| 你的想法 | 已有对应 |
|---|---|
| 每个动作一张证书 | object-capability / capability token |
| 一次性、用掉失效 | TBAC、one-time capabilities、`jti` + consume store |
| 绑定设备 | DPoP、mTLS、WebCrypto non-extractable key |
| 绑定视图/上下文 | user-driven access control、Sandstorm Powerbox、transaction authorization |
| 高危动作用户在场 | WebAuthn UV、PSD2 dynamic linking、EMV 3DS |
| 旧证书失效、不能续杯 | capability consumption、revocation、issuance choke point |
| 每动作 scope | OAuth RAR、macaroons/Biscuit caveats、UCAN |
| 服务端 ACL | ReBAC/ABAC（OpenFGA/SpiceDB/Cerbos/Oso）at mint time |

### 1.2 最接近的 prior art

- **Sandstorm Powerbox**：应用向平台请求 capability，用户在 picker 里选具体对象；应用拿到的是“那个对象”的 capability，不是全局权限。Sandstorm 还用 pseudo-ACL 追踪谁持有哪些 capability。
- **User-driven access control**（Roesner et al., IEEE S&P 2012）：权限在用户动作的当下、上下文里授予。
- **TBAC**（Thomas & Sandhu, 1997）：权限随 task/workflow 激活、消费、撤销。
- **OWASP Transaction Authorization / PSD2 dynamic linking**：每笔交易唯一凭证，绑定金额/收款人，服务端状态机。
- **DPoP / WebAuthn**：proof-of-possession + 用户在场。
- **Macaroons / Biscuit / UCAN**：可衰减、可委托的 capability。

### 1.3 结论

你的设计不是“重新发明密码学”，而是把几条成熟路线组合成一个 **开发者友好的 MVC 层**。真正难的不是 token 格式，而是：

1. **issuance 是新的边界**：`/cap` 是 policy oracle + mint；如果 XSS 能静默 mint，一次性/旧证书失效都白搭。
2. **原子消费**：check → await → act 是经典双花 bug。
3. **用户在场**：客户端 `isTrusted` 不是安全边界；必须服务端可验证（WebAuthn UV/带外）。
4. **scope 授权**：capability 绑定 scope ≠ scope 本身被授权；服务端必须 `can(user, action, resource)`。
5. **view 不是安全边界**：view 是 UX guard；服务端权威是 ACL + scope + presence。

---

## 2. MVC + S 的定义与命名

### 2.1 四层

```text
Model      业务数据 + 服务端权威状态 + 审计
View       纯投影：只渲染 allowed actions 和 redacted fields
Controller 把用户意图映射成 action；调用 secrecy.execute()
Secrecy    capability 层：issue / prove / consume / verify / revoke / audit
```

- **Model**：服务端是权威；客户端只持有 `state` 投影。
- **View**：隐藏按钮只是 UX；真正的授权在服务端。
- **Controller**：只调用 `secrecy.execute(action, { scope, body })`，不碰 crypto/token。
- **Secrecy**：框架无关的 capability 客户端 + 服务端 verifier/store。

### 2.2 “S” 应该叫什么

“Secrecy” 作为品牌可以保留，但技术上要区分：

- **Secrecy = need-to-know / 信息隐藏 / 字段投影**（Parnas information hiding）。
- **Capability / Authority = 授权**（谁能做什么）。

如果 S 指授权层，建议叫 **MVC + Capability** 或 **MVC + Authority**；如果坚持 “MVC + S”，请在文档里写清楚：

> **S = Secrecy as need-to-know projection + Capability as authorization.**

否则容易把“隐藏 UI/字段”误当成安全边界。

---

## 3. 架构与开发者 API

### 3.1 最小开发者用法

```js
const secrecy = new Secrecy({
  api: "/api",
  policy: window.SECRECY_POLICY,
  presenceProvider: new ModalCodePresenceProvider() // 高危动作才需要
});

await secrecy.init(); // PoP challenge -> sign -> register

const home = secrecy.view("home");
await home.execute("createPost", {
  scope: { boardId: "b1" },
  body: { text: "hello" }
});
```

业务代码只看到 `scope` / `body`；capability、proof、nonce、presence token 都在 core 里。

### 3.2 Policy manifest（client-safe）

```js
{
  version: 2,
  views: {
    login:   { actions: [] },
    home:    { actions: ["createPost", "post:edit", "post:submit"] },
    chat:    { actions: ["sendMessage", "mention", "chat:join", "chat:leave"] },
    profile: { actions: ["changeAvatar"] }
  },
  actions: {
    createPost: {
      scope: { boardId: "BoardId" },
      body:  { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 300,
      presence: false,
      authorize: "board.write"        // 服务端解析，不下发 ACL 逻辑
    },
    changeAvatar: {
      scope: { mime: "AvatarMime", maxSize: "Bytes1to104857600" },
      body:  { reason: "Text1to200" },
      risk: "high", maxUses: 1, ttlSeconds: 120,
      presence: true,
      authorize: "self.profile"
    }
  }
}
```

### 3.3 服务端 authorizer（server-only）

```js
// server-policy.js — 不打包到浏览器
{
  "board.write": (auth, scope) => boards.can(auth.userId, scope.boardId, "editor"),
  "chat.write":  (auth, scope) => chats.isMember(auth.userId, scope.chatId),
  "chat.mention":(auth, scope) => chats.canMention(auth.userId, scope.chatId, scope.userIds),
  "self.profile":(auth) => true
}
```

**issue 和 use 都调用**；成员关系在 issue 后被撤销，use 仍然失败。

### 3.4 Capability 形状

```json
{
  "v": 1,
  "capId": "cap_...",
  "userId": "u_...",
  "deviceId": "dev_...",
  "deviceJkt": "sha256(canonical JWK)",
  "action": "createPost",
  "view": "home",
  "scope": { "boardId": "b1" },
  "bodyHash": "sha256(body)",
  "seq": 1,
  "nonce": "...",
  "maxUses": 1,
  "exp": 1730000000,
  "parentCap": null,
  "prevHash": null
}
```

Proof 签名覆盖：`capId | action | view | deviceJkt | scopeHash | bodyHash | seq | nonce | prevHash`。

### 3.5 错误码

| 错误 | 含义 |
|---|---|
| `ACTION_NOT_ALLOWED_IN_VIEW` | 动作不在当前 view 的声明里 |
| `ACTION_MISMATCH` | capability 的 action 与请求不一致 |
| `SCOPE_DENIED` | 请求 scope 与 capability 不一致 |
| `CAPABILITY_CONSUMED` | 已消费/重放 |
| `CAPABILITY_EXPIRED` | 过期 |
| `PRESENCE_REQUIRED` | 高危动作需要 presence |
| `PRESENCE_CODE_INVALID` | OOB code 错 |
| `PRESENCE_SCOPE_MISMATCH` | presence token 与 scope/body 不匹配 |
| `DEVICE_MISMATCH` | capability 绑定到别的设备 |
| `DEVICE_REVOKED` | 设备已撤销 |
| `FORBIDDEN` | 服务端 ACL 拒绝 |
| `SEQ_MISMATCH` | 多步流程 parent/prevHash 不匹配 |

---

## 4. 核心如何保持极简、好维护、好扩展

### 4.1 文件边界

| 文件 | 职责 | 行数（v2.1） |
|---|---|---:|
| `src/public/secrecy.js` | 客户端 capability core：PoP、issue、proof、presence、execute | 476 |
| `src/public/protocol.js` | 共享 canonicalization / hash / base64url / proof string | 171 |
| `src/public/presence.js` | PresenceProvider 接口 + WebAuthn stub + static-code helper | 70 |
| `src/public/policy.js` | client-safe policy manifest | ~100 |
| `server-policy.js` | server-only authorizers + policy validation | 226 |
| `src/server.js` | HTTP API + verifier + store + audit | 1986 |
| `src/public/app.js` | MVC views/controllers + OOB modal + XSS lab | ~1200 |

> 客户端 core 保持 <500 行；服务端大是因为它同时包含 demo API、store、audit、rate limit 和 XSS lab。生产应拆分 `store/`、`auth/`、`api/`。

### 4.2 扩展方式

- **新增 action**：只改 `policy.js` + controller；core 不改。
- **新增 view**：只改 `policy.js` + view；core 不改。
- **新增 scope 类型**：在 `server-policy.js` 的 type registry 加校验；不要下发到浏览器。
- **新增 presence provider**：实现 `requestPresence({action, scope, body, challenge})`，返回 `{code}` 或 `{assertion}`。
- **换存储**：实现 `consumeCapability` / `issueChild` / `consumePresence` / `redeemChallenge` / `revokeDevice` 的 Store 接口；HTTP handler 不跨 await check-then-set。
- **换 token 格式**：保持 mint/verify/consume 边界，JWT → Biscuit/UCAN 不影响业务代码。

### 4.3 为什么业务代码不需要碰 crypto

`secrecy.execute` 内部完成：

1. 校验 view/action；
2. 规范化 scope/body；
3. 算 scopeHash/bodyHash；
4. 高危动作走 presence provider；
5. 申请 capability；
6. 用 non-extractable device key 签 proof；
7. 调 `/api/action`；
8. 处理 `CAPABILITY_CONSUMED` / `PRESENCE_REQUIRED` / `SEQ_MISMATCH` 等错误；
9. 保存 receipt / sequence link。

Controller 只处理业务成功/失败。

---

## 5. 安全模型

### 5.1 它保护什么

| 攻击 | 结果 |
|---|---|
| 重放已消费 capability | `CAPABILITY_CONSUMED` |
| 并发双花同一 capability | 只允许一次成功（2/50 并发测试） |
| 用发帖 capability 改头像 | `ACTION_NOT_ALLOWED_IN_VIEW` / `ACTION_MISMATCH` |
| 在 home 调 profile 动作 | `ACTION_NOT_ALLOWED_IN_VIEW` |
| 篡改 capability scope/body | `INVALID_CAPABILITY` / `SCOPE_DENIED` |
| 跨设备使用 capability | `DEVICE_MISMATCH` |
| 非成员向 board/chat 写 | `FORBIDDEN` |
| 成员被撤销后继续用旧 capability | use 时 ACL 再检查 → `FORBIDDEN` |
| 无 presence 申请高危 capability | `PRESENCE_REQUIRED` |
| 错误 OOB code | `PRESENCE_CODE_INVALID` |
| presence token 换 scope/body | `PRESENCE_SCOPE_MISMATCH` |
| 并发重放 PoP challenge | 只创建一个 session（2/50 测试） |
| JWK 重编码绕过吊销 | canonical JWK + RFC 7638 + revoked 检查 |
| 匿名读 audit | `401` |
| 撤销设备后继续用 | `DEVICE_REVOKED` |
| 多步 post 跳过/复用 | `SEQ_MISMATCH` / `CAPABILITY_CONSUMED` |
| 草稿在 edit 后被篡改 | `DRAFT_HASH_MISMATCH` |

### 5.2 它不保护什么

| 威胁 | 说明 |
|---|---|
| 同源 XSS 用掉当前 capability | XSS 可以驱动当前流程一次；这是“bounded/scoped/detectable/revocable”，不是 XSS-proof |
| 同源 XSS keylog OOB code | demo 的 console code 是带外通道，但用户输入后同页 XSS 可读 |
| 浏览器/OS 被控制 | 恶意浏览器/扩展可以读 DOM、调 key |
| 复制整个浏览器 profile | 可能复制设备 key；硬件绑定才能防 |
| WebAuthn UV | 只实现了 contract/stub + test fake；生产要真 WebAuthn |
| 多进程/多实例 | 当前是 in-memory single-process；生产要 DB CAS/事务 |
| HMAC 对称/进程内 | 生产要非对称/轮换/HSM |
| 丢失响应后的重试 | 有 receipt，但没有 idempotency lookup |
| per-capability 撤销 | 目前只有 whole-device revoke |
| audit 防篡改 | in-memory、capped、非 hash chain |
| CSRF/BFF/HttpOnly | 当前是 JS memory bearer session |
| 分布式限流/Sybil | best-effort in-memory |

### 5.3 正确的安全声明

> **这不是“XSS 不能代替用户操作”。**
>
> 它是：**XSS 最多用掉当前这一张、只能做这个动作、留下审计、触发吊销/重认证；它不能静默 mint 新的高危 capability，也不能跨设备/跨动作复用。**

---

## 6. 迭代记录

### v1

- 静态 MVC + capability core + smoke test。
- 浏览器矩阵 17/17。
- 对抗测试发现：
  - **P0 并发双花**：同一 capability 并发两次都成功。
  - **P0 presence 绕过**：直接调 `/api/presence` 拿 token。
  - **P1 audit 未鉴权**。

### v2（reviewer 第一轮后）

- 修：
  - 原子 consume（check+set after last await）。
  - OOB presence（server console code）+ scope/body 绑定。
  - 服务端 ACL（board/chat/mention/self）。
  - JWK canonicalization + RFC 7638 + 注册 PoP + 持久撤销。
  - audit 鉴权/脱敏。
  - proof 绑定 view/JKT/scope/body/seq/nonce/parent。
  - `maxUses`/policy validation、revocation-in-flight、draft hash、shared protocol、`execute(action,{scope,body})`、demo gating、rate limit、state 401。
- 测试：smoke 11/11、security 11/11、browser 18/18、adversarial 5/5。

### v2.1（reviewer 第二轮后）

- 修：
  - **PoP challenge 并发重放**（新 P0）：verify 后原子 consume challenge；2/50 并发只创建一个 session；注册限流；challenge 5 次失败烧毁；session cap。
  - **action-time presence**：presence token 在 `/api/action` 消费，绑定最终 scopeHash/bodyHash；provider 支持 `{code}` 或 `{assertion}`。
  - **board ACL principal**：`boardMembers` 检查 user；chat join/leave 变成 capability action，移除 ambient endpoints。
  - **draft 在 submit 时重新 hash**。
  - **audit 脱敏 + timing-safe admin token**。
  - 注册/state/audit 限流、quota、`DEMO` 服务端 gating。
- 测试：smoke 11/11、security 19/19、browser 18/18、adversarial 5/5。

---

## 7. 测试结果

### 7.1 服务端

```bash
cd mvc-secrecy
node src/test/smoke.mjs
# 11 passed, 0 failed

node src/test/security.mjs
# 19 passed, 0 failed
```

`security.mjs` 覆盖：

- PoP challenge 2/50 并发重放 → 一个 session
- action capability 2/50 并发双花 → 一次成功
- OOB presence、错误 code、scope/body 替换
- board/chat/mention ACL、成员撤销 continuity
- JWK canonicalization、PoP、padded/whitespace 拒绝、持久撤销
- audit 匿名 401、非 admin 脱敏、admin 全量
- proof/body/view/capability tamper、过期、malformed
- policy validation、revocation-in-flight、draft hash、demo gating、rate limit

### 7.2 浏览器（Playwright）

```bash
BASE_URL=http://127.0.0.1:8789 \
SERVER_LOG=.../mvc-secrecy-server-v21.log \
NODE_PATH=$(npm root -g) \
node src/test/browser/browser.mjs
# 18 passed, 0 failed
```

覆盖：

- login / PoP registration
- createPost
- reuse → `CAPABILITY_CONSUMED`
- cross-action → `ACTION_NOT_ALLOWED_IN_VIEW`
- unauthorized board → `FORBIDDEN`
- view guard
- OOB presence（从 server log 读 6 位码）→ 改头像
- sendMessage / mention
- 第二设备 → `DEVICE_MISMATCH`
- XSS：cross-action blocked、reuse blocked、wrong code blocked、allowed action once
- audit
- revoke → `DEVICE_REVOKED`

### 7.3 对抗（Playwright）

```bash
BASE_URL=http://127.0.0.1:8789 ... node src/test/browser/adversarial.mjs
# 5 passed, 0 failed
```

覆盖：

- 并发双花 → 一个 200，一个 409
- 旧 `/api/presence` → 410
- 错误 OOB code → `PRESENCE_CODE_INVALID`
- presence token 换 scope/body → `PRESENCE_SCOPE_MISMATCH`
- 匿名 audit → 401

---

## 8. 生产化建议

### 8.1 Top 3（来自 `REVIEW-V2.md`）

1. **把 OOB console code 换成真正的 WebAuthn UV + 可信显示**
   - 不要用 stdout 当带外通道；不要把 code 和 action/scope 一起打日志。
   - WebAuthn challenge 绑定 `{action, scopeHash, bodyHash, deviceId, view, nonce}`；服务端验证 origin/rpId/flags.UP/flags.UV/signCount。
   - 高价值动作在可信显示上确认交易详情（PSD2 dynamic linking）。

2. **把内存/HMAC 换成可事务化的 Store + 非对称/轮换 token**
   - `consumeCapability` / `issueChild` / `consumePresence` / `redeemChallenge` / `revokeDevice` 用 DB conditional update/CAS。
   - 多进程/多实例安全；加 idempotency/receipt lookup；加 per-capability revocation。
   - HMAC → 非对称签名/轮换/HSM。

3. **BFF + HttpOnly session + CSRF + 打包**
   - 当前 bearer session 在 JS memory；生产用 BFF、`__Host-` HttpOnly cookie、CSRF、rotation/logout。
   - 把 client core 打成库；server 拆 `store/`、`auth/`、`api/`、`authorizers/`；提供 framework adapters。
   - CSP/Trusted Types/SRI；demo lab 独立 origin；生产构建移除 `demo-hooks.js` 和 `window.secrecy`。

### 8.2 产品化取舍

| 场景 | 建议 |
|---|---|
| 普通 CRUD + 同源 session | 不要上 capability；session + CSRF + server policy 就够 |
| 有高危动作（支付、改头像、@全体、删除） | 只对高危动作做 per-action capability + presence |
| 需要 delegation/offline | 用 Biscuit/UCAN，不要自造 |
| 需要跨设备/多端 | 每设备一张 key；WebAuthn/passkey；不要共享私钥 |
| 需要审计/合规 | capability registry + append-only audit + per-device revocation |
| 纯静态托管 | 加 BFF/serverless，否则客户端检查不是安全边界 |

---

## 9. 如何运行

```bash
cd <repo>/mvc-secrecy
node src/server.js
# http://127.0.0.1:8787
# http://127.0.0.1:8787/?demo=1   (XSS lab + signing-oracle demo hook)
```

- 高危动作的 6 位 code 会打印在 **server 终端**。
- `node src/test/smoke.mjs`
- `node src/test/security.mjs`

浏览器测试（需要 Playwright）：

```bash
cd <repo>
PORT=8789 DEMO=1 node src/server.js > tmp/server.log 2>&1 &
BASE_URL=http://127.0.0.1:8789 \
SERVER_LOG=$PWD/tmp/server.log \
NODE_PATH=$(npm root -g) \
node src/test/browser/browser.mjs

BASE_URL=http://127.0.0.1:8789 \
SERVER_LOG=$PWD/tmp/server.log \
NODE_PATH=$(npm root -g) \
node src/test/browser/adversarial.mjs
```

---

## 10. 文件地图

```text
mvc-secrecy/
  README.md                 # 项目介绍 + quick start + 截图
  LICENSE
  package.json
  src/
    server.js               # HTTP API + verifier + MemoryStore + audit + rate limit
    server-policy.js        # server-only ACL/authorizers + policy validation
    public/
      index.html
      app.js                # MVC views/controllers + OOB modal + XSS lab
      secrecy.js            # 客户端 capability core (476 lines)
      protocol.js           # shared canonicalization/hash/proof/base64url
      presence.js           # PresenceProvider + WebAuthn stub + static code
      policy.js             # client-safe policy manifest
      demo-hooks.js         # demo-only signing oracle (?demo=1 / DEMO=1)
      styles.css
    test/
      smoke.mjs             # 11 checks
      security.mjs          # 19 checks
      browser/
        browser.mjs         # 18 Playwright UI checks
        adversarial.mjs     # 5 Playwright adversarial checks
  docs/
    DESIGN.md               # 架构/威胁模型/API/限制
    FINAL-REPORT.md         # 中文总报告（本文件）
    RESEARCH.md             # prior art / 标准 / 批评
    REVIEW.md               # reviewer v1 批评
    REVIEW-V2.md            # reviewer v2 批评
    V2-NOTES.md
    V2.1-NOTES.md
```

---

## 11. 最后一句

**MVC + S 的正确姿势不是“把 UI 藏起来”，而是：**

> **每个动作一张显式、最小权限、一次性、绑定设备、可审计、可撤销的 capability；issuance 是新的边界；同源 XSS 可以用掉当前一张，但不能无限续杯。**

这就是你这个 idea 最有价值的部分。
