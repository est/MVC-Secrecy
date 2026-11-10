# Prior Art — “MVC + Capability” / “MVC + S”

> 目标：回答“有没有人这么搞过”，并为 `mvc-secrecy/` 的设计提供依据。
>
> 结论：**没有主流 MVC 框架直接提供“视图上下文 → 每动作一次性、带 scope、绑定设备的 capability”这一层**。它是几条成熟路线的交集，不是一个新密码学原语。真正难的不是 token 格式，而是 **issuance、原子消费、用户在场、XSS 边界**。

---

## 1. Object-capability 基础

| 工作 | 时间 | 核心思想 | 对本项目的意义 |
|---|---:|---|---|
| Dennis & Van Horn, *Programming Semantics for Multiprogrammed Computations* | 1966 | capability 是“不可伪造的引用”，持有即授权 | “授权靠持有具体能力，不靠全局身份查表” |
| Saltzer & Schroeder, *The Protection of Information in Computer Systems* | 1975 | least privilege、fail-safe defaults、complete mediation | POLA / 最小权限 |
| Hardy, *The Confused Deputy* | 1988 | 有特权的 deputy 会被诱导滥用 ambient authority | 不能把“已登录”当成万能权限 |
| Miller, Yee & Shapiro, *Capability Myths Demolished* | 2003 | 反驳 Equivalence / Confinement / Irrevocability 三个迷思 | capability 可以 confinement、可以撤销（配合 indirection/expiry） |
| Miller, *Robust Composition* | 2006 | 组合、attenuation、revocation、membrane | scope/attenuation/撤销的理论基础 |
| Bussard & Molva, *One-Time Capabilities for Authorizations without Trust* | 2004 | 一次性凭证 + 本地验证 + 防双用 | “一次性 capability”的学术先例 |

**映射到 Web action：**

```text
capability = (issuer, subject, action, resource, context constraints,
              expiry, single-use id, device-key thumbprint, signature)
```

UI 不应持有 ambient authority（“用户登录了，所以什么都能做”），而应持有**服务器愿意授权的动作描述**；用户触发动作时，才申请一张具体的 capability。UI 是 capability 的**选择器/显示器**，不是授权者。

> 重要：object-capability 是一种设计纪律（无 ambient authority、显式引用），不是“用了 JWT 就叫 capability”。

---

## 2. Capability token 格式

| 格式 | 密码学/模型 | 离线衰减 | PoP/设备绑定 | 浏览器 JS | 成熟度/适用性 |
|---|---|---|---|---|---|
| **Macaroons** | 链式 HMAC + caveats + third-party caveats | ✅ 追加 caveat | ❌ 原生 bearer | 有，但 JS 库老旧 | 概念强；`macaroons.js` 最后发布 2022；新项目不建议 |
| **Biscuit** | 公钥签名 + Datalog + 追加 block + revocation ID | ✅ | 可加 `cnf`/proof，非内置 | ✅ WASM | spec v3.3；适合 delegation/attenuation |
| **UCAN** | 公钥 + DID + delegation chain + invocation + revocation | ✅ | ✅ 原生 key-based | ✅ `ucanto` | WG spec v1.0.0，**不是 IETF RFC**；web3/local-first |
| **ZCAP-LD** | Linked-data proofs + capability chain + invocation | ✅ | ✅ key-based | 技术可行，JSON-LD 重 | W3C CCG draft v0.4.0，**不是 Recommendation**；Solid 生态 |
| **GNAP** | Grant negotiation + key proof + continuation | 不是 token 格式 | ✅ | 浏览器生态薄 | RFC 9635（2024-10）；概念可借 |
| **OAuth 2.0 RAR** | `authorization_details` 结构化授权 | ❌ | 靠 DPoP/mTLS | ✅ | RFC 9396（2023-05）；适合 consent，不是 per-click |
| **DPoP** | 每请求 proof-of-possession JWT | ❌ | ✅ | ✅，但 key 存储是弱点 | RFC 9449（2023-09）；浏览器里是 damage limitation |
| **Token Binding** | TLS 层绑定 | ❌ | ✅ | ❌ | RFC 8471，**已废弃**；Chromium v70 移除 |
| **mTLS** | 证书绑定 token | ❌ | ✅ | 不适合普通 Web | RFC 8705；服务间强，浏览器不适合 |
| **HTTP Message Signatures** | 签名 method/URL/headers/body digest | ❌ | ✅ | 可行 | RFC 9421（2024-02）；比 DPoP 更适合 action-bound |
| **JWT/JOSE** | 签名/加密 claims | ❌ | 无原生 PoP | ✅ | 成熟基线；配 DPoP + 服务端消费 |

**推荐组合：** **PoP + 短 TTL + 服务端一次性消费**。需要 delegation/offline 时再加 Biscuit/UCAN；不要为了“capability 美学”上草案格式。

---

## 3. UI / 上下文授权 prior art

“Capability-based UI”不是标准术语；没有 RFC/主流框架。最接近的严谨工作：

- **User-driven access control** — Roesner et al., IEEE S&P 2012：权限在用户动作的**当下、上下文里**授予，而不是安装时一次性弹窗。这正是“view/context → action capability”的 UX 模型。
- **Sandstorm Powerbox** — 应用向平台请求一个“实现某接口的 capability”；平台弹出 picker；用户选具体对象；应用拿到的是**那个对象**的 capability，不是全局访问权。Sandstorm 还用“pseudo-ACL”追踪谁持有哪些 capability，解决“谁有访问权”的审计问题。
- **OWASP Transaction Authorization** — 每笔交易唯一授权凭证、服务端生成/校验、受控状态转换、有限有效期、防篡改。
- **PSD2 dynamic linking** — 认证码必须绑定到具体的金额和收款人；EMV 3-D Secure 也是 per-transaction cryptogram。这是“每动作/每交易授权”的真实生产证明。
- **Intent-based authorization (IBAC)** — 2025–26 的 AI agent 术语：从声明的 intent 派生 per-request 权限；可借概念，不是标准安全原语。
- **MVC 安全模式** — 授权必须在服务端；隐藏 UI 只是 UX，不是安全边界（Martin Fowler）。View 是 `(model state, allowed actions, redacted fields)` 的投影；Controller 只把用户意图映射成 action request；Model/domain service 拥有策略、capability、状态机和审计。
- **“Secrecy”作为信息隐藏** — Parnas 的 information hiding / need-to-know 是**数据最小化/投影**，不是授权。把 S 叫 “Secrecy” 容易混淆；建议叫 **Capability / Authority**，或明确 “Secrecy = need-to-know projection”。

---

## 4. 一次性 / 有状态 capability

| 机制 | 工作方式 | 适用 | 限制 |
|---|---|---|---|
| Server nonce challenge | 服务器发 nonce，客户端签名 nonce + context；服务器存 used nonces | 高危动作、freshness | 多一次往返；nonce store |
| `jti` + consume store | token 有唯一 ID；验证时原子 insert/mark used | 通用一次性 | 分布式一致性、重试语义 |
| Sequence numbers | 每设备单调计数器；服务器存 high-water mark/window | 设备发起的流 | desync、丢消息、多设备 |
| Hash chains / TESLA | 单向 key chain；按顺序 reveal preimage | 广播/流 | 时间同步、延迟；不适合交互 UI |
| One-time signatures | Lamport/Merkle/Winternitz：每消息一个 key | 低量、hash-based trust | key/signature 大；状态管理 |
| Capability chains | delegation link，每层衰减 parent | delegation/offline | 本身不是一次性；验证成本 |
| Transaction authorization | 每交易凭证绑定金额/收款人；服务器状态机 | 支付/高价值 | 合规/UX 重；需要可信显示 |
| Idempotency keys | 去重重试；存结果 | exactly-once *effect* | 不是安全 token；要存响应 |

**关键先例：**

- **TBAC**（Thomas & Sandhu, 1997）：权限随 task/workflow 激活、跟踪、暂停、消费、撤销。直接对应“action 消费 capability”。
- **UCON ABC**（Park & Sandhu, 2004）：continuity + mutability，适合状态机语义。
- **One-time capabilities**（Bussard & Molva, 2004）。
- **TESLA**（RFC 4082, 2005）：hash-chain 广播认证。
- **Forward-secure signatures**（Bellare & Miner, 1999）：key 演化，当前 key 泄露不能伪造过去签名。
- **HOTP/TOTP**（RFC 4226/6238）：部署广泛的一次性认证，但认证的是“用户”，不是“具体动作”。
- **OWASP transaction authorization**：唯一凭证 + 服务端状态 + 有限有效期 + 受控转换。

**Exactly-once 是迷思。** “一次性”应定义为 **at-most-once successful effect**，需要：唯一 `jti`、原子 consume、状态机（issued → presented → reserved → executed → consumed）、idempotency key、以及消费与业务效果的同一事务/outbox/saga。

---

## 5. 浏览器安全模型

### 5.1 同源 XSS 是主威胁

- 同源 JS 拥有和 app 一样的权限：读 DOM、调用 API、读 IndexedDB、**调用 non-extractable key 签名**。
- RFC 9449 §11.4 明确：如果攻击者能在 client context 执行代码，DPoP 不再保证安全；non-extractable key 只防**导出**，不防**使用**。
- BFF 能减少 token 暴露，但不能阻止同源 XSS 带着用户 session 调 BFF。
- 真正有效的缓解：**预防 XSS**（CSP/Trusted Types/SRI/COOP/COEP/sandboxed iframe）+ **缩短 TTL** + **一次性消费** + **服务端异常检测** + **高危动作用户在场**。

### 5.2 WebCrypto / IndexedDB

- `crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, false, ["sign","verify"])` → private key non-extractable。
- `CryptoKeyPair` 可 structured-clone 到 IndexedDB；Chrome/Safari 实测可跨页面重载复用（Firefox 曾有 Bug 1348279，需验证当前版本）。
- `RTCCertificate` 也可持久化，但只用于 DTLS，不是通用 crypto key。
- 不要把 extractable key 放 localStorage；那等于放弃设备绑定。

### 5.3 WebAuthn / passkeys

- WebAuthn Level 3 是 W3C Recommendation（2026-08）。
- WebAuthn 是**抗钓鱼认证**，不是 authorization；assertion 签的是 challenge，authenticator UI 默认不显示“给谁转多少钱”。
- 高危动作要 **UV（user verification）+ 交易详情绑定 + 可信显示**；PSD2 dynamic linking 是成熟参考。
- Synced passkeys 可能跨设备同步；“device-bound”要用 device-bound passkey/security key。

### 5.4 DPoP 在浏览器

- 可行：non-extractable P-256 key + 每请求 proof JWT。
- 但 RFC 10017（Browser-Based Apps BCP, 2026-08）仍推荐 **BFF pattern**；浏览器是 hostile execution environment。
- DPoP proof 覆盖 method/URL，不覆盖 body；action 绑定要加 body hash / RFC 9421。

### 5.5 防御纵深

| 控制 | 帮助 | 不解决 |
|---|---|---|
| CSP3 | 阻止 inline/未授权 script | 同源被允许/被攻陷的 script |
| Trusted Types | 结构性阻止 DOM XSS sink | 逻辑 bug、服务端注入、恶意依赖 |
| SRI | 检测第三方 script 篡改 | 动态 import、被攻陷的 origin |
| COOP/COEP/CORP | 跨源隔离、Spectre 缓解 | origin 内部 XSS |
| Sandboxed iframe | 不可信内容放 opaque origin | 同源 app code；postMessage bug |
| 独立 origin/tenant | 限制 cookie/storage/authority 范围 | 共享后端被攻陷 |

---

## 6. 现有产品/实验

| 东西 | 展示了什么 | 限制 |
|---|---|---|
| **Sandstorm** | capability-based web app 平台：grains、Powerbox picker、Cap’n Proto capabilities、pseudo-ACL | 平台级，不是 MVC；不是 per-action one-time |
| **Waterken web-key / Capper** | capability URL 作为 authority | 泄露/撤销问题；bearer URL |
| **Agoric SES / CapTP / Endo** | object capabilities + secure JS composition | runtime/framework，不是 web MVC auth |
| **LND macaroons** | 生产级可衰减 bearer token（caveats: permissions/IP） | bearer；无 PoP；不是一次性 |
| **HashiCorp Vault response wrapping** | 单次、限时 wrapping token；服务端消费 | secret delivery，不是 UI action |
| **AWS S3 presigned URL** | 限时、限定操作的 capability URL | 到期前可重复；URL 泄露 |
| **Google Docs / Dropbox / GitHub gist share link** | 主流 capability URL | bearer、长寿命、粗粒度撤销 |
| **AT Protocol permission sets** | 细粒度 OAuth scope（`repo:`/`rpc:`/`blob:`/`account:`）+ DPoP-bound token | 有 scope，不是 per-action/one-time |
| **UCAN / Storacha** | 可委托、可衰减的 storage capability；DID chain | web3 生态；spec 非 IETF；库 churn |
| **ZCAP-LD / Solid** | linked-data capability chain + invocation proof | CCG draft；JSON-LD 复杂；niche |
| **PSD2 SCA dynamic linking / EMV 3DS** | per-transaction authorization 绑定金额/收款人；服务端状态机 | 支付专用；合规/UX 重 |

---

## 7. 为什么 per-action capability 会失败（批评清单）

1. **Issuance 是新的边界。** `/cap` 是 policy oracle + mint；策略错/被攻陷，per-action 粒度只是把攻击拆成更小的请求。
2. **XSS 绕过“设备绑定”。** non-extractable key 是签名 oracle；同源 XSS 可以申请 capability、签 proof。只能靠防 XSS + 短 TTL + 一次性 + 异常检测。
3. **无状态 token 可重放。** 没有 `jti` store 的签名 JWT 不是一次性；加了 store 就有分布式一致性问题。
4. **Exactly-once 是迷思。** 重试/超时/崩溃需要 idempotency + 状态机。
5. **View/context desync 与 TOCTOU。** 用户看到“PNG ≤1KB”，客户端发“JPEG ≤100MB”；服务器必须从权威状态重算 context hash，并绑定资源版本/ETag。PSD2 dynamic linking 是成熟答案。
6. **DoS on mint/verify。** 每动作 mint 是放大点；限流、限制 token 大小、先验签再查 DB/策略、限制 delegation 深度。
7. **UX 摩擦。** 每次点击都 passkey/consent 会毁掉可用性；低危用短 TTL session-scoped capability，高危才 per-action + UV。
8. **Key management。** 多设备、轮换、丢失、隐私模式、Firefox IndexedDB CryptoKey、synced passkeys、recovery。
9. **Revocation。** 无状态 capability 到期前无法撤销；短 TTL + per-device revocation + user epoch + deny list。
10. **Auditability。** 纯 capability 回答不了“现在谁有访问权”；需要 capability registry/pseudo-ACL（Sandstorm 的 insight）。
11. **Capability URL 泄露。** history/log/Referer/screenshot/chat/第三方 script；W3C TAG Good Practices for Capability URLs。
12. **Attenuation 不是免费的。** caveat/Datalog/policy 语言容易配错；third-party caveat 增加 discharge 复杂度。
13. **标准/采用风险。** UCAN/ZCAP 不是 IETF/W3C Recommendation；GNAP 浏览器生态薄；Token Binding 已死；macaroons.js 老旧。
14. **“Secrecy” 可能变成 security by obscurity。** 如果 S 只是隐藏 UI/字段，它不是授权模型；要区分 confidentiality（need-to-know projection）和 authorization（capability）。
15. **延迟/可用性。** 每动作一次 mint 往返；mint 服务挂了 app 变只读；设计 degraded mode。

---

## 8. 该借什么 / 不该做什么

### 借

- **POLA / no ambient authority**：每个动作显式、最小权限。
- **Attenuation/caveats**（Macaroons/Biscuit/UCAN）：需要 delegation/offline 时再用；优先 Biscuit 而不是老 Macaroons。
- **DPoP-style PoP** + non-extractable device key + 短 TTL + `cnf`/JWK thumbprint + server nonce。
- **RAR-style structured `authorization_details`**：action/resource/amount/payee/context 的 JSON 形状。
- **GNAP 的 grant/key-proof/continuation 概念**：多步审批/delegation；不必上整个协议。
- **TBAC/UCON**：task-scoped permissions、consumption、continuity、状态机。
- **Sandstorm Powerbox**：用户在选择器里授予具体对象；pseudo-ACL 做审计。
- **OWASP transaction authorization / PSD2 dynamic linking**：per-action 绑定展示内容、服务端生成、唯一凭证、受控状态转换。
- **ReBAC/ABAC at mint time, capability at use time**：OpenFGA/SpiceDB/Cerbos/Oso 做 `can()`；结果装进 capability；enforcement point 原子消费。
- **BFF pattern**（RFC 10017）+ HttpOnly session + CSRF。
- **CSP/Trusted Types/SRI/COOP/COEP/sandboxed iframe** 作为 defense-in-depth。

### 不借

- 不要把隐藏 UI 当安全。
- 不要把 capability 放 URL/localStorage/长寿命 JWT；用 HttpOnly session 或 in-memory/IndexedDB key；`Referrer-Policy: no-referrer`；`Cache-Control: no-store`。
- 不要指望 non-extractable key 阻止 XSS；它只阻止导出。
- 不要从纯客户端静态 app 签发 per-action capability；没有 trust anchor。
- 不要把无状态 JWT 叫“一次性”；一次性需要服务端状态/challenge。
- 不要自造 crypto/token 格式；用 `jose`/WebCrypto/Biscuit/UCAN。
- 不要用 Token Binding（已废弃）。
- 不要用 mTLS 做普通浏览器客户端。
- 不要用 `macaroons.js` 新项目。
- 不要为了 capability 美学上 UCAN/ZCAP/GNAP；只在需要 DID/linked-data/delegation 时用。
- 不要每次点击都 passkey/consent；risk-based step-up。
- 不要信任客户端传来的 view/context；服务端重算 context hash + resource version。
- 不要把 confidentiality 和 authorization 混为一谈。
- 不要忘记 idempotency/retry；exactly-once 不可达。
- 不要跳过 audit：capId/action/resource/context hash/decision/consumption/device key ID。

---

## 9. 推荐的最小架构（与 `mvc-secrecy/` 对应）

```text
Browser (MVC View)
  ├─ HttpOnly session cookie + CSRF
  ├─ non-extractable device key (IndexedDB)
  └─ view/action descriptors
        │
        ▼
BFF / serverless API (Controller + PEP)
  ├─ POST /cap        → policy/ACL check → mint short-lived capability
  ├─ POST /action     → verify capability + PoP + context + consume
  └─ policy engine    → plain code | Cerbos | Oso | OpenFGA/SpiceDB
        │
        ▼
Domain model / DB (Model)
  ├─ business transaction
  ├─ used_cap / idempotency store
  └─ audit log
```

**关键点：**

1. **Authenticate**（WebAuthn/passkey 或 OIDC）；HttpOnly `__Host-session` + CSRF。
2. **Enroll device key**；注册 PoP；多设备/撤销。
3. **Server-side action manifest**；view model 只返回 allowed action descriptors + `contextHash`。
4. **服务端重算 contextHash**：view ID、resource ID、resource version/ETag、action params、policy version、server nonce。
5. **Mint on intent**：session + action + resource + contextHash；高危 step-up；60s TTL。
6. **Present with proof**：DPoP 或 RFC 9421，覆盖 method/URL/body hash/nonce。
7. **Verify in order**：size/alg → signature → claims → `cnf.jkt` → contextHash → replay → policy/state → execute。
8. **Consume atomically**：`INSERT ... ON CONFLICT DO NOTHING` / `SET NX` / conditional update；业务效果同事务/outbox；idempotency key。
9. **Render actions from server descriptors**；隐藏/禁用只做 UX。
10. **Revoke**：短 TTL + per-device + user epoch + policy version。
11. **Harden**：CSP/Trusted Types/SRI/COOP/COEP/sandbox；限流；audit。
12. **Upgrade path**：需要 offline delegation 时 JWT → Biscuit；需要 DID 时 UCAN；保持 mint/verify/consume 边界不变。

---

## 10. 参考链接

- Dennis & Van Horn 1966: https://dl.acm.org/doi/10.1145/365230.365252
- Saltzer & Schroeder 1975: https://www.cs.virginia.edu/~evans/cs551/saltzer/
- Hardy, Confused Deputy 1988: https://dl.acm.org/doi/10.1145/54289.871709
- Miller, Capability Myths Demolished 2003: https://papers.agoric.com/assets/pdf/papers/capability-myths-demolished.pdf
- Miller, Robust Composition 2006: https://papers.agoric.com/assets/pdf/papers/robust-composition.pdf
- Bussard & Molva 2004: https://dl.acm.org/doi/10.5555/977406.978674
- Macaroons NDSS 2014: https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/
- Biscuit spec: https://doc.biscuitsec.org/reference/specifications.html
- UCAN spec: https://github.com/ucan-wg/spec
- ZCAP-LD: https://w3c-ccg.github.io/zcap-spec/
- GNAP RFC 9635: https://www.rfc-editor.org/rfc/rfc9635.html
- OAuth RAR RFC 9396: https://www.rfc-editor.org/rfc/rfc9396.html
- DPoP RFC 9449: https://www.rfc-editor.org/rfc/rfc9449.html
- HTTP Message Signatures RFC 9421: https://www.rfc-editor.org/rfc/rfc9421.html
- Token Binding RFC 8471 (abandoned): https://www.rfc-editor.org/rfc/rfc8471.html
- mTLS RFC 8705: https://www.rfc-editor.org/rfc/rfc8705.html
- WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- OAuth Browser-Based Apps BCP RFC 10017: https://www.rfc-editor.org/rfc/rfc10017.html
- OWASP Transaction Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html
- Sandstorm: https://sandstorm.io/how-it-works
- W3C TAG Capability URLs: https://www.w3.org/2001/tag/doc/capability-urls/
- TBAC: https://profsandhu.com/confrnc/ifip/i97tbac.pdf
- UCON ABC: https://dl.acm.org/doi/10.1145/984334.984339
- TESLA RFC 4082: https://www.rfc-editor.org/rfc/rfc4082.html
- Forward-secure signatures: https://eprint.iacr.org/1999/016
- Oso: https://www.osohq.com/
- Cerbos: https://www.cerbos.dev/
- OpenFGA: https://openfga.dev/
- SpiceDB: https://authzed.com/docs/spicedb/concepts/zanzibar
- Permify: https://permify.co/
- Casbin: https://casbin.org/
- OPA: https://www.openpolicyagent.org/
- AT Protocol permission sets: https://atproto.com/guides/permission-sets
- LND macaroons: https://github.com/lightningnetwork/lnd/blob/master/docs/macaroons.md
- Vault response wrapping: https://developer.hashicorp.com/vault/docs/concepts/response-wrapping
- S3 presigned URLs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
