# REVIEW-V2 — MVC + Secrecy v2

> Historical artifact: code paths in this document refer to the v1/v2 layout. Current source is under `src/`, docs under `docs/`.

**Reviewer note:** strict second-pass security/API review. No code was modified; this file is the only output. Probes were black-box HTTP calls against the running v2 demo and added demo users/posts to the in-memory server (a restart resets it).

**Artifacts read:** `server.js`, `server-policy.js`, `public/protocol.js`, `public/secrecy.js`, `public/presence.js`, `public/app.js`, `public/demo-hooks.js`, `public/policy.js`, `public/index.html`, `DESIGN.md`, `README.md`, `V2-NOTES.md`, `test/smoke.mjs`, `test/security.mjs`, `test/helpers.mjs`, and the v1 `REVIEW.md`.

**Test status (as reported by the main agent):** `test/smoke.mjs` 11/11, `test/security.mjs` 11/11, Playwright browser v2 18/18, Playwright adversarial v2 5/5. I did not re-run Playwright; I re-read the checked-in suites and ran the targeted probes below.

**Additional probes run for this review:**

| Probe | Result |
|---|---|
| v1 P0-1 regression: 10 parallel `POST /api/action` with one capability/proof over independent raw sockets | **1 × 200, 9 × 409 `CAPABILITY_CONSUMED`, 1 business write** — fixed |
| New PoP regression: 2 parallel `POST /api/register` with the same challenge + proof | **2 × 200, same `deviceId`, two sessions**; sequential replay is 403 — **new issue N1** |
| `deviceJkt` in registration response | Present, 64 hex chars |
| Unauthorized board `b_secret_tenant` | 403 `FORBIDDEN`; `b1` 200 — v1 P0-4 fixed for arbitrary IDs |
| Canonical key re-register after revoke | 403 `DEVICE_REVOKED` |
| Padded JWK challenge | 400 `INVALID_JWK` — v1 P0-5 fixed |

---

## 1. Verdict

v2 is a strong teaching prototype and a credible design starting point — the v1 action double-spend, presence-scope substitution, arbitrary-scope issuance and JWK-encoding revocation bypass are fixed and verified — but it is not yet a reusable library: registration PoP is replayable under concurrency, presence is a demo-only console channel with a code-only provider seam, and ambient chat-membership writes plus session/ACL/packaging gaps remain.

---

## 2. Fixed / remaining table (v1 `REVIEW.md` P0/P1)

### 2.1 P0 findings

| ID | v1 issue | v2 status | Code evidence |
|---|---|---|---|
| P0-1 | Concurrent double-spend | **Fixed** | `server.js:1284-1308`; `MemoryStore.consumeCapability` `server.js:540-554`; raw 10-way probe; `test/security.mjs:193-199` 2/50 raw-socket tests |
| P0-2 | Presence was a client-only/forgeable gate | **Partially fixed (demo-only)** | OOB endpoints `server.js:917-1054`; old route 410 `server.js:1553-1559`; `isTrusted`/`grantPresence` removed. But code is logged (`server.js:969-973`), same-page XSS can keylog the typed code, and the unit is a demo channel, not WebAuthn (docs: `DESIGN.md:369-373`, `README.md:206-208`) |
| P0-3 | Presence token not bound to scope/body | **Fixed** | Challenge/token carry `scopeHash`/`bodyHash` (`server.js:953-965`, `1026-1036`); consume checks both (`server.js:596-601`); substitution tests `test/security.mjs:248-264` |
| P0-4 | Scope client-declared, never authorized | **Partially fixed** | Server authorizer at issue/use (`server.js:783-786`, `1278-1282`; `server-policy.js:27-82`); arbitrary `b_secret_tenant` 403. But `board.write` is an allowlist that ignores the principal (`server-policy.js:28-33`); only chat has membership. See N7 |
| P0-5 | JWK re-encoding revocation bypass | **Fixed** | Strict canonical JWK (`server.js:151-181`), RFC 7638 thumbprint (`197-200`), PoP registration (`653-761`); padded/whitespace rejected, canonical revoked key 403. New PoP replay is N1 |

### 2.2 P1 findings

| ID | v1 issue | v2 status | Code evidence / remaining gap |
|---|---|---|---|
| P1-1 | `deviceJkt` was `undefined` | **Fixed** | `publicDevice` `server.js:207-216`; register response `753-760`; payload `863-881`; smoke asserts it `test/smoke.mjs:54-60` |
| P1-2 | Registration had no proof-of-possession | **Partially fixed** | PoP added `server.js:653-761`; but challenge check is before two awaits and `used=true` is set after them (`661-673`, `685-697`) — replay N1; no register rate limit |
| P1-3 | Revocation incomplete/racy | **Fixed in single process; partial for production** | Commit re-checks device/record (`server.js:1285-1308`), store checks `record.revoked` (`540-554`), in-flight test `test/security.mjs:660-703`. Still no per-cap/account revoke; state/audit are read-only after revoke by design (`1381`, `1429`) |
| P1-4 | Audit unauthenticated/incomplete/forgeable | **Mostly fixed** | Auth/scoping `server.js:1428-1475`; fields `363-384`; admin token `1430-1432`; denied userId fixed via `req._auth`. Remaining: non-admin raw `scopeHash`/`bodyHash` (`1461-1462`), admin compare not timing-safe, no dropped counter/hash chain/requestId, no audit rate limit (N8/N9) |
| P1-5 | `maxUses` structurally one-use | **Fixed by narrowing** | Policy validation requires `maxUses === 1` (`server-policy.js:145-147`); store counter still there (`server.js:546-550`). Multi-use is explicitly out of scope (`DESIGN.md:314-318`) |
| P1-6 | No policy validation; immortal caps | **Mostly fixed** | `validatePolicy` `server-policy.js:106-190`; boot call `server.js:21`; tests `test/security.mjs:639-658`. Remaining: view names not pattern-checked (`server-policy.js:117-118`), scope/body type sets not category-separated (`96-104`), type registry duplicated (`server.js:249-298` + `server-policy.js:16-25`) |
| P1-7 | HMAC symmetric/redundant | **Remains by design** | `server.js:38-43`, `135-144`; secret length checked (`38-40`); store remains authority; docs `DESIGN.md:210-214`. Not a bug for the demo, not a library-grade token format |
| P1-8 | Hand-rolled DPoP gaps | **Partially fixed** | Proof now binds method/path/action/view/JKT/scope/body/seq/nonce/prevHash (`public/protocol.js:137-152`); JKT checked (`server.js:1209-1211`). Still no `iat`/`jti`/`ath`/server nonce, no `parentCap`, proof verified after state checks (`1252-1266`). See N10 |
| P1-9 | Two-step didn't bind content; parent burned at issue | **Mostly fixed** | `post:edit` stores `draftId`/`draftHash` (`server.js:1112-1126`); child scope checked (`817-827`); reissue after unused expired child (`829-848`); tests `test/security.mjs:705-791`. **But the final draft is not re-hashed at use** (N6); links still client-memory (`secrecy.js:302-307`) |
| P1-10 | Demo hook always on | **Partially fixed** | Instance/global gated (`secrecy.js:97`, `app.js:21,33,38`); file is still served (`index.html:39`) and `DemoHooks`/`Secrecy` are globals (`demo-hooks.js:108`, `secrecy.js:466`); any same-origin script can instantiate (N11) |
| P1-11 | Protocol triplicated; `__proto__` non-injective | **Fixed** | Shared `public/protocol.js` used by browser/server/tests; null-prototype canonicalization and dangerous-key rejection (`53-76`); strict base64url (`113-135`); proof strings (`137-156`) |
| P1-12 | `execute(action, params)` conflated scope/body; global view | **Improved, partial** | New `execute(action,{scope,body})` (`secrecy.js:221-310`), `view()`/`can()`/`actions()` (`116-145`), richer errors. App still uses `enterView` (`app.js:152`); `view()` is not exercised; provider seam is code-only; no idempotency/AbortSignal; `_links` keyed by action (`302-307`) |
| P1-13 | Session/auth hardening; `/api/state` expiry bug | **Partially fixed** | POST content-type enforced (`server.js:1542-1547`); state 401 (`1381`); audit 401 (`1429`). Still JS bearer, 24h, no rotation/logout/CSRF/Origin/BFF; docs honest (`DESIGN.md:520-535`) |
| P1-14 | Unbounded resources / no rate limits | **Partially fixed** | Fixed-window limits `server.js:393-406`, calls at `625,770,920,988,1164,1481`; no limits on register, state, audit or chat; per-device keys are Sybil-able; caps/drafts/users/sessions still unbounded (`51-65`, `1666-1683`) |
| P1-15 | `/api/state` over-exposed | **Mostly fixed** | Auth and scoping `server.js:1380-1425`; users/messages/drafts/caps scoped; no `parentCap`/`prevHash` in capability summaries. Remaining: feed spans all visible boards (`1382`,`1420`), `viaCap` is returned unmasked (`feed`/`messages`), revoked sessions still read state/audit by design |

**Bottom line:** most of the v1 P0s are genuinely fixed for the demo's stated threat model — action double-spend, presence-scope substitution, arbitrary-scope issuance and JWK re-encoding. Presence remains a demo-only OOB channel, and board authorization remains an allowlist. The remaining P0-class risk is the registration PoP race (N1), which is the same check→await→act class as the v1 action double-spend. Everything else is P1/P2 hardening or an explicitly demo-only choice.

---

## 3. New issues introduced by v2

### N1 — Registration PoP challenge is replayable under concurrency (P1-high; confirmed)

**Locations:** `server.js:661-673` (challenge check), `server.js:685-692` (`await importVerifyKey` / `await subtle.verify`), `server.js:697` (`challengeRecord.used = true`), `server.js:653-761` (no rate limit on `/api/register`).

**Evidence:** two independent raw-socket `POST /api/register` requests with the same challenge and proof both returned **200**, produced the **same `deviceId`**, and returned **two different sessions**. A third sequential replay returned 403 `INVALID_REGISTRATION_CHALLENGE`. `handleRegisterChallenge` (`640-641`) invalidates a previous challenge only when a *new* challenge is requested; it does not make the existing challenge single-use under concurrency.

**Impact:**
- The documented "single-use" PoP challenge (`DESIGN.md:155-157`) is not single-use.
- An attacker who captures a registration request (demo runs HTTP; logs/proxies in real deployments) can mint a session for that device without the private key. That session can call `/api/revoke` (device DoS), read `/api/state` and `/api/audit`, and mint capabilities (though it cannot sign action proofs).
- Concurrent replay can mint many sessions for one device within the 60 s challenge window; sessions are unbounded (`sessions` map, `737-743`), so this is also a memory/session flood.
- Invalid proofs leave the challenge valid (`697` runs only after a valid proof), and `/api/register` has no rate limit, so an attacker can spam expensive ECDSA verifies and audit entries with one challenge.

**Fix:**
- After `await subtle.verify`, re-check `challengeRecord.used` and `challengeRecord.exp`, then set `used = true` **in one synchronous block** before creating the device/session. A `Store.consumeRegistrationChallenge(challenge, jkt, now)` conditional update is the reusable form:
  ```sql
  UPDATE registration_challenges
  SET used = 1, used_at = ?
  WHERE challenge = ? AND used = 0 AND exp > ? AND jkt = ?
  RETURNING challenge;
  ```
  Zero rows => `INVALID_REGISTRATION_CHALLENGE`.
- Add `attempts` to the registration challenge and burn it after N invalid proofs; rate-limit `/api/register` per IP and per JKT, not only `/api/register/challenge`.
- Cap sessions per device and rotate/invalidate old sessions on re-registration, or make registration idempotent for a device.
- Add a 2/50-way PoP replay test: exactly one 200, one `INVALID_REGISTRATION_CHALLENGE`, one session; then a sequential replay must fail. This test is missing from `test/security.mjs`.

**Verdict on this item:** this is the one remaining **P0-class atomicity bug** if registration proofs are in scope as capturable secrets. At minimum it is a must-fix P1 before calling the layer reusable.

---

### N2 — OOB presence code is logged with action/scope/body; the "separate channel" is demo-only

**Locations:** `server.js:951` (code generation), `server.js:969-973` (`console.log` includes `challenge`, `code`, `action`, `device`, `scope`, `body`, `exp`); `test/security.mjs:105-106` parses the code from stdout; docs `DESIGN.md:369-373`, `README.md:206-208`.

**Evidence:** the code is intentionally printed only to server stdout, and the security test depends on reading it. The log line contains the full normalized scope/body; for `changeAvatar` the body includes a free-text `reason` (`policy.js:57`).

**Impact:**
- Anyone with access to stdout/logs (developer terminal, CI logs, container log aggregation, process supervisor) can approve a high-risk action. The "separate channel" is only separate from HTTP; it is not necessarily a trusted user channel.
- The code is printed at challenge creation, before the user approves; a log reader can use it within the 90 s window.
- Same-page XSS can read the code after the user types it (docs acknowledge). It can also replace the modal and capture the code. This is not WebAuthn UV.
- Logging the body/scope can leak sensitive transaction data.

**Fix:**
- Introduce a server-side `PresenceChannel` abstraction: `request({ challenge, code, action, scope, body })` with a default CLI/demo implementation and no code in logs by default. Only the test channel (under `ALLOW_TEST_HOOKS=1`) may print codes.
- Redact `body`/`scope` in logs; log hashes or a transaction ID instead.
- For production, replace with WebAuthn UV and server-side assertion verification; do not use stdout as an approval channel.
- Add a test that production mode emits no code to stdout and the HTTP response never contains it; keep the test-channel capture only under the test flag.

As a teaching demo, the console channel is acceptable if labeled; as a library default, it is not.

---

### N3 — Presence is consumed at issuance, not at action (P2 design; P1 for high-value actions)

**Locations:** `server.js:788-796` consumes the presence token during `POST /api/capabilities`; `handleAction` `server.js:1161-1374` has no presence check; capability TTL for `changeAvatar` is 120 s (`policy.js:55-62`), presence token TTL is 30 s (`server.js:30`); `DESIGN.md:360-361` states consumption at issuance; `V2-NOTES.md:95-96` lists it as an open question.

**Impact:** after a user approves a specific `changeAvatar` transaction, the resulting one-use capability can be used for up to 120 s without any further presence check. A stolen capability + proof can be used in that window; the scope/body binding limits the blast radius to the approved transaction, so this is not the v1 "approve a benign scope, substitute another" bug. For high-value transactions, however, presence should gate the final action, not only minting.

**Fix:** add a policy mode (`presence: "issue" | "action"`); for action mode, require a presence token at `/api/action`, bound to the final `bodyHash`/`scopeHash`, and consume it in the commit block. At minimum, make the capability TTL ≤ presence token TTL for presence-gated actions and document that the approval covers a 120 s window.

---

### N4 — The `PresenceProvider` seam cannot actually carry a WebAuthn assertion (P1/P2 API)

**Locations:** `public/presence.js:20-49` (base + WebAuthn stub); `public/secrecy.js:258-273` (`codeValue?.code`, then `POST /presence/verify {challenge, code}`); `server.js:985-1053` (verify accepts only a six-digit `code`); `README.md:160-165` says a production provider returns a WebAuthn assertion.

**Evidence:** a provider that returns a WebAuthn assertion object has no `.code`; `_execute` turns it into `undefined` and throws `PRESENCE_CANCELLED`. If a provider wraps the assertion as `{ code: assertion }`, the server rejects it with `PRESENCE_CODE_INVALID` because `server.js:1006` requires `/^\d{6}$/`. `WebAuthnPresenceProvider` is an explicit throwing stub (`presence.js:35-48`).

**Impact:** the advertised provider seam is really an OOB-code seam. Swapping in WebAuthn requires changing the client, the server endpoint and the presence token model; it is not a drop-in provider. This undermines the "pluggable presence" design and the production path.

**Fix:** define a typed presence proof:
```ts
type PresenceProof =
  | { kind: "oob"; code: string }
  | { kind: "webauthn"; assertion: PublicKeyCredentialJSON };
```
The client sends `presenceProof` (or `code`/`assertion`), and the server selects a verifier (`oob` vs `webauthn`) under a `PresenceVerifier` registry. Bind the challenge to `{deviceId, action, view, scopeHash, bodyHash, serverNonce}` and verify `clientDataJSON`, origin, rpIdHash, UP/UV, signature, and signCount for WebAuthn. Add a contract test with a fake assertion verifier. The UI provider should receive the server challenge response's `scopeHash`/`bodyHash`, not only client-computed values.

---

### N5 — `/api/chat/join` and `/api/chat/leave` are ambient writes outside the capability layer (P1/P2 design)

**Locations:** `server.js:1515-1531` (`handleChatMembership`), routes `server.js:1564-1565`; docs `DESIGN.md:441-442` calls them "Demo membership mutation".

**Evidence:** both endpoints require only `requireAuth`; there is no `serverPolicy.authorize` call, no capability, no scope, no presence and no rate limit. `test/security.mjs:358-371` uses `/api/chat/leave` to demonstrate ACL continuity, but the endpoint is reachable by any active session in the normal app.

**Impact:** any authenticated device can mutate chat membership without a capability. This contradicts the central "business writes require capabilities" model. An XSS can remove the user from `c_general` (self-DoS) and rejoin; if an admin removal flow is added, the user can rejoin on their own. It is not cross-user escalation today, but it is an unguarded write path and a test backdoor.

**Fix:** make `chat.join`/`chat.leave` capabilities (scope `{chatId}`, server authorizer, possibly presence/admin), or gate them behind `ALLOW_TEST_HOOKS`/an admin token and remove them from the production API. Add rate limiting and audit the decision, not only the mutation.

---

### N6 — The final draft is not re-hashed at use; `V2-NOTES.md` is inaccurate

**Locations:** `server.js:1112-1126` computes `draftHash = sha256(body.text)` at `post:edit`; `server.js:1129-1140` compares the **stored** `draft.draftHash` to `scope.draftHash` and `draft.boardId` to `scope.boardId`; there is no `sha256(draft.text)` in `post:submit`.

**Evidence:** `V2-NOTES.md:43-45` says "the final draft is re-hashed at use". It is not. The handler trusts `draft.draftHash`; if `draft.text` can be changed by a future edit endpoint, an admin/DB operation, or a memory bug without updating the stored hash, the submit publishes text that was never covered by the approved hash. (Today the draft has no mutation endpoint, so the practical impact is limited; this is a reusable-library correctness gap.)

**Fix:** at `post:submit`, recompute `const actualHash = sha256(draft.text)` and require `actualHash === scope.draftHash` **and** `actualHash === draft.draftHash`; otherwise `DRAFT_HASH_MISMATCH`. Add a test hook or a real draft-edit action that mutates `draft.text` between edit and submit and assert the submit fails. Correct `V2-NOTES.md:43-45`.

---

### N7 — `board.write` is a resource allowlist, not a per-principal ACL

**Locations:** `server-policy.js:13` (`BOARDS = {"b1","b2"}`), `server-policy.js:28-33` (`board.write(scope)` ignores `auth`), `server-policy.js:192-194` (`visibleBoards` returns all), `server.js:1382/1420` (state feed over all visible boards).

**Evidence:** the v1 P0-4 attack (arbitrary `b_secret_tenant`) is fixed: 403 `FORBIDDEN`. But any registered user can write and read `b1`/`b2`; there is no board membership/ownership relation. Only `chat.write` (`35-43`) and `chat.mention` (`45-57`) check the principal. `self.profile` (`59-62`) is self-only.

**Impact:** the demo's board ACL is public-write/public-read with a resource allowlist. If the design is presented as "server-side ACL authorization", a reader may assume per-user board authorization that does not exist. For a multi-tenant deployment this is an authorization gap, not just a demo choice.

**Fix:** either model board membership/ownership (Zanzibar-style `board:editor`) and check it in `board.write` and `visibleBoards`, or rename the authorizer `board.publicWrite` and document that boards are public. Add a test where user A is denied user B's board; keep the existing arbitrary-ID test as regression.

---

### N8 — Audit/state redaction and admin hardening

**Locations:** `server.js:1450-1468` (non-admin map), `1457-1463` (mask `capId`/`deviceId`/`parentCap`), `1461-1462` (**raw `scopeHash`/`bodyHash`**), `1464` (raw `resultId`), `1430-1432` (admin token string compare), `33` (`ADMIN_TOKEN` no length validation), `1472` (`total` is filtered length), `382` (5,000 cap, silent shift); `server.js:67-87/1420-1421` feed/messages still include full `viaCap`.

**Impact:**
- Non-admin audit masks IDs but returns deterministic `bodyHash`/`scopeHash`; for low-entropy bodies/reasons an audit reader can dictionary-confirm the content.
- `viaCap` in `/api/state` exposes full capability IDs for other users' posts/messages, inconsistent with audit masking. A cap ID alone is not authority without the envelope/proof, but it is a correlation leak.
- Admin token comparison is not timing-safe, has no minimum length, no rate limit, and no audit of admin access. `ADMIN_TOKEN` defaults empty (safe), but a weak env value is easy to brute force.
- No dropped-event counter, no hash chain, no `requestId`; docs admit in-memory/non-tamper-evident (`DESIGN.md:425`).

**Fix:** omit or mask `scopeHash`/`bodyHash`/`resultId` for non-admin (or make them admin-only); mask `viaCap` in state; use `crypto.timingSafeEqual` for the admin token, require ≥32 chars, rate-limit admin audit, and audit admin reads; add a `dropped` counter and hash chain/`requestId`; add `total` as the true total or rename it.

---

### N9 — Rate-limit bypass/Sybil and missing limits; registration DoS

**Locations:** `server.js:393-406` (`rateLimit`), calls at `625` (register challenge), `770` (issue), `920` (presence challenge), `988` (presence verify), `1164` (action), `1481` (revoke). No calls in `handleRegister` (`653-761`), `handleState` (`1380`), `handleAudit` (`1428`), `handleChatMembership` (`1515`).

**Impact:**
- Limits are per **device** (and per IP for registration challenges). An attacker can register many devices (30 challenge/min/IP) and multiply the per-device budgets; 300 actions/min/device × many devices.
- `/api/register` has no rate limit at all. A valid challenge remains valid on invalid proofs (`697` is after verification), so one challenge can be used to spam expensive ECDSA verification and audit entries.
- `handleRegisterChallenge:640-641` invalidates any outstanding challenge for the same JKT; an unauthenticated attacker who knows a public JWK can repeatedly invalidate a victim's registration challenge (low-cost DoS).
- State/audit/chat membership have no limits; the limiter is fixed-window and in-memory, with no global/edge component; `Retry-After` is JSON-only, not an HTTP header.
- Presence-code brute force is bounded by 5 attempts/challenge and 10 challenges/min/device, but a Sybil attacker can get more; presence alone still does not enable an action without the device key.

**Fix:** rate-limit `/api/register` per IP and per JKT; add a per-challenge attempt counter and burn after N failures; allow multiple outstanding registration challenges per JKT or stop invalidating on mere request; cap sessions per device; add limits for state/audit/chat; add a global/edge limiter and an HTTP `Retry-After`; expose metrics. Test the Sybil and invalid-proof paths.

---

### N10 — Proof/session binding, verification order, and signature comparison

**Locations:** `public/protocol.js:137-152` (proof string), `server.js:1252-1266` (proof verification after scope/sequence checks), `server.js:1227-1234` (parent check omits `parent.revoked`/`parent.exp`), `server.js:1179` (`capability.sig !== record.sig` string compare).

**Impact:**
- The proof does not bind the session token (`ath`), an `iat`/`jti`, or a server nonce. A captured capability+proof can be replayed with a different session of the same device before the one-use consume; one-use limits the window, but there is no timestamp/session binding.
- The proof binds `prevHash`, not `parentCap`; the store/HMAC binds parentCap today, but a stateless token profile would need it explicitly.
- The registration proof (`public/protocol.js:154-156`) has no `aud`/issuer/origin, so it is not tied to a deployment; the challenge is random, but a multi-deployment library should add an audience/origin.
- Proof verification is after scope/body and sequence/parent checks, so a caller with a session but no device key can probe those state-dependent errors before proving possession. (Capability `used`/`exp` are now checked in the commit after the proof, which is an improvement over v1.) The docs explicitly choose the remaining order (`DESIGN.md:275-292`), but the v1 P1-8 concern is only partially addressed.
- `capability.sig !== record.sig` is a non-constant-time string compare of an HMAC; `capabilitySignatureValid` is timing-safe, so the extra compare is redundant and should be removed or made timing-safe.
- At action time the parent's `revoked` and `exp` are not checked (`1227-1234`); if per-capability revocation is added, a revoked parent can still validate a child chain.

**Fix:** add DPoP-style `ath = sha256(sessionToken)`, `iat`, `jti` and a server nonce; bind `parentCap`; verify the proof before mutable-state checks; move the parent check/expiry into the commit or a store primitive; use `timingSafeEqual` for the sig compare; add replay/expiry/session tests.

---

### N11 — `?demo=1` gating is build hygiene, not a security boundary

**Locations:** `public/index.html:39` always loads `/demo-hooks.js`; `public/demo-hooks.js:108` sets `global.DemoHooks`; `public/secrecy.js:466` sets `global.Secrecy`; `public/secrecy.js:76` default `dbName = "secrecy-mvc-demo"`; `public/secrecy.js:405-421` loads the same IndexedDB key; `public/app.js:21,33,38` enables the instance/window handle only for `?demo=1`; `DESIGN.md:513-515` says the file is loaded but not instantiated/exposed.

**Impact:** without `?demo=1`, the app does not set `window.secrecy` and does not instantiate a demo object. But any same-origin script can instantiate its own client:
```js
const s = new Secrecy({ policy: window.SECRECY_POLICY, demoHooks: true });
await s.init();          // same IndexedDB key, PoP registration
// s.demo.sign(...) / s.execute(...)
```
`DemoHooks` and `Secrecy` are globals, the key is in the same origin's IndexedDB, and `init()` can obtain a new session. The class's signing ability is the fundamental in-page oracle; the gate only hides a prepared handle. This is documented in `DESIGN.md:513-515` ("page-level demo switch, not a production build boundary"), but `README.md:27` ("not installed") and `DESIGN.md:513-515` ("not ... exposed") are imprecise for the class.

**Fix:** build-time exclude `demo-hooks.js` from production; use a separate entry/origin/iframe for the lab; do not expose `Secrecy`/`DemoHooks` as globals in production (use modules); optionally namespace/disable the signing API when not in demo; make the docs say "the instance/window handle is gated; the class/file and the IndexedDB key are still present."

---

### N12 — App still uses legacy global `enterView`; `view()`/`can()` are untested; client packaging/parity

**Locations:** `public/app.js:152` (`secrecy.enterView(view)`); `public/secrecy.js:116-145` (`enterView`, `view`, `can`, `actions`); `README.md:134,143`; `package.json:1-15` has no `exports`/module entry; `public/secrecy.js:466` global IIFE; `public/secrecy.js:242-244,389-394` client-computed hashes; `server.js:1219-1225` server comparison; `secrecy.js:375,380` `join("|")` key comparison.

**Impact:** the new `view()` handle exists but the app still uses the global mutable `enterView`; no checked-in test exercises `view()`, `can()`, `actions()` or the legacy wrapper. The client library is a global IIFE with hardcoded `fetch`/`indexedDB`/`crypto`; it is not importable as a module. Client and server recompute scope/body hashes independently; current validators happen to agree, but a future scope type/normalization (or a key containing `|`) can cause a proof mismatch. The presence challenge's server `scopeHash`/`bodyHash` are ignored by the client (it uses its own).

**Fix:** use `const view = secrecy.view(state.view)` in the router/controllers and deprecate `enterView`; add client tests for `view()`, `can()`, `actions()`, legacy wrapper and provider; compare sorted arrays rather than `join("|")`; have the client use the server's challenge/payload hashes for presence/proof where possible; package `secrecy.js`/`presence.js` as ESM/UMD with injectable `fetch`/IDB/crypto and no globals; add a module entry and types.

---

### N13 — Smaller production/demo hardening items

- **Static files:** `server.js:1615-1638` uses a lexical path check and `fs.readFile` follows symlinks; add `fs.realpath` containment. No CSP/frame-ancestors/CORP/COOP (deliberate for the lab; production needs them). `demo-hooks.js` is always served.
- **Read-only after revoke:** `handleState`/`handleAudit` use `requireSession` (`1381`,`1429`), so a revoked device can still read feed/messages/users/drafts/audit. This is documented (`DESIGN.md:511-512`, `README.md:220-221`) but is not full revocation; if reads are sensitive, add a dedicated `/api/me/revocation`/status endpoint and require `requireAuth` for data, or scope the read-only response to revocation metadata.
- **Presence token burn:** `handleIssueCapability` consumes presence (`788-796`) before parent/other checks (`801-852`); a future high-risk multi-step action could burn an approval on a failed issue. Reorder or consume at the end.
- **Admin token:** `server.js:33,1430-1432` — no minimum length, no timing-safe compare, no rate limit. Add all three.
- **Audit attribution:** `sendError` uses `req._audit.action` (`495-496`), which is set from `body.action` before validation (`773`, `1167`); a forged action can appear in a denied audit event. Use the validated payload action or mark `untrusted`.
- **Registration challenge before revoked check:** `used = true` at `697` before `devicesByJkt` revoked check `700-706`; a revoked key burns a challenge; harmless but confusing.
- **`demo-hooks` flake:** `demo-hooks.js:98-100` uses code `"000000"`; there is a 1-in-1,000,000 chance the real code is `000000`, making the demo report `UNEXPECTED_PRESENCE_SUCCESS`. Use an invalid-length/format code or a code known not to match.
- **Policy validation:** view names are not checked against the action-name pattern (`server-policy.js:117-118`), and `SCOPE_TYPES`/`BODY_TYPES` are not category-separated (`96-104`); a view name containing `|` or a body type used as scope passes validation. Validate view names and separate scope/body type registries.
- **`viaCap`:** feed/messages expose full capability IDs (`server.js:67-87,1420-1421`, `app.js:310,465`) while audit masks them; mask or omit for consistency.
- **`capability.sig`:** `server.js:1179` string compare; remove it (the timing-safe `capabilitySignatureValid` already covers the record) or use `timingSafeEqual`.

---

## 4. API assessment

### 4.1 `execute(action, {scope, body})`, `view()`, `can()`, `actions()`

The new explicit request shape is a clear improvement:

```js
await secrecy.execute("createPost", {
  scope: { boardId: "b1" },
  body: { text: "hello" }
});

const home = secrecy.view("home");
home.can("createPost");       // true
home.actions();               // ["createPost", "post:edit", "post:submit"]
await home.execute("createPost", { scope: { boardId: "b1" }, body: { text: "hi" } });
```

- `execute` correctly returns the business result and stores a `receipt` in `secrecy.lastReceipt` (`secrecy.js:290`). Good.
- `view()` returns a handle without mutating `currentView` (`135-145`); this is the right design. **But the checked-in app still uses `enterView` (`app.js:152`) and no test exercises `view()`.** The README shows both; it should make `view()` the primary API and deprecate `enterView`.
- `can()`/`actions()` are simple and useful; they are view-aware but not server-aware (a client policy can be stale). Fine.
- The legacy wrapper `execute(action, params)` is implemented (`348-369`); it works, but the split relies on policy scope/body key lists, which are client policy; keep it as a compatibility shim, not the primary API.
- No `AbortSignal`, timeout, or idempotency key is implemented despite the v2 proposal. For a one-use capability, an idempotency/receipt lookup is more important than an abort signal: a lost response after consume leaves the client unable to tell whether the write happened.
- `_links` is keyed by action (`302-307`), so two concurrent `post:edit` flows overwrite each other; use a flow/continuation ID or persist the sequence server-side.
- The client `_normalizeRequest` compares keys with `join("|")` (`375,380`); use sorted-array equality. It normalizes only `userIds`; new scope/body types need shared validators to avoid client/server hash drift.

### 4.2 Does business code avoid crypto/tokens?

**Yes, for the checked-in business controllers.** `createPost` (`app.js:664-667`), `saveDraft` (`684-687`), `publishDraft` (`704-707`), `sendMessage` (`734`) and `changeAvatar` (`758`) only build `scope`/`body` and call `secrecy.execute`. No controller calls `crypto.subtle`, computes hashes, sees a capability envelope, proof, nonce, or presence token. The load check references `window.SECRECY_PROTOCOL` only to fail fast (`app.js:15`).

The exceptions are outside business controllers:
- The presence modal/provider receives `scope`/`body` and the client-computed `scopeHash`/`bodyHash` (`secrecy.js:258-267`; `app.js:773-838`). That is a UI/security-provider concern, not business logic, but it does mean the provider sees hashes.
- The `?demo=1` XSS hook intentionally exposes raw signing (`demo-hooks.js`); it is demo-only in intent, but see N11.

So the claim is true for app controllers; the library boundary is clean.

### 4.3 `PresenceProvider`

The interface (`PresenceProvider.requestPresence({action, view, scope, body, scopeHash, bodyHash, challenge, exp})`) is a good seam for a UI confirmation. The app's `ModalCodePresenceProvider` displays the exact transaction and asks for the console code. However, as noted in N4, the actual transport is code-only, and the WebAuthn provider is a throwing stub. The seam is not yet a production abstraction.

Improvements:
- Pass the server challenge response's `scopeHash`/`bodyHash` to the provider, not only client-computed values.
- Return a discriminated `PresenceProof` (code vs assertion), and let the server select the verifier.
- Make the provider optional per action (already via `config.presence`); keep the default `PRESENCE_PROVIDER_MISSING` error.
- Support `AbortSignal`/cancel; the modal returns `PRESENCE_CANCELLED` today.
- Keep the `StaticCodePresenceProvider` for tests, but not in production.

### 4.4 Errors, extensibility, packaging

- Errors are much better: `code`, `status`, `source`, `retryable`, `details`, `auditId` (`secrecy.js:14-24`, `423-462`); the app can distinguish `PRESENCE_REQUIRED`, `PRESENCE_SCOPE_MISMATCH`, `RATE_LIMITED`, etc. Good.
- `PRESENCE_REQUIRED` no longer carries a challenge in the error; the client calls `/presence/challenge` itself (`secrecy.js:255-257`). That is cleaner.
- Adding an action with an existing scope/body type: policy + server authorizer + `performAction` + controller. Adding a **new type** still requires editing both `TYPE_VALIDATORS` (`server.js:249-298`) and `SCOPE_TYPES` (`server-policy.js:16-25`); the "client layer is generic" claim holds only within the existing type set.
- The client library is a global IIFE (`secrecy.js:466`), `presence.js`/`demo-hooks.js` are globals, and `package.json` has no `exports`/module entry. For a reusable library, add ESM/UMD, types, injectable `fetch`/IndexedDB/WebCrypto, and a separate demo entry.
- No idempotency key/receipt lookup; no session rotation/logout; no per-cap revoke; no account model; see §6.5.

### 4.5 What is still demo-only (be explicit)

- **Presence:** console OOB six-digit code, printed to stdout with action/scope/body; not WebAuthn UV; same-page XSS can keylog; code-only provider seam.
- **Store:** in-memory, single-process; `consumeCapability` is atomic only in this process; no DB CAS/transactions; caps/drafts/users/sessions unbounded.
- **Tokens:** HMAC-SHA256 symmetric, per-process secret; no `kid`/rotation/`iss`/`aud`/`typ`/`jti`; store is the real authority.
- **Sessions:** bearer token in JS memory, 24 h, no rotation/logout/CSRF/Origin/BFF; no account/multi-device model.
- **Audit:** in-memory, capped, no hash chain/tamper evidence, no dropped counter; admin token is a static env secret.
- **Presence/authorization:** console code; board ACL is a resource allowlist; `/api/chat/join|leave` ambient; no per-user board ownership.
- **Client:** global IIFE, no module exports/types, hardcoded browser APIs; `view()` not used by the app; no idempotency.
- **XSS:** no CSP/Trusted Types; demo hooks file served; `?demo=1` is page-level, not a build boundary.
- **Revocation:** writes blocked; read-only state/audit allowed by design; device-only, no per-cap/account.
- **Rate limits:** best-effort fixed windows; per-device Sybil; no global/edge; no limits on register/state/audit/chat.
- **Static:** lexical path check (symlink follows); no frame/CORP/COOP; no TLS/proxy story.

---

## 5. Naming and "MVC + S"

**The design is coherent, but the name is not.** The code/docs now correctly define the layer as a server-authorized **authority/capability layer**, not confidentiality (`DESIGN.md:5-18`, `README.md:3-9`). The word "Secrecy" still implies confidentiality and collides with the "secret" (HMAC key). `DESIGN.md:17-18` says "See §17 for" the naming explanation, but §17 is the production path; there is no naming section. That is a concrete doc bug.

**What to call it:**
- Call the pattern **"MVC + Authority"** (or **"MVC + Permits"**), and call the artifact a **capability token**.
- Define S once at the top of both README and DESIGN: **"S = a server-authorized, scope-bound, single-use authority layer (capabilities + presence + ACL + audit); 'Secrecy' is the historical project name and does not mean confidentiality."**
- Rename the library class/error in a future major version: `Secrecy` → `Authority`/`Permit`, `SecrecyError` → `AuthorityError`, `secrecy.execute` → `authority.execute`/`permit.use`. The wire prefix `secrecy:v2` can stay for compatibility or move to `authority:v2` with a version bump.
- Keep "Secrecy" only as the demo/project name: "MVC + Authority (formerly MVC + Secrecy)." Update the browser title/brand and README heading, or at least add a one-line subtitle.
- Rename "presence" to "user verification" when WebAuthn and "confirmation" when UX-only; do not call a console code "presence" in a production claim.
- "View" is still overloaded (MVC view vs policy UI context); consider "surface" or "UI context" in the policy, or keep "view" with an explicit definition.

**Is MVC + S coherent?** Yes, as an application pattern: Model = server state; View = render functions; Controller = event handlers; S = the authority layer between controllers and the server (client capability client + server policy/store/ACL/audit). It is not a standard fourth MVC tier and should not be presented as a framework. The clean `execute()` seam is the strongest part. The `view()` handle is the right refinement, but the app still uses the legacy global `enterView`.

---

## 6. Remaining P0/P1/P2 and required tests

### 6.1 Priority list

**P0:** None in the demo's stated action-authority threat model. **N1 (PoP challenge replay) is P1-high and becomes P0-class if registration requests/proofs are considered capturable secrets**; fix it before calling the layer reusable.

**P1 (before a reusable library):**
1. **N1** — PoP challenge replay/session flood; no register rate; invalid-proof DoS.
2. **N2** — OOB code logging/channel; no production presence channel.
3. **N4** — `PresenceProvider` cannot carry WebAuthn; code-only server endpoint.
4. **N5** — ambient `/api/chat/join|leave`.
5. **N6** — draft hash not recomputed at use; V2-NOTES false.
6. **N7** — board ACL is not per-principal.
7. **P1-13/N10** — session/CSRF/BFF, proof `ath`/`iat`/`jti`, verification order.
8. **P1-14/N9** — rate-limit Sybil and missing limits.
9. **N11/N12** — demo gating is not a boundary; module packaging/no globals; app still `enterView`.

**P2:**
- N3 presence at issuance vs action.
- N8 audit redaction/admin/tamper; `viaCap` masking.
- N13 static/CSP/symlink, read-only revocation, presence burn, admin token, audit attribution, policy view names, sig compare.
- N10 parent revocation/expiry at action; `parentCap` proof binding.
- P1-7 HMAC by design; `uses`/`maxUses` simplification.
- `secrecy.reconnect`/`resetDevice` cleanup (`_links`, `lastReceipt`), `me()` lacks `revokedAt`, `_links` action-keyed.

### 6.2 Required v2 tests

Add these to `test/security.mjs` (or a new `test/v2-*.mjs`). Keep the existing 11/11 suites as regression.

| ID | Test | Expected |
|---|---|---|
| V2-T01 ★ | 2/50 parallel `/api/register` with the same challenge+proof over independent sockets | Exactly one 200, one `INVALID_REGISTRATION_CHALLENGE`; one session; sequential replay fails. This is the missing N1 test. |
| V2-T02 | Invalid registration proof spam with one valid challenge | Rate limit/attempt cap; challenge burns after N attempts; no unbounded ECDSA/audit work. |
| V2-T03 | New challenge for the same JKT while an old one is outstanding | Decide: old remains valid or is invalidated; no unauthenticated DoS of the legitimate challenge. |
| V2-T04 | Revoke device during PoP verify; register after revoke | 403 `DEVICE_REVOKED`; no session; challenge state consistent. |
| V2-T05 | Chat join/leave without a capability; with a capability | Denied unless capability/admin/test flag; rate-limited; audit. |
| V2-T06 | Mutate `draft.text` between edit and submit (test hook or draft-edit action) | `DRAFT_HASH_MISMATCH`; no publish; recomputed hash, not stored hash. |
| V2-T07 | Presence at action: issue high-risk cap with presence, wait > token TTL, use | If action-time mode: `PRESENCE_REQUIRED`; if issue-time: documented window and cap TTL ≤ token TTL. |
| V2-T08 | PresenceProvider contract: OOB code and WebAuthn assertion | Code path works; assertion path is accepted by a fake verifier; no `.code`-only assumption. |
| V2-T09 | OOB production mode: no code in stdout/HTTP/logs; test channel only | No secret in stdout; code never in HTTP; body/scope redacted; wrong/expired/replayed code fails. |
| V2-T10 | Audit: anonymous 401; A cannot see B; non-admin no raw hashes/other IDs; admin timing/rate/min | Scoped/redacted; admin only with a strong token; dropped counter/hash chain/requestId. |
| V2-T11 | Audit/state: `viaCap` masked; user with no chat sees only self; revoked read-only behavior | No cross-user cap IDs; state scope correct; read-only revocation documented. |
| V2-T12 | Rate-limit Sybil: many devices; state/audit/chat limits; Retry-After | Per-user/global limits; 429 with header/JSON; no per-device multiplication. |
| V2-T13 | Proof/session: captured cap+proof used with another session of same device; `ath`/`iat`/`jti` if added | Rejected when session binding is enabled; one-use otherwise; timestamp/nonce tests. |
| V2-T14 | Proof `parentCap` binding; parent revoked/expired at action | Rejected if per-cap revocation/expiry is in scope; child chain invalid. |
| V2-T15 | `view()`, `can()`, `actions()`, legacy wrapper, provider in browser/Node | Correct view guard; no global `enterView` needed; legacy still works; errors `source/retryable`. |
| V2-T16 | Normalization parity for every scope/body type; a new type | Client and server produce identical scope/body hashes; new type registration tested; no `join` delimiter collision. |
| V2-T17 | Demo build/gating: production bundle omits `demo-hooks.js`; no `window.secrecy`/demo; new `Secrecy({demoHooks:true})` cannot instantiate/sign | Demo hooks absent in production; class/module not exposed; IndexedDB namespace isolated. |
| V2-T18 | Policy validation: view name pattern including the pipe character, scope/body category mismatch, new type, cycle | Boot fails with a clear error; no delimiter ambiguity. |
| V2-T19 | Static: encoded traversal, symlink escape, CSP/frame/CORP in production mode; `x-test` hooks off | Contained; headers present; test hooks disabled by default. |
| V2-T20 | Sequence: active child reissue, consumed child, parent/child revocation, `post:edit` handler failure | `CAPABILITY_CONSUMED`/`SEQ_MISMATCH`/`DRAFT_HASH_MISMATCH`; no publish; audit outcome. |
| V2-T21 | Registration session cap/rotation; reconnect/re-register | Bounded sessions per device; old sessions invalidated/rotated; no session flood. |
| V2-T22 | Audit attribution: forged `capId`/`action` in a denied request; admin token timing | Audit uses validated action/record or marks untrusted; no log poisoning; timing-safe admin. |
| V2-T23 | Lost response after consume; idempotency/receipt lookup (future) | User can determine whether the write happened; no blind retry. |
| V2-T24 | Multi-process/fake store: two processes consume same cap; child issue/presence consume | Exactly one success across processes; conditional updates/unique constraints. |

---

## 7. Top 3 before calling it a reusable library

1. **Close the last check→await→set race — registration PoP.** Re-check `used`/`exp` and set `used` in one synchronous block after `subtle.verify`; make it a store primitive; rate-limit `/api/register`, add challenge attempts, cap sessions. Run the 2/50-way PoP replay test. The action path is fixed; the pattern must be applied everywhere.
2. **Make presence a real, pluggable, server-verified factor.** Replace the stdout console code with a `PresenceChannel`/`PresenceVerifier` abstraction; implement WebAuthn UV (challenge/origin/rpId/UP/UV/signature/signCount) and bind it to device+action+scopeHash+bodyHash+nonce; consume at action for high-value transactions; never log codes/bodies by default; make `PresenceProvider` return a typed code-or-assertion proof.
3. **Remove ambient authority and package for reuse.** Capability-protect `/api/chat/join|leave`; add per-principal/tenant board authorization; move sessions to a BFF/HttpOnly/CSRF/Origin model (or a hardened token strategy); add idempotency/receipt; export the client as ESM/UMD with no globals and injectable browser APIs; keep the demo lab on a separate origin/build.

---

## 8. What to keep (genuine strengths)

- **The business seam is still excellent.** Controllers call `secrecy.execute(action, {scope, body})`; no tokens/proofs/WebCrypto. `app.js:664-667,684-687,704-707,734,758`.
- **Exact scope/body/view/device/JKT binding.** `server.js:1209-1225`, `public/protocol.js:137-152`; the v1 scope/body substitution is fixed.
- **Server-authoritative store and atomic action commit.** `server.js:540-554,1284-1308`; verified one 200/9 consumed in a 10-way raw test.
- **PoP registration + canonical JWK.** `server.js:151-181,653-761`; padded/whitespace rejected, canonical revoked key 403, `deviceJkt` fixed. Keep; add the PoP atomic fix.
- **Issue-time and use-time authorization.** `server-policy.js:27-82`; chat membership continuity works; arbitrary board IDs are denied. Keep and strengthen board ACL.
- **Audit fields and scoping.** `server.js:363-384,1428-1475`; `auditId`, decision, outcome, scope/body hashes, parentCap, resultId; authenticated/scoped. Keep; add redaction/tamper evidence.
- **Shared protocol module.** `public/protocol.js`; null-prototype canonicalization, dangerous-key rejection, strict base64url, proof strings. This is the right direction.
- **Policy validation at boot.** `server-policy.js:106-190`; fails closed for TTL/maxUses/authorizer/parent/next/dangerous keys. Keep; add view-name/type-category checks.
- **Error model.** `secrecy.js:14-24,423-462`; `code`/`source`/`retryable`/`details`; distinguishes presence/scope/sequence/rate errors.
- **`view()`/`can()`/`actions()` and receipts.** Right API direction; adopt `view()` in the app and test it.
- **Honest documentation.** `README.md:3-9,202-221`, `DESIGN.md:1-18,458-535`, `V2-NOTES.md:65-81`; the "bounded, not XSS-proof" framing is rare and valuable. Keep it; correct the specific false claims (PoP single-use, draft re-hash, demo gating).
- **The XSS demo is real and bounded.** `app.js:948-1064`; it shows cross-action, replay, presence challenge, wrong code and one allowed use; the `?demo=1` instance gating is good build hygiene (not a security boundary).
- **The tests are independent and useful.** `test/security.mjs` uses raw sockets and a spawned server for presence codes/delay/TTL; `test/smoke.mjs` covers the happy path. Keep and extend with the missing tests above.

---

*End of second-pass review.*
