# REVIEW — MVC + Secrecy

> Historical artifact: code paths in this document refer to the v1/v2 layout. Current source is under `src/`, docs under `docs/`.

**Reviewer note:** strict security/API review. No code was modified. This is the only file written. The probes below were read-only HTTP calls against the running demo at `http://127.0.0.1:8787`; they added demo users/posts to the in-memory server (a restart resets everything).

**Artifacts reviewed:** `server.js`, `public/secrecy.js`, `public/app.js`, `public/policy.js`, `public/index.html`, `DESIGN.md`, `README.md`, `test/smoke.mjs`, and `.probe/mvc-secrecy-test-plan.md`.

**Baseline:** the supplied smoke test passes 11/11. It is a good sequential regression suite, but it does not exercise concurrency, presence-scope binding, JWK canonicalization, audit authorization, or scope authorization. Those are exactly where the P0s are.

---

## 1. Verdict

This is a well-factored, unusually honest prototype with a genuinely clean `execute(action, params)` seam and a server-authoritative store worth preserving, but it is not yet a capability security layer — the reproducible concurrent double-spend, the client-only/forgeable presence gate, the presence token unbound to scope, the client-declared scope with no server-side authorization, and the JWK-encoding revocation bypass are P0s, and the "Secrecy" name advertises confidentiality rather than the authority this layer actually provides.

---

## Evidence summary

| Probe | Result | Implication |
|---|---|---|
| `test/smoke.mjs` | 11/11 pass | Baseline; sequential only. |
| Playwright, two parallel `POST /api/action` with same capability/proof | 2/2 returned 200 and both wrote | **P0-1 confirmed** (reported by the user; code-verified below). |
| Raw-socket pairs (`http.request`, `agent:false`, both bodies written in the same tick), 40 pairs | **40/40 pairs had two 200s**, 0 single-success | **P0-1**: the race is reliable when the transport actually overlaps requests. |
| 25-way `fetch` of the same capability | 1 success, 24 `CAPABILITY_CONSUMED` | Undici/HTTP scheduling serialized this probe; it is **not** a mitigation. Do not test concurrency with `fetch` alone. |
| Concurrent child issuance for the same consumed parent | `[200, 409]` = one OK, one `CAPABILITY_CONSUMED` | Parent `childCapId` link is atomic **today** (no await after body read). Fragile; see P0-1b. |
| Presence: benign `changeAvatar` `{png,1024}` → challenge → token → issue with `{jpeg,104857600}` | Issue 200, action 200, avatar updated to 100 MB | **P0-3 confirmed**: presence is not bound to scope/body. |
| Direct `POST /api/presence` from a non-browser client with the challenge, then issue + action | 200 token, action 200, no click | **P0-2 confirmed**: presence is not a server-verifiable gate. The smoke test itself does this at `test/smoke.mjs:314`. |
| Register key → revoke → re-register the **same key** with `x`/`y` base64url-padded (`=`) | Padded registration 200, new `deviceId`, action with the same private key 200 | **P0-5 confirmed**: full revocation bypass via non-canonical JWK encoding. |
| Issue `createPost` for `b_secret_tenant` (arbitrary board string), then execute | 200 / 200, post lands in `b_secret_tenant` | **P0-4 confirmed**: scope is client-declared and never authorized against an ACL. |
| Issue `mention` with `u_nonexistent` | Issue 200, action 400 `VALIDATION_ERROR` | Issuance does not validate resource existence/authorization. |
| Tamper capability `payload.scope` (keep `sig`) | 403 `INVALID_CAPABILITY` | Good; keep as regression test. |
| Spoof `view:"profile"` for a `createPost` capability issued for `home` | 403 `ACTION_NOT_ALLOWED_IN_VIEW` | Good; keep as regression test. |
| `GET /api/audit?limit=1` with no auth | 200, 131 events, including `capId`/`deviceId`/`action`/`reason` | **P1-4 confirmed**: security log is public. |
| Audit `consumed` record | Fields: `action,capId,detail,deviceId,id,reason,time,type,userId`; `detail:null`; no scope/body/result/parent | **P1-4**: cannot reconstruct what was authorized/written. |
| Audit `denied` record for an authenticated request | `userId:null` | **P1-4**: denials are not attributable to a user. |
| `POST /api/capabilities` with `view:"constructor"` / `view:"__proto__"` | 500 `INTERNAL_ERROR` | **P1-6**: policy maps are prototype-chain lookups; remote 500. |
| `crypto.subtle.generateKey(..., false)` | Public key `extractable:true`, private `false`; public JWK export works, private export blocked | Confirms the non-extractable key claim (strength to keep). |

---

## 2. P0 — must fix

### P0-1 — Concurrent double-spend: check → `await` → act

**Severity:** P0. **Confirmed** by Playwright (2/2) and raw sockets (40/40 pairs).

**Locations:**
- `server.js:944-950` — replay check: `if (record.used || record.uses >= payload.maxUses)`.
- `server.js:986-999` — `await subtle.verify(...)` yields the event loop.
- `server.js:1001-1013` — sets `record.used = true`, `record.uses += 1`, `record.chainHash`.
- `server.js:1015` — `performAction(...)`.
- `DESIGN.md:243-251` — incorrectly claims the event loop makes the check-and-set atomic.
- `test/smoke.mjs:199-225` — only sequential reuse is tested.
- `.probe/mvc-secrecy-test-plan.md:35` (row 17) — the required concurrency test is missing.

**Attack:**
1. Attacker has one valid capability + proof (XSS, stolen in-flight token, or a capability not yet consumed).
2. Sends two `POST /api/action` requests over two connections in parallel.
3. Both handlers read `record.used === false` *before* either awaits.
4. Both await ECDSA verification; both pass.
5. Both set `record.used` and call `performAction`; both writes happen.
6. Audit records two `consumed` events for one `maxUses:1` capability, with no alert.

The second request never re-checks `record.used` after the await, so it does **not** need to resume before the first request's mutation; it only needs to have passed the check before the first mutation. Any real overlap works.

**Fix:**
Move the replay/expiry/revocation check to **after the last `await`**, immediately before the mutation, and perform the check + set in one synchronous critical section. The non-mutating proof verification can stay before it.

```js
// 1. All non-mutating checks (envelope, action/view/device, scope, sequence) and proof verification.
const proofValid = await subtle.verify(...);
if (!proofValid) throw new HttpError(403, "INVALID_PROOF", "Device signature is invalid");

// 2. Commit: no await between the check and the mutation.
if (record.used || record.uses >= payload.maxUses) throw new HttpError(409, "CAPABILITY_CONSUMED", ...);
if (record.revoked || auth.device.revokedAt) throw new HttpError(403, "DEVICE_REVOKED", ...);
if (payload.exp < now()) throw new HttpError(410, "CAPABILITY_EXPIRED", ...);
record.uses += 1;
record.used = record.uses >= payload.maxUses;
record.usedAt = now();
record.chainHash = sha256Hex(signedText);
auditEvent("consumed", ...);
const result = performAction(action, params, record, auth); // must remain synchronous
```

For a real store, do not rely on the process model. Use a conditional update / compare-and-swap:

```sql
UPDATE capabilities
SET uses = uses + 1,
    used = CASE WHEN uses + 1 >= max_uses THEN 1 ELSE 0 END,
    used_at = ?, chain_hash = ?
WHERE cap_id = ? AND used = 0 AND uses < max_uses AND exp > ?
RETURNING uses;
```

Zero rows returned means `CAPABILITY_CONSUMED`. This is required as soon as there is more than one process or any DB.

**Regression test:** two and fifty parallel requests over separate sockets/connections for the same capability/proof; exactly one 200, N−1 `CAPABILITY_CONSUMED`; exactly one business write; exactly one `consumed` audit event. Do not use a single `fetch` pool as the only test.

---

### P0-2 — Presence is not a server-verifiable gate; it is bypassable by any script or HTTP client

**Severity:** P0 **if presence is claimed as a security control**; the code/UI do claim it ("High-risk action", "Confirm user presence", "Presence gate"). If it is demoted to UX-only in code and docs, it becomes P2.

**Locations:**
- `server.js:724-772` — `/api/presence` exchanges a challenge for a token with no user-verification proof.
- `server.js:451-459` — the challenge is returned in the 403 body to the caller.
- `secrecy.js:272-293` — `grantPresence(action, event)` checks `event.isTrusted`; it accepts **any object**, so `{ isTrusted: true }` passes.
- `app.js:745-749` — the modal checks the real event's `isTrusted`; this is client-side only.
- `test/smoke.mjs:314` — the smoke test itself calls `/api/presence` directly with the challenge, proving no browser click is required.
- `DESIGN.md:290-310` and `README.md:153-155` — acknowledge the limitation, but the UI still sells it as a control.

**Attack:**
1. Any script in the page (XSS), or any client holding the session token, calls `POST /api/capabilities` for `changeAvatar`; gets 403 `PRESENCE_REQUIRED` + `challenge`.
2. Calls `POST /api/presence { challenge }`; gets `presenceToken`, with no click and no human.
3. Calls `POST /api/capabilities` with the token; gets the high-risk capability.
4. Calls `POST /api/action` with a proof. XSS can complete this step because the page's non-extractable key is a signing oracle; a remote client with only the stolen session token can still mint the capability but cannot sign the action proof.

Even the client-side "speed bump" is forgeable: `secrecy.grantPresence("changeAvatar", { isTrusted: true })` passes `secrecy.js:274-276`. A real synthetic DOM `dispatchEvent` has `isTrusted:false`, but a script does not need to dispatch an event; it can call the method directly.

**Fix (choose one, honestly):**
- **Production:** implement WebAuthn user verification. Register a credential per device; on the high-risk action call `navigator.credentials.get({ publicKey: { challenge, userVerification: "required", ... } })`; verify server-side: `clientDataJSON.type === "webauthn.get"`, `challenge` matches the server challenge, `origin`/`crossOrigin` are expected, `rpIdHash === sha256(rpId)`, `flags.UP` and `flags.UV` are set, the signature verifies with the stored credential public key, `signCount` advances, and `credentialId` is bound to the device. Bind the WebAuthn challenge to `{action, scopeHash, bodyHash, deviceId, view, serverNonce}`; single-use and short TTL. Consume the presence grant at `/api/action` (or immediately before), not merely at issuance.
- **Demo / no WebAuthn:** remove "presence" from the security claims, label it "UX confirmation — not a security boundary", delete `isTrusted` as a control, and stop calling it a gate. Keep the modal as a demo of the intended WebAuthn flow, but do not claim it protects anything.

Do not accept a DOM `event` object as proof. The verifier must be the server, not the client. Rate-limit challenge issuance and keep at most one outstanding challenge per device/action.

**Regression test:** a non-browser client calls `/api/presence` directly with a challenge and must **not** obtain a usable high-risk capability (after WebAuthn). `grantPresence` with `{isTrusted:true}` must fail. A Playwright synthetic click must not grant; a real click + WebAuthn assertion must.

---

### P0-3 — Presence token is not bound to scope/body: consent substitution

**Severity:** P0. **Confirmed**: benign `{mime:"image/png", maxSize:1024}` challenge → token → issue with `{mime:"image/jpeg", maxSize:104857600}` → 200 → action 200.

**Locations:**
- `server.js:438-449` — `presenceChallenge(device, action, view)` stores no scope/hash.
- `server.js:461-485` — `consumePresenceToken(token, auth, action, view)` checks device/action/view only.
- `server.js:672-674` — consumes the token at issuance, not at action, and not against a scope.
- `secrecy.js:224-227` — `_presenceTokens[action]` is keyed by action only.
- `secrecy.js:272-293` — `grantPresence(action, event)` has no scope/body argument.
- `app.js:692-713` — `pendingPresence` stores `{action, params}`, but the modal displays only the action (`app.js:726`).
- `DESIGN.md:301-302` — claims binding to device + action + view; scope/body are absent.

**Attack:**
1. User requests `changeAvatar` with a benign `{mime:"image/png", maxSize:1024}`; sees a presence prompt.
2. The prompt is approved.
3. A script swaps the retry scope/body to `{mime:"image/jpeg", maxSize:104857600}`; the token still matches device/action/view, so the capability is issued.
4. The action executes with the larger scope.

This is the PSD2 "dynamic linking" failure: the approval is not bound to the transaction details the user saw. The user approved "PNG ≤1 KB", the server authorized "JPEG ≤100 MB".

**Fix:**
- Store `scopeHash` (and `bodyHash` for the final action) in the challenge and token records. `consumePresenceToken` must compare them exactly.
- At `handleIssueCapability`, compute `scopeHash = sha256Hex(normalizedScope)` and `bodyHash = sha256Hex(params/body)`; pass them to `throwPresenceRequired` and `consumePresenceToken`.
- `/api/presence` must require the same `scopeHash`/`bodyHash` (or carry them in the challenge) and reject mismatches.
- Display the exact scope and body summary in the modal; require the user to approve that specific transaction. For `changeAvatar`, show MIME + max size.
- For high-risk, require the presence token at `/api/action`, bound to the final `bodyHash`, or set the capability TTL ≤ the presence token TTL and include a `presenceJti` in the payload for audit.
- Client: key `_presenceTokens` by `action + view + scopeHash`, not action alone; `grantPresence({ challenge, scope, body })`, not `grantPresence(action, event)`.

**Regression test:** benign scope challenge → token → substituted scope/body must fail `PRESENCE_REQUIRED` (or a specific `PRESENCE_SCOPE_MISMATCH`); same scope/body succeeds.

---

### P0-4 — Scope is client-declared and never authorized: "scoped" ≠ "authorized"

**Severity:** P0 as a pattern; immediate demo impact is limited because `b1`/`b2` have no ACL. Any real deployment that copies this will mint capabilities for resources the caller cannot access.

**Locations:**
- `server.js:599-607` — issuance trusts `body.action`/`body.view`/`body.scope`; only key shape and value syntax are normalized.
- `server.js:275-311` — `normalizeScope`/`scopeFromParams` validate keys/types, not ownership, membership, or existence.
- `public/policy.js:30-78` — declares scope **keys**; there is no authorizer, resource type, or relation.
- `server.js:782-885` — handlers trust `payload.scope` (e.g., `createPost` uses `payload.scope.boardId`).
- `DESIGN.md:85-91` — says policy controls "which scope keys", not values; `DESIGN.md:434-446` correctly says view is not a boundary but never addresses scope authorization.
- `.probe/mvc-secrecy-test-plan.md:25` — row 12 tests only capability-vs-request mismatch, not whether the issued scope was allowed.

**Attack:**
1. An authenticated user requests `createPost` with `{ boardId: "b_secret_tenant" }` (any string).
2. The server issues the capability (200).
3. The user executes it; the post lands in `b_secret_tenant` (200).

The same applies to `post:edit`/`post:submit` on any board, and `mention` with any up-to-20 user IDs (nonexistent IDs are accepted at issuance, then fail at action). The capability is cryptographically bound to a scope, but the scope itself is chosen by the client. The server never asks "may this user write this board/chat?" This is the difference between **authenticating the scope** and **authorizing the scope**.

**Fix:**
- Add a server-side `authorize(action, scope, auth)` per action, resolved from a server-only authorizer key. Examples:
  - `board.write`: `boards.can(auth.userId, scope.boardId, "editor")`
  - `chat.write`: `chats.isMember(auth.userId, scope.chatId)`
  - `chat.mention`: `chats.canMention(auth.userId, scope.chatId, scope.userIds)`
  - `self.profile`: `scope.userId === auth.userId`
- Call it at issuance **and again at use** (continuity; membership can be revoked between issue and use). Fail closed with `FORBIDDEN`/`SCOPE_DENIED`.
- Use a relationship store (Zanzibar-style tuples) or explicit ACL tables. Do not infer authorization from a client-declared ID.
- Consider a Powerbox-style UI: the user picks an authorized resource; the server returns a scope-bound capability. The client should not be the source of resource IDs unless the server validates them.
- Keep the client-safe policy manifest (views, scope key names, labels) separate from server authorizers; never ship ACL logic to the browser as the authority.

**Regression test:** user A issues for user B's board/chat → denied; after membership revocation, a still-valid capability fails at use; re-issue denied.

---

### P0-5 — JWK canonicalization bug: revocation bypass with the same private key

**Severity:** P0. **Confirmed end-to-end.** A revoked device key can be re-registered as a "new" device by changing the base64url encoding of `x`/`y`, and the same private key still signs valid proofs. Revocation is not durable.

**Locations:**
- `server.js:157-169` — `jwkThumbprint` hashes the raw `x`/`y` strings.
- `server.js:491-513` — `sanitizePublicJwk` only checks `typeof x/y === "string"` (`502-504`); no length/canonical-encoding check.
- `server.js:523-536` — `subtle.importKey` accepts padded/whitespace variants; `jkt` is computed from the raw strings.
- `server.js:536-545` — `devicesByJkt.get(jkt)`; the revoked check only sees the exact jkt.
- `server.js:547-567` — a new jkt creates a new device/user.
- `server.js:1082-1089` — revocation is keyed by `deviceId`/jkt.
- `DESIGN.md:108-116` — claims re-registering the same JWK reuses the device unless revoked.

**Attack:**
1. Device key K is registered; attacker steals K, or the owner revokes a compromised key.
2. Owner revokes K; `devicesByJkt` retains jkt(K) as revoked.
3. Attacker re-registers the **same** K with `x`/`y` padded:

```js
const padded = {
  ...jwk,
  x: jwk.x.replace(/=+$/, "") + "=",
  y: jwk.y.replace(/=+$/, "") + "="
};
```

`importKey` accepts it; `jwkThumbprint` hashes the padded strings → jkt′ ≠ jkt(K); `devicesByJkt` misses the revoked record → new `deviceId`.
4. Attacker signs with K; `POST /api/action` verifies under the imported padded JWK and succeeds.

Verified: base register 200 → revoke 200 → same encoding 403 `DEVICE_REVOKED` → padded 200 (new `deviceId`) → action 200 ("posted after revocation via padded JWK"). A local probe also showed `importKey` accepts trailing whitespace (`jwk.x + " "`) and produces a different jkt; the same re-registration path applies.

**Fix:**
- Canonicalize before thumbprinting. Decode `x`/`y` with strict base64url (no padding, no whitespace), require exactly 32 bytes (43 base64url chars for P-256), re-encode unpadded; or `importKey` and then `exportKey("jwk", key)` to obtain the canonical public JWK. Compute RFC 7638 thumbprint over the canonical `{crv,kty,x,y}`.
- Validate `x`/`y` with a strict regex (`^[A-Za-z0-9_-]{43}$`) and reject `=`, spaces, and non-canonical points. Store the canonical JWK and canonical jkt.
- Use a unique index on the canonical jkt; `INSERT ... ON CONFLICT` / `devicesByJkt` by canonical jkt.
- Fix the missing `device.jkt` field at the same time (P1-1); otherwise the token still lacks the jkt claim. Fixing the field name alone does **not** fix this bypass.
- Add a regression test for padded, whitespace, `ext`/`key_ops`-mutated, and invalid-length variants; the revoked key must remain revoked and no new `deviceId` may appear.

---

### P0-1b — Atomicity audit of the other state transitions (requested)

The action path is the only one with a real check→await→act race today, but the code relies on "no `await` in this block" rather than on an atomic store contract. With a DB, a new authorizer, or async WebAuthn, every row below becomes racy.

| Path | Check | Await between check and mutation? | Single process now | Multi-process / future async | Fix |
|---|---|---|---|---|---|
| Action consume (`server.js:944-1015`) | `record.used/uses` at 944 | **Yes**, `subtle.verify` at 988 | **BROKEN** (40/40) | **BROKEN** | Re-check + set after the await, or conditional `UPDATE ... WHERE used=0`. |
| Parent → child issue (`server.js:619-707`) | parent `used`, `childCapId`, `prevHash` at 619-663 | **No** after `await readJson` at 600 | **OK** (probe: 1 OK / 1 `CAPABILITY_CONSUMED`) | Fragile: any new await or second process | Transactional `UPDATE ... SET child_cap_id=? WHERE cap_id=? AND child_cap_id IS NULL AND used=1`; insert child in the same transaction; unique index on `parent_cap_id`. |
| Presence token consume (`server.js:461-485`, called 672-674) | `used`, `exp`, device/action/view at 466-473 | **No**; sync | **OK** | Fragile if WebAuthn/DB verification is added before consume | Conditional `UPDATE presence_tokens SET used=1 WHERE token=? AND used=0 AND exp>? AND device_id=? AND action=? AND view=? AND scope_hash=?`. |
| Presence challenge redeem (`server.js:733-746`) | `used`, `exp`, device at 733-738 | **No**; sync | **OK** | Fragile | Conditional update / single-use delete with `RETURNING`. |
| Register same JWK (`server.js:523-567`) | `devicesByJkt.get(jkt)` at 537 | `importKey` at 525 is **before** get/set; no await between get and set | Duplicate same-jkt registrations reuse the device; **no PoP** | Fragile; unique index needed | Unique index on canonical jkt; `INSERT ... ON CONFLICT`; PoP challenge (P1-2). |
| Revoke (`server.js:1082-1105`) | sets `revokedAt`, marks caps | **No**; sync | Works, but an in-flight action does not re-check after its await | **BROKEN race** with action commit | Re-check `device.revokedAt`/`record.revoked` in the action commit; conditional update `revoked_at IS NULL`. |
| Sweeper (`server.js:1252-1263`) | deletes expired sessions/presence | **No** | OK | OK | Also prune capabilities/drafts (P1-14). |

**Specific answers:**

- **`handleIssueCapability` parent `childCapId`:** no current await/check race. After `await readJson` (`server.js:600`), the function is synchronous through the parent checks (`619-663`), `capabilities.set` (`706`), and `parentRecord.childCapId = capId` (`707`). The probe confirms one 200 / one `CAPABILITY_CONSUMED`. But the check and the link are two separate mutations (`capabilities.set`, then `parentRecord.childCapId`); a crash between them, or a second process, can break the invariant. Do not rely on the event loop: use a single transactional `issueChild`.
- **Presence token consumption:** atomic today because `consumePresenceToken` checks and sets `record.used` synchronously (`466-477`) and is called after `readJson`. If WebAuthn verification is added, it becomes async; verify first, then conditional-consume (or reserve with a short TTL and roll back on failure).
- **Presence challenge redemption:** atomic today for the same reason (`733-746`).
- **Revocation:** the flag mutation is atomic, but the action commit does not re-check it after the ECDSA await. A device revoked during a slow verify can still complete one action. Re-check in the commit block (P0-1 fix).

**Recommendation:** define a `Store` interface with atomic primitives — `consumeCapability`, `issueChild`, `consumePresence`, `redeemChallenge`, `revokeDevice` — and make handlers call them. In SQL, each primitive is a conditional update/transaction with a unique constraint; in memory, a synchronous critical section. Then the concurrency tests target the primitives, not the HTTP timing.

---

## 3. P1 — should fix

| ID | Area | Location | One-line |
|---|---|---|---|
| P1-1 | Correctness | `server.js:186,560,588,683` | `deviceJkt` is stored as `deviceJkt` but read as `device.jkt`; it is `undefined` everywhere. |
| P1-2 | Identity | `server.js:515-593` | Registration has no proof-of-possession; anyone with the public JWK gets a session and can revoke/rename the device. |
| P1-3 | Revocation | `server.js:934-950,1091-1105` | `record.revoked` is never checked; revocation can race an in-flight action; no per-cap/account revoke. |
| P1-4 | Audit | `server.js:191-206,413-432,1071-1080` | Audit is unauthenticated, misses scope/body/result/user on denials, trusts client `capId`/`action` for attribution. |
| P1-5 | Correctness | `server.js:688,944,1003` | `maxUses` is structurally one-use; `record.used` is set on the first use, so `maxUses>1` can never work. |
| P1-6 | Policy | `server.js:689,941; public/policy.js` | No boot validation; missing `ttl` → `NaN` `exp` → immortal capability; prototype-chain lookups can 500. |
| P1-7 | Token | `server.js:27-29,139-155,906-908` | HMAC `sig` is symmetric and redundant with the store; verifies the client payload, not the stored record; no `iss/aud/kid`. |
| P1-8 | Proof | `server.js:126-137,986-999` | Hand-rolled DPoP misses method/path/`iat`/`jti`/`ath`/server nonce; proof verified after state checks; `deviceJkt` not checked. |
| P1-9 | Sequence | `server.js:707,859-882` | `post:submit` does not bind the draft text; parent is burned at child issuance; failed edit can still link a child. |
| P1-10 | Demo | `secrecy.js:129,416-463; app.js:1121` | `demo` signing oracle is always on; `window.secrecy` is global; production misuse trap. |
| P1-11 | Protocol | `server.js:101-137; secrecy.js:26-58; smoke.mjs:36-68` | Canonicalization/proof duplicated three times; `__proto__` key is dropped → non-injective body hash; delimiter ambiguity in `action`. |
| P1-12 | API | `secrecy.js:148-152,202-269,330-349; app.js:692-782` | `execute(action, params)` conflates scope/body; global `enterView`; presence is a 3-step dance; errors lack source/retryable. |
| P1-13 | Session | `server.js:329-378,395-411,1033-1061` | 24h bearer in JS memory, no rotation/logout; no Origin/Sec-Fetch-Site; `/api/state` returns 200 `me:null` on expiry, so the client's 401 path is dead. |
| P1-14 | DoS | `server.js:47-53,74,204,1252-1263` | Unbounded users/devices/capabilities/drafts; no rate limits/quotas; caps/drafts never pruned. |
| P1-15 | Privacy | `server.js:1033-1069` | `/api/state` returns all users/feed/messages, unauthenticated; exposes `parentCap`/`prevHash`. |

### P1-1 — `deviceJkt` is never populated

`server.js:560` creates the device with `deviceJkt: jkt`, but `publicDevice` reads `device.jkt` (`server.js:186`), the register response reads `device.jkt` (`server.js:588`), and the capability payload reads `auth.device.jkt` (`server.js:683`). `device.jkt` is `undefined`, so JSON omits the field. Consequences: `/api/register` returns no `deviceJkt`; `/api/state` `me.device.deviceJkt` is missing; the capability payload has no `deviceJkt` claim; the UI displays a blank thumbprint (`app.js:210,376`); `DESIGN.md:124-141` claims the field exists. The smoke test never asserts it.

**Fix:** store `jkt` consistently (or read `deviceJkt` everywhere); add `assert(reg.deviceJkt)` and `assert(cap.payload.deviceJkt === reg.deviceJkt)` to the smoke test. Combine with P0-5 canonicalization. Device binding still works via `deviceId`, so this is correctness/claim integrity, not an authority bypass.

### P1-2 — Registration has no proof-of-possession; re-register is a revoke/rename oracle

`server.js:515-593` accepts any public JWK, creates a session for it, and reuses the device by jkt. No challenge/signature proves the caller holds the private key. Verified: register the same JWK twice → same `deviceId`, a new token; the second token can `POST /api/revoke` (200) and rename the device (`deviceName` update at `569`, user name at `571-574`); the victim then gets `DEVICE_REVOKED`. Anyone who knows the public JWK (public by definition; logs, backups, another app, key transparency) gets a session bound to the victim's device and can revoke/rename it. They still cannot sign actions without the private key, but this is a DoS/identity-integrity issue and becomes P0 once one account has multiple devices or account recovery.

**Fix:** `POST /api/register/challenge` → nonce; client signs `register:v1|<nonce>|<jkt>|<deviceNameHash>`; server verifies with the submitted JWK, checks challenge single-use/exp, then binds/reuses. Require PoP for re-registration and revocation; rate-limit. Consider WebAuthn/passkeys for the device credential. Do not let an unauthenticated caller rename an existing device.

### P1-3 — Revocation is incomplete and racy

`record.revoked` is set on revoke (`server.js:1091-1105`) but `handleAction` never checks it (`server.js:934-950`); only `requireAuth` checks `device.revokedAt` (`370-376`). The cap flag is dead code; per-capability revocation is not exposed (`DESIGN.md:464`). Revocation can interleave with an in-flight action during `await subtle.verify` (`986-999`): `requireAuth` was checked before the await, and the commit does not re-check, so a revoked device can complete one action. `handleIssueCapability` does not check `parentRecord.revoked` (`619-663`), so a revoked parent can still issue a child if per-cap revocation is added. Sessions are not deleted on revoke (they remain until TTL; `requireAuth` rejects). There is no account-level/other-device revoke because each device is its own user; a stolen device can only be revoked from itself.

**Fix:** re-check `auth.device.revokedAt` and `record.revoked` in the action commit; enforce `record.revoked` on every use; conditional update `revoked_at IS NULL`; add per-cap revoke (`POST /api/capabilities/:id/revoke`) and account-level revoke; check `parentRecord.revoked`; audit each.

### P1-4 — Audit is unauthenticated, incomplete, and forgeable

`GET /api/audit` has no auth (`server.js:1071-1080`); verified 200 with 131 events, including `capId`, `deviceId`, `action`, `reason`. Anyone can read the security log; an attacker can use it to see which capabilities are consumed and enumerate devices. `auditEvent` (`191-206`) lacks `scopeHash`, `bodyHash`, `parentCap`, `resultId`, `outcome`, and `requestId`; a `consumed` event cannot say what was authorized or written (verified: `detail:null`). `sendError` (`413-432`) logs `denied` with `userId:null` even for authenticated requests (verified), and uses the client-supplied `req._auditCapId`/`_auditAction` (`894`, `601`) for attribution; an attacker can poison the log with arbitrary capIds/actions. It logs 404/500 as `denied`, and every 4xx (including malformed JSON) — noisy. No hash chain/tamper evidence; the in-memory 2000 cap drops oldest silently (`204`); no dropped counter. `detail` may leak user IDs/existence.

**Fix:** require auth; filter by `auth.userId`/`deviceId`; add an admin scope for full audit; never use client-supplied `capId`/`action` (use the looked-up record; mark `untrusted`); add `scopeHash`, `bodyHash`, `parentCap`, `resultId`, `outcome`, `requestId`, `userId` (denied), and privacy-reviewed `ip`/`ua`; separate `denied` from `error`; append-only + `prevHash`/`eventHash`; expose `/api/audit/verify`; add a `dropped` counter; redact `detail`. Keep the current breadth (issue/consume/deny/revoke) — it is a strength; make it trustworthy and scoped.

### P1-5 — `maxUses` is structurally one-use; `uses` is meaningless

`handleAction` sets `record.used = true` on the first use (`server.js:1003`); the check `record.used || record.uses >= payload.maxUses` (`944`) means any `maxUses > 1` still fails on the second use. The `uses` counter can reach 2 only via the double-spend bug (P0-1), and `used` is true anyway. Policy advertises `maxUses` (`public/policy.js:34,41,48,55,64,72`) and the payload carries it (`688`), so the API promises multi-use but does not deliver.

**Fix:** either enforce one-use only (`maxUses === 1`, remove `uses`/`maxUses` from the token) or implement `record.uses += 1; record.used = record.uses >= payload.maxUses;` in the commit. For multi-use, require a fresh proof/nonce per use and define idempotency semantics. Validate `maxUses` as an integer 1..N at issuance. Add a test with a test policy that sets `maxUses: 2`.

### P1-6 — Policy has no validation; a missing TTL creates an immortal capability

`server.js:689` computes `exp: issuedAt + config.ttl * 1000`; if `ttl` is missing/non-numeric, `exp` is `NaN`; `payload.exp < now()` (`941`) is false forever; JSON/HMAC turn `NaN` into `null`; the capability never expires. `config.maxUses` missing → `record.uses >= undefined` false; `record.used` still one-use. `config.scope` missing → `[...config.scope]` throws → 500. `risk` is never used by the server; `requiresPresence` can contradict `risk`. `parent`/`next` are not validated (unknown action, cycle, mismatched scope). `views` lists `login`, `viewFeed`, `openChat` with no action config (`public/policy.js:23-24`), so they look like actions but `actionConfig` throws. Policy maps are normal objects: `view:"constructor"` / `"__proto__"` passes `!policy.views[view]` (truthy inherited value) and then `.includes` is undefined → **verified 500**. `action:"constructor"` is caught by the view check today, but the lookup is still unsafe.

**Fix:** `validatePolicy(policy)` at boot: version; every view entry is an action with config or explicitly `uiOnly`; every action has typed `scope`, `ttlSeconds > 0`, integer `maxUses >= 1`, `presence` enum, server `authorize` key, reciprocal/acyclic `parent`/`next` with compatible scope; `risk` consistent with presence; reject `__proto__`/`constructor`/`prototype` keys; use null-prototype maps and `Object.hasOwn` for all lookups; fail fast with a clear error. Add unit tests.

### P1-7 — HMAC capability signature is redundant, symmetric, and incompletely bound

`HMAC_SECRET` (`server.js:27-29`) is per-process; `capabilitySignature` (`139-144`) signs `stableStringify(payload)`; `capabilitySignatureValid` (`146-155`) verifies the **client-supplied** payload, not the stored `record`/`record.sig`; `handleAction` then uses `record.payload` (`910`). Since the store is authoritative, the HMAC adds no security: an attacker cannot mint a capability without a store record; a server compromise exposes the secret anyway. It adds a secret-handling burden, a canonicalization dependency, and a misleading `INVALID_CAPABILITY` path. The payload lacks `iss`, `aud`, `kid`, `typ`, `jti`; no key rotation; `SECRECY_SECRET` length/entropy is not validated.

**Fix:** drop `sig` and use the random `capId` as an opaque handle + store lookup (simplest), or use Ed25519/JWS with `kid`/JWKS, `iss`/`aud`/`typ`/`iat`/`exp`/`jti`, and verify the stored/canonical payload. If keeping HMAC, compare `capability.sig` to `record.sig` and verify `record.payload`; add `kid` and rotation; document that the store is the real authority. Add a test that a valid envelope for cap A cannot be used for cap B (already) and that a tampered stored record fails.

### P1-8 — The device proof is a hand-rolled DPoP with missing bindings

`proofString` (`server.js:126-137`, `secrecy.js:47-58`) binds `capId|action|scopeHash|seq|nonce|bodyHash|prevHash`; it does not bind HTTP method/path/audience, `iat`/`exp`, session token hash, or a server nonce. `deviceJkt` is not checked against `auth.device.jkt` (and is undefined, P1-1). A proof is valid until the capability expires/consumes; if a capability is multi-use (P1-5) or a proof leaks, replay is possible within TTL. The ECDSA verify is **after** the state checks (`986-999`), so a caller with a session but no device key (or a stolen capability) can probe `CAPABILITY_CONSUMED`/`SEQ_MISMATCH`/`SCOPE_DENIED` state before proving possession; the test plan's expected order (`#36`) is not met. The delimiter-based string is ambiguous if an action name can contain `|` (policy-controlled, but unvalidated).

**Fix:** use a DPoP-style JWS: header `{typ:"dpop+jwt", alg:"ES256", jwk}`, claims `{jti, htm:"POST", htu, iat, exp, ath: sha256(sessionToken), nonce}`; verify `htm`/`htu`/`iat`/`exp`/`jti` (replay cache), `ath`, and `cnf.jkt` from the session; or at minimum add `method`, `path`, `iat`, `exp`, `jti`, server nonce, and check `payload.deviceJkt === auth.device.jkt`. Verify the proof before mutable-state checks (after basic envelope/parse) to avoid oracles. Validate action names (`^[a-zA-Z0-9:_-]+$`) or use a length-prefixed/JWS encoding. Add negative tests for method/path/iat/jti/ath tampering.

### P1-9 — Two-step flow does not bind the final content; parent is burned at issue

`post:submit` scope is only `boardId` (`public/policy.js:71-77`); its proof body hash covers `{boardId}` (`server.js:982-984`); the published text comes from the server draft (`server.js:859-882`). The final capability authorizes "publish whatever draft exists," not the text the user saw. If the draft can change between edit and submit (same device/session, future multi-user/admin, TOCTOU), the final confirmation does not cover it. `post:submit` ignores `params.text` if sent (scope only `boardId`).

`parentRecord.childCapId = capId` is set at issuance (`707`), so a child that is never used (crash, navigation, attacker) permanently burns the parent; a new edit step is required. `post:edit` creates the draft after consumption (`844-857`); if it throws, `chainHash` is set and a child can be issued for a nonexistent draft (`859-870` fails, but the parent is burned).

**Fix:** include `draftId` and `draftHash = sha256(text)` in the child scope (and in the parent's draft record); require the submit proof to bind them; verify the draft hash at submit. Or make `post:submit` params include `{draftId, textHash}` and compare. Use a standard chain (Biscuit/UCAN/macaroon caveat) if you want offline attenuation. Burn the parent when the child is **consumed**, not issued, or allow re-issue until the child is used/expired; add `childIssuedAt`/`childExp` and audit. Make the business handler atomic with the parent link (same store transaction).

### P1-10 — Demo hook is always on and is a signing oracle; `window.secrecy` is global

`secrecy.js:129` sets `this.demo = this._createDemoApi()` unconditionally; `416-463` exposes `issue`, `sign`, `call`, `tryIssue`, `lastUse`, `deviceId`; `sign` (`421`) signs arbitrary `(capability, action, params)` with the non-extractable key. `app.js:1121` sets `window.secrecy = secrecy`. Any XSS (or any script on the page) gets a raw signing oracle and can bypass the client view/scope pre-checks; this is more power than the honest "stolen capability" story. The README says "do not ship it" (`secrecy.js:9-10`), but there is no technical gate.

The XSS demo's step 3 (`app.js:989-993`) only omits the presence token; it does not exercise the direct `/api/presence` bypass (P0-2), so the demo understates the residual risk. The text says "steals a fresh capability" but `lab.issue` mints a new one via the session (`app.js:931-935`), not steals an in-flight one.

**Fix:** default `demoHooks: false`; move the demo API to a separate `demo-hooks.js` loaded only on the demo page/origin; `sign` requires an explicit unsafe opt-in and is rate-limited/audited; remove `window.secrecy` in production; run the XSS demo on a separate origin or sandboxed iframe with a strict CSP; add step 3b that calls `/api/presence` directly and shows success (or, after the fix, failure); fix the "steals" wording.

### P1-11 — Protocol/canonicalization is triplicated; `__proto__` handling is non-injective

`canonicalize`/`stableStringify`/`proofString` are duplicated in `server.js:101-137`, `secrecy.js:26-58`, `test/smoke.mjs:36-68`; the comment acknowledges it (`server.js:101-104`). Drift is caught only for tested paths; an untested edge (unicode, numbers, `undefined`, `-0`, `__proto__`) can make client/server disagree. `canonicalize` assigns `output[key] = ...` on a normal `{}`; a key named `__proto__` invokes the prototype setter and is dropped/mutates the prototype, so two distinct JSON bodies can hash the same (`{"boardId":"b1","__proto__":{...}}` vs `{"boardId":"b1"}`). JSON.parse creates an own `__proto__` data property, so direct handler reads are mostly safe today, but the body hash is not injective and any future merge/spread/`for...in`/inherited read is a smuggling risk. `normalizeScope` also assigns `normalized[key]` from policy keys; a `__proto__` policy key would pollute.

**Fix:** one shared `protocol.js` (UMD or dual ESM/CJS) used by server/client/test; `canonicalize` returns `Object.create(null)` and rejects `__proto__`/`constructor`/`prototype`; define a JSON-safe value domain (no `undefined`, functions; finite numbers only); add golden test vectors and a cross-implementation test (client bundle vs Node). Reject non-plain objects at the API boundary. Validate action names or use a length-prefixed encoding.

### P1-12 — `execute(action, params)` conflates scope and body; view/presence APIs leak orchestration

`execute(action, params)` (`secrecy.js:202-209`) derives scope from `params` using `config.scope` (`330-349`); business fields and scope fields share one object. Adding a policy scope key silently changes what is authorized; a business param that happens to share a scope key is promoted to scope; client-side scope validation is partial (`userIds` is checked for array/non-empty but not element types; other scope keys are not validated), so type errors become server round-trips. `enterView` (`148-152`) is global mutable state; two concurrent flows/components/tabs can conflict; `_links`/`_presenceTokens` are keyed by action only (`125-127`, `224-231`), so concurrent same-action flows overwrite.

Presence is a 3-step dance (catch `PRESENCE_REQUIRED` → `grantPresence(action, event)` → retry `execute`) duplicated in `app.js:692-782`; `grantPresence` takes a DOM event (and trusts it), and the modal ignores its `challenge` argument (`showPresenceModal(challenge)` at `715`, unused). Errors expose `extra.challenge` and mix client/server codes; no `retryable`/`source`.

**Fix:** v2 `execute(action, { scope, body }, options)` with explicit scope/body; `authority.view(name)` returns a `ViewHandle` (no global state); `executeWithPresence`/`options.presence` callback; key `_links`/`_presenceTokens` by `action+scopeHash` or a flow id; `grantPresence` takes `{challenge, scope, body}` (or a WebAuthn assertion), never a DOM event; typed errors with `source`, `retryable`, `details`, `auditId`; client-side schema validation for every scope type. Keep the one-line business call as the default; the options object is optional.

### P1-13 — Session/auth hardening; `/api/state` returns 200 `me:null` on expiry, so the client's 401 path is dead

`createSession` (`server.js:329-338`) is a 24h bearer; no rotation/refresh/logout; stored in JS memory (`secrecy.js:165-171`); `readBearer` (`340-347`) accepts `X-Device-Token`/`Authorization`; `readJson` (`395-411`) accepts any content type; no `Origin`/`Sec-Fetch-Site` check; no CORS (good), no CSRF token. The custom header + JSON mitigates browser CSRF today, but it is fragile (proxy/content-type, future cookie auth). `handleState` uses `optionalAuth` (`1033-1035`): an expired/invalid token yields 200 with `me:null`, not 401. `refreshState` (`app.js:155-173`) only handles `UNAUTHENTICATED`, so the "session expired — sign in again" path never triggers; the UI silently loses `me`.

**Fix:** short-lived rotating sessions, refresh endpoint, server-side session revocation, logout; `HttpOnly`/`SameSite` cookie + CSRF token or a BFF; require `application/json`; check `Origin`/`Sec-Fetch-Site` for state-changing requests; return 401 from `/api/state` when a token is present but invalid (or have the client detect `me:null`); rotate on privilege change; add tests.

### P1-14 — Resource exhaustion / no quotas

`users`, `devices`, `capabilities`, `drafts` are unbounded (`server.js:47-53`); capabilities are intentionally never pruned (`1249-1251`); drafts never pruned; `/api/register` is unauthenticated and creates a user/device per new JWK; `/api/capabilities` can be called repeatedly with a valid session. An attacker can OOM the process or exhaust memory with registrations/caps/drafts; no rate limits/quotas (`DESIGN.md:431,460`).

**Fix:** per-IP/per-device/per-action rate limits and quotas; TTL-prune expired caps/drafts (keep a consumed tombstone for a bounded window); cap total devices/caps/drafts per user/IP; require PoP/registration limits; add `Retry-After`; monitor.

### P1-15 — `/api/state` over-exposes data

`handleState` (`server.js:1033-1069`) returns all `users` (`1062`), `feed` (`1063`), `messages` (`1064`), and the policy (`1067`) to any caller, including unauthenticated; `visibleCapabilities` includes `parentCap`/`prevHash` (`1047-1048`); drafts are device-scoped (`1055-1057`) but text is returned. Demo content is public, but this is a privacy/tenant-isolation gap and exposes sequence links.

**Fix:** authenticate; scope feed/messages/users to the caller's tenant/boards/chats; redact `prevHash`/`parentCap` unless the caller owns the chain; return only the caller's drafts/caps; keep a public read-only demo mode explicit and separate from the production profile.

---

## 4. P2 — optional, UX, docs, extensibility

### 4.1 Prior art: what to borrow, what to reinvent, what to drop

| Concern | This prototype | Standard / prior art | Recommendation |
|---|---|---|---|
| Capability model | Bearer token in a server store + device proof | Object-capability/POLA; macaroons; Biscuit; UCAN | Keep the server-authoritative store and the one-use commit. Borrow attenuation/caveats/chains if you need delegation; don't invent a new token format. |
| Proof of possession | Custom `secrecy:v1` ECDSA proof string | DPoP (RFC 9449), JWS `cnf.jkt` (RFC 7800) | Borrow `htm`/`htu`/`iat`/`jti`/`ath`/server `nonce` and `cnf.jkt`. This is the closest standard to what the code already does. |
| User presence | `event.isTrusted` + challenge/token | WebAuthn UV; PSD2 dynamic linking; OWASP transaction authorization | Borrow WebAuthn UV and exact scope/body display. Drop `isTrusted` as a control. |
| Scope authorization | Client declares scope keys | Zanzibar/ReBAC; RAR `authorization_details` (RFC 9396); Sandstorm Powerbox | Borrow server-side relationship checks and typed `authorization_details`. Add a Powerbox-style UI where the user picks an authorized resource. |
| Multi-step | `parentCap`/`prevHash` | Macaroon caveats; Biscuit; UCAN `prf`/`att`; UCON continuity | Keep the two-step concept, but bind `draftHash`/`draftId`; consider a standard chain for >2 steps. |
| Revocation | Device flag + dead cap flag | OAuth revocation; Biscuit revocation IDs; UCAN revocation | Fix canonical JWK; add per-cap and account-level revocation; enforce the flag; short TTLs. |
| Sessions | Bearer in JS memory | BFF + `HttpOnly` cookies; OAuth token exchange (RFC 8693) | Move token custody server-side (BFF); keep WebAuthn/DPoP for the device. |
| XSS defense | No CSP; demo on same origin | CSP/Trusted Types; sandboxed iframe/separate origin | Isolate the XSS demo; strict CSP in production; Trusted Types. |
| Audit | In-memory array | Append-only hash chain; SIEM | Tamper-evident, scoped, correlated by `requestId`/`auditId`. |
| UI authority | `view` as a policy hint | Powerbox; BFF | Keep `view` as UX only; make the server the authorizer. |

**Borrow:** DPoP fields, WebAuthn UV, RAR/`authorization_details`, Zanzibar/ReBAC, Powerbox, PSD2 dynamic linking, OWASP transaction authorization, Biscuit/UCAN/macaroons for attenuation, UCON continuity/obligations, BFF for session custody, CSP/Trusted Types/sandboxed origin.

**Reinventing the wheel:** the HMAC envelope (JWT/JOSE), the proof string (DPoP), the presence challenge/token (WebAuthn), the `prevHash` chain (macaroon/Biscuit/UCAN), the `view` guard (UX only), the `revoked` flag (OAuth revocation).

**Drop:** HMAC `sig` if the store is authoritative; `demo` from the core; `isTrusted` as a control; `maxUses`/`used` duplication; the dead `record.revoked` flag (or enforce it); `view` from security claims; the "Secrecy" name.

### 4.2 Naming: "Secrecy" is the wrong property; "MVC + S" is undefined

"Secrecy" means confidentiality (encryption, secret storage). This layer is about **authority/authorization** (who may do what, once, with what scope, with what proof). A reader will expect secret-keeping, then find capabilities, hashes, and revocation. It also collides with "secret" (the HMAC key) and muddles the threat model.

- Rename the layer to **Permit**, **Warrant**, **Grant**, or **Authority**. "Capability" is accurate but overloaded; use "capability token" for the artifact and "authority layer" for S.
- `secrecy.execute` → `authority.execute` / `permit.use`; `Secrecy` → `Authority`; `SecrecyError` → `AuthorityError`.
- Define **S** once at the top of README/DESIGN: "S = a server-issued, scope-bound, single-use authority layer (not confidentiality)." Or rename the pattern "MVC + Grants."
- Rename "view" to "surface" or "UI context" to avoid the MVC view/policy-context ambiguity; or keep "view" but define it in the policy as a UI context, not a security principal.
- Rename "presence" to "user verification" when WebAuthn, and "confirmation" when UX-only. Do not call a client click "presence."
- Rename `demo` to `unsafeLab`/`demoOnly` so it is obvious it must not ship.

### 4.3 Docs honesty: fix the false claims and add a "known broken" section

Keep the excellent framing ("not XSS-proof; bounded, scoped, detectable, revocable") and the honest threat model, but correct these:

- **"One-time / single use"** (`README.md:7-8`, `DESIGN.md:243-251`): false under concurrency (P0-1). Add "single-use after the P0-1 fix; currently double-spendable under parallel requests."
- **"Re-registering the same JWK reuses the device (unless revoked)"** (`DESIGN.md:108-116`): false for non-canonical encodings (P0-5). Add the canonicalization caveat.
- **`deviceJkt` in the payload** (`DESIGN.md:124-141`): currently absent (`undefined`, P1-1). Fix code or remove the claim.
- **"Cannot use a capability after device revocation"** (`DESIGN.md:400-409`): false via padded JWK (P0-5) and racy in-flight actions (P1-3). Add caveats.
- **"Every issue/consume/denial/revocation is logged"** (`DESIGN.md:17-18`, `312-342`): denials lack `userId` (P1-4); add scope/body/result/outcome.
- **"Presence gate"**: label it "simulated UX confirmation; bypassable by any script; not a security control" until WebAuthn (P0-2).
- **"Bounded"**: qualify as "bounded to the client-chosen scope; resource authorization is not implemented" (P0-4).
- **"A stolen session can mint ... but still cannot produce action proofs without the private key"** (`DESIGN.md:454-457`, `README.md:161-163`): true for a remote token thief, false for XSS, which has the page's signing oracle. Say "without script execution in the page (or the private key)."
- **"Node's single-threaded event loop makes check-and-set atomic"** (`DESIGN.md:246-248`): false across `await`; remove or scope to synchronous blocks.

Add a "Known broken in this prototype" list (P0-1..P0-5) so readers do not mistake the demo for a security boundary.

### 4.4 Presence/UX

- Display the exact action, scope, body summary, capability ID, expiry, and device in the confirmation modal. The current modal shows only the action (`app.js:726`).
- Keep at most one outstanding challenge per device/action; invalidate older challenges; show expiry; cancel invalidates.
- Do not use `isTrusted` as a security signal; if WebAuthn is not implemented, say "demo confirmation" in the modal and remove "high-risk" language or mark it "not enforced."
- Add a clear error for "presence token expired/scope changed; re-approve."

### 4.5 Error/API UX

- Stable error enum with `source: "client"|"server"`, `retryable`, `details`, `auditId`. Currently client and server codes share names (`SCOPE_DENIED`, `ACTION_NOT_ALLOWED_IN_VIEW`, `PRESENCE_REQUIRED`) with no source.
- `PRESENCE_REQUIRED` should carry `challenge`, `scopeHash`, `bodyHash`, `expiresAt`; the client should not have to reach into `error.extra`.
- Do not reveal `UNKNOWN_CAPABILITY` vs `INVALID_CAPABILITY` to unauthenticated callers; use 403 for both and rate-limit. The current 404 vs 403 distinction is an oracle (limited by 144-bit IDs, but unnecessary).
- Add `idempotencyKey` per `execute` and a receipt lookup, so a network failure after consumption does not leave the user unsure whether the write happened. The current one-use model makes retries ambiguous (`CAPABILITY_CONSUMED` after a lost response).
- Add a `receipt`/`auditId` to the execute result for support and correlation, while still returning the business result.

### 4.6 Policy/extensibility

- The capability core is generic, but `normalizeScopeValue` hardcodes `userIds`/`maxSize` (`server.js:252-273`). A new typed scope (amount, currency, enum) requires editing the core, violating the "only policy + handler + controller" goal. Use a typed schema: `scope: { boardId: "BoardId", userIds: "UserIdList1to20", maxSize: "Bytes1to100MiB" }` with server-side validators.
- `risk` is declared but unused; derive `presence` from `risk` or validate the pair.
- `views` mixes actions and UI-only names (`login`, `viewFeed`, `openChat`); split `actions` from `ui`.
- Add `aud`/tenant, `nbf`/clock skew, per-action budgets, obligations (`audit`, `notify`, `rate`), and a JSON Schema. Negotiate `policy.version` with `/api/policy`; the client currently never checks the server's policy version (`server.js:1144-1149`, `1067`).
- Keep server authorizers out of the shared client policy file.

### 4.7 Code structure and size

- `public/secrecy.js` is 468 lines (<500, meets the target), but ~50 lines are the demo API (`416-463`) and ~60 are IndexedDB (`67-109`, `367-383`); the core protocol/client is ~360. Removing the demo API leaves ~420. Split into `protocol.js` (~80), `client.js` (~280), `demo-hooks.js` (~50). Then the "core <500" claim is robust, not incidental.
- `server.js` is 1264 lines: extract `http.js`, `policy-schema.js`, `store.js`, `audit.js`, `presence.js`, and `handlers/*`. The capability core is small; the file is large because it mixes HTTP, policy, business, audit, and static serving.
- `app.js` is 1126 lines of template strings; fine for a demo, but a small render helper/partials would reduce duplication. The `esc()` discipline is good.
- `test/smoke.mjs` is 480 lines; keep it, but add a shared protocol module and a concurrency harness (raw sockets/Playwright), not only `fetch`.

### 4.8 HTTP/static/CSP

- No CSP by design (`server.js:1219`); in production add strict CSP + Trusted Types + `frame-ancestors`/`X-Frame-Options` + CORP/COOP + Referrer-Policy. Isolate the XSS demo on a separate origin or sandboxed iframe.
- `handleStatic` path containment is lexical (`server.js:1193-1202`); it does not resolve symlinks. Use `fs.realpath` and verify the real path is under `PUBLIC_DIR`. No directory listing (good).
- `readJson` accepts any content type; require `application/json` for state-changing POSTs. Check `Origin`/`Sec-Fetch-Site`; keep CORS closed.
- `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` are good; keep.
- `resetDevice` (`secrecy.js:312-328`) deletes the local key but does not revoke the server device/caps or clear the session. A user may think "Forget local key" revokes. Call `/api/revoke` first (with confirmation) or label it "forget local key (server capabilities remain until expiry)"; test.
- `changeAvatar` validates MIME only at action (`server.js:832-835`), not at issuance; validate at issue.
- `mention` checks user existence only at action (`server.js:812-830`); check at issue to avoid guaranteed-to-fail capabilities.
- Clock skew: `exp < now()` only (`941`); add `nbf`, `iat`, and ±30s leeway; the client has `serverTime` but doesn't use it.
- Audit UI shows only type/action/reason/capId (`app.js:804-819`); add scope/body hash/result and filters/pagination.
- Multi-tab: same IndexedDB key, separate sessions and in-memory links; one tab's `post:edit` link is invisible to the other, and concurrent edits can burn parents. Persist the continuation or key links by flow id; test two tabs.

---

## 5. Proposed v2 API and policy

This is a proposal, not an implementation. It keeps the clean business seam and fixes the P0s by making scope/body explicit, binding presence, and moving atomicity into the store.

### 5.1 Client API

```ts
// public/authority.js — business code sees this and nothing below it
type Policy = {
  version: number;
  views: Record<string, { actions: string[]; ui?: string[] }>;
  actions: Record<string, ActionSpec>;
};

class Authority {
  constructor(opts: {
    api: string;
    policy: Policy;
    deviceName?: string;
    dbName?: string;
    demoHooks?: boolean;        // default false; demo page opts in explicitly
  });

  init(): Promise<{ user: User; device: Device }>;   // PoP challenge -> sign -> register
  view(name: string): ViewHandle;                     // no global currentView
  execute(action: string, req: { scope: Scope; body?: Body }, opts?: ExecuteOptions): Promise<Result>;
  confirmPresence(req: { challenge: string; assertion: WebAuthnAssertion }): Promise<PresenceReceipt>;
  revokeDevice(): Promise<RevokeResult>;
  resetDevice(): Promise<void>;                       // revokes first, then deletes the key
  on(event: "ready" | "error" | "presence" | "revoked", fn: (value: any) => void): () => void;
  lastReceipt(): Receipt | null;
}

class ViewHandle {
  execute(action: string, req: { scope: Scope; body?: Body }, opts?: ExecuteOptions): Promise<Result>;
  can(action: string): boolean;
  actions(): string[];
}

type ExecuteOptions = {
  presence?: (req: {
    action: string; scope: Scope; scopeHash: string; bodyHash: string; challenge: string;
  }) => Promise<PresenceAssertion>;               // WebAuthn or explicit demo confirmation
  idempotencyKey?: string;
  signal?: AbortSignal;
};

type Result = { data: unknown; receipt: Receipt };
type Receipt = {
  capId: string; action: string; view: string;
  scopeHash: string; bodyHash: string; exp: number;
  auditId: string;
  sequence?: { nextAction: string; continuation: string };
};
type AuthorityError = Error & {
  code: string; source: "client" | "server"; status: number;
  retryable: boolean; details: Record<string, unknown>; auditId?: string;
};
```

Business code stays one line:

```js
const { data } = await home.execute("createPost", {
  scope: { boardId: "b1" },
  body: { text: "hello" }
});
```

### 5.2 Server endpoints

```text
POST /api/register/challenge   {} -> { challenge, exp }
POST /api/register             { publicKeyJwk, challenge, proof, deviceName }
                               -> { userId, deviceId, deviceJkt, session }
POST /api/session/refresh      -> { session }                     // rotating
POST /api/capabilities         { action, view, scope, bodyHash, presenceToken?, parent? }
                               -> { capability: { id, action, view, scopeHash, bodyHash, exp, parentCap? }, receipt }
POST /api/presence/challenge   { action, scopeHash, bodyHash } -> { challenge, exp }
POST /api/presence/verify      { challenge, webauthnAssertion }
                               -> { presenceToken, exp, scopeHash, bodyHash }
POST /api/action               { capabilityId, proof, action, scope, body, view, presenceToken? }
                               -> { result, receipt, sequence? }
POST /api/revoke               { deviceId? } -> { ... }            // self; admin for account
GET  /api/state                -> 401 if a token is present but invalid; scoped data
GET  /api/audit                -> 401; scoped to caller; admin scope for all
GET  /api/policy               -> { version, policy }              // client-safe only
```

Key changes: `capabilityId` + `proof` instead of the full envelope; explicit `scope` + `body`; `bodyHash` bound at issuance; presence challenge/token carry `scopeHash`/`bodyHash`; proof is DPoP-like (`htm`, `htu`, `iat`, `jti`, `ath`, `nonce`).

### 5.3 Policy manifest (client-safe)

```js
// public/policy.js — no secrets, no server authorizers
module.exports = {
  version: 2,
  views: {
    login:   { actions: [], ui: ["login"] },
    home:    { actions: ["createPost", "post:edit", "post:submit"], ui: ["viewFeed", "openChat"] },
    chat:    { actions: ["sendMessage", "mention"] },
    profile: { actions: ["changeAvatar"] }
  },
  actions: {
    createPost: {
      scope: { boardId: "BoardId" },
      body: { text: "Text1to2000" },
      risk: "low",
      maxUses: 1,
      ttlSeconds: 300,
      presence: "none",
      authorize: "board.write"              // resolved server-side
    },
    sendMessage: {
      scope: { chatId: "ChatId" },
      body: { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 60, presence: "none",
      authorize: "chat.write"
    },
    mention: {
      scope: { chatId: "ChatId", userIds: "UserIdList1to20" },
      body: { text: "Text1to2000" },
      risk: "medium", maxUses: 1, ttlSeconds: 60, presence: "none",
      authorize: "chat.mention"
    },
    changeAvatar: {
      scope: { mime: "ImageMime", maxSize: "Bytes1to100MiB" },
      body: {},
      risk: "high", maxUses: 1, ttlSeconds: 120,
      presence: "webauthn",                  // bound to scopeHash + bodyHash
      authorize: "self.updateProfile"
    },
    "post:edit": {
      scope: { boardId: "BoardId" },
      body: { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 300, presence: "none",
      authorize: "board.write",
      next: {
        action: "post:submit",
        bind: ["boardId"],
        carry: ["draftId", "draftHash"]      // the child authorizes the exact content
      }
    },
    "post:submit": {
      scope: { boardId: "BoardId", draftId: "DraftId", draftHash: "Sha256" },
      body: {},
      risk: "low", maxUses: 1, ttlSeconds: 300, presence: "none",
      authorize: "board.write",
      parent: "post:edit"
    }
  }
};
```

### 5.4 Server-only authorizers

```js
// server/authorizers.js — never shipped to the browser
module.exports = {
  "board.write":        (auth, scope) => boards.can(auth.userId, scope.boardId, "editor"),
  "chat.write":         (auth, scope) => chats.isMember(auth.userId, scope.chatId),
  "chat.mention":       (auth, scope) => chats.canMention(auth.userId, scope.chatId, scope.userIds),
  "self.updateProfile": (auth) => true
};
```

Issuance and use both call `authorizers[config.authorize](auth, scope)`; a missing authorizer is a boot error (fail closed). This is the Zanzibar/Powerbox-style check the current code lacks.

### 5.5 Atomic store interface

```js
// server/store.js — the only place that mutates capability state
consumeCapability({ capId, deviceId, proofHash, now })
  -> { ok: true, uses, chainHash } | { ok: false, reason: "CONSUMED" | "EXPIRED" | "REVOKED" }

issueChild({ parentCapId, deviceId, prevHash, child })
  -> { ok: true, child } | { ok: false, reason: "CONSUMED" | "SEQ_MISMATCH" | "EXPIRED" }

consumePresence({ token, deviceId, action, view, scopeHash, bodyHash, now })
  -> boolean

redeemChallenge({ challenge, deviceId, now })
  -> record | null

revokeDevice({ deviceId, now })
  -> { revokedCapabilities }
```

In SQL, each is a conditional update/transaction with a unique constraint; in memory, one synchronous critical section. The HTTP handlers never check-then-set across an `await`.

### 5.6 Migration notes

- `execute(action, params)` can keep working via a compatibility wrapper that splits params into `scope`/`body` using the policy; deprecate it.
- Keep `secrecy.execute` as an alias if you must, but rename the class/module.
- The demo page can load `demo-hooks.js` explicitly; production builds omit it and `window.secrecy`.

---

## 6. Required v2 tests

The current smoke suite is a good sequential baseline. Add the following; the marked ★ are the ones that would have caught the P0s.

### Protocol / crypto

| ID | Test | Expected |
|---|---|---|
| T01 | Shared canonicalization vectors across server/client/test: nested objects/arrays, unicode, `-0`, large ints, `__proto__`, `constructor`, `prototype` | Identical bytes; dangerous keys rejected; body hash injective. |
| T02 | Tamper every capability payload field (`v, capId, userId, deviceId, deviceJkt, action, scope, seq, nonce, maxUses, exp, parentCap, prevHash, view, iat`) | `INVALID_CAPABILITY` or the specific `*_MISMATCH`; never a write. |
| T03 | Malformed envelope: missing payload/sig, non-string sig, oversized, unknown capId | 400/403/404 with a stable code; no stack; no state change. |
| T04 | Proof binds action/scope/seq/nonce/bodyHash/prevHash/method/path/iat/jti/ath | Each tamper → `INVALID_PROOF`; no state probe before proof. |
| T05 | Replay the same proof with a different body/params | `INVALID_PROOF`; ★ catches body-binding regressions. |
| T06 | Expired capability; `nbf`/clock skew; short-TTL test policy | `CAPABILITY_EXPIRED`; no immortal cap from missing `ttl`. |
| T07 | JWK: padded/whitespace `x`/`y`, non-canonical point, `d` present, wrong curve, wrong length | 400; same key → same canonical jkt; ★ revoked key stays revoked. |
| T08 | `deviceJkt` in register response, state, and capability payload | Present and equal to the canonical thumbprint; ★ catches P1-1. |
| T09 | Valid envelope for cap A used for cap B; `iss`/`aud`/`kid` mismatch; key rotation | Rejected; old keys rejected/rotated; ★ catches token-binding regressions. |

### Atomicity / concurrency

| ID | Test | Expected |
|---|---|---|
| T10 ★ | 2/10/50 parallel `/api/action` with the same cap+proof over separate connections | Exactly 1 success, N−1 `CAPABILITY_CONSUMED`; 1 business write; 1 `consumed` audit. |
| T11 | Multi-use policy: concurrent different bodies | `uses` increments exactly; no lost update; each authorized body once. |
| T12 | Two concurrent child issuances for the same parent | 1 OK, 1 `CAPABILITY_CONSUMED`; 1 child; parent link consistent. |
| T13 | Two concurrent `/api/presence` with the same challenge | 1 token, 1 invalid. |
| T14 | Two concurrent `/api/capabilities` with the same presence token | 1 OK, 1 rejected. |
| T15 | Revoke during an in-flight action (delay verify or test hook) | Action fails `DEVICE_REVOKED` (or is documented as pre-revocation with timestamps); no post-revocation write. |
| T16 | Two server processes / fake store with conditional updates; same cap concurrently | Exactly 1 success across processes. |
| T17 | Crash between consume and perform | Cap burned; `outcome:"failed"`; no double write; receipt/idempotency. |

### Presence

| ID | Test | Expected |
|---|---|---|
| T18 ★ | High-risk issuance without token; with valid WebAuthn assertion | `PRESENCE_REQUIRED` + challenge; 200 with assertion. |
| T19 ★ | Direct `/api/presence` with challenge, no user verification; `grantPresence({isTrusted:true})` | Rejected (WebAuthn) / explicitly UX-only (demo); no high-risk capability. |
| T20 ★ | Benign challenge → token → substituted scope/body | `PRESENCE_REQUIRED`/`PRESENCE_SCOPE_MISMATCH`; same scope/body → 200. |
| T21 | Token bound to different device/action/view | Rejected. |
| T22 | Token/challenge replay and expiry; new challenge invalidates old | Rejected; one outstanding challenge. |
| T23 | Presence at `/api/action` bound to `bodyHash` | Different body → rejected; same body → 200. |
| T24 | Playwright: synthetic click vs real click + WebAuthn; modal shows exact scope | Synthetic rejected; real accepted; scope visible. |

### Scope authorization

| ID | Test | Expected |
|---|---|---|
| T25 ★ | Issue for a board/chat the caller cannot access | `FORBIDDEN`/`SCOPE_DENIED`; no capability. |
| T26 | `mention` nonexistent/blocked user | Denied at issue (not only at action). |
| T27 | Membership revoked after issuance | Capability use fails (continuity); re-issue denied. |
| T28 | Scope types: maxSize 0/negative/too large, bad MIME, 21 userIds, duplicates, strings | Denied at issue; normalized values match. |
| T29 | Extra params cannot widen scope; client scope is not trusted | `SCOPE_DENIED`; proof body binds the rest. |
| T30 | Cross-tenant IDs in `/api/state`/drafts/caps | Not visible. |

### Sequence / multi-step

| ID | Test | Expected |
|---|---|---|
| T31 | Skip `post:edit` → `post:submit` | `SEQ_MISMATCH`. |
| T32 | Reuse `post:edit` for a second child | `CAPABILITY_CONSUMED`. |
| T33 | Wrong/old `prevHash`; child scope ≠ parent; cross-device child | `SEQ_MISMATCH`/`SCOPE_DENIED`. |
| T34 | Expired/revoked parent | `CAPABILITY_EXPIRED`/`DEVICE_REVOKED`; no child use. |
| T35 | Child issued but unused; parent burn/cancel semantics | Parent not permanently burned (or documented); expiry respected. |
| T36 ★ | Change draft text between edit and submit | `DRAFT_HASH_MISMATCH`; no publish. |
| T37 | `post:edit` handler failure (invalid text) | Cap burned; no child can publish a nonexistent draft; `outcome:"failed"`. |

### Device / revocation

| ID | Test | Expected |
|---|---|---|
| T38 | Cross-device: B uses A's cap with B's proof; B uses A's cap with A's proof | `DEVICE_MISMATCH`; no write. |
| T39 ★ | Re-register same JWK exact/padded/whitespace/`ext`/`key_ops`; revoked key | Same canonical device; PoP required; revoked → 403; no new `deviceId`. |
| T40 | Revoke: all caps fail; sessions fail; presence tokens/challenges deleted; re-register canonical jkt fails; new key works | `DEVICE_REVOKED`; one-way; no bypass. |
| T41 | Per-cap revocation (if added) | Revoked cap fails on the same device; parent/child revoked; audit. |

### Audit

| ID | Test | Expected |
|---|---|---|
| T42 ★ | Unauth `/api/audit`; A reads B's events; admin reads all | 401; scoped/redacted; admin scope separate. |
| T43 ★ | Every issue/consume/deny/revoke has user/device/cap/action/reason/time; consumed has scopeHash/bodyHash/resultId/parentCap/outcome; denied has `userId` | Complete and attributable. |
| T44 | Forged capId/action in the request | Not trusted; audit uses the looked-up record or marks `untrusted`. |
| T45 | Tamper an event; `/api/audit/verify`; cap overflow | Verification fails; `dropped` counter; append-only. |
| T46 | Double-spend attempts | Exactly one `consumed`; denied/anomaly counter; alertable. |

### Client / browser

| ID | Test | Expected |
|---|---|---|
| T47 | Key persistence across reload; reset clears; private key non-extractable | Same device after reload; no private export; reset behavior documented. |
| T48 | `execute` view guard; `ViewHandle`; two tabs/flows | Rejected before network; no clobbered `_links`/presence. |
| T49 | Presence modal: cancel, expiry, re-request; errors | Clear UX; no stuck state; no `window.secrecy`/demo in production. |
| T50 ★ | XSS demo on isolated origin: cross-action, replay, presence bypass, one allowed use; CSP when demo off | Blocked/allowed as documented; direct presence bypass blocked after fix; audit shows attempts. |
| T51 | Network failure after consume; idempotency/receipt | User sees "may have succeeded"; no blind retry; receipt lookup. |

### Policy / HTTP

| ID | Test | Expected |
|---|---|---|
| T52 ★ | Missing `ttl`/`maxUses`/`scope`, unknown view action, unknown/cyclic parent/next, risk/presence mismatch, `__proto__`/`constructor` keys | Boot fails with a clear message; no immortal cap; no 500. |
| T53 | Static: traversal (encoded, symlink), HEAD, method, content-type | Contained; 404/405; no symlink escape. |
| T54 | Body size, invalid JSON, wrong content-type, Origin/Sec-Fetch-Site, rate limits, expired token state | 413/400/401/429; no CSRF; 401 not 200 `me:null`. |
| T55 | Unknown vs invalid capability; 404/403 enumeration | Uniform 403 or rate-limited; no stack. |

---

## 7. What to keep (genuine strengths)

- **The business seam is excellent.** `app.js:612-686` controllers are one-liners around `secrecy.execute(action, params)`; no controller touches `crypto.subtle`, canonicalization, proof strings, capability tokens, or presence tokens. This is the best part of the prototype and should survive v2.
- **Scope is derived from the request and compared to the capability** (`server.js:952-960`), not trusted from the token. This correctly prevents "use a `b1` capability with `boardId:b2`" and is the right pattern; it needs an authorization layer above it, not replacement.
- **Server-authoritative store.** The client cannot mint or consume; the server owns `capabilities`, `devices`, `sessions`, `presence*`, `drafts`, `audit`. This is the right trust boundary.
- **Non-extractable device key + ECDSA proof.** `secrecy.js:99-109` generates with `extractable:false`; only the public JWK is sent (`161-164`); IndexedDB persists the `CryptoKey` (`367-383`). Verified: public key exportable, private key not. Keep this.
- **Consume-before-side-effect bias.** `server.js:1001-1015` burns the capability before the business write; a handler error does not allow replay. The implementation has the P0-1 race, but the *principle* is right; fix the commit, don't change the bias.
- **Clear error envelope and codes.** `server.js:384-432`, `README.md:365-385`, `secrecy.js:405-412`: `SCOPE_DENIED`, `PRESENCE_REQUIRED`, `CAPABILITY_CONSUMED`, `SEQ_MISMATCH`, `DEVICE_REVOKED`, `INVALID_PROOF` are distinguishable; the UI can react. Add `source`/`retryable`, keep the codes.
- **Declarative policy shared client/server.** `public/policy.js` is a UMD file required by `server.js:15` and loaded by `index.html:36`; one manifest, no drift for the fields it covers. Keep the idea; add a schema and split server authorizers.
- **Honest threat model.** `DESIGN.md:17-21`, `387-432`, `448-469` and `README.md:17-20` explicitly say "not XSS-proof", "bounded/scoped/detectable/revocable", "presence simulated", "HMAC symmetric", "in-memory". This is rare and valuable; keep it and correct the specific false claims (4.3).
- **The XSS demo is real.** `app.js:892-1034` injects an actual `<script>` element and shows blocked cross-action/replay attempts and one allowed use. Keep the demo, but isolate it, remove the always-on signing oracle from the core, and add the direct presence-bypass step.
- **Audit + revocation + one-way rotation.** `server.js:191-206`, `1082-1126`; revoked JWK cannot re-register *for the exact encoding*; rotation creates a new identity. Keep; fix canonicalization, scope the audit, enforce the flag.
- **Good output encoding.** `app.js:43-50` `esc()` is used for every dynamic value in the templates; toasts use `textContent`; the audit/XSS logs escape. The app itself has no obvious DOM XSS; the injected script is deliberate. Keep this discipline.
- **No dependencies, readable structure, good tests for the happy path.** The smoke test is independent of the client (reimplements the protocol, so drift is caught), runs with `fetch` + `node:crypto`, and prints per-check PASS/FAIL. Keep it and extend it.
- **The two-step parent/prevHash concept** is a reasonable minimal state machine; it just needs content binding (`draftHash`) and consumption-time parent burn.
- **`PRESENCE_REQUIRED` + challenge retry UX** is a good UX skeleton for WebAuthn; keep the flow, replace the trust.

---

## Appendix A — Reproduction sketches

These are sketches, not files to add to the repo.

**A.1 Double-spend (raw sockets; `fetch` may serialize):**

```js
// Register a device, issue a createPost capability, and build one valid proof.
// Then send the same body over two independent sockets, writing both before reading:
const [a, b] = await Promise.all([
  rawRequest("/api/action", token, body), // http.request({ agent: false })
  rawRequest("/api/action", token, body)
]);
// Expected after fix: one 200, one 409 CAPABILITY_CONSUMED.
// Observed: 40/40 pairs had two 200s.
```

**A.2 Presence scope substitution:**

```js
const benign = await issue(token, "changeAvatar", { mime: "image/png", maxSize: 1024 }, "profile");
const { challenge } = benign.data.error;             // 403 PRESENCE_REQUIRED
const { presenceToken } = await presence(token, challenge);
const substituted = { mime: "image/jpeg", maxSize: 104857600 };
const issued = await issue(token, "changeAvatar", substituted, "profile", { presenceToken });
// Observed: 200; the action with the substituted scope also 200s.
```

**A.3 JWK padding revocation bypass:**

```js
const padded = {
  ...publicJwk,
  x: publicJwk.x.replace(/=+$/, "") + "=",
  y: publicJwk.y.replace(/=+$/, "") + "="
};
// register canonical -> revoke -> register padded -> new deviceId -> sign with the same private key -> 200.
// Local probe: x + " " (trailing whitespace) also imports and changes the jkt.
```

**A.4 Audit:**

```bash
curl -s http://127.0.0.1:8787/api/audit?limit=1
# Observed: 200 with events, no Authorization header.
```

**A.5 Key extractability (confirms the strength):**

```js
const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
pair.publicKey.extractable;  // true
pair.privateKey.extractable; // false
await crypto.subtle.exportKey("jwk", pair.publicKey);  // OK
await crypto.subtle.exportKey("jwk", pair.privateKey); // InvalidAccessException
```

---

*End of review.*
