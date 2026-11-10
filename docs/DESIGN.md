# DESIGN — MVC + Secrecy v2.1

> Layout: source is under `src/`, docs are under `docs/`. Paths below are relative to the repository root.

## 1. What this is

A small **server-authorized authority layer** in front of an MVC app. For each
write, the browser obtains a capability that is:

- issued for one action;
- bound to an exact scope and request body hash;
- bound to a device key (ECDSA P-256) and its canonical JWK thumbprint;
- single-use after an atomic server-side commit;
- checked against a server-only ACL at **issuance and use**;
- optionally gated by a presence approval that is consumed at **action time**
  (console OOB in demo; WebAuthn contract for production);
- auditable and revocable.

The honest claim is **bounded, scoped, detectable, revocable** authority. This is
not an XSS-proof or confidentiality design. The layer is named "Secrecy" for
continuity with v1; it is really an authorization/capability layer. See §16 for
prior art and naming notes.

## 2. MVC + S

```
Browser (app.js, views/controllers)
  └─ secrecy.execute(action, { scope, body })
       └─ src/public/secrecy.js
            ├─ device key + PoP registration
            ├─ presence provider (OOB / WebAuthn seam)
            ├─ capability request + proof signing
            └─ HTTP /api
                 └─ src/server.js
                      ├─ protocol.js (canonicalization/proof helpers)
                      ├─ src/public/policy.js (client-safe shape/metadata)
                      ├─ server-policy.js (ACLs + boot validation)
                      ├─ MemoryStore (atomic capability transitions)
                      └─ business state + audit
```

- **Model**: server-authoritative maps for users, devices, capabilities, drafts,
  presence grants, feed/messages and audit. The browser keeps a projection from
  `GET /api/state`.
- **View**: static HTML/CSS + hash router; views render from state.
- **Controller**: submit handlers call `secrecy.execute(...)`. They never touch
  tokens, hashes, signatures, presence tokens or WebCrypto.
- **Secrecy layer**: protocol, key custody, registration PoP, capability
  lifecycle, presence-provider orchestration and proof signing.

## 3. Shared modules

| File | Runs where | Purpose |
|---|---|---|
| `src/public/protocol.js` | browser + server + tests | canonicalization, hashes, base64url, proof strings |
| `src/public/policy.js` | browser + server | client-safe views, scope/body keys and action metadata |
| `server-policy.js` | server only | ACL authorizers + strict policy boot validation |
| `src/public/presence.js` | browser | provider interface, WebAuthn stub, static-code helper |
| `src/public/secrecy.js` | browser | framework-agnostic client (<500 lines) |
| `src/public/demo-hooks.js` | browser, demo-only instance | XSS lab signing oracle; served only with server `DEMO` on and instantiated only with `?demo=1` |
| `src/server.js` | Node | HTTP, verifier, in-memory store, business, audit |

`protocol.js` rejects `__proto__`/`prototype`/`constructor` keys, uses null-
prototype canonical objects, rejects non-finite/non-JSON values, and provides
strict unpadded base64url decoding. This prevents the v1 non-injective body-hash
and prototype-chain lookup classes of bug.

## 4. Policy and server authorization

`src/public/policy.js` (v2) is client-safe:

```js
{
  version: 2,
  views: {
    login:   { actions: [], ui: ["login"] },
    home:    { actions: ["createPost", "post:edit", "post:submit"], ui: ["viewFeed", "openChat"] },
    chat:    { actions: ["sendMessage", "mention", "chat:join", "chat:leave"] },
    profile: { actions: ["changeAvatar"] }
  },
  actions: {
    createPost: {
      scope: { boardId: "BoardId" },
      body: { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 300,
      presence: false, authorize: "board.write"
    },
    sendMessage: {
      scope: { chatId: "ChatId" }, body: { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 60,
      presence: false, authorize: "chat.write"
    },
    mention: {
      scope: { chatId: "ChatId", userIds: "UserIdList1to20" },
      body: { text: "Text1to2000" },
      risk: "medium", maxUses: 1, ttlSeconds: 60,
      presence: false, authorize: "chat.mention"
    },
    "chat:join": {
      scope: { chatId: "ChatId" }, body: {},
      risk: "low", maxUses: 1, ttlSeconds: 60,
      presence: false, authorize: "chat.join"
    },
    "chat:leave": {
      scope: { chatId: "ChatId" }, body: {},
      risk: "low", maxUses: 1, ttlSeconds: 60,
      presence: false, authorize: "chat.leave"
    },
    changeAvatar: {
      scope: { mime: "AvatarMime", maxSize: "Bytes1to104857600" },
      body: { reason: "Text1to200" },
      risk: "high", maxUses: 1, ttlSeconds: 120,
      presence: true, authorize: "self.profile"
    },
    "post:edit": {
      scope: { boardId: "BoardId" }, body: { text: "Text1to2000" },
      risk: "low", maxUses: 1, ttlSeconds: 300,
      presence: false, authorize: "board.write",
      next: "post:submit"
    },
    "post:submit": {
      scope: { boardId: "BoardId", draftId: "DraftId", draftHash: "Sha256" },
      body: {},
      risk: "low", maxUses: 1, ttlSeconds: 300,
      presence: false, authorize: "board.write",
      parent: "post:edit"
    }
  }
}
```

`server-policy.js` is the authority. Demo ACLs:

- `board.write`: the board must be `b1`/`b2` **and** the authenticated user must
  be a member of that board (`boardMembers`). Membership is checked at issue and
  again at use.
- `chat.write`: chat `c_general` and current membership.
- `chat.mention`: same chat membership, plus every mentioned user must exist and
  be a member of that chat.
- `chat.join`: known chat; join is a capability action.
- `chat.leave`: known chat and current membership; leave is a capability action.
- `self.profile`: self-only change; there is no target user in the scope.

`authorize()` is called:

1. at capability issuance, before any token is minted;
2. again at use, after proof verification and immediately before commit, so a
   membership or ACL change denies an already-issued capability.

Boot validation (`validatePolicy`) fails closed for missing/invalid
`ttlSeconds`, `maxUses !== 1`, unknown authorizer, non-reciprocal sequence links,
dangerous keys, unknown view actions and malformed scope/body types.

## 5. Registration and canonical identity

### JWK canonicalization

The server accepts only EC P-256 public JWKs with:

- `x`/`y` matching `^[A-Za-z0-9_-]{43}$`;
- strict unpadded base64url decode to exactly 32 bytes;
- re-encode equals input (rejects padding, whitespace, non-canonical encodings);
- no private `d`.

It stores the canonical `{kty,crv,x,y}` and computes an RFC 7638 thumbprint over
`{crv,kty,x,y}`. `devicesByJkt` is keyed by that canonical thumbprint.
`device.jkt` is the single property used everywhere; the public API name is
`deviceJkt`.

### Proof-of-possession

1. `POST /api/register/challenge` `{publicKeyJwk, deviceName}` returns
   `{challenge, exp, jkt, deviceNameHash}`. The server stores the challenge bound
   to canonical JKT + deviceNameHash, single-use and short-lived.
2. The client signs:
   ```text
   register:v2|<challenge>|<jkt>|<deviceNameHash>
   ```
3. `POST /api/register` verifies the ECDSA signature with the submitted JWK,
   then **atomically consumes** the challenge via
   `RegistrationChallengeStore.consume()` and creates/reuses the device/session
   in one synchronous block. The challenge consume is after the final await, so
   concurrent replays cannot both succeed.
4. `/api/register` is rate-limited per IP and per JKT; invalid proofs increment a
   challenge attempt counter (burned after five); sessions are capped per device.

This prevents an attacker who only knows the public JWK from getting a session,
renaming the device or revoking it. Re-registering the same canonical key with
valid PoP reuses the device; if it was revoked, registration fails with
`DEVICE_REVOKED`. Padded/whitespace encodings are rejected before lookup, so they
cannot create a second identity.

Sessions are random bearer tokens held in JS memory. They identify the device for
issuance/revocation; action execution additionally requires the private key.

## 6. Capability format and proof

Capability envelope returned by `POST /api/capabilities`:

```json
{ "payload": { ... }, "sig": "base64url HMAC-SHA256" }
```

Payload:

```json
{
  "v": 2,
  "capId": "cap_…",
  "userId": "u_…",
  "deviceId": "dev_…",
  "deviceJkt": "canonical thumbprint",
  "action": "createPost",
  "view": "home",
  "scope": { "boardId": "b1" },
  "scopeHash": "sha256 hex",
  "bodyHash": "sha256 hex",
  "seq": 1,
  "nonce": "nonce_…",
  "maxUses": 1,
  "exp": 1760000000000,
  "parentCap": null,
  "prevHash": null,
  "iat": 1760000000000
}
```

`scopeHash = SHA-256(stableStringify(normalized scope))`;
`bodyHash = SHA-256(stableStringify(normalized body))`. `userIds` are sorted and
de-duplicated.

The token HMAC is a demo integrity envelope. The authoritative capability record
is in the server store; HMAC does not make the store unnecessary and is symmetric.
Production should use an asymmetric signed token/JWS profile with `kid`,
rotation, `iss`/`aud`/`typ`, or simply treat the random capability ID as an opaque
handle backed by a transactional store.

### Device proof

The browser signs this exact UTF-8 string with ECDSA P-256 / SHA-256 (raw 64-byte
IEEE P1363 signature, base64url):

```text
secrecy:v2|POST|/api/action|<capId>|<action>|<view>|<deviceJkt>|<scopeHash>|<bodyHash>|<seq>|<nonce>|<prevHash or empty>
```

This binds method, path, capability, action, view, device thumbprint, exact scope,
exact body, sequence, nonce and parent link. Tampering with any tested field is
rejected before the business write.

## 7. Issuance checks

`POST /api/capabilities` body:

```json
{
  "action": "createPost",
  "view": "home",
  "scope": { "boardId": "b1" },
  "body": { "text": "hello" },
  "presenceToken": "optional",
  "parentCap": "optional",
  "prevHash": "optional"
}
```

Order:

1. session/device auth and rate limit;
2. action exists (`Object.hasOwn`), view exists and declares action;
3. normalize scope/body against policy types; exact key sets;
4. compute scopeHash/bodyHash;
5. **server ACL authorize**;
6. for presence actions, validate (but do not consume) the presence token against
   scopeHash/bodyHash; the same token must be presented at action time;
7. parent/child invariants for sequences;
8. create payload (capId, nonce, exp, seq, parentCap, prevHash, view, deviceJkt);
9. HMAC envelope, store record, audit `issued`.

A capability is never issued for a board/chat the caller cannot use. The client-
declared scope is only a request; `server-policy.js` is the authority.

## 8. Action verification and atomic consume

`POST /api/action` body:

```json
{
  "capability": { "payload": {…}, "sig": "…" },
  "proof": "base64url ECDSA",
  "action": "createPost",
  "view": "home",
  "scope": { "boardId": "b1" },
  "body": { "text": "hello" },
  "presenceToken": "optional; required for presence:true actions"
}
```

Verification order:

1. session auth and rate limit;
2. capability exists, request envelope exactly matches the stored record, HMAC
   valid;
3. view declares action; capability view/action/device/deviceJkt match;
4. normalize scope/body; compare exact scope, scopeHash and bodyHash;
5. sequence parent exists, was consumed and `prevHash` matches;
6. **proof verification** with the registered device key;
7. test-only delay (if enabled);
8. **ACL re-authorization** (continuity);
9. **synchronous commit block**:
   - re-check device not revoked;
   - for presence actions, validate the presence token against final
     action/view/scopeHash/bodyHash; consume it only after the capability commit
     succeeds;
   - `Store.consumeCapability()` checks record existence/device/revoked/expiry/
     uses, increments `uses`, sets `used`, records `chainHash`, no `await`;
10. synchronous business handler;
11. audit `consumed` with outcome/resultId;
12. response + receipt.

The commit is the key P0 fix. In v1 the replay check occurred before
`await subtle.verify`, so two concurrent requests could both pass and both write.
Now there is no `await` between the final mutable-state checks and the mutation.
`Store.consumeCapability()` is a Store-style primitive; the HTTP handler never
does check-then-set across an await.

For a multi-process/DB deployment, use a conditional update/transaction:

```sql
UPDATE capabilities
SET uses = uses + 1,
    used = CASE WHEN uses + 1 >= max_uses THEN 1 ELSE 0 END,
    used_at = ?, chain_hash = ?
WHERE cap_id = ? AND used = 0 AND uses < max_uses AND revoked = 0 AND exp > ?
RETURNING uses;
```

Zero rows means `CAPABILITY_CONSUMED` (or the relevant revoked/expired reason).
A unique key on `parent_cap_id` / transactional `issueChild` is also required.

## 9. Single-use and sequence state

Policy validation enforces `maxUses: 1` for now, avoiding an underspecified
multi-use/reservation API. The store still keeps a `uses` counter and sets
`used` when it reaches `maxUses`.

### Two-step post

`post:edit` has scope `{boardId}` and body `{text}`. Its business handler:

- creates a draft with `draftId`, `draftHash = sha256(text)`, device and board;
- records `draftId`/`draftHash` on the consumed edit capability;
- returns `sequence = { nextAction, parentCap, prevHash, nextScope }`.

`post:submit` scope is `{boardId, draftId, draftHash}`, body `{}`. Issuance
requires:

- parent is the same device's consumed `post:edit`, unrevoked and unexpired;
- `prevHash` equals the parent's chain hash;
- child scope's board/draftId/draftHash equal the parent's draft binding.

At use, the business handler re-reads the stored draft, recomputes
`sha256(draft.text)`, and requires it to match both `scope.draftHash` and the
stored draft binding before publishing. A draft mutated after edit/submit-issue is
`DRAFT_HASH_MISMATCH`; the content is never published.

Parent burn semantics: an issued but unused child does **not** permanently burn
the parent. If that child expires unused, a replacement child can be issued. Once
a child is consumed, further child issuance fails `CAPABILITY_CONSUMED`.

## 10. Presence: out-of-band code (demo) vs WebAuthn (production)

The v2 demo removes the v1 client-click presence claim.

1. `POST /api/presence/challenge` with `{action, view, scope, body}`:
   - requires auth, rate-limit, action requires presence, view check, scope/body
     normalization, ACL check;
   - creates a single-use challenge bound to device + action + view + scopeHash +
     bodyHash, TTL 90 s;
   - generates a six-digit code with `crypto.randomInt`;
   - stores only its SHA-256 hash and, when server `DEMO` is on, prints the code
     plus action/device/scopeHash/bodyHash (not raw scope/body) to the **server
     console**;
   - invalidates older outstanding challenges for the same device/action.
2. The UI modal shows the exact action/scope/body and asks for the console code.
3. `POST /api/presence/verify` accepts a typed proof:
   ```json
   { "challenge": "pch_…", "proof": { "kind": "oob", "code": "123456" } }
   ```
   or
   ```json
   { "challenge": "pch_…", "proof": { "kind": "webauthn", "assertion": { … } } }
   ```
   - OOB: max 5 attempts per challenge, demo-only when `DEMO` is on;
   - WebAuthn: routed to a verifier contract; the demo has no production verifier
     and accepts only a test-only fake under `ALLOW_TEST_HOOKS=1`;
   - single-use challenge, 30 s presence token;
   - token bound to device/action/view/scopeHash/bodyHash.
4. Issuance validates the token but does **not** consume it. `/api/action` requires
   the token for `presence:true` actions and consumes it inside the synchronous
   commit after the capability commit. A scope/body mismatch is
   `PRESENCE_SCOPE_MISMATCH`; a missing/replayed/expired token is
   `PRESENCE_REQUIRED`.

The code is **not** returned over HTTP. A script that can only make HTTP requests
cannot read the server console. The XSS demo therefore fails the direct presence
bypass and wrong-code checks. The OOB path is demo-only; `DEMO=0` rejects it.

### What this is not

The console code is a demo out-of-band channel, not WebAuthn user verification.
Same-page XSS can read the code **after the user types it**, or call
`/api/presence/verify` with a stolen code. A compromised host/log channel defeats
it. It also lacks authenticator binding, origin/rpId verification and sign
counter semantics.

`src/public/presence.js` defines the `PresenceProvider` seam and a
`WebAuthnPresenceProvider` stub. Production must:

- call `navigator.credentials.get({ publicKey: { challenge, userVerification:
  "required", ... } })`;
- verify `clientDataJSON.type`, challenge, origin, crossOrigin;
- verify `rpIdHash`, UP and UV flags, signature with the stored credential key;
- bind the WebAuthn challenge to device + action + scopeHash + bodyHash + a
  server nonce;
- advance/check `signCount`;
- return `{ assertion }` from the provider; v2.1 already consumes the resulting
  token at action time and binds it to the final scopeHash/bodyHash.

## 11. Audit and revocation

Audit events contain:

```json
{
  "auditId": "aud_…",
  "type": "consumed",
  "decision": "allow",
  "time": "…",
  "capId": "…",
  "action": "createPost",
  "deviceId": "…",
  "userId": "…",
  "scopeHash": "…",
  "bodyHash": "…",
  "parentCap": null,
  "resultId": "post_…",
  "outcome": "success",
  "reason": "CAPABILITY_CONSUMED",
  "detail": null
}
```

- `GET /api/audit` requires a valid session (read-only session accepted so a
  revoked device can see its own revocation).
- Non-admin events are filtered to the caller's user/device; `capId`,
  `deviceId`, `parentCap`, `resultId`, `scopeHash` and `bodyHash` are masked and
  other-user fields are absent.
- If `ADMIN_TOKEN` (≥32 chars) is configured, `x-admin-token` sees all events
  unmasked. The token comparison hashes both values and uses `timingSafeEqual`.
- Audit and state reads are rate-limited per device.
- `POST /api/revoke` marks the device revoked and all its capabilities revoked,
  clears presence grants, logs `revoked` events, and rejects future writes with
  `DEVICE_REVOKED`.
- The action commit re-checks both `auth.device.revokedAt` and `record.revoked`,
  so an action in its proof-verification window cannot complete after revocation.
- Revocation is one-way for the key. Rotate the local device key for a new
  identity.

Audit is in-memory, capped at 5,000 events, and not tamper-evident.

## 12. HTTP API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/register/challenge` | none | Start PoP registration |
| POST | `/api/register` | none | Verify PoP and create/reuse device |
| POST | `/api/capabilities` | device | Authorize + issue capability |
| POST | `/api/action` | device | Verify proof, consume capability + presence token atomically, execute |
| POST | `/api/presence/challenge` | device | Start OOB confirmation |
| POST | `/api/presence/verify` | device | Verify OOB/WebAuthn proof, issue scoped presence token |
| POST | `/api/presence` | — | Removed: returns 410 |
| GET | `/api/state` | device | Scoped resync; 401 if invalid |
| GET | `/api/audit` | device | Scoped/redacted audit; admin optional |
| POST | `/api/revoke` | device | Revoke all capabilities |
| GET | `/api/health` | none | Liveness (+ `demo` flag) |

`chat:join`/`chat:leave` are capability actions under `/api/action` with scope
`{chatId}`, not ambient HTTP writes. Test-only membership/draft mutation hooks
exist only under `ALLOW_TEST_HOOKS=1` and are disabled by default.

Auth: `X-Device-Token` or `Authorization: Bearer …`. POST requires
`application/json` in v2.

Error envelope: `{ "error": { "code", "message", ... } }`.

Important codes: `UNAUTHENTICATED`, `DEVICE_REVOKED`, `FORBIDDEN`,
`ACTION_NOT_ALLOWED_IN_VIEW`, `ACTION_MISMATCH`, `SCOPE_DENIED`, `BODY_MISMATCH`,
`CAPABILITY_CONSUMED`, `CAPABILITY_EXPIRED`, `DEVICE_MISMATCH`,
`INVALID_CAPABILITY`, `INVALID_PROOF`, `PRESENCE_REQUIRED`,
`PRESENCE_SCOPE_MISMATCH`, `PRESENCE_CODE_INVALID`,
`PRESENCE_PROOF_INVALID`, `PRESENCE_WEBAUTHN_NOT_IMPLEMENTED`,
`PRESENCE_OOB_DISABLED`, `SEQ_MISMATCH`,
`DRAFT_HASH_MISMATCH`, `RATE_LIMITED`, `QUOTA_EXCEEDED`, `INVALID_JWK`,
`INVALID_REGISTRATION_CHALLENGE`, `INVALID_REGISTRATION_PROOF`.

## 13. Threat model

| Threat | v2 behavior |
|---|---|
| Double-spend two concurrent requests | Synchronous store commit; exactly one success |
| Registration PoP replay | Atomic challenge consume after verify; one session |
| Replay after success | `CAPABILITY_CONSUMED` |
| Scope/body substitution | Exact normalized comparison + proof binding |
| Cross-action/view use | Action/view checks + view in proof |
| Cross-device use | Device ID + JKT + proof verification |
| Stolen capability without device key | `INVALID_PROOF` |
| Stolen session token | Can mint low-risk capabilities, but cannot sign action proofs. Can cause nuisance/rate use. |
| Stolen session + same-page XSS | Can use the page's signing oracle; bounded to one authorized use per capability and audited |
| Unauthorized resource | Server ACL denies at issue and use; board membership is per principal |
| Membership revoked after issue | Use denied by continuity recheck |
| JWK re-encoding bypass | Strict canonical JWK + canonical JKT index |
| Registration spoofing | PoP challenge/signature required |
| Presence bypass by direct HTTP | No code returned; wrong code fails; challenge bound/rate-limited; OOB disabled with DEMO=0 |
| Presence approval substitution | Token bound to scopeHash/bodyHash; consumed at action |
| Presence token replay/expiry | Action requires unused, unexpired token and consumes it |
| In-flight revocation | Commit rechecks revoked |
| Expired cap | Commit checks `exp` |
| Token/envelope tampering | Store comparison + HMAC + proof |
| Policy misconfiguration | Boot validation fails closed |
| Prototype pollution via `__proto__` | Protocol canonicalizer rejects dangerous keys |
| Server compromise | Full state/secret/audit; not defended |
| Phishing/clickjacking | Not addressed |
| Multi-instance double-spend | Not addressed; requires DB CAS |

### XSS: what remains possible

The demo's XSS simulation shows the residual power honestly:

- a stolen post capability cannot become `changeAvatar` or leave its exact
  scope/body;
- a consumed capability cannot be replayed;
- high-risk authority cannot be minted without an OOB code;
- one allowed action can succeed once and is audited;
- the user can revoke.

A same-page script can still read the console code when the user types it, use
the page's non-extractable key as a signing oracle, and act once within any
still-valid capability. The defense is bound authority, not secrecy from XSS.

## 14. What is explicitly not a security boundary

- **View**: client-supplied UI context; useful routing/policy guard, not proof of
  what the user sees.
- **Console OOB code**: demo channel, not WebAuthn UV; same-page keylogging
  defeats it.
- **HMAC envelope**: symmetric, process-local, store is authoritative.
- **In-memory `consumeCapability`**: atomic only in one process. Use DB CAS for
  multiple processes.
- **Rate limits**: simple in-memory fixed windows; not a hard security control.
- **Audit**: in-memory, capped, not signed/hash-chained.
- **Revoked read access**: `/api/state` and `/api/audit` accept a valid read-only
  session after revocation so the UI can display revocation. Writes are blocked.
- **Demo hooks**: with server `DEMO=0`, `demo-hooks.js` is not served. With
  `DEMO=1`, the file/class is present but the instance/global is only enabled with
  `?demo=1`. The query flag is build hygiene, not a security boundary: any
  same-origin script can instantiate the global client when the file is served.
  A production build must omit the file and use a separate origin for the lab.
- **No CSP**: the lab injects a script. Production needs strict CSP/Trusted Types/
  separate origin.
- **Avatar**: metadata only.

## 15. Intentional limitations

- Single process, in-memory state, no persistence.
- HMAC capability signatures, per-boot secret.
- Bearer sessions in JS memory; no rotating refresh, logout, account model,
  cookies, CSRF/origin hardening.
- No idempotency key/receipt lookup for a lost response after consume.
- No per-capability revocation endpoint; only whole-device shown.
- No multi-use policy; `maxUses` must be 1.
- No clock-skew leeway/`nbf`; demo clocks assumed close.
- Presence code TTL 90 s, token 30 s, five attempts. WebAuthn is a documented
  contract/stub plus a test-only fake verifier, not a production verifier.
- In-memory audit capped at 5,000; no tamper evidence; admin token is a static
  env secret.
- Rate limits are best-effort fixed windows; no global/edge limiter or Sybil
  resistance beyond per-device/per-IP counters.
- Resource caps are small in-memory safeguards, not capacity planning.
- Sequence links are in client memory; reload requires a new edit step even
  though the draft remains.
- `DEMO` controls whether `demo-hooks.js` and OOB codes are available; `?demo=1`
  is only a page instance/global switch, not a production build boundary.

## 16. Prior art and what to borrow

| Concern | This demo | Standard / prior art |
|---|---|---|
| Capability/authority | Store-backed one-use token | Object-capability/POLA, macaroons, Biscuit, UCAN |
| Proof of possession | Custom ECDSA proof string | DPoP (RFC 9449), JWS `cnf.jkt` |
| User presence | Console OOB code (demo) | WebAuthn UV; PSD2 dynamic linking; OWASP transaction authorization |
| Scope authorization | Server ACL functions | Zanzibar/ReBAC, RAR `authorization_details`, Sandstorm Powerbox |
| Sequence/attenuation | `parentCap`/`prevHash` + draft hash | Macaroon caveats, Biscuit, UCAN `prf`/`att`, UCON continuity |
| Revocation | Device flag + cap flags | OAuth revocation, Biscuit revocation IDs, UCAN revocation |
| Sessions | JS bearer token | BFF + HttpOnly cookies, OAuth token exchange/rotation |
| XSS defense | Demo-only hooks, no CSP | CSP/Trusted Types, isolated origin/iframe |
| Audit | In-memory scoped log | Append-only hash chain, SIEM, request correlation |
| Transaction approval | Exact scope/body in modal | WebAuthn UV, PSD2 dynamic linking, OWASP transaction authorization |

Borrow DPoP-style proof fields, WebAuthn UV, RAR/Powerbox authorization
details, Zanzibar-style ACLs, DB compare-and-swap, and BFF session custody.
Do not reinvent token formats if a standard profile fits.

## 17. Production path / extension

1. Implement the WebAuthn verifier contract and bind the assertion to
   `{deviceId, action, view, scopeHash, bodyHash, serverNonce}`. v2.1 already
   consumes the resulting presence token at action time; add origin/rpId/UV/
   signature/signCount verification.
2. Replace HMAC capability envelopes with Ed25519/ES256 + `kid`/JWKS/rotation, or
   keep random handles and rely on the transactional store.
3. Replace memory with a database; implement `consumeCapability`, `issueChild`,
   `redeemChallenge`, `consumePresence` and `revokeDevice` as conditional
   updates/transactions with unique constraints.
4. Add strict policy schema validation at build/start, typed scope validators and
   an authorizer registry resolved server-side.
5. Add session rotation/logout, HttpOnly cookies or a BFF, CSRF/origin checks,
   rate-limit metrics, and account-level device management.
6. Add per-capability revocation, idempotency keys/receipts, and a durable
   tamper-evident audit.
7. Add CSP, Trusted Types, frame protections, and isolate the XSS lab on a
   separate origin.
8. Add clock skew/`nbf`, per-action budgets/quotas, and distributed anomaly
   detection for `CAPABILITY_CONSUMED` / `PRESENCE_SCOPE_MISMATCH` bursts.

To add an action: extend `src/public/policy.js` with scope/body types and metadata,
add a server authorizer in `server-policy.js`, add a synchronous business handler
in `src/server.js`, and add a controller call. The client layer is generic.

## 18. Tests

`src/test/smoke.mjs` uses the running server and covers registration, createPost,
scope/body binding, view/action, device binding, mention, presence challenge
shape, sequence/draft binding, scoped audit, revocation and state auth.

`src/test/security.mjs` starts an isolated server on an ephemeral port and captures
OOB codes from stdout. It uses raw `http.request` sockets (not only fetch) for
2/50-way action and registration concurrency, plus test-only
`x-test-verify-delay`/`x-test-ttl-ms`, board membership and draft mutation hooks.
The hooks are disabled unless `ALLOW_TEST_HOOKS=1`; they are not production
features. The suite also checks action-time presence binding, PoP challenge burn,
audit redaction, draft re-hashing, chat capability writes, state rate limiting,
the WebAuthn assertion seam, and `DEMO=0` demo-hook gating.
