# V2 NOTES

> Historical artifact: code paths in this document refer to the v1/v2 layout. Current source is under `src/`, docs under `docs/`.

## What changed

### P0

- **Atomic consume**: replay/expiry/revocation checks moved after the last
  `await`; `MemoryStore.consumeCapability()` performs re-check + `uses++` + `used`
  in one synchronous critical section. The action commit re-checks
  `auth.device.revokedAt` and `record.revoked`. Regression tests use raw sockets
  for 2 and 50 parallel requests and assert one 200, N−1
  `CAPABILITY_CONSUMED`, one write and one consumed audit.
- **Real separate presence channel**: removed client-click presence. Added
  `POST /api/presence/challenge` and `/api/presence/verify`; a six-digit code is
  printed only to the server console when `DEMO` is on and exchanged for a
  single-use presence token bound to device + action + view + scopeHash +
  bodyHash. Wrong code, replay, expiry and scope/body substitution fail. The old
  `/api/presence` route returns 410.
  **v2.1:** the token is validated at issue and consumed at **action time**; the
  action body must include it.
- **PresenceProvider seam**: `public/presence.js` defines the provider interface,
  a WebAuthn UV stub, and a static-code helper. **v2.1:** a provider may return
  `{code}` or `{assertion}`; the server accepts typed OOB/WebAuthn proof shapes
  and has a documented WebAuthn contract with a test-only fake verifier. The app
  uses a modal provider that asks for the console code. `grantPresence`/
  `isTrusted` removed.
- **Server-side scope authorization**: `server-policy.js` authorizes boards,
  chats, mentions and self-profile at issuance and again at use. Membership
  changes deny already-issued capabilities. **v2.1:** board writes also require
  per-user board membership; `chat:join`/`chat:leave` are capability actions, not
  ambient routes.
- **JWK canonicalization / durable revocation**: strict unpadded base64url,
  exactly 32 bytes, canonical re-encode, canonical RFC 7638 JKT, unique canonical
  index, and registration proof-of-possession. Padded/whitespace JWKs are rejected
  and cannot resurrect a revoked key. `device.jkt` naming fixed.
- **Presence binding tests**: scope and body substitution both return
  `PRESENCE_SCOPE_MISMATCH`; the same token can still be used for the approved
  transaction.

### P1 (high-value)

- **Shared protocol module**: `public/protocol.js` is used by browser, server and
  tests for canonicalization, strict base64url, hashes and proof strings; it
  rejects dangerous keys and uses null-prototype objects.
- **Proof bindings**: proof string now binds method, path, capId, action, view,
  deviceJkt, scopeHash, bodyHash, seq, nonce and prevHash.
- **Policy validation at boot**: missing TTL, `maxUses !== 1`, unknown
  authorizer, dangerous keys and broken parent/next links fail startup.
- **Two-step content binding**: `post:submit` scope includes `draftId` and
  `draftHash`; the final draft is re-hashed at use. An unused expired child can be
  reissued; a consumed child permanently spends the parent.
- **Authenticated/scoped audit**: `GET /api/audit` requires a session, filters to
  caller, masks cap/device/hash/result IDs for non-admin, includes auditId,
  action, scopeHash, bodyHash, decision, outcome, parentCap and resultId. Admin
  token (≥32 chars, timing-safe compare) can view all. Anonymous audit is 401.
- **`/api/state`** now requires auth, returns 401 for invalid tokens, scopes
  feed/messages/users and omits other devices' capabilities/sequence links.
  A revoked read-only session may fetch state/audit to display revocation.
- **Demo hooks gated**: **v2.1:** `demo-hooks.js` is served only when server
  `DEMO` is on (default on for the demo; `DEMO=0` disables). `window.secrecy` and
  the signing-oracle instance additionally require `?demo=1`; the query flag is
  not a security boundary.
- **Rate limits**: basic in-memory per-device/IP limits for register,
  capability issuance, actions, presence challenge/verify, state, audit and
  revoke; 429 `RATE_LIMITED` with retryAfter. **v2.1:** session/device/draft/
  capability resource caps are also enforced.
- **API ergonomics**: `execute(action, {scope, body}, options)`, legacy
  `execute(action, params)` wrapper, `can(action)`, `actions()`, `view(name)`
  handles, `presence` option/provider and richer errors (`source`, `retryable`,
  `details`).
- **Request hygiene**: POST requires `application/json`; expired/malformed
  capability and proof paths tested.

## Intentionally still simplified

- HMAC capability signatures are symmetric and process-local; the store is the
  authority.
- In-memory state and single-process atomicity. A real deployment needs DB
  conditional updates/transactions.
- Presence is a console OOB code, not WebAuthn UV. Same-page XSS can read the
  code after the user types it. The WebAuthn verifier is a contract/stub; the
  test-only fake verifier is not production authentication.
- Bearer session in JS memory; no account auth, rotation, logout, cookie/BFF,
  CSRF/origin hardening.
- No idempotency key/receipt lookup after a lost response; response includes a
  receipt but retries are not deduplicated.
- No per-capability revocation UI/API; device revocation only.
- No clock skew/`nbf`, no persistent/tamper-evident audit, no CSP (the lab needs
  script injection), avatar metadata only.
- With server `DEMO=1`, the demo-hooks file is still shipped to the browser even
  when the page does not use `?demo=1`. Set `DEMO=0` and use a separate origin for
  production.

## Validation

- `test/smoke.mjs`: 11/11 pass.
- `test/security.mjs`: **v2.1:** 19/19 checks pass (2/50 action and PoP
  registration concurrency, PoP burn, presence at action, WebAuthn seam, board
  ACL, chat capability writes, JWK/PoP, audit redaction, tamper, policy,
  in-flight revoke, sequence re-hash, rate limits, DEMO gating).
- An additional Node shim run exercised the actual browser `public/secrecy.js`
  against a spawned server: registration PoP, v2 execute, legacy wrapper,
  presence provider OOB code, sequence, state/audit and demo-hook attack path all
  behaved as expected.

## Open questions

- ~~Should presence approval be consumed at issuance or action?~~ Resolved in
  v2.1: validate at issue, consume at action. WebAuthn verification remains.
- Should sessions be moved to a BFF with HttpOnly cookies, or keep a JS bearer
  token plus WebAuthn/DPoP?
- How to make the UI view/context server-verifiable without turning it into a
  security principal? Powerbox-style server-issued resource choices are one path.
- What is the right multi-use/reservation API, if any? v2 enforces `maxUses: 1`.
- Should sequence continuation descriptors persist server-side to survive reload
  and multi-tab?
- What is the production capability token format: opaque handle + store, or
  asymmetric JWS with rotation and offline verification?
