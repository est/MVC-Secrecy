"use strict";

/*
 * MVC + Secrecy v2 server.
 *
 * Plain Node.js http, no dependencies. The server is the authority for devices,
 * capabilities, presence grants, ACLs, sequence state and audit. All state is
 * in memory and resets on restart.
 */

const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const protocol = require("./public/protocol.js");
const policy = require("./public/policy.js");
const serverPolicy = require("./server-policy.js");

// Fail closed at boot: missing TTL, maxUses != 1, unknown authorizer, dangerous
// keys or broken parent/next links stop the process before accepting traffic.
serverPolicy.validatePolicy(policy);

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_BODY_BYTES = 256 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const REGISTER_CHALLENGE_TTL_MS = 60 * 1000;
const PRESENCE_CHALLENGE_TTL_MS = 90 * 1000;
const PRESENCE_TOKEN_TTL_MS = 30 * 1000;
const PRESENCE_MAX_ATTEMPTS = 5;
const MAX_CAPABILITIES_PER_DEVICE = 1000;
const MAX_DRAFTS_PER_DEVICE = 50;
const MAX_DEVICES = 10000;
const ALLOW_TEST_HOOKS = process.env.ALLOW_TEST_HOOKS === "1";
const DEMO =
  process.env.DEMO === "1" ||
  (process.env.DEMO !== "0" && process.env.NODE_ENV !== "production");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
if (ADMIN_TOKEN && ADMIN_TOKEN.length < 32) {
  throw new Error("ADMIN_TOKEN must be at least 32 characters when set");
}
const TEST_VERIFY_DELAY_MS = ALLOW_TEST_HOOKS
  ? Math.max(0, Number(process.env.TEST_VERIFY_DELAY_MS || 0))
  : 0;

if (process.env.SECRECY_SECRET && process.env.SECRECY_SECRET.length < 32) {
  throw new Error("SECRECY_SECRET must be at least 32 characters");
}
const HMAC_SECRET = process.env.SECRECY_SECRET
  ? Buffer.from(process.env.SECRECY_SECRET, "utf8")
  : crypto.randomBytes(32);

const subtle = crypto.webcrypto.subtle;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const users = new Map([
  ["u_alice", { userId: "u_alice", name: "Alice", avatar: null, createdAt: Date.now() }],
  ["u_bob", { userId: "u_bob", name: "Bob", avatar: null, createdAt: Date.now() }]
]);
const chatMembers = new Map([["c_general", new Set(["u_alice", "u_bob"])]]);
const boardMembers = new Map([
  ["b1", new Set(["u_alice", "u_bob"])],
  ["b2", new Set(["u_alice", "u_bob"])]
]);
const devices = new Map();
const devicesByJkt = new Map();
const sessions = new Map();
const presenceChallenges = new Map();
const presenceTokens = new Map();
const drafts = new Map();
const rateBuckets = new Map();
const audit = [];

const feed = [
  {
    id: "post_welcome",
    userId: "u_alice",
    boardId: "b1",
    text: "Welcome to the Secrecy v2 demo. Writes require server-authorized, one-use capabilities.",
    createdAt: Date.now() - 60_000,
    viaCap: null
  }
];
const messages = [
  {
    id: "msg_welcome",
    chatId: "c_general",
    userId: "u_bob",
    text: "Send a message, mention members, or try the OOB presence flow in Profile.",
    mentions: [],
    createdAt: Date.now() - 45_000,
    viaCap: null
  }
];

// ---------------------------------------------------------------------------
// Errors, ids and protocol helpers
// ---------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function now() {
  return Date.now();
}

function randomToken(prefix) {
  return `${prefix}_${crypto.randomBytes(18).toString("base64url")}`;
}

function randomHex(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Wraps protocol canonicalization errors as client-facing 400s. */
function stable(value) {
  try {
    return protocol.stableStringify(value);
  } catch (error) {
    throw new HttpError(400, error.code || "INVALID_JSON_STRUCTURE", error.message);
  }
}

function sha256(value) {
  return protocol.sha256HexSync(value);
}

function proofText(payload, action, scopeHash, bodyHash) {
  return protocol.proofString(payload, action, scopeHash, bodyHash);
}

function capabilitySignature(payload) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(stable(payload)).digest("base64url");
}

function capabilitySignatureValid(payload, signature) {
  if (typeof signature !== "string") return false;
  const expected = Buffer.from(capabilitySignature(payload), "utf8");
  const actual = Buffer.from(signature, "utf8");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function normalizeDeviceName(value) {
  const trimmed = typeof value === "string" ? value.trim().slice(0, 80) : "";
  return trimmed || "Unnamed browser";
}

function sanitizePublicJwk(value) {
  if (!protocol.isPlainObject(value)) {
    throw new HttpError(400, "INVALID_JWK", "publicKeyJwk must be a plain object");
  }
  if (value.kty !== "EC" || value.crv !== "P-256") {
    throw new HttpError(400, "INVALID_JWK", "Only EC P-256 public keys are accepted");
  }
  if (value.d) {
    throw new HttpError(400, "INVALID_JWK", "Never send a private key");
  }

  const axes = {};
  for (const axis of ["x", "y"]) {
    const encoded = value[axis];
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
      throw new HttpError(400, "INVALID_JWK", `${axis} must be canonical unpadded base64url`);
    }
    let bytes;
    try {
      bytes = protocol.b64urlDecodeStrict(encoded);
    } catch {
      throw new HttpError(400, "INVALID_JWK", `${axis} is not canonical base64url`);
    }
    if (bytes.length !== 32 || protocol.b64urlEncode(bytes) !== encoded) {
      throw new HttpError(400, "INVALID_JWK", `${axis} must decode to 32 canonical bytes`);
    }
    axes[axis] = encoded;
  }

  return { kty: "EC", crv: "P-256", x: axes.x, y: axes.y };
}

async function importVerifyKey(jwk) {
  try {
    return await subtle.importKey(
      "jwk",
      { ...jwk, ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch {
    throw new HttpError(400, "INVALID_JWK", "Public key could not be imported");
  }
}

function jwkThumbprint(jwk) {
  // RFC 7638 required members in lexicographic order.
  return sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

function publicUser(user) {
  if (!user) return null;
  return { userId: user.userId, name: user.name, avatar: user.avatar || null };
}

function publicDevice(device) {
  if (!device) return null;
  return {
    deviceId: device.deviceId,
    userId: device.userId,
    deviceName: device.deviceName,
    deviceJkt: device.jkt,
    revokedAt: device.revokedAt || null
  };
}

function inferView(action) {
  for (const [view, definition] of Object.entries(policy.views)) {
    if ((definition.actions || []).includes(action)) return view;
  }
  return null;
}

function actionConfig(action) {
  if (typeof action !== "string" || !Object.hasOwn(policy.actions, action)) {
    throw new HttpError(400, "UNKNOWN_ACTION", `Unknown action: ${action}`);
  }
  return policy.actions[action];
}

function requireActionInView(action, view) {
  if (typeof view !== "string" || !Object.hasOwn(policy.views, view)) {
    throw new HttpError(400, "UNKNOWN_VIEW", `Unknown view: ${view}`);
  }
  if (!(policy.views[view].actions || []).includes(action)) {
    throw new HttpError(
      403,
      "ACTION_NOT_ALLOWED_IN_VIEW",
      `Action ${action} is not allowed in view ${view}`
    );
  }
}

// ---------------------------------------------------------------------------
// Scope/body validation
// ---------------------------------------------------------------------------

const TYPE_VALIDATORS = {
  BoardId(value) {
    return requireString(value, "boardId", 64);
  },
  ChatId(value) {
    return requireString(value, "chatId", 64);
  },
  UserIdList1to20(value) {
    if (
      !Array.isArray(value) ||
      value.length < 1 ||
      value.length > 20 ||
      !value.every((item) => typeof item === "string" && item.length > 0)
    ) {
      throw new HttpError(403, "SCOPE_DENIED", "userIds must contain 1-20 user IDs");
    }
    return [...new Set(value)].sort();
  },
  AvatarMime(value) {
    if (value !== "image/png" && value !== "image/jpeg") {
      throw new HttpError(403, "SCOPE_DENIED", "Unsupported avatar MIME type");
    }
    return value;
  },
  Bytes1to104857600(value) {
    if (!Number.isInteger(value) || value < 1 || value > 104857600) {
      throw new HttpError(403, "SCOPE_DENIED", "maxSize must be an integer 1..104857600");
    }
    return value;
  },
  DraftId(value) {
    const text = requireString(value, "draftId", 128);
    if (!/^draft_[A-Za-z0-9_-]+$/.test(text)) {
      throw new HttpError(403, "SCOPE_DENIED", "Invalid draftId");
    }
    return text;
  },
  Sha256(value) {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
      throw new HttpError(403, "SCOPE_DENIED", "Invalid sha256 value");
    }
    return value;
  },
  Text1to2000(value) {
    return requireText(value, "text", 2000);
  },
  Text1to200(value) {
    return requireText(value, "reason", 200);
  }
};

function requireString(value, label, maxLength) {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength) {
    throw new HttpError(403, "SCOPE_DENIED", `${label} must be 1-${maxLength} characters`);
  }
  return value;
}

function requireText(value, label, maxLength) {
  if (
    typeof value !== "string" ||
    value.trim().length < 1 ||
    value.length > maxLength
  ) {
    throw new HttpError(400, "VALIDATION_ERROR", `${label} must be 1-${maxLength} characters`);
  }
  return value;
}

function normalizeFields(action, fields, schema, kind) {
  if (!protocol.isPlainObject(fields)) {
    throw new HttpError(
      kind === "scope" ? 403 : 400,
      kind === "scope" ? "SCOPE_DENIED" : "INVALID_BODY",
      `${kind} must be a plain object`
    );
  }
  const expected = Object.keys(schema).sort();
  const actual = Object.keys(fields).sort();
  if (stable(expected) !== stable(actual)) {
    throw new HttpError(
      kind === "scope" ? 403 : 400,
      kind === "scope" ? "SCOPE_DENIED" : "INVALID_BODY",
      `${kind} for ${action} must contain exactly: ${Object.keys(schema).join(", ") || "(none)"}`
    );
  }
  const normalized = Object.create(null);
  for (const key of Object.keys(schema)) {
    protocol.assertSafeKey(key);
    const validator = TYPE_VALIDATORS[schema[key]];
    if (!validator) {
      throw new HttpError(500, "INTERNAL_ERROR", `No validator for ${schema[key]}`);
    }
    normalized[key] = validator(fields[key]);
  }
  return normalized;
}

function normalizeScope(action, scope, config) {
  return normalizeFields(action, scope, config.scope, "scope");
}

function normalizeBody(action, body, config) {
  return normalizeFields(action, body, config.body, "body");
}

function hashes(scope, body) {
  return { scopeHash: sha256(scope), bodyHash: sha256(body) };
}

// ---------------------------------------------------------------------------
// Audit, rate limiting and errors
// ---------------------------------------------------------------------------

function auditEvent(type, fields = {}) {
  const event = {
    auditId: randomHex("aud"),
    type,
    decision: fields.decision || (type === "denied" || type === "error" ? "deny" : "allow"),
    time: new Date().toISOString(),
    capId: fields.capId || null,
    action: fields.action || null,
    deviceId: fields.deviceId || null,
    userId: fields.userId || null,
    scopeHash: fields.scopeHash || null,
    bodyHash: fields.bodyHash || null,
    parentCap: fields.parentCap || null,
    resultId: fields.resultId || null,
    outcome: fields.outcome || null,
    reason: fields.reason || null,
    detail: fields.detail || null
  };
  audit.push(event);
  if (audit.length > 5000) audit.shift();
  return event;
}

function maskId(value) {
  if (!value) return null;
  const text = String(value);
  if (text.length <= 10) return text;
  return `${text.slice(0, 8)}...${text.slice(-4)}`;
}

function adminTokenMatches(value) {
  if (!ADMIN_TOKEN || typeof value !== "string") return false;
  const provided = crypto.createHash("sha256").update(value).digest();
  const expected = crypto.createHash("sha256").update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(provided, expected);
}

function rateLimit(key, limit, windowMs) {
  const t = now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.reset <= t) {
    bucket = { count: 0, reset: t + windowMs };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    throw new HttpError(429, "RATE_LIMITED", "Too many requests; retry later", {
      retryAfter: Math.ceil((bucket.reset - t) / 1000)
    });
  }
}

function readBearer(req) {
  const header = req.headers.authorization || "";
  if (typeof header === "string" && header.startsWith("Bearer ")) {
    return header.slice("Bearer ".length).trim();
  }
  const token = req.headers["x-device-token"];
  return Array.isArray(token) ? token[0] : token || "";
}

function optionalAuth(req) {
  const token = readBearer(req);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.exp < now()) return null;
  const device = devices.get(session.deviceId);
  if (!device) return null;
  return {
    token,
    session,
    device,
    user: users.get(device.userId),
    userId: device.userId,
    deviceId: device.deviceId
  };
}

function requireSession(req) {
  const auth = optionalAuth(req);
  if (!auth) throw new HttpError(401, "UNAUTHENTICATED", "Register a device first");
  req._auth = auth;
  return auth;
}

function requireAuth(req) {
  const auth = requireSession(req);
  if (auth.device.revokedAt) {
    throw new HttpError(403, "DEVICE_REVOKED", "This device has been revoked");
  }
  return auth;
}

function authContext() {
  return {
    policy,
    users,
    isChatMember(userId, chatId) {
      const members = chatMembers.get(chatId);
      return Boolean(members && members.has(userId));
    },
    isBoardMember(userId, boardId) {
      const members = boardMembers.get(boardId);
      return Boolean(members && members.has(userId));
    }
  };
}

function createSession(device) {
  const t = now();
  const existing = [...sessions.values()]
    .filter((session) => session.deviceId === device.deviceId)
    .sort((a, b) => a.createdAt - b.createdAt);
  const MAX_SESSIONS_PER_DEVICE = 10;
  while (existing.length >= MAX_SESSIONS_PER_DEVICE) {
    sessions.delete(existing.shift().token);
  }
  const token = randomToken("sess");
  sessions.set(token, {
    token,
    deviceId: device.deviceId,
    userId: device.userId,
    createdAt: t,
    exp: t + SESSION_TTL_MS
  });
  return token;
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  res.end(payload);
}

async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      throw new HttpError(413, "BODY_TOO_LARGE", "Request body is too large");
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON");
  }
}

function sendError(req, res, error) {
  const status = error.status || 500;
  const code = error.code || "INTERNAL_ERROR";
  if (req.url?.startsWith("/api/")) {
    auditEvent(status >= 500 ? "error" : "denied", {
      decision: "deny",
      capId: req._audit?.capId || null,
      action: req._audit?.action || null,
      deviceId: req._auth?.device?.deviceId || null,
      userId: req._auth?.user?.userId || null,
      scopeHash: req._audit?.scopeHash || null,
      bodyHash: req._audit?.bodyHash || null,
      parentCap: req._audit?.parentCap || null,
      reason: code,
      detail: error.message
    });
  }
  sendJson(res, status, {
    error: {
      code,
      message: error.message || "Internal error",
      ...(error.extra || {})
    }
  });
}

function setAuditContext(req, fields) {
  req._audit = { ...(req._audit || {}), ...fields };
}

// ---------------------------------------------------------------------------
// Capability store with a synchronous atomic consume primitive
// ---------------------------------------------------------------------------

class MemoryStore {
  constructor() {
    this.capabilities = new Map();
  }

  add(record) {
    this.capabilities.set(record.payload.capId, record);
  }

  get(capId) {
    return this.capabilities.get(capId) || null;
  }

  /**
   * IMPORTANT: synchronous. All checks and mutations happen in one critical
   * section. Callers must not await between proof verification and this call.
   */
  consumeCapability({ capId, deviceId, signedText, nowMs }) {
    const record = this.capabilities.get(capId);
    if (!record) return { ok: false, reason: "INVALID_CAPABILITY" };
    if (record.payload.deviceId !== deviceId) return { ok: false, reason: "DEVICE_MISMATCH" };
    if (record.revoked) return { ok: false, reason: "DEVICE_REVOKED" };
    if (record.payload.exp < nowMs) return { ok: false, reason: "CAPABILITY_EXPIRED" };
    if (record.used || record.uses >= record.payload.maxUses) {
      return { ok: false, reason: "CAPABILITY_CONSUMED" };
    }
    record.uses += 1;
    record.used = record.uses >= record.payload.maxUses;
    record.usedAt = nowMs;
    record.chainHash = sha256(signedText);
    return { ok: true, record, chainHash: record.chainHash, uses: record.uses };
  }

  revokeDevice(deviceId, nowMs) {
    let count = 0;
    for (const record of this.capabilities.values()) {
      if (record.payload.deviceId !== deviceId || record.revoked) continue;
      record.revoked = true;
      record.revokedAt = nowMs;
      count += 1;
    }
    return count;
  }
}

const store = new MemoryStore();

function enforceCapabilityQuota(deviceId) {
  const records = [...store.capabilities.values()].filter(
    (record) => record.payload.deviceId === deviceId
  );
  if (records.length < MAX_CAPABILITIES_PER_DEVICE) return;
  const t = now();
  for (const record of records.sort((a, b) => a.issuedAt - b.issuedAt)) {
    if (record.payload.exp < t || record.revoked) {
      store.capabilities.delete(record.payload.capId);
    }
    if (
      [...store.capabilities.values()].filter(
        (item) => item.payload.deviceId === deviceId
      ).length < MAX_CAPABILITIES_PER_DEVICE
    ) {
      return;
    }
  }
  throw new HttpError(429, "QUOTA_EXCEEDED", "Device capability quota exceeded");
}

/**
 * Registration challenges also use a Store-like conditional consume. The
 * consume below is synchronous and must be called after the final await
 * (signature verification) so concurrent replayed proofs cannot both succeed.
 */
class RegistrationChallengeStore {
  constructor() {
    this.byChallenge = new Map();
    this.byJkt = new Map();
  }

  issue(jkt, record) {
    const previous = this.byJkt.get(jkt);
    if (previous) previous.used = true;
    this.byChallenge.set(record.challenge, record);
    this.byJkt.set(jkt, record);
  }

  get(challenge) {
    return this.byChallenge.get(challenge) || null;
  }

  recordFailure(record, maxAttempts = 5) {
    if (!record) return;
    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts >= maxAttempts) record.used = true;
  }

  consume({ challenge, jkt, deviceNameHash, nowMs }) {
    const record = this.byChallenge.get(challenge);
    if (
      !record ||
      record.used ||
      record.exp < nowMs ||
      record.jkt !== jkt ||
      record.deviceNameHash !== deviceNameHash
    ) {
      return null;
    }
    record.used = true;
    record.usedAt = nowMs;
    return record;
  }

  sweep(nowMs) {
    for (const [challenge, record] of this.byChallenge) {
      if (record.exp < nowMs || record.used) this.byChallenge.delete(challenge);
    }
  }
}

const registrationChallenges = new RegistrationChallengeStore();

// ---------------------------------------------------------------------------
// Presence: out-of-band six-digit code printed on the server console
// ---------------------------------------------------------------------------

function presenceRequiredError() {
  return new HttpError(
    403,
    "PRESENCE_REQUIRED",
    "High-risk action requires an out-of-band presence confirmation",
    { challengeEndpoint: "/api/presence/challenge", verifyEndpoint: "/api/presence/verify" }
  );
}

function validatePresenceToken(token, auth, action, view, scopeHash, bodyHash) {
  if (typeof token !== "string" || token.length === 0) throw presenceRequiredError();
  const record = presenceTokens.get(token);
  if (
    !record ||
    record.used ||
    record.exp < now() ||
    record.deviceId !== auth.device.deviceId ||
    record.action !== action ||
    record.view !== view
  ) {
    throw presenceRequiredError();
  }
  if (record.scopeHash !== scopeHash || record.bodyHash !== bodyHash) {
    throw new HttpError(
      403,
      "PRESENCE_SCOPE_MISMATCH",
      "Presence approval was for a different scope or body"
    );
  }
  return record;
}

function markPresenceTokenUsed(record, auth, action, scopeHash, bodyHash) {
  record.used = true;
  record.usedAt = now();
  auditEvent("presence", {
    decision: "allow",
    deviceId: auth.device.deviceId,
    userId: auth.device.userId,
    action,
    scopeHash,
    bodyHash,
    reason: "PRESENCE_TOKEN_CONSUMED",
    outcome: "success"
  });
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

async function handleRegisterChallenge(req, res) {
  const body = await readJson(req);
  const ip = req.socket.remoteAddress || "unknown";
  rateLimit(`register-challenge:${ip}`, 30, 60_000);

  const jwk = sanitizePublicJwk(body.publicKeyJwk);
  const deviceName = normalizeDeviceName(body.deviceName);
  const jkt = jwkThumbprint(jwk);
  if (devices.size >= MAX_DEVICES && !devicesByJkt.has(jkt)) {
    throw new HttpError(429, "QUOTA_EXCEEDED", "Device quota exceeded");
  }
  const deviceNameHash = sha256(deviceName);
  const challenge = randomToken("rch");
  const record = {
    challenge,
    jkt,
    deviceNameHash,
    exp: now() + REGISTER_CHALLENGE_TTL_MS,
    attempts: 0,
    used: false
  };
  registrationChallenges.issue(jkt, record);

  sendJson(res, 200, {
    challenge,
    exp: record.exp,
    jkt,
    deviceNameHash
  });
}

async function handleRegister(req, res) {
  const body = await readJson(req);
  const ip = req.socket.remoteAddress || "unknown";
  rateLimit(`register:${ip}`, 120, 60_000);

  const jwk = sanitizePublicJwk(body.publicKeyJwk);
  const deviceName = normalizeDeviceName(body.deviceName);
  const jkt = jwkThumbprint(jwk);
  rateLimit(`register-jkt:${jkt}`, 120, 60_000);
  const deviceNameHash = sha256(deviceName);
  const challengeRecord = registrationChallenges.get(body.challenge);

  if (
    !challengeRecord ||
    challengeRecord.used ||
    challengeRecord.exp < now() ||
    challengeRecord.jkt !== jkt ||
    challengeRecord.deviceNameHash !== deviceNameHash
  ) {
    throw new HttpError(
      403,
      "INVALID_REGISTRATION_CHALLENGE",
      "Registration challenge is missing, expired, used or bound to different data"
    );
  }

  let proofBytes;
  try {
    proofBytes = protocol.b64urlDecodeStrict(body.proof);
  } catch {
    registrationChallenges.recordFailure(challengeRecord);
    throw new HttpError(403, "INVALID_REGISTRATION_PROOF", "Proof must be base64url");
  }
  if (proofBytes.length !== 64) {
    registrationChallenges.recordFailure(challengeRecord);
    throw new HttpError(403, "INVALID_REGISTRATION_PROOF", "Invalid ECDSA proof length");
  }

  const verifyKey = await importVerifyKey(jwk);
  const signed = protocol.registrationProofString(body.challenge, jkt, deviceNameHash);
  let valid = false;
  try {
    valid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      proofBytes,
      Buffer.from(signed, "utf8")
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    registrationChallenges.recordFailure(challengeRecord);
    throw new HttpError(403, "INVALID_REGISTRATION_PROOF", "Device signature is invalid");
  }

  // Atomic PoP challenge consume: this is the last await above. Concurrent
  // replays re-check used/exp/binding and only one can claim the challenge.
  const consumed = registrationChallenges.consume({
    challenge: body.challenge,
    jkt,
    deviceNameHash,
    nowMs: now()
  });
  if (!consumed) {
    throw new HttpError(
      403,
      "INVALID_REGISTRATION_CHALLENGE",
      "Registration challenge was already consumed"
    );
  }

  let device = devicesByJkt.get(jkt);
  if (device && device.revokedAt) {
    throw new HttpError(
      403,
      "DEVICE_REVOKED",
      "This canonical device key was revoked; generate a new key"
    );
  }

  if (!device) {
    const userId = randomHex("u");
    users.set(userId, {
      userId,
      name: deviceName,
      avatar: null,
      createdAt: now()
    });
    chatMembers.get("c_general").add(userId);
    boardMembers.get("b1").add(userId);
    boardMembers.get("b2").add(userId);
    device = {
      deviceId: randomHex("dev"),
      userId,
      deviceName,
      jkt,
      publicKeyJwk: jwk,
      verifyKey,
      createdAt: now(),
      revokedAt: null
    };
    devices.set(device.deviceId, device);
    devicesByJkt.set(jkt, device);
  } else {
    // PoP proved possession, so rename is allowed.
    device.deviceName = deviceName;
    device.verifyKey = verifyKey;
    const user = users.get(device.userId);
    if (user) user.name = deviceName;
  }

  const token = createSession(device);

  auditEvent("registered", {
    deviceId: device.deviceId,
    userId: device.userId,
    reason: "DEVICE_REGISTERED",
    outcome: "success",
    detail: { deviceName, deviceJkt: jkt }
  });

  sendJson(res, 200, {
    userId: device.userId,
    deviceId: device.deviceId,
    deviceJkt: device.jkt,
    deviceToken: token,
    device: publicDevice(device),
    user: publicUser(users.get(device.userId))
  });
}

// ---------------------------------------------------------------------------
// Capability issuance
// ---------------------------------------------------------------------------

async function handleIssueCapability(req, res) {
  const body = await readJson(req);
  const auth = requireAuth(req);
  rateLimit(`capability:${auth.device.deviceId}`, 300, 60_000);

  const action = body.action;
  setAuditContext(req, { action });
  const config = actionConfig(action);
  const view = body.view || inferView(action);
  requireActionInView(action, view);

  const scope = normalizeScope(action, body.scope, config);
  const actionBody = normalizeBody(action, body.body ?? {}, config);
  const { scopeHash, bodyHash } = hashes(scope, actionBody);
  setAuditContext(req, { scopeHash, bodyHash });

  const acl = serverPolicy.authorize(action, scope, auth, authContext());
  if (!acl.ok) {
    throw new HttpError(403, acl.code || "FORBIDDEN", acl.message);
  }

  if (config.presence) {
    // Validate but do not consume: v2.1 consumes the approval at action time,
    // bound again to the final request hashes.
    validatePresenceToken(
      body.presenceToken,
      auth,
      action,
      view,
      scopeHash,
      bodyHash
    );
  } else if (body.presenceToken) {
    throw new HttpError(400, "PRESENCE_NOT_REQUIRED", "This action does not use presence");
  }

  let parentRecord = null;
  if (config.parent) {
    parentRecord = store.get(body.parentCap);
    if (
      !parentRecord ||
      parentRecord.payload.deviceId !== auth.device.deviceId ||
      parentRecord.payload.action !== config.parent ||
      !parentRecord.used ||
      parentRecord.revoked ||
      parentRecord.payload.exp < now()
    ) {
      throw new HttpError(409, "SEQ_MISMATCH", "Parent step is missing, used or expired");
    }
    if (!body.prevHash || body.prevHash !== parentRecord.chainHash) {
      throw new HttpError(409, "SEQ_MISMATCH", "prevHash does not match parent");
    }
    if (
      scope.boardId !== parentRecord.payload.scope.boardId ||
      scope.draftId !== parentRecord.draftId ||
      scope.draftHash !== parentRecord.draftHash
    ) {
      throw new HttpError(
        403,
        "DRAFT_HASH_MISMATCH",
        "Child scope does not match the parent draft content"
      );
    }

    if (parentRecord.childCapId) {
      const existingChild = store.get(parentRecord.childCapId);
      if (existingChild && existingChild.used) {
        throw new HttpError(
          409,
          "CAPABILITY_CONSUMED",
          "Parent already produced a consumed child step"
        );
      }
      if (existingChild && !existingChild.revoked && existingChild.payload.exp >= now()) {
        throw new HttpError(
          409,
          "CAPABILITY_CONSUMED",
          "Parent already has an active child step"
        );
      }
      if (existingChild) {
        existingChild.revoked = true;
        existingChild.revokedAt = now();
      }
    }
  } else if (body.parentCap || body.prevHash) {
    throw new HttpError(409, "SEQ_MISMATCH", "This action does not accept a parent");
  }

  const issuedAt = now();
  let ttlMs = config.ttlSeconds * 1000;
  if (ALLOW_TEST_HOOKS && req.headers["x-test-ttl-ms"]) {
    const override = Number(req.headers["x-test-ttl-ms"]);
    if (Number.isInteger(override) && override > 0 && override <= 60_000) {
      ttlMs = override;
    }
  }

  const payload = {
    v: 2,
    capId: randomToken("cap"),
    userId: auth.device.userId,
    deviceId: auth.device.deviceId,
    deviceJkt: auth.device.jkt,
    action,
    view,
    scope,
    scopeHash,
    bodyHash,
    seq: parentRecord ? parentRecord.payload.seq + 1 : 1,
    nonce: randomToken("nonce"),
    maxUses: config.maxUses,
    exp: issuedAt + ttlMs,
    parentCap: parentRecord ? parentRecord.payload.capId : null,
    prevHash: parentRecord ? parentRecord.chainHash : null,
    iat: issuedAt
  };
  const record = {
    payload,
    sig: capabilitySignature(payload),
    used: false,
    uses: 0,
    revoked: false,
    issuedAt,
    chainHash: null,
    childCapId: null,
    draftId: null,
    draftHash: null
  };
  enforceCapabilityQuota(auth.device.deviceId);
  store.add(record);
  if (parentRecord) parentRecord.childCapId = payload.capId;
  setAuditContext(req, { capId: payload.capId, parentCap: payload.parentCap });

  auditEvent("issued", {
    capId: payload.capId,
    action,
    deviceId: auth.device.deviceId,
    userId: auth.device.userId,
    scopeHash,
    bodyHash,
    parentCap: payload.parentCap,
    reason: "CAPABILITY_ISSUED",
    outcome: "issued"
  });

  sendJson(res, 200, { capability: { payload, sig: record.sig } });
}

// ---------------------------------------------------------------------------
// Presence challenge / verification
// ---------------------------------------------------------------------------

async function handlePresenceChallenge(req, res) {
  const body = await readJson(req);
  const auth = requireAuth(req);
  rateLimit(`presence-challenge:${auth.device.deviceId}`, 10, 60_000);

  const action = body.action;
  setAuditContext(req, { action });
  const config = actionConfig(action);
  if (!config.presence) {
    throw new HttpError(400, "PRESENCE_NOT_REQUIRED", "Action does not require presence");
  }
  const view = body.view || inferView(action);
  requireActionInView(action, view);
  const scope = normalizeScope(action, body.scope, config);
  const actionBody = normalizeBody(action, body.body ?? {}, config);
  const { scopeHash, bodyHash } = hashes(scope, actionBody);
  setAuditContext(req, { scopeHash, bodyHash });

  const acl = serverPolicy.authorize(action, scope, auth, authContext());
  if (!acl.ok) throw new HttpError(403, acl.code || "FORBIDDEN", acl.message);

  // Invalidate previous outstanding challenges for this device/action.
  for (const record of presenceChallenges.values()) {
    if (
      !record.used &&
      record.deviceId === auth.device.deviceId &&
      record.action === action
    ) {
      record.used = true;
      record.invalidated = true;
    }
  }

  const challenge = randomToken("pch");
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
  const exp = now() + PRESENCE_CHALLENGE_TTL_MS;
  const record = {
    challenge,
    codeHash: sha256(code),
    attempts: 0,
    deviceId: auth.device.deviceId,
    userId: auth.device.userId,
    action,
    view,
    scopeHash,
    bodyHash,
    exp,
    used: false
  };
  presenceChallenges.set(challenge, record);

  // Demo out-of-band channel: the code appears on the server console only when
  // DEMO is enabled. Production must use a WebAuthn verifier instead.
  if (DEMO) {
    console.log(
      `[presence] challenge=${challenge} code=${code} action=${action} ` +
        `device=${maskId(auth.device.deviceId)} scopeHash=${scopeHash} bodyHash=${bodyHash} ` +
        `exp=${new Date(exp).toISOString()}`
    );
  }

  sendJson(res, 200, {
    challenge,
    exp,
    action,
    view,
    scopeHash,
    bodyHash
  });
}

function normalizePresenceProof(body) {
  if (body.proof && typeof body.proof === "object") {
    if (body.proof.kind === "oob") {
      return { kind: "oob", code: String(body.proof.code || "").trim() };
    }
    if (body.proof.kind === "webauthn") {
      return { kind: "webauthn", assertion: body.proof.assertion };
    }
    throw new HttpError(400, "PRESENCE_PROOF_INVALID", "Unknown presence proof kind");
  }
  if (typeof body.code === "string") {
    return { kind: "oob", code: body.code.trim() };
  }
  throw new HttpError(
    400,
    "PRESENCE_PROOF_REQUIRED",
    "Send proof:{kind:'oob',code} or proof:{kind:'webauthn',assertion}"
  );
}

/**
 * Production contract (not implemented here):
 * `assertion` is a PublicKeyCredential JSON object whose clientDataJSON binds
 * the server challenge; verify type=="webauthn.get", challenge, origin,
 * rpIdHash, UP/UV flags, signature and signCount against the registered
 * credential before returning. The demo accepts only an explicit test-only
 * fake assertion when ALLOW_TEST_HOOKS=1.
 */
async function verifyWebAuthnPresence(record, assertion, auth) {
  if (
    ALLOW_TEST_HOOKS &&
    assertion &&
    assertion.type === "test-presence-assertion" &&
    assertion.verified === true &&
    assertion.challenge === record.challenge
  ) {
    auditEvent("presence", {
      deviceId: auth.device.deviceId,
      userId: auth.device.userId,
      action: record.action,
      scopeHash: record.scopeHash,
      bodyHash: record.bodyHash,
      reason: "TEST_WEBAUTHN_ASSERTION_ACCEPTED",
      outcome: "success"
    });
    return;
  }
  throw new HttpError(
    501,
    "PRESENCE_WEBAUTHN_NOT_IMPLEMENTED",
    "No production WebAuthn verifier is configured",
    {
      contract: {
        assertion: "PublicKeyCredential JSON",
        checks: [
          "clientDataJSON.type == webauthn.get",
          "challenge matches the server challenge",
          "origin/rpIdHash match the deployment",
          "UP and UV flags are set",
          "signature verifies with the device credential",
          "signCount advances"
        ],
        bind: "deviceId + action + view + scopeHash + bodyHash + serverNonce"
      }
    }
  );
}

async function handlePresenceVerify(req, res) {
  const body = await readJson(req);
  const auth = requireAuth(req);
  rateLimit(`presence-verify:${auth.device.deviceId}`, 30, 60_000);
  setAuditContext(req, { action: "presence" });

  const record = presenceChallenges.get(body.challenge);
  if (
    !record ||
    record.used ||
    record.exp < now() ||
    record.deviceId !== auth.device.deviceId
  ) {
    throw new HttpError(
      403,
      "PRESENCE_CHALLENGE_INVALID",
      "Presence challenge is missing, expired, used or bound to another device"
    );
  }

  const proof = normalizePresenceProof(body);
  if (proof.kind === "oob") {
    if (!DEMO) {
      throw new HttpError(
        400,
        "PRESENCE_OOB_DISABLED",
        "The console-code provider is demo-only; configure WebAuthn UV"
      );
    }
    const code = proof.code;
    if (!/^\d{6}$/.test(code)) {
      record.attempts += 1;
      if (record.attempts >= PRESENCE_MAX_ATTEMPTS) record.used = true;
      throw new HttpError(403, "PRESENCE_CODE_INVALID", "Enter the six-digit console code");
    }

    record.attempts += 1;
    const expected = Buffer.from(record.codeHash, "utf8");
    const actual = Buffer.from(sha256(code), "utf8");
    const matches =
      expected.length === actual.length && crypto.timingSafeEqual(expected, actual);

    if (!matches) {
      if (record.attempts >= PRESENCE_MAX_ATTEMPTS) record.used = true;
      throw new HttpError(403, "PRESENCE_CODE_INVALID", "Invalid presence code");
    }
  } else if (proof.kind === "webauthn") {
    await verifyWebAuthnPresence(record, proof.assertion, auth);
  } else {
    throw new HttpError(400, "PRESENCE_PROOF_INVALID", "Unknown presence proof kind");
  }

  record.used = true;
  const presenceToken = randomToken("pres");
  const exp = now() + PRESENCE_TOKEN_TTL_MS;
  presenceTokens.set(presenceToken, {
    token: presenceToken,
    deviceId: auth.device.deviceId,
    userId: auth.device.userId,
    action: record.action,
    view: record.view,
    scopeHash: record.scopeHash,
    bodyHash: record.bodyHash,
    exp,
    used: false
  });

  auditEvent("presence", {
    deviceId: auth.device.deviceId,
    userId: auth.device.userId,
    action: record.action,
    scopeHash: record.scopeHash,
    bodyHash: record.bodyHash,
    reason: "PRESENCE_CODE_VERIFIED",
    outcome: "success"
  });

  sendJson(res, 200, {
    presenceToken,
    exp,
    scopeHash: record.scopeHash,
    bodyHash: record.bodyHash
  });
}

// ---------------------------------------------------------------------------
// Business actions (must stay synchronous)
// ---------------------------------------------------------------------------

function performAction(action, scope, body, record, auth) {
  if (action === "createPost") {
    const post = {
      id: randomHex("post"),
      userId: auth.user.userId,
      boardId: scope.boardId,
      text: body.text,
      createdAt: now(),
      viaCap: record.payload.capId
    };
    feed.push(post);
    return { post };
  }

  if (action === "sendMessage") {
    const message = {
      id: randomHex("msg"),
      chatId: scope.chatId,
      userId: auth.user.userId,
      text: body.text,
      mentions: [],
      createdAt: now(),
      viaCap: record.payload.capId
    };
    messages.push(message);
    return { message };
  }

  if (action === "mention") {
    const message = {
      id: randomHex("msg"),
      chatId: scope.chatId,
      userId: auth.user.userId,
      text: body.text,
      mentions: scope.userIds,
      createdAt: now(),
      viaCap: record.payload.capId
    };
    messages.push(message);
    return { message };
  }

  if (action === "chat:join") {
    chatMembers.get(scope.chatId).add(auth.user.userId);
    return { member: true, chatId: scope.chatId };
  }

  if (action === "chat:leave") {
    chatMembers.get(scope.chatId).delete(auth.user.userId);
    return { member: false, chatId: scope.chatId };
  }

  if (action === "changeAvatar") {
    auth.user.avatar = {
      mime: scope.mime,
      maxSize: scope.maxSize,
      reason: body.reason,
      updatedAt: new Date().toISOString()
    };
    return { user: publicUser(auth.user) };
  }

  if (action === "post:edit") {
    const draft = {
      draftId: randomHex("draft"),
      userId: auth.user.userId,
      deviceId: auth.device.deviceId,
      boardId: scope.boardId,
      text: body.text,
      draftHash: sha256(body.text),
      editCapId: record.payload.capId,
      createdAt: now()
    };
    drafts.set(draft.draftId, draft);
    const deviceDrafts = [...drafts.values()]
      .filter((item) => item.deviceId === auth.device.deviceId)
      .sort((a, b) => a.createdAt - b.createdAt);
    while (deviceDrafts.length > MAX_DRAFTS_PER_DEVICE) {
      drafts.delete(deviceDrafts.shift().draftId);
    }
    record.draftId = draft.draftId;
    record.draftHash = draft.draftHash;
    return { draft };
  }

  if (action === "post:submit") {
    const draft = drafts.get(scope.draftId);
    if (
      !draft ||
      draft.deviceId !== auth.device.deviceId ||
      draft.editCapId !== record.payload.parentCap
    ) {
      throw new HttpError(409, "SEQ_MISMATCH", "Draft is missing or not linked to this sequence");
    }
    const actualHash = sha256(draft.text);
    if (
      actualHash !== scope.draftHash ||
      actualHash !== draft.draftHash ||
      draft.boardId !== scope.boardId
    ) {
      throw new HttpError(409, "DRAFT_HASH_MISMATCH", "Draft content changed after edit");
    }
    const post = {
      id: randomHex("post"),
      userId: auth.user.userId,
      boardId: draft.boardId,
      text: draft.text,
      createdAt: now(),
      viaCap: record.payload.capId
    };
    feed.push(post);
    drafts.delete(draft.draftId);
    return { post };
  }

  throw new HttpError(400, "UNKNOWN_ACTION", `No handler for ${action}`);
}

// ---------------------------------------------------------------------------
// Action use: proof verify -> ACL recheck -> synchronous atomic commit
// ---------------------------------------------------------------------------

async function handleAction(req, res) {
  const body = await readJson(req);
  const auth = requireAuth(req);
  rateLimit(`action:${auth.device.deviceId}`, 300, 60_000);

  const action = body.action;
  setAuditContext(req, { action });

  const capability = body.capability;
  if (!capability || !capability.payload || typeof capability.sig !== "string") {
    throw new HttpError(403, "INVALID_CAPABILITY", "Capability envelope is missing");
  }
  const record = store.get(capability.payload.capId);
  if (!record) {
    throw new HttpError(403, "INVALID_CAPABILITY", "Capability is not valid");
  }
  if (
    stable(record.payload) !== stable(capability.payload) ||
    !capabilitySignatureValid(record.payload, record.sig)
  ) {
    throw new HttpError(403, "INVALID_CAPABILITY", "Capability was tampered with");
  }

  const payload = record.payload;
  setAuditContext(req, {
    capId: payload.capId,
    action: payload.action,
    scopeHash: payload.scopeHash,
    bodyHash: payload.bodyHash,
    parentCap: payload.parentCap
  });

  const view = body.view || payload.view || inferView(action);
  requireActionInView(action, view);
  if (payload.view !== view) {
    throw new HttpError(
      403,
      "ACTION_NOT_ALLOWED_IN_VIEW",
      `Capability view ${payload.view} does not match ${view}`
    );
  }
  if (payload.action !== action) {
    throw new HttpError(403, "ACTION_MISMATCH", `Capability is for ${payload.action}`);
  }
  if (payload.deviceId !== auth.device.deviceId) {
    throw new HttpError(403, "DEVICE_MISMATCH", "Capability belongs to another device");
  }
  if (payload.deviceJkt !== auth.device.jkt) {
    throw new HttpError(403, "DEVICE_MISMATCH", "Capability thumbprint mismatch");
  }

  const config = actionConfig(action);
  const scope = normalizeScope(action, body.scope, config);
  const actionBody = normalizeBody(action, body.body ?? {}, config);
  if (stable(scope) !== stable(payload.scope)) {
    throw new HttpError(403, "SCOPE_DENIED", "Request scope does not match capability");
  }
  const { scopeHash, bodyHash } = hashes(scope, actionBody);
  if (scopeHash !== payload.scopeHash) {
    throw new HttpError(403, "SCOPE_DENIED", "Scope hash mismatch");
  }
  if (bodyHash !== payload.bodyHash) {
    throw new HttpError(403, "BODY_MISMATCH", "Request body does not match capability");
  }

  if (config.parent) {
    if (!payload.parentCap || !payload.prevHash) {
      throw new HttpError(409, "SEQ_MISMATCH", "Missing sequence parent");
    }
    const parent = store.get(payload.parentCap);
    if (!parent || !parent.used || payload.prevHash !== parent.chainHash) {
      throw new HttpError(409, "SEQ_MISMATCH", "Sequence link is invalid");
    }
  } else if (payload.parentCap) {
    throw new HttpError(409, "SEQ_MISMATCH", "Unexpected sequence parent");
  }

  if (typeof body.proof !== "string") {
    throw new HttpError(403, "INVALID_PROOF", "A device proof is required");
  }
  let proofBytes;
  try {
    proofBytes = protocol.b64urlDecodeStrict(body.proof);
  } catch {
    throw new HttpError(403, "INVALID_PROOF", "Proof must be canonical base64url");
  }
  if (proofBytes.length !== 64) {
    throw new HttpError(403, "INVALID_PROOF", "Invalid ECDSA proof length");
  }

  const signedText = proofText(payload, action, scopeHash, bodyHash);
  let proofValid = false;
  try {
    proofValid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      auth.device.verifyKey,
      proofBytes,
      Buffer.from(signedText, "utf8")
    );
  } catch {
    proofValid = false;
  }
  if (!proofValid) {
    throw new HttpError(403, "INVALID_PROOF", "Device signature is invalid");
  }

  // Test-only delay to make in-flight revocation and double-spend races
  // deterministic. The commit below rechecks all mutable state.
  if (
    ALLOW_TEST_HOOKS &&
    req.headers["x-test-verify-delay"] === "1" &&
    TEST_VERIFY_DELAY_MS > 0
  ) {
    await sleep(TEST_VERIFY_DELAY_MS);
  }

  // Continuity: membership/ACL can change between issuance and use.
  const acl = serverPolicy.authorize(action, scope, auth, authContext());
  if (!acl.ok) {
    throw new HttpError(403, acl.code || "FORBIDDEN", acl.message);
  }

  // ---- synchronous commit block: no await until performAction returns ----
  if (auth.device.revokedAt) {
    throw new HttpError(403, "DEVICE_REVOKED", "Device was revoked before commit");
  }

  // Presence gates the final action in v2.1. Validate here, consume only after
  // the capability commit succeeds, all without yielding the event loop.
  let presenceRecord = null;
  if (config.presence) {
    presenceRecord = validatePresenceToken(
      body.presenceToken,
      auth,
      action,
      view,
      scopeHash,
      bodyHash
    );
  } else if (body.presenceToken) {
    throw new HttpError(400, "PRESENCE_NOT_REQUIRED", "This action does not use presence");
  }

  const commit = store.consumeCapability({
    capId: payload.capId,
    deviceId: auth.device.deviceId,
    signedText,
    nowMs: now()
  });
  if (!commit.ok) {
    const map = {
      CAPABILITY_CONSUMED: [409, "CAPABILITY_CONSUMED", "Capability has already been used"],
      CAPABILITY_EXPIRED: [410, "CAPABILITY_EXPIRED", "Capability has expired"],
      DEVICE_REVOKED: [403, "DEVICE_REVOKED", "Capability or device was revoked"],
      DEVICE_MISMATCH: [403, "DEVICE_MISMATCH", "Capability belongs to another device"],
      INVALID_CAPABILITY: [403, "INVALID_CAPABILITY", "Capability is not valid"]
    };
    const [status, code, message] = map[commit.reason] || [
      403,
      "INVALID_CAPABILITY",
      "Capability could not be consumed"
    ];
    throw new HttpError(status, code, message);
  }
  if (presenceRecord) {
    markPresenceTokenUsed(presenceRecord, auth, action, scopeHash, bodyHash);
  }

  let result;
  let consumedAudit;
  try {
    result = performAction(action, scope, actionBody, commit.record, auth);
    consumedAudit = auditEvent("consumed", {
      capId: payload.capId,
      action,
      deviceId: auth.device.deviceId,
      userId: auth.user.userId,
      scopeHash,
      bodyHash,
      parentCap: payload.parentCap,
      resultId: result.post?.id || result.message?.id || result.draft?.draftId || null,
      reason: "CAPABILITY_CONSUMED",
      outcome: "success"
    });
  } catch (error) {
    auditEvent("consumed", {
      capId: payload.capId,
      action,
      deviceId: auth.device.deviceId,
      userId: auth.user.userId,
      scopeHash,
      bodyHash,
      parentCap: payload.parentCap,
      resultId: null,
      reason: "CAPABILITY_CONSUMED",
      outcome: "failed",
      detail: error.message
    });
    throw error;
  }

  let sequence = null;
  if (config.next) {
    const draft = result.draft;
    sequence = {
      nextAction: config.next,
      parentCap: payload.capId,
      prevHash: commit.chainHash,
      nextScope: draft
        ? {
            boardId: draft.boardId,
            draftId: draft.draftId,
            draftHash: draft.draftHash
          }
        : null
    };
  }

  sendJson(res, 200, {
    ok: true,
    result,
    sequence,
    receipt: {
      auditId: consumedAudit.auditId,
      capId: payload.capId,
      action,
      view,
      scopeHash,
      bodyHash,
      exp: payload.exp
    }
  });
}

// ---------------------------------------------------------------------------
// State, audit, revocation, membership
// ---------------------------------------------------------------------------

async function handleState(req, res) {
  const auth = requireSession(req);
  rateLimit(`state:${auth.device.deviceId}`, 120, 60_000);
  const boards = new Set(serverPolicy.visibleBoards(auth, authContext()));
  const chats = new Set(
    serverPolicy.visibleChats().filter((chatId) => {
      const members = chatMembers.get(chatId);
      return members && members.has(auth.user.userId);
    })
  );

  const visibleUserIds = new Set([auth.user.userId]);
  for (const chatId of chats) {
    for (const userId of chatMembers.get(chatId) || []) visibleUserIds.add(userId);
  }

  const visibleCapabilities = [...store.capabilities.values()]
    .filter((record) => record.payload.deviceId === auth.device.deviceId)
    .slice(-50)
    .map((record) => ({
      capId: record.payload.capId,
      action: record.payload.action,
      scope: record.payload.scope,
      scopeHash: record.payload.scopeHash,
      bodyHash: record.payload.bodyHash,
      seq: record.payload.seq,
      exp: record.payload.exp,
      used: record.used,
      uses: record.uses
    }));

  const visibleDrafts = [...drafts.values()].filter(
    (draft) => draft.deviceId === auth.device.deviceId
  );

  sendJson(res, 200, {
    serverTime: new Date().toISOString(),
    me: { user: publicUser(auth.user), device: publicDevice(auth.device) },
    users: [...users.values()]
      .filter((user) => visibleUserIds.has(user.userId))
      .map(publicUser),
    feed: feed
      .filter((post) => boards.has(post.boardId))
      .slice(-100)
      .map((post) => ({ ...post, viaCap: maskId(post.viaCap) })),
    messages: messages
      .filter((message) => chats.has(message.chatId))
      .slice(-100)
      .map((message) => ({ ...message, viaCap: maskId(message.viaCap) })),
    drafts: visibleDrafts,
    capabilities: visibleCapabilities,
    policyVersion: policy.version
  });
}

async function handleAudit(req, res, url) {
  const auth = requireSession(req);
  rateLimit(`audit:${auth.device.deviceId}`, 120, 60_000);
  const admin = adminTokenMatches(req.headers["x-admin-token"]);
  const requested = Number(url.searchParams.get("limit") || 100);
  const limit = Number.isFinite(requested)
    ? Math.max(1, Math.min(500, requested))
    : 100;

  let events = audit;
  if (!admin) {
    events = audit.filter(
      (event) =>
        event.userId === auth.user.userId ||
        event.deviceId === auth.device.deviceId
    );
  }

  const visible = events
    .slice(-limit)
    .reverse()
    .map((event) => {
      if (admin) return event;
      return {
        auditId: event.auditId,
        type: event.type,
        decision: event.decision,
        time: event.time,
        capId: maskId(event.capId),
        action: event.action,
        deviceId: maskId(event.deviceId),
        userId: event.userId === auth.user.userId ? event.userId : null,
        scopeHash: maskId(event.scopeHash),
        bodyHash: maskId(event.bodyHash),
        parentCap: event.parentCap ? maskId(event.parentCap) : null,
        resultId: maskId(event.resultId),
        outcome: event.outcome,
        reason: event.reason
      };
    });

  sendJson(res, 200, {
    events: visible,
    total: events.length,
    admin
  });
}

async function handleRevoke(req, res) {
  await readJson(req);
  const auth = requireAuth(req);
  setAuditContext(req, { action: "revoke" });
  rateLimit(`revoke:${auth.device.deviceId}`, 10, 60_000);

  if (!auth.device.revokedAt) auth.device.revokedAt = now();
  const count = store.revokeDevice(auth.device.deviceId, now());

  for (const [challenge, record] of presenceChallenges) {
    if (record.deviceId === auth.device.deviceId) presenceChallenges.delete(challenge);
  }
  for (const [token, record] of presenceTokens) {
    if (record.deviceId === auth.device.deviceId) presenceTokens.delete(token);
  }

  for (const record of store.capabilities.values()) {
    if (record.payload.deviceId !== auth.device.deviceId) continue;
    auditEvent("revoked", {
      capId: record.payload.capId,
      action: record.payload.action,
      deviceId: auth.device.deviceId,
      userId: auth.user.userId,
      reason: "DEVICE_REVOKED",
      outcome: "revoked"
    });
  }
  auditEvent("revoked", {
    deviceId: auth.device.deviceId,
    userId: auth.user.userId,
    reason: "DEVICE_REVOKED",
    outcome: "revoked",
    detail: { revokedCapabilities: count }
  });

  sendJson(res, 200, { ok: true, revokedCapabilities: count });
}

async function handleTestBoardMembership(req, res) {
  if (!ALLOW_TEST_HOOKS) throw new HttpError(404, "NOT_FOUND", "Test hooks disabled");
  const body = await readJson(req);
  const auth = requireAuth(req);
  rateLimit(`test-board:${auth.device.deviceId}`, 30, 60_000);
  const boardId = body.boardId;
  const members = boardMembers.get(boardId);
  if (!members) throw new HttpError(400, "UNKNOWN_BOARD", `Unknown board ${boardId}`);
  if (body.member) members.add(auth.user.userId);
  else members.delete(auth.user.userId);
  auditEvent("membership", {
    deviceId: auth.device.deviceId,
    userId: auth.user.userId,
    action: "board.membership",
    reason: body.member ? "BOARD_MEMBER_ADDED" : "BOARD_MEMBER_REMOVED",
    outcome: "success"
  });
  sendJson(res, 200, { ok: true, boardId, member: members.has(auth.user.userId) });
}

async function handleTestMutateDraft(req, res) {
  if (!ALLOW_TEST_HOOKS) throw new HttpError(404, "NOT_FOUND", "Test hooks disabled");
  const body = await readJson(req);
  const auth = requireAuth(req);
  const draft = drafts.get(body.draftId);
  if (!draft || draft.deviceId !== auth.device.deviceId) {
    throw new HttpError(404, "DRAFT_NOT_FOUND", "Draft not found for this device");
  }
  draft.text = requireText(body.text, "text", 2000);
  auditEvent("draft", {
    deviceId: auth.device.deviceId,
    userId: auth.user.userId,
    action: "post:edit",
    reason: "TEST_DRAFT_MUTATED",
    outcome: "success",
    detail: { draftId: draft.draftId }
  });
  sendJson(res, 200, { ok: true, draftId: draft.draftId, draftHash: draft.draftHash });
}

// ---------------------------------------------------------------------------
// API routing
// ---------------------------------------------------------------------------

async function handleApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const route = `${req.method} ${url.pathname}`;

  try {
    if (
      req.method === "POST" &&
      !/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"] || "")
    ) {
      throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "POST bodies must be application/json");
    }
    if (route === "POST /api/register/challenge") return await handleRegisterChallenge(req, res);
    if (route === "POST /api/register") return await handleRegister(req, res);
    if (route === "POST /api/capabilities") return await handleIssueCapability(req, res);
    if (route === "POST /api/presence/challenge") return await handlePresenceChallenge(req, res);
    if (route === "POST /api/presence/verify") return await handlePresenceVerify(req, res);
    if (route === "POST /api/presence") {
      throw new HttpError(
        410,
        "PRESENCE_API_CHANGED",
        "Use /api/presence/challenge and /api/presence/verify"
      );
    }
    if (route === "POST /api/action") return await handleAction(req, res);
    if (route === "GET /api/state") return await handleState(req, res);
    if (route === "GET /api/audit") return await handleAudit(req, res, url);
    if (route === "POST /api/revoke") return await handleRevoke(req, res);
    if (route === "POST /api/test/board-membership") return await handleTestBoardMembership(req, res);
    if (route === "POST /api/test/mutate-draft") return await handleTestMutateDraft(req, res);
    if (route === "GET /api/health") {
      return sendJson(res, 200, {
        ok: true,
        time: new Date().toISOString(),
        policyVersion: policy.version,
        demo: DEMO
      });
    }
    throw new HttpError(404, "NOT_FOUND", `No API route for ${route}`);
  } catch (error) {
    if (error instanceof HttpError) {
      sendError(req, res, error);
      return;
    }
    console.error(error);
    sendError(req, res, new HttpError(500, "INTERNAL_ERROR", "Internal error"));
  }
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

async function handleStatic(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { allow: "GET, HEAD" });
    res.end("Method not allowed");
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400);
    res.end("Bad request");
    return;
  }
  if (pathname === "/") pathname = "/index.html";
  if (pathname === "/demo-hooks.js" && !DEMO) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Demo hooks disabled (DEMO=0)");
    return;
  }

  const relative = pathname.replace(/^\/+/, "");
  const filePath = path.resolve(PUBLIC_DIR, relative);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  let content;
  try {
    content = await fs.readFile(filePath);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }

  res.writeHead(200, {
    "content-type": MIME_TYPES[path.extname(filePath)] || "application/octet-stream",
    "content-length": content.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
    // No CSP: the explicit ?demo=1 XSS lab injects a script.
  });
  res.end(req.method === "HEAD" ? undefined : content);
}

// ---------------------------------------------------------------------------
// Startup and housekeeping
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  try {
    if (req.url && req.url.startsWith("/api/")) await handleApi(req, res);
    else await handleStatic(req, res);
  } catch (error) {
    console.error("Unhandled request error", error);
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      res.end("Internal error");
    }
  }
});

server.listen(PORT, HOST, () => {
  const actualPort = server.address().port;
  console.log(`Secrecy v2.1 demo listening on http://${HOST}:${actualPort}`);
  console.log("State is in memory; restart for a clean demo.");
  console.log(`[demo] DEMO=${DEMO ? "1" : "0"}`);
  if (ALLOW_TEST_HOOKS) console.log("[test] ALLOW_TEST_HOOKS=1");
});

const sweeper = setInterval(() => {
  const t = now();
  for (const [token, session] of sessions) {
    if (session.exp < t) sessions.delete(token);
  }
  registrationChallenges.sweep(t);
  for (const [challenge, record] of presenceChallenges) {
    if (record.exp < t) presenceChallenges.delete(challenge);
  }
  for (const [token, record] of presenceTokens) {
    if (record.exp < t) presenceTokens.delete(token);
  }
  for (const [key, bucket] of rateBuckets) {
    if (bucket.reset < t) rateBuckets.delete(key);
  }
}, 60_000);
sweeper.unref();
