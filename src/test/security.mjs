#!/usr/bin/env node
/*
 * v2 security regression suite.
 *
 * By default this starts its own isolated server on an ephemeral port so it can
 * read presence codes from stdout and use test-only delay/ttl hooks without
 * affecting a developer's running demo.
 *
 *   node test/security.mjs
 *
 * If BASE_URL is set, the suite uses that server instead. Presence-code tests
 * are then skipped unless that server is also emitting codes to this process,
 * which is only possible when the suite spawned it.
 */

import crypto from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import {
  expectCode,
  issueCapability,
  makeDevice,
  protocol,
  rawPost,
  registerDevice,
  request,
  signProof,
  signText,
  sleep,
  useCapability,
  waitFor
} from "./helpers.mjs";

const require = createRequire(import.meta.url);
const serverPolicy = require("../server-policy.js");
const basePolicy = require("../public/policy.js");
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let passed = 0;
let failed = 0;
let child = null;
let BASE = (process.env.BASE_URL || "").replace(/\/+$/, "");
let ADMIN_TOKEN =
  process.env.ADMIN_TOKEN || "security-admin-0123456789abcdef0123456789abcdef";
const presenceCodes = new Map();
let stdoutBuffer = "";
let externalServer = Boolean(BASE);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function check(name, task) {
  try {
    await task();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  ${name}`);
    console.error(`      ${error.message}`);
  }
}

function assertThrows(fn, label) {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(`${label} should have failed validation`);
}

function startServer() {
  return new Promise((resolve, reject) => {
    ADMIN_TOKEN = `test-admin-${crypto.randomBytes(32).toString("hex")}`;
    child = spawn(process.execPath, ["server.js"], {
      cwd: ROOT,
      env: {
        ...process.env,
        PORT: "0",
        HOST: "127.0.0.1",
        DEMO: "1",
        ALLOW_TEST_HOOKS: "1",
        TEST_VERIFY_DELAY_MS: "250",
        ADMIN_TOKEN
      },
      stdio: ["ignore", "pipe", "pipe"]
    });

    const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
    child.on("error", (error) => reject(error));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdoutBuffer += chunk;
      const lines = stdoutBuffer.split("\n");
      stdoutBuffer = lines.pop() || "";
      for (const line of lines) {
        const portMatch = line.match(/listening on http:\/\/127\.0\.0\.1:(\d+)/);
        if (portMatch && !BASE && !externalServer) {
          BASE = `http://127.0.0.1:${portMatch[1]}`;
          clearTimeout(timer);
          resolve();
        }
        const codeMatch = line.match(/\[presence\] challenge=(\S+) code=(\d{6})/);
        if (codeMatch) presenceCodes.set(codeMatch[1], codeMatch[2]);
      }
    });
  });
}

async function waitForPresenceCode(challenge) {
  if (externalServer) {
    throw new Error("Presence-code tests need the suite-spawned server");
  }
  const code = await waitFor(() => presenceCodes.get(challenge), 3000);
  if (!code) throw new Error("presence code did not appear on server stdout");
  return code;
}

async function adminRequest(pathname, options = {}) {
  return request(BASE, pathname, {
    ...options,
    headers: { ...(options.headers || {}), "x-admin-token": ADMIN_TOKEN }
  });
}

async function runConcurrency(parallelism) {
  const device = makeDevice(`Concurrency-${parallelism}`);
  await registerDevice(BASE, device);
  const scope = { boardId: "b1" };
  const body = { text: `parallel-${parallelism}-${Date.now()}` };
  const issued = await issueCapability(BASE, device.token, {
    action: "createPost",
    view: "home",
    scope,
    body
  });
  assert(issued.status === 200, `issue failed: ${JSON.stringify(issued.data)}`);
  const capability = issued.data.capability;
  const proof = signProof(device, capability, "createPost", scope, body);
  const requestBody = {
    capability,
    proof,
    action: "createPost",
    view: "home",
    scope,
    body
  };

  const responses = await Promise.all(
    Array.from({ length: parallelism }, () =>
      rawPost(BASE, "/api/action", {
        token: device.token,
        body: requestBody,
        headers: { "x-test-verify-delay": "1" }
      })
    )
  );

  const successes = responses.filter((response) => response.status === 200);
  assert(successes.length === 1, `expected one 200, got ${successes.length}`);
  for (const response of responses.filter((item) => item.status !== 200)) {
    expectCode(response, "CAPABILITY_CONSUMED");
  }

  const state = await request(BASE, "/api/state", { method: "GET", token: device.token });
  assert(state.status === 200, "state failed");
  const writes = state.data.feed.filter((post) => post.text === body.text);
  assert(writes.length === 1, `expected one business write, got ${writes.length}`);

  const audit = await adminRequest("/api/audit?limit=500", {
    method: "GET",
    token: device.token
  });
  assert(audit.status === 200, "audit failed");
  const consumed = audit.data.events.filter(
    (event) => event.type === "consumed" && event.capId === capability.payload.capId
  );
  assert(consumed.length === 1, `expected one consumed audit, got ${consumed.length}`);
}

// ---------------------------------------------------------------------------
// Start and run
// ---------------------------------------------------------------------------

if (!BASE) await startServer();

try {
  const health = await request(BASE, "/api/health", { method: "GET" });
  assert(health.status === 200, "health check failed");

  async function runRegistrationReplay(parallelism) {
    const device = makeDevice(`PoP-Replay-${parallelism}`);
    const challenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: device.publicJwk, deviceName: device.label }
    });
    assert(challenge.status === 200, `PoP challenge failed: ${JSON.stringify(challenge.data)}`);
    const proof = signText(
      device,
      protocol.registrationProofString(
        challenge.data.challenge,
        challenge.data.jkt,
        challenge.data.deviceNameHash
      )
    );
    const registrationBody = {
      publicKeyJwk: device.publicJwk,
      deviceName: device.label,
      challenge: challenge.data.challenge,
      proof
    };

    const responses = await Promise.all(
      Array.from({ length: parallelism }, () =>
        rawPost(BASE, "/api/register", { body: registrationBody })
      )
    );
    const successes = responses.filter((response) => response.status === 200);
    assert(successes.length === 1, `expected one 200, got ${successes.length}`);
    assert(successes[0].data.deviceToken, "successful registration has no session");
    for (const response of responses.filter((item) => item.status !== 200)) {
      expectCode(response, "INVALID_REGISTRATION_CHALLENGE");
    }

    const sequentialReplay = await rawPost(BASE, "/api/register", {
      body: registrationBody
    });
    expectCode(sequentialReplay, "INVALID_REGISTRATION_CHALLENGE");
  }

  await check("PoP challenge: 2 parallel registration replays create one session", async () => {
    await runRegistrationReplay(2);
  });

  await check("PoP challenge: 50 parallel registration replays create one session", async () => {
    await runRegistrationReplay(50);
  });

  await check("PoP challenge burns after repeated invalid proofs", async () => {
    const device = makeDevice("PoP-Failures");
    const challenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: device.publicJwk, deviceName: device.label }
    });
    assert(challenge.status === 200, "challenge failed");
    for (let index = 0; index < 5; index += 1) {
      const failed = await request(BASE, "/api/register", {
        body: {
          publicKeyJwk: device.publicJwk,
          deviceName: device.label,
          challenge: challenge.data.challenge,
          proof: "AAAA"
        }
      });
      expectCode(failed, "INVALID_REGISTRATION_PROOF");
    }
    // Even a correct proof cannot reuse a burned challenge.
    const proof = signText(
      device,
      protocol.registrationProofString(
        challenge.data.challenge,
        challenge.data.jkt,
        challenge.data.deviceNameHash
      )
    );
    const afterBurn = await request(BASE, "/api/register", {
      body: {
        publicKeyJwk: device.publicJwk,
        deviceName: device.label,
        challenge: challenge.data.challenge,
        proof
      }
    });
    expectCode(afterBurn, "INVALID_REGISTRATION_CHALLENGE");
  });

  await check("atomic consume: 2 parallel requests, exactly one write", async () => {
    await runConcurrency(2);
  });

  await check("atomic consume: 50 parallel requests, exactly one write", async () => {
    await runConcurrency(50);
  });

  await check("presence: HTTP challenge/verify, wrong code fails, scope/body bound", async () => {
    if (externalServer) {
      console.log("      (skipped on external BASE_URL: cannot read server stdout)");
      return;
    }
    const device = makeDevice("Presence");
    await registerDevice(BASE, device);
    const scope = { mime: "image/png", maxSize: 1024 };
    const body = { reason: "benign approval" };

    const noToken = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope,
      body
    });
    expectCode(noToken, "PRESENCE_REQUIRED");

    const legacy = await request(BASE, "/api/presence", {
      token: device.token,
      body: { challenge: "anything" }
    });
    expectCode(legacy, "PRESENCE_API_CHANGED");

    const challenge = await request(BASE, "/api/presence/challenge", {
      token: device.token,
      body: { action: "changeAvatar", view: "profile", scope, body }
    });
    assert(challenge.status === 200, `challenge failed: ${JSON.stringify(challenge.data)}`);
    assert(!challenge.data.code, "challenge response leaked the code");
    const code = await waitForPresenceCode(challenge.data.challenge);

    const wrongCode = code === "000000" ? "111111" : "000000";
    const wrong = await request(BASE, "/api/presence/verify", {
      token: device.token,
      body: {
        challenge: challenge.data.challenge,
        proof: { kind: "oob", code: wrongCode }
      }
    });
    expectCode(wrong, "PRESENCE_CODE_INVALID");

    const verified = await request(BASE, "/api/presence/verify", {
      token: device.token,
      body: {
        challenge: challenge.data.challenge,
        proof: { kind: "oob", code }
      }
    });
    assert(verified.status === 200, `verify failed: ${JSON.stringify(verified.data)}`);
    assert(verified.data.scopeHash && verified.data.bodyHash, "token is not bound to hashes");
    const presenceToken = verified.data.presenceToken;

    const substitutedScope = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope: { mime: "image/jpeg", maxSize: 104857600 },
      body,
      presenceToken
    });
    expectCode(substitutedScope, "PRESENCE_SCOPE_MISMATCH");

    const substitutedBody = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope,
      body: { reason: "substituted approval text" },
      presenceToken
    });
    expectCode(substitutedBody, "PRESENCE_SCOPE_MISMATCH");

    const issued = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken
    });
    assert(issued.status === 200, `bound issue failed: ${JSON.stringify(issued.data)}`);

    // v2.1: the same approval must also be presented and consumed at action time.
    const withoutActionToken = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "changeAvatar",
      view: "profile",
      scope,
      body
    });
    expectCode(withoutActionToken, "PRESENCE_REQUIRED");

    const otherBody = { reason: "different approved transaction" };
    const otherChallenge = await request(BASE, "/api/presence/challenge", {
      token: device.token,
      body: { action: "changeAvatar", view: "profile", scope, body: otherBody }
    });
    assert(otherChallenge.status === 200, "second challenge failed");
    const otherCode = await waitForPresenceCode(otherChallenge.data.challenge);
    const otherVerified = await request(BASE, "/api/presence/verify", {
      token: device.token,
      body: {
        challenge: otherChallenge.data.challenge,
        proof: { kind: "oob", code: otherCode }
      }
    });
    assert(otherVerified.status === 200, "second verify failed");

    const wrongActionToken = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken: otherVerified.data.presenceToken
    });
    expectCode(wrongActionToken, "PRESENCE_SCOPE_MISMATCH");

    const used = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken
    });
    assert(used.status === 200, `high-risk action failed: ${JSON.stringify(used.data)}`);

    const replayToken = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken
    });
    expectCode(replayToken, "PRESENCE_REQUIRED");

    const replayChallenge = await request(BASE, "/api/presence/verify", {
      token: device.token,
      body: {
        challenge: challenge.data.challenge,
        proof: { kind: "oob", code }
      }
    });
    expectCode(replayChallenge, "PRESENCE_CHALLENGE_INVALID");
  });

  await check("presence provider proof shape: WebAuthn assertion seam", async () => {
    if (externalServer && !process.env.ALLOW_TEST_HOOKS) {
      console.log("      (skipped: fake WebAuthn verifier requires ALLOW_TEST_HOOKS)");
      return;
    }
    const device = makeDevice("WebAuthnSeam");
    await registerDevice(BASE, device);
    const scope = { mime: "image/png", maxSize: 4096 };
    const body = { reason: "webauthn seam" };
    const challenge = await request(BASE, "/api/presence/challenge", {
      token: device.token,
      body: { action: "changeAvatar", view: "profile", scope, body }
    });
    assert(challenge.status === 200, "challenge failed");
    const verified = await request(BASE, "/api/presence/verify", {
      token: device.token,
      body: {
        challenge: challenge.data.challenge,
        proof: {
          kind: "webauthn",
          assertion: {
            type: "test-presence-assertion",
            verified: true,
            challenge: challenge.data.challenge
          }
        }
      }
    });
    assert(verified.status === 200, `assertion seam failed: ${JSON.stringify(verified.data)}`);
    const token = verified.data.presenceToken;
    const issued = await issueCapability(BASE, device.token, {
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken: token
    });
    assert(issued.status === 200, "assertion-bound issue failed");
    const used = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "changeAvatar",
      view: "profile",
      scope,
      body,
      presenceToken: token
    });
    assert(used.status === 200, "assertion-bound action failed");
  });

  await check("rate limit: presence challenge returns 429 after the per-device budget", async () => {
    const device = makeDevice("RateLimit");
    await registerDevice(BASE, device);
    const scope = { mime: "image/png", maxSize: 1024 };
    const body = { reason: "rate limit test" };
    let limited = null;
    for (let index = 0; index < 11; index += 1) {
      const response = await request(BASE, "/api/presence/challenge", {
        token: device.token,
        body: { action: "changeAvatar", view: "profile", scope, body }
      });
      if (response.status === 429) {
        limited = response;
        break;
      }
      assert(response.status === 200, `challenge ${index} failed`);
    }
    assert(limited, "expected a 429 after 10 presence challenges");
    expectCode(limited, "RATE_LIMITED");
  });

  await check("rate limit: /api/state returns 429 after the per-device budget", async () => {
    const device = makeDevice("StateRate");
    await registerDevice(BASE, device);
    let limited = null;
    for (let index = 0; index < 121; index += 1) {
      const response = await request(BASE, "/api/state", {
        method: "GET",
        token: device.token
      });
      if (response.status === 429) {
        limited = response;
        break;
      }
      assert(response.status === 200, `state ${index} failed`);
    }
    assert(limited, "expected a 429 after 120 state reads");
    expectCode(limited, "RATE_LIMITED");
  });

  await check("board ACL: non-member denied and membership continuity", async () => {
    if (externalServer && !process.env.ALLOW_TEST_HOOKS) {
      console.log("      (skipped: board membership hook requires ALLOW_TEST_HOOKS)");
      return;
    }
    const device = makeDevice("BoardACL");
    await registerDevice(BASE, device);

    const badBoard = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope: { boardId: "b_secret_tenant" },
      body: { text: "tenant escape" }
    });
    expectCode(badBoard, "FORBIDDEN");

    const scope = { boardId: "b1" };
    const body = { text: `board continuity ${Date.now()}` };
    const issued = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope,
      body
    });
    assert(issued.status === 200, "pre-removal issue failed");

    const removed = await request(BASE, "/api/test/board-membership", {
      token: device.token,
      body: { boardId: "b1", member: false }
    });
    assert(removed.status === 200, `board membership hook failed: ${JSON.stringify(removed.data)}`);

    const denied = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "createPost",
      view: "home",
      scope,
      body
    });
    expectCode(denied, "FORBIDDEN");

    const reissue = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope,
      body
    });
    expectCode(reissue, "FORBIDDEN");
  });

  await check("chat membership is capability-protected, not ambient", async () => {
    const device = makeDevice("ChatACL");
    await registerDevice(BASE, device);

    const badMention = await issueCapability(BASE, device.token, {
      action: "mention",
      view: "chat",
      scope: { chatId: "c_general", userIds: ["u_nonexistent"] },
      body: { text: "hello ghost" }
    });
    expectCode(badMention, "FORBIDDEN");

    const protoView = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "__proto__",
      scope: { boardId: "b1" },
      body: { text: "prototype lookup" }
    });
    expectCode(protoView, "UNKNOWN_VIEW");

    const scope = { chatId: "c_general" };
    const body = { text: "issued while still a member" };
    const issued = await issueCapability(BASE, device.token, {
      action: "sendMessage",
      view: "chat",
      scope,
      body
    });
    assert(issued.status === 200, "pre-leave issue failed");

    const ambient = await request(BASE, "/api/chat/leave", {
      token: device.token,
      body: {}
    });
    expectCode(ambient, "NOT_FOUND");

    const leaveIssued = await issueCapability(BASE, device.token, {
      action: "chat:leave",
      view: "chat",
      scope,
      body: {}
    });
    assert(leaveIssued.status === 200, "chat:leave issue failed");
    const left = await useCapability(BASE, device.token, device, {
      capability: leaveIssued.data.capability,
      action: "chat:leave",
      view: "chat",
      scope,
      body: {}
    });
    assert(left.status === 200, `chat:leave failed: ${JSON.stringify(left.data)}`);

    const denied = await useCapability(BASE, device.token, device, {
      capability: issued.data.capability,
      action: "sendMessage",
      view: "chat",
      scope,
      body
    });
    expectCode(denied, "FORBIDDEN");

    const reissue = await issueCapability(BASE, device.token, {
      action: "sendMessage",
      view: "chat",
      scope,
      body
    });
    expectCode(reissue, "FORBIDDEN");

    const joinIssued = await issueCapability(BASE, device.token, {
      action: "chat:join",
      view: "chat",
      scope,
      body: {}
    });
    assert(joinIssued.status === 200, "chat:join issue failed");
    const joined = await useCapability(BASE, device.token, device, {
      capability: joinIssued.data.capability,
      action: "chat:join",
      view: "chat",
      scope,
      body: {}
    });
    assert(joined.status === 200, "chat:join failed");

    const allowedAgain = await issueCapability(BASE, device.token, {
      action: "sendMessage",
      view: "chat",
      scope,
      body
    });
    assert(allowedAgain.status === 200, "post-rejoin issue failed");
  });

  await check("JWK canonicalization, PoP and durable revocation", async () => {
    const device = makeDevice("JWK");
    const registered = await registerDevice(BASE, device);
    assert(registered.deviceJkt, "missing canonical JKT");

    const cap = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope: { boardId: "b1" },
      body: { text: "before revocation" }
    });
    assert(cap.status === 200, "pre-revoke issue failed");

    const revoked = await request(BASE, "/api/revoke", {
      token: device.token,
      body: {}
    });
    assert(revoked.status === 200, "revoke failed");

    const denied = await useCapability(BASE, device.token, device, {
      capability: cap.data.capability,
      action: "createPost",
      view: "home",
      scope: { boardId: "b1" },
      body: { text: "before revocation" }
    });
    expectCode(denied, "DEVICE_REVOKED");

    const challenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: device.publicJwk, deviceName: "JWK re-register" }
    });
    assert(challenge.status === 200, "challenge for revoked key failed");
    const pop = signText(
      device,
      protocol.registrationProofString(
        challenge.data.challenge,
        challenge.data.jkt,
        challenge.data.deviceNameHash
      )
    );
    const reRegister = await request(BASE, "/api/register", {
      body: {
        publicKeyJwk: device.publicJwk,
        deviceName: "JWK re-register",
        challenge: challenge.data.challenge,
        proof: pop
      }
    });
    expectCode(reRegister, "DEVICE_REVOKED");

    const padded = {
      ...device.publicJwk,
      x: `${device.publicJwk.x}=`,
      y: `${device.publicJwk.y}=`
    };
    const paddedChallenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: padded, deviceName: "padded" }
    });
    expectCode(paddedChallenge, "INVALID_JWK");

    const whitespace = {
      ...device.publicJwk,
      x: `${device.publicJwk.x} `,
      y: device.publicJwk.y
    };
    const whitespaceChallenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: whitespace, deviceName: "whitespace" }
    });
    expectCode(whitespaceChallenge, "INVALID_JWK");

    const noPop = makeDevice("NoPoP");
    const noPopChallenge = await request(BASE, "/api/register/challenge", {
      body: { publicKeyJwk: noPop.publicJwk, deviceName: "NoPoP" }
    });
    const noPopRegister = await request(BASE, "/api/register", {
      body: {
        publicKeyJwk: noPop.publicJwk,
        deviceName: "NoPoP",
        challenge: noPopChallenge.data.challenge,
        proof: "AAAA"
      }
    });
    expectCode(noPopRegister, "INVALID_REGISTRATION_PROOF");
  });

  await check("audit: 401 anonymous, scoped/redacted for users, full for admin", async () => {
    const a = makeDevice("Audit-A");
    const b = makeDevice("Audit-B");
    await registerDevice(BASE, a);
    await registerDevice(BASE, b);

    const bodyA = { text: `audit-a-${Date.now()}` };
    const bodyB = { text: `audit-b-${Date.now()}` };
    for (const [device, body] of [
      [a, bodyA],
      [b, bodyB]
    ]) {
      const issued = await issueCapability(BASE, device.token, {
        action: "createPost",
        view: "home",
        scope: { boardId: "b1" },
        body
      });
      assert(issued.status === 200, "audit fixture issue failed");
      const used = await useCapability(BASE, device.token, device, {
        capability: issued.data.capability,
        action: "createPost",
        view: "home",
        scope: { boardId: "b1" },
        body
      });
      assert(used.status === 200, "audit fixture action failed");
    }

    const anonymous = await request(BASE, "/api/audit", { method: "GET" });
    expectCode(anonymous, "UNAUTHENTICATED");

    const aAudit = await request(BASE, "/api/audit?limit=500", {
      method: "GET",
      token: a.token
    });
    assert(aAudit.status === 200, "A audit failed");
    assert(
      aAudit.data.events.every((event) => event.userId !== b.userId),
      "A saw B's user events"
    );
    assert(
      aAudit.data.events.some((event) => typeof event.capId === "string" && event.capId.includes("...")),
      "non-admin capId was not redacted"
    );
    for (const event of aAudit.data.events) {
      for (const field of ["scopeHash", "bodyHash"]) {
        assert(
          event[field] === null || !/^[0-9a-f]{64}$/.test(event[field]),
          `non-admin ${field} was not redacted`
        );
      }
    }

    const wrongAdmin = await request(BASE, "/api/audit?limit=10", {
      method: "GET",
      token: a.token,
      headers: { "x-admin-token": "wrong-admin-token" }
    });
    assert(wrongAdmin.status === 200, "wrong admin token request failed");
    assert(wrongAdmin.data.admin === false, "wrong admin token gained admin");

    const hashA = protocol.sha256HexSync(bodyA);
    const adminAudit = await adminRequest("/api/audit?limit=500", {
      method: "GET",
      token: a.token
    });
    assert(adminAudit.status === 200, "admin audit failed");
    assert(adminAudit.data.admin === true, "admin flag missing");
    assert(
      adminAudit.data.events.some((event) => event.deviceId === b.deviceId),
      "admin could not see B events"
    );
    const consumedA = adminAudit.data.events.find(
      (event) => event.type === "consumed" && event.bodyHash === hashA
    );
    assert(consumedA, "admin consumed event missing");
    assert(consumedA.scopeHash && consumedA.resultId, "consumed event lacks binding fields");
    assert(consumedA.outcome === "success", "consumed outcome missing");
  });

  await check("proof bindings: body/view/proof/capability tamper and expiry", async () => {
    const device = makeDevice("Tamper");
    await registerDevice(BASE, device);
    const scope = { boardId: "b1" };
    const body = { text: `tamper-${Date.now()}` };
    const issued = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope,
      body
    });
    assert(issued.status === 200, "issue failed");
    const capability = issued.data.capability;
    const proof = signProof(device, capability, "createPost", scope, body);

    const wrongBody = await useCapability(BASE, device.token, device, {
      capability,
      action: "createPost",
      view: "home",
      scope,
      body: { text: "substituted body" }
    });
    expectCode(wrongBody, "BODY_MISMATCH");

    const flipped = `${proof.slice(0, -1)}${proof.endsWith("A") ? "B" : "A"}`;
    const badProof = await request(BASE, "/api/action", {
      token: device.token,
      body: { capability, proof: flipped, action: "createPost", view: "home", scope, body }
    });
    expectCode(badProof, "INVALID_PROOF");

    const tamperedCapability = {
      payload: { ...capability.payload, scope: { boardId: "b2" } },
      sig: capability.sig
    };
    const tampered = await request(BASE, "/api/action", {
      token: device.token,
      body: {
        capability: tamperedCapability,
        proof,
        action: "createPost",
        view: "home",
        scope: { boardId: "b2" },
        body
      }
    });
    expectCode(tampered, "INVALID_CAPABILITY");

    const wrongView = await useCapability(BASE, device.token, device, {
      capability,
      action: "createPost",
      view: "profile",
      scope,
      body
    });
    expectCode(wrongView, "ACTION_NOT_ALLOWED_IN_VIEW");

    const correct = await useCapability(BASE, device.token, device, {
      capability,
      action: "createPost",
      view: "home",
      scope,
      body
    });
    assert(correct.status === 200, "correct use after failed attempts did not succeed");

    const shortLived = await issueCapability(
      BASE,
      device.token,
      {
        action: "createPost",
        view: "home",
        scope: { boardId: "b1" },
        body: { text: "expires quickly" }
      },
      { headers: { "x-test-ttl-ms": "60" } }
    );
    assert(shortLived.status === 200, "short-lived issue failed");
    await sleep(120);
    const expired = await useCapability(BASE, device.token, device, {
      capability: shortLived.data.capability,
      action: "createPost",
      view: "home",
      scope: { boardId: "b1" },
      body: { text: "expires quickly" }
    });
    expectCode(expired, "CAPABILITY_EXPIRED");

    const malformed = await request(BASE, "/api/action", {
      token: device.token,
      body: {
        capability: { payload: { capId: "cap_missing" }, sig: "x" },
        proof: "AA",
        action: "createPost",
        view: "home",
        scope,
        body
      }
    });
    expectCode(malformed, "INVALID_CAPABILITY");
  });

  await check("policy validation rejects ttl/maxUses/dangerous-key mistakes", async () => {
    const missingTtl = structuredClone(basePolicy);
    delete missingTtl.actions.createPost.ttlSeconds;
    assertThrows(() => serverPolicy.validatePolicy(missingTtl), "missing ttl");

    const multiUse = structuredClone(basePolicy);
    multiUse.actions.createPost.maxUses = 2;
    assertThrows(() => serverPolicy.validatePolicy(multiUse), "maxUses 2");

    const dangerous = JSON.parse(JSON.stringify(basePolicy));
    dangerous.actions.createPost.scope = JSON.parse('{"__proto__":"BoardId"}');
    assertThrows(() => serverPolicy.validatePolicy(dangerous), "dangerous key");

    const cycle = structuredClone(basePolicy);
    cycle.actions["post:submit"].next = "post:edit";
    cycle.actions["post:edit"].parent = "post:submit";
    assertThrows(() => serverPolicy.validatePolicy(cycle), "sequence cycle");

    serverPolicy.validatePolicy(basePolicy);
  });

  await check("revocation during in-flight action blocks the commit", async () => {
    const device = makeDevice("InFlight");
    await registerDevice(BASE, device);
    const scope = { boardId: "b1" };
    const body = { text: `inflight-${Date.now()}` };
    const issued = await issueCapability(BASE, device.token, {
      action: "createPost",
      view: "home",
      scope,
      body
    });
    assert(issued.status === 200, "issue failed");
    const proof = signProof(device, issued.data.capability, "createPost", scope, body);
    const pending = rawPost(BASE, "/api/action", {
      token: device.token,
      body: {
        capability: issued.data.capability,
        proof,
        action: "createPost",
        view: "home",
        scope,
        body
      },
      headers: { "x-test-verify-delay": "1" }
    });

    await sleep(80);
    const revoked = await request(BASE, "/api/revoke", {
      token: device.token,
      body: {}
    });
    assert(revoked.status === 200, "revoke failed");
    const result = await pending;
    expectCode(result, "DEVICE_REVOKED");

    const observer = makeDevice("Observer");
    await registerDevice(BASE, observer);
    const state = await request(BASE, "/api/state", { method: "GET", token: observer.token });
    assert(state.status === 200, "observer state failed");
    assert(
      !state.data.feed.some((post) => post.text === body.text),
      "revoked in-flight action still wrote"
    );
  });

  await check("two-step flow binds draft hash; unused expired child can be reissued", async () => {
    const device = makeDevice("Sequence");
    await registerDevice(BASE, device);
    const editBody = { text: `sequence-${Date.now()}` };
    const editIssued = await issueCapability(BASE, device.token, {
      action: "post:edit",
      view: "home",
      scope: { boardId: "b1" },
      body: editBody
    });
    assert(editIssued.status === 200, "edit issue failed");
    const edited = await useCapability(BASE, device.token, device, {
      capability: editIssued.data.capability,
      action: "post:edit",
      view: "home",
      scope: { boardId: "b1" },
      body: editBody
    });
    assert(edited.status === 200, "edit failed");
    const draft = edited.data.result.draft;
    const sequence = edited.data.sequence;

    const wrongDraft = await issueCapability(BASE, device.token, {
      action: "post:submit",
      view: "home",
      scope: { boardId: "b1", draftId: draft.draftId, draftHash: "0".repeat(64) },
      body: {},
      parentCap: sequence.parentCap,
      prevHash: sequence.prevHash
    });
    expectCode(wrongDraft, "DRAFT_HASH_MISMATCH");

    const shortChild = await issueCapability(
      BASE,
      device.token,
      {
        action: "post:submit",
        view: "home",
        scope: sequence.nextScope,
        body: {},
        parentCap: sequence.parentCap,
        prevHash: sequence.prevHash
      },
      { headers: { "x-test-ttl-ms": "60" } }
    );
    assert(shortChild.status === 200, "short child issue failed");
    await sleep(120);

    const childIssued = await issueCapability(BASE, device.token, {
      action: "post:submit",
      view: "home",
      scope: sequence.nextScope,
      body: {},
      parentCap: sequence.parentCap,
      prevHash: sequence.prevHash
    });
    assert(childIssued.status === 200, "reissue after unused child expiry failed");
    const child = childIssued.data.capability;

    const substituted = await useCapability(BASE, device.token, device, {
      capability: child,
      action: "post:submit",
      view: "home",
      scope: { ...sequence.nextScope, draftHash: "f".repeat(64) },
      body: {}
    });
    expectCode(substituted, "SCOPE_DENIED");

    const submitted = await useCapability(BASE, device.token, device, {
      capability: child,
      action: "post:submit",
      view: "home",
      scope: sequence.nextScope,
      body: {}
    });
    assert(submitted.status === 200, `submit failed: ${JSON.stringify(submitted.data)}`);

    const parentReuse = await issueCapability(BASE, device.token, {
      action: "post:submit",
      view: "home",
      scope: sequence.nextScope,
      body: {},
      parentCap: sequence.parentCap,
      prevHash: sequence.prevHash
    });
    expectCode(parentReuse, "CAPABILITY_CONSUMED");
  });

  await check("draft content is re-hashed at submit use", async () => {
    if (externalServer && !process.env.ALLOW_TEST_HOOKS) {
      console.log("      (skipped: draft mutation hook requires ALLOW_TEST_HOOKS)");
      return;
    }
    const device = makeDevice("DraftMutation");
    await registerDevice(BASE, device);
    const originalText = `draft-original-${Date.now()}`;
    const mutatedText = `draft-mutated-${Date.now()}`;
    const editIssued = await issueCapability(BASE, device.token, {
      action: "post:edit",
      view: "home",
      scope: { boardId: "b1" },
      body: { text: originalText }
    });
    assert(editIssued.status === 200, "edit issue failed");
    const edited = await useCapability(BASE, device.token, device, {
      capability: editIssued.data.capability,
      action: "post:edit",
      view: "home",
      scope: { boardId: "b1" },
      body: { text: originalText }
    });
    assert(edited.status === 200, "edit failed");
    const draft = edited.data.result.draft;
    const sequence = edited.data.sequence;

    const childIssued = await issueCapability(BASE, device.token, {
      action: "post:submit",
      view: "home",
      scope: sequence.nextScope,
      body: {},
      parentCap: sequence.parentCap,
      prevHash: sequence.prevHash
    });
    assert(childIssued.status === 200, "child issue failed");

    const mutated = await request(BASE, "/api/test/mutate-draft", {
      token: device.token,
      body: { draftId: draft.draftId, text: mutatedText }
    });
    assert(mutated.status === 200, `draft mutation failed: ${JSON.stringify(mutated.data)}`);

    const denied = await useCapability(BASE, device.token, device, {
      capability: childIssued.data.capability,
      action: "post:submit",
      view: "home",
      scope: sequence.nextScope,
      body: {}
    });
    expectCode(denied, "DRAFT_HASH_MISMATCH");

    const state = await request(BASE, "/api/state", { method: "GET", token: device.token });
    assert(state.status === 200, "state failed");
    assert(
      !state.data.feed.some(
        (post) => post.text === originalText || post.text === mutatedText
      ),
      "a mutated draft was published"
    );
  });
  await check("demo gating: DEMO=0 does not serve demo-hooks.js", async () => {
    const demoChild = spawn(process.execPath, ["server.js"], {
      cwd: ROOT,
      env: {
        ...process.env,
        PORT: "0",
        HOST: "127.0.0.1",
        DEMO: "0"
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let demoBase = null;
    let demoBuffer = "";
    demoChild.stdout.setEncoding("utf8");
    demoChild.stdout.on("data", (chunk) => {
      demoBuffer += chunk;
      const lines = demoBuffer.split("\n");
      demoBuffer = lines.pop() || "";
      for (const line of lines) {
        const match = line.match(/listening on http:\/\/127\.0\.0\.1:(\d+)/);
        if (match) demoBase = `http://127.0.0.1:${match[1]}`;
      }
    });
    try {
      assert(await waitFor(() => demoBase, 5000), "DEMO=0 server did not start");
      const health = await request(demoBase, "/api/health", { method: "GET" });
      assert(health.status === 200, "DEMO=0 health failed");
      assert(health.data.demo === false, "DEMO=0 health reports demo");
      const hooks = await fetch(`${demoBase}/demo-hooks.js`);
      assert(hooks.status === 404, "DEMO=0 served demo-hooks.js");
    } finally {
      demoChild.kill("SIGTERM");
    }
  });
} catch (error) {
  failed += 1;
  console.error("FATAL", error.stack || error);
} finally {
  if (child) child.kill("SIGTERM");
}

console.log("");
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
