#!/usr/bin/env node
/*
 * Sequential end-to-end smoke test for Secrecy v2.
 *
 * Run the server first:
 *   node server.js
 * Then:
 *   node test/smoke.mjs
 */

import {
  expectCode,
  issueCapability,
  makeDevice,
  registerDevice,
  request,
  useCapability
} from "./helpers.mjs";

const BASE = (process.env.BASE_URL || "http://127.0.0.1:8787").replace(/\/+$/, "");
let passed = 0;
let failed = 0;

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

try {
  const health = await request(BASE, "/api/health", { method: "GET" });
  assert(health.status === 200, `health returned ${health.status}`);
} catch (error) {
  console.error(`Server is not reachable at ${BASE}.`);
  console.error("Start it with: node server.js");
  console.error(`Detail: ${error.message}`);
  process.exit(1);
}

const alice = makeDevice("Smoke A");
const bob = makeDevice("Smoke B");
const ctx = {};

await check("register devices with proof-of-possession and canonical JKT", async () => {
  const a = await registerDevice(BASE, alice);
  const b = await registerDevice(BASE, bob);
  assert(a.deviceJkt && a.deviceJkt.length > 20, "missing deviceJkt");
  assert(b.deviceJkt && b.deviceJkt.length > 20, "missing deviceJkt for B");
  assert(a.deviceId !== b.deviceId, "devices must differ");
});

await check("createPost: issue, execute, then CAPABILITY_CONSUMED", async () => {
  const scope = { boardId: "b1" };
  const body = { text: "hello from v2 smoke" };
  const issued = await issueCapability(BASE, alice.token, {
    action: "createPost",
    view: "home",
    scope,
    body
  });
  assert(issued.status === 200, `issue failed: ${JSON.stringify(issued.data)}`);
  ctx.createCap = issued.data.capability;
  assert(ctx.createCap.payload.deviceJkt === alice.deviceJkt, "capability missing deviceJkt");

  const used = await useCapability(BASE, alice.token, alice, {
    capability: ctx.createCap,
    action: "createPost",
    view: "home",
    scope,
    body
  });
  assert(used.status === 200, `action failed: ${JSON.stringify(used.data)}`);
  assert(used.data.result.post.text === body.text, "post text mismatch");
  assert(used.data.receipt, "missing receipt");

  const reused = await useCapability(BASE, alice.token, alice, {
    capability: ctx.createCap,
    action: "createPost",
    view: "home",
    scope,
    body
  });
  expectCode(reused, "CAPABILITY_CONSUMED");
});

await check("scope/body binding rejects board and body substitution", async () => {
  const issued = await issueCapability(BASE, alice.token, {
    action: "createPost",
    view: "home",
    scope: { boardId: "b1" },
    body: { text: "scope source" }
  });
  assert(issued.status === 200, "issue failed");
  const wrongScope = await useCapability(BASE, alice.token, alice, {
    capability: issued.data.capability,
    action: "createPost",
    view: "home",
    scope: { boardId: "b2" },
    body: { text: "scope source" }
  });
  expectCode(wrongScope, "SCOPE_DENIED");

  const wrongBody = await useCapability(BASE, alice.token, alice, {
    capability: issued.data.capability,
    action: "createPost",
    view: "home",
    scope: { boardId: "b1" },
    body: { text: "substituted body" }
  });
  expectCode(wrongBody, "BODY_MISMATCH");
});

await check("view/action binding rejects cross-action use", async () => {
  const issued = await issueCapability(BASE, alice.token, {
    action: "createPost",
    view: "home",
    scope: { boardId: "b1" },
    body: { text: "cross action" }
  });
  assert(issued.status === 200, "issue failed");
  const denied = await useCapability(BASE, alice.token, alice, {
    capability: issued.data.capability,
    action: "changeAvatar",
    view: "home",
    scope: { mime: "image/png", maxSize: 1048576 },
    body: { reason: "nope" }
  });
  expectCode(denied, "ACTION_NOT_ALLOWED_IN_VIEW");

  const issueDenied = await issueCapability(BASE, alice.token, {
    action: "changeAvatar",
    view: "home",
    scope: { mime: "image/png", maxSize: 1048576 },
    body: { reason: "nope" }
  });
  expectCode(issueDenied, "ACTION_NOT_ALLOWED_IN_VIEW");
});

await check("device binding and valid message/mention flows", async () => {
  const scope = { chatId: "c_general" };
  const body = { text: "legitimate A message" };
  const issued = await issueCapability(BASE, alice.token, {
    action: "sendMessage",
    view: "chat",
    scope,
    body
  });
  assert(issued.status === 200, "issue failed");

  const stolen = await useCapability(BASE, bob.token, bob, {
    capability: issued.data.capability,
    action: "sendMessage",
    view: "chat",
    scope,
    body
  });
  expectCode(stolen, "DEVICE_MISMATCH");

  const used = await useCapability(BASE, alice.token, alice, {
    capability: issued.data.capability,
    action: "sendMessage",
    view: "chat",
    scope,
    body
  });
  assert(used.status === 200, `sendMessage failed: ${JSON.stringify(used.data)}`);

  const mentionScope = { chatId: "c_general", userIds: ["u_bob", "u_alice"] };
  const mentionBody = { text: "hello @Alice @Bob" };
  const mentionIssued = await issueCapability(BASE, alice.token, {
    action: "mention",
    view: "chat",
    scope: mentionScope,
    body: mentionBody
  });
  assert(mentionIssued.status === 200, "mention issue failed");
  const mentionUsed = await useCapability(BASE, alice.token, alice, {
    capability: mentionIssued.data.capability,
    action: "mention",
    view: "chat",
    scope: mentionScope,
    body: mentionBody
  });
  assert(mentionUsed.status === 200, "mention failed");
  assert(mentionUsed.data.result.message.mentions.length === 2, "mentions missing");
});

await check("server-side scope authorization rejects unknown board/mention", async () => {
  const badBoard = await issueCapability(BASE, alice.token, {
    action: "createPost",
    view: "home",
    scope: { boardId: "b_secret_tenant" },
    body: { text: "tenant escape" }
  });
  expectCode(badBoard, "FORBIDDEN");

  const badMention = await issueCapability(BASE, alice.token, {
    action: "mention",
    view: "chat",
    scope: { chatId: "c_general", userIds: ["u_nonexistent"] },
    body: { text: "hello ghost" }
  });
  expectCode(badMention, "FORBIDDEN");
});

await check("presence: challenge/verify is a separate channel (wrong code fails)", async () => {
  const scope = { mime: "image/png", maxSize: 1048576 };
  const body = { reason: "smoke presence" };
  const noToken = await issueCapability(BASE, alice.token, {
    action: "changeAvatar",
    view: "profile",
    scope,
    body
  });
  expectCode(noToken, "PRESENCE_REQUIRED");

  const challenge = await request(BASE, "/api/presence/challenge", {
    token: alice.token,
    body: { action: "changeAvatar", view: "profile", scope, body }
  });
  assert(challenge.status === 200, `challenge failed: ${JSON.stringify(challenge.data)}`);
  assert(challenge.data.challenge, "missing challenge");
  assert(!challenge.data.code, "code must never be returned over HTTP");

  const wrong = await request(BASE, "/api/presence/verify", {
    token: alice.token,
    body: { challenge: challenge.data.challenge, code: "abc" }
  });
  expectCode(wrong, "PRESENCE_CODE_INVALID");

  const oldEndpoint = await request(BASE, "/api/presence", {
    token: alice.token,
    body: { challenge: challenge.data.challenge }
  });
  expectCode(oldEndpoint, "PRESENCE_API_CHANGED");
});

await check("two-step post binds draft hash and parent/child one-use", async () => {
  const editScope = { boardId: "b2" };
  const editBody = { text: "two-step v2 post" };
  const editIssued = await issueCapability(BASE, alice.token, {
    action: "post:edit",
    view: "home",
    scope: editScope,
    body: editBody
  });
  assert(editIssued.status === 200, "edit issue failed");
  const edited = await useCapability(BASE, alice.token, alice, {
    capability: editIssued.data.capability,
    action: "post:edit",
    view: "home",
    scope: editScope,
    body: editBody
  });
  assert(edited.status === 200, `edit failed: ${JSON.stringify(edited.data)}`);
  const draft = edited.data.result.draft;
  const sequence = edited.data.sequence;
  assert(draft?.draftId && draft.draftHash, "missing draft binding");
  assert(sequence?.nextScope?.draftHash === draft.draftHash, "nextScope missing draft hash");

  const wrongHash = await issueCapability(BASE, alice.token, {
    action: "post:submit",
    view: "home",
    scope: { boardId: "b2", draftId: draft.draftId, draftHash: "0".repeat(64) },
    body: {},
    parentCap: sequence.parentCap,
    prevHash: sequence.prevHash
  });
  expectCode(wrongHash, "DRAFT_HASH_MISMATCH");

  const submitScope = sequence.nextScope;
  const submitIssued = await issueCapability(BASE, alice.token, {
    action: "post:submit",
    view: "home",
    scope: submitScope,
    body: {},
    parentCap: sequence.parentCap,
    prevHash: sequence.prevHash
  });
  assert(submitIssued.status === 200, `submit issue failed: ${JSON.stringify(submitIssued.data)}`);
  const submitCap = submitIssued.data.capability;

  const substituted = await useCapability(BASE, alice.token, alice, {
    capability: submitCap,
    action: "post:submit",
    view: "home",
    scope: { ...submitScope, draftHash: "f".repeat(64) },
    body: {}
  });
  expectCode(substituted, "SCOPE_DENIED");

  const submitted = await useCapability(BASE, alice.token, alice, {
    capability: submitCap,
    action: "post:submit",
    view: "home",
    scope: submitScope,
    body: {}
  });
  assert(submitted.status === 200, `submit failed: ${JSON.stringify(submitted.data)}`);
  assert(submitted.data.result.post.text === editBody.text, "submitted text mismatch");

  const parentReuse = await issueCapability(BASE, alice.token, {
    action: "post:submit",
    view: "home",
    scope: submitScope,
    body: {},
    parentCap: sequence.parentCap,
    prevHash: sequence.prevHash
  });
  expectCode(parentReuse, "CAPABILITY_CONSUMED");

  const childReuse = await useCapability(BASE, alice.token, alice, {
    capability: submitCap,
    action: "post:submit",
    view: "home",
    scope: submitScope,
    body: {}
  });
  expectCode(childReuse, "CAPABILITY_CONSUMED");
});

await check("authenticated audit is scoped to the caller", async () => {
  const response = await request(BASE, "/api/audit?limit=200", {
    method: "GET",
    token: alice.token
  });
  assert(response.status === 200, `audit failed: ${JSON.stringify(response.data)}`);
  const events = response.data.events;
  assert(Array.isArray(events) && events.length > 0, "audit empty");
  assert(events.every((event) => event.deviceId !== bob.deviceId), "A saw B events");
  assert(events.some((event) => event.type === "issued"), "missing issued event");
  assert(events.some((event) => event.type === "consumed"), "missing consumed event");
  assert(events.some((event) => event.type === "denied"), "missing denied event");
});

await check("revocation invalidates existing and future capabilities", async () => {
  const issued = await issueCapability(BASE, alice.token, {
    action: "createPost",
    view: "home",
    scope: { boardId: "b1" },
    body: { text: "after revocation" }
  });
  assert(issued.status === 200, "pre-revocation issue failed");

  const revoked = await request(BASE, "/api/revoke", {
    token: alice.token,
    body: {}
  });
  assert(revoked.status === 200, `revoke failed: ${JSON.stringify(revoked.data)}`);
  assert(revoked.data.revokedCapabilities >= 1, "nothing revoked");

  const denied = await useCapability(BASE, alice.token, alice, {
    capability: issued.data.capability,
    action: "createPost",
    view: "home",
    scope: { boardId: "b1" },
    body: { text: "after revocation" }
  });
  expectCode(denied, "DEVICE_REVOKED");
});

await check("state requires auth and resyncs scoped data", async () => {
  const anonymous = await request(BASE, "/api/state", { method: "GET" });
  expectCode(anonymous, "UNAUTHENTICATED");
  const invalid = await request(BASE, "/api/state", {
    method: "GET",
    token: "sess_not_a_real_token"
  });
  expectCode(invalid, "UNAUTHENTICATED");
  const response = await request(BASE, "/api/state", {
    method: "GET",
    token: bob.token
  });
  assert(response.status === 200, `state failed: ${JSON.stringify(response.data)}`);
  assert(response.data.me?.device?.deviceId === bob.deviceId, "wrong device in state");
  assert(
    response.data.feed.some((post) => post.text === "two-step v2 post"),
    "two-step post missing"
  );
  assert(Array.isArray(response.data.drafts), "drafts missing");
});

console.log("");
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
