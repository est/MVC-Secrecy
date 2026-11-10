import crypto from "node:crypto";
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export const protocol = require("../public/protocol.js");

export function makeDevice(label) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  return {
    label,
    privateKey,
    publicJwk: publicKey.export({ format: "jwk" })
  };
}

export function signText(device, text) {
  return crypto
    .sign("sha256", Buffer.from(text), {
      key: device.privateKey,
      dsaEncoding: "ieee-p1363"
    })
    .toString("base64url");
}

export function normalizeScope(scope) {
  const normalized = { ...scope };
  if (Array.isArray(normalized.userIds)) {
    normalized.userIds = [...new Set(normalized.userIds)].sort();
  }
  return normalized;
}

export function signProof(device, capability, action, scope, body) {
  const scopeHash = protocol.sha256HexSync(normalizeScope(scope));
  const bodyHash = protocol.sha256HexSync(body);
  const text = protocol.proofString(capability.payload, action, scopeHash, bodyHash);
  return signText(device, text);
}

export async function request(base, path, { method = "POST", token, body, headers = {} } = {}) {
  const finalHeaders = { ...headers };
  if (token) finalHeaders["x-device-token"] = token;
  if (body !== undefined) finalHeaders["content-type"] = "application/json";

  let response;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers: finalHeaders,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch (error) {
    throw new Error(
      `Cannot reach ${base}${path}. Start the server with "node server.js". (${error.message})`
    );
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    // Non-JSON error.
  }
  return { status: response.status, data };
}

export async function registerDevice(base, device, deviceName = device.label) {
  const challenge = await request(base, "/api/register/challenge", {
    body: { publicKeyJwk: device.publicJwk, deviceName }
  });
  if (challenge.status !== 200) {
    throw new Error(`register challenge failed: ${JSON.stringify(challenge.data)}`);
  }
  const text = protocol.registrationProofString(
    challenge.data.challenge,
    challenge.data.jkt,
    challenge.data.deviceNameHash
  );
  const proof = signText(device, text);
  const registered = await request(base, "/api/register", {
    body: {
      publicKeyJwk: device.publicJwk,
      deviceName,
      challenge: challenge.data.challenge,
      proof
    }
  });
  if (registered.status !== 200) {
    throw new Error(`register failed: ${JSON.stringify(registered.data)}`);
  }
  device.userId = registered.data.userId;
  device.deviceId = registered.data.deviceId;
  device.deviceJkt = registered.data.deviceJkt;
  device.token = registered.data.deviceToken;
  return registered.data;
}

export async function issueCapability(base, token, fields, { headers = {} } = {}) {
  return request(base, "/api/capabilities", { token, headers, body: fields });
}

export async function useCapability(base, token, device, fields) {
  const { capability, action, view, scope, body, presenceToken, headers = {} } = fields;
  const proof = signProof(device, capability, action, scope, body);
  const actionBody = { capability, proof, action, view, scope, body };
  if (presenceToken) actionBody.presenceToken = presenceToken;
  return request(base, "/api/action", { token, headers, body: actionBody });
}

export function expectCode(response, code) {
  const actual = response.data?.error?.code;
  if (response.status < 400) {
    throw new Error(`expected error ${code}, got ${response.status}`);
  }
  if (actual !== code) {
    throw new Error(
      `expected ${code}, got ${actual || "no code"} (${JSON.stringify(response.data)})`
    );
  }
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function rawPost(base, path, { token, body, headers = {} } = {}) {
  const url = new URL(base);
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: url.hostname,
        port: url.port,
        path,
        method: "POST",
        agent: false,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...(token ? { "x-device-token": token } : {}),
          ...headers
        }
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let data = null;
          try {
            data = JSON.parse(text);
          } catch {
            // Leave null.
          }
          resolve({ status: res.statusCode, data });
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

export async function waitFor(predicate, timeoutMs = 3000, intervalMs = 20) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await sleep(intervalMs);
  }
  return null;
}
