/*
 * Shared protocol helpers for browser, Node server and tests.
 *
 * UMD: sets window.SECRECY_PROTOCOL in the browser; module.exports in Node.
 * This module deliberately contains no secrets and no environment-specific
 * policy. Hash helpers use WebCrypto asynchronously in the browser. Node also
 * gets a synchronous SHA-256 helper for the atomic commit block.
 */
(function (root, factory) {
  const protocol = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = protocol;
  } else {
    root.SECRECY_PROTOCOL = protocol;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const dangerousKeys = new Set(["__proto__", "prototype", "constructor"]);
  const encoder = new TextEncoder();

  let nodeCrypto = null;
  if (typeof require === "function") {
    try {
      nodeCrypto = require("node:crypto");
    } catch {
      // Browser or a bundler without require.
    }
  }

  function protocolError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }

  function assertSafeKey(key) {
    if (dangerousKeys.has(key)) {
      throw protocolError("DANGEROUS_KEY", `Forbidden object key: ${key}`);
    }
  }

  function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  /**
   * JSON-safe canonicalization with sorted object keys and null prototypes.
   * Dangerous keys and non-JSON values are rejected rather than dropped.
   */
  function canonicalize(value) {
    if (value === null) return null;
    const type = typeof value;
    if (type === "string" || type === "boolean") return value;
    if (type === "number") {
      if (!Number.isFinite(value)) {
        throw protocolError("NON_FINITE_NUMBER", "Only finite numbers are allowed");
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(canonicalize);
    if (type === "object") {
      if (!isPlainObject(value)) {
        throw protocolError("NON_PLAIN_OBJECT", "Only plain JSON objects are allowed");
      }
      const output = Object.create(null);
      for (const key of Object.keys(value).sort()) {
        assertSafeKey(key);
        output[key] = canonicalize(value[key]);
      }
      return output;
    }
    throw protocolError("NON_JSON_VALUE", `Unsupported value type: ${type}`);
  }

  function stableStringify(value) {
    return JSON.stringify(canonicalize(value));
  }

  function hex(bytes) {
    return [...new Uint8Array(bytes)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  async function sha256Hex(value) {
    const input = typeof value === "string" ? value : stableStringify(value);
    const subtle = globalThis.crypto?.subtle || nodeCrypto?.webcrypto?.subtle;
    if (!subtle) throw new Error("WebCrypto SHA-256 is unavailable");
    return hex(await subtle.digest("SHA-256", encoder.encode(input)));
  }

  // Node-only helper for synchronous critical sections. Never used in browsers.
  function sha256HexSync(value) {
    if (!nodeCrypto) throw new Error("sha256HexSync is only available in Node");
    const input = typeof value === "string" ? value : stableStringify(value);
    return nodeCrypto.createHash("sha256").update(input).digest("hex");
  }

  function b64urlEncode(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /**
   * Strict unpadded base64url. Rejects whitespace, padding, bad length and
   * non-canonical encodings (the function round-trips the result).
   */
  function b64urlDecodeStrict(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw protocolError("INVALID_BASE64URL", "Invalid unpadded base64url");
    }
    if (value.length % 4 === 1) {
      throw protocolError("INVALID_BASE64URL", "Invalid base64url length");
    }
    const padded =
      value.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (value.length % 4)) % 4);
    let binary;
    try {
      binary = atob(padded);
    } catch {
      throw protocolError("INVALID_BASE64URL", "Invalid base64url");
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    if (b64urlEncode(bytes) !== value) {
      throw protocolError("INVALID_BASE64URL", "Non-canonical base64url");
    }
    return bytes;
  }

  function proofString(payload, action, scopeHash, bodyHash) {
    return [
      "secrecy:v2",
      "POST",
      "/api/action",
      payload.capId,
      action,
      payload.view,
      payload.deviceJkt,
      scopeHash,
      bodyHash,
      String(payload.seq),
      payload.nonce,
      payload.prevHash || ""
    ].join("|");
  }

  function registrationProofString(challenge, jkt, deviceNameHash) {
    return ["register:v2", challenge, jkt, deviceNameHash].join("|");
  }

  return {
    dangerousKeys,
    assertSafeKey,
    isPlainObject,
    canonicalize,
    stableStringify,
    sha256Hex,
    sha256HexSync,
    b64urlEncode,
    b64urlDecodeStrict,
    proofString,
    registrationProofString
  };
});
