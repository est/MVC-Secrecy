"use strict";

/*
 * Secrecy v2 client: execute(action, {scope, body}) owns registration PoP,
 * capability issuance, presence orchestration and device proofs. Demo hooks
 * are a signing oracle and exist only when demoHooks:true.
 */

(function (global) {
  const protocol = global.SECRECY_PROTOCOL;
  if (!protocol) throw new Error("protocol.js must load before secrecy.js");
  const encoder = new TextEncoder();

  class SecrecyError extends Error {
    constructor(code, message, extra = {}) {
      super(message);
      this.name = "SecrecyError";
      this.code = code;
      this.status = extra.status || 0;
      this.source = extra.source || "client";
      this.retryable = Boolean(extra.retryable);
      this.details = extra.details || extra;
      this.extra = extra;
    }
  }

  function openDatabase(name) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("device")) db.createObjectStore("device");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("IndexedDB open failed"));
    });
  }

  async function idb(name, mode, key, value) {
    const db = await openDatabase(name);
    try {
      return await new Promise((resolve, reject) => {
        const store = db.transaction("device", mode === "get" ? "readonly" : "readwrite")
          .objectStore("device");
        const request =
          mode === "put"
            ? store.put(value, key)
            : mode === "delete"
              ? store.delete(key)
              : store.get(key);
        request.onsuccess = () => resolve(mode === "get" ? request.result || null : true);
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
  }

  async function generateDeviceKey() {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    return {
      privateKey: pair.privateKey,
      publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey)
    };
  }

  class Secrecy {
    constructor({
      api = "/api",
      policy,
      deviceName = "Demo browser",
      dbName = "secrecy-mvc-demo",
      demoHooks = false,
      presenceProvider = null
    } = {}) {
      if (!policy) throw new Error("Secrecy requires a policy manifest");
      this.api = String(api).replace(/\/+$/, "");
      this.policy = policy;
      this.deviceName = deviceName;
      this.dbName = dbName;
      this.demoHooks = Boolean(demoHooks);
      this.presenceProvider = presenceProvider;
      this.currentView = null;
      this.ready = false;
      this.device = null;
      this.user = null;
      this.lastReceipt = null;
      this._privateKey = null;
      this._initPromise = null;
      this._listeners = new Map();
      this._links = {};
      this._lastUse = null;
      this.demo = this.demoHooks && global.DemoHooks ? new global.DemoHooks(this) : null;
    }

    on(event, handler) {
      if (!this._listeners.has(event)) this._listeners.set(event, new Set());
      this._listeners.get(event).add(handler);
      return () => this._listeners.get(event)?.delete(handler);
    }

    _emit(event, value) {
      for (const handler of [...(this._listeners.get(event) || [])]) {
        try {
          handler(value);
        } catch (error) {
          console.error(`Secrecy listener for ${event} failed`, error);
        }
      }
    }

    enterView(view) {
      this._assertView(view);
      this.currentView = view;
      this._emit("view", view);
    }

    actions(viewName = this.currentView) {
      if (!viewName || !Object.hasOwn(this.policy.views, viewName)) return [];
      return [...(this.policy.views[viewName].actions || [])];
    }

    can(action, viewName = this.currentView) {
      return Boolean(viewName && this.actions(viewName).includes(action));
    }

    /**
     * A handle for a view without mutating global UI context. Useful for
     * componentised UIs and concurrent flows.
     */
    view(viewName) {
      this._assertView(viewName);
      const self = this;
      return {
        name: viewName,
        execute: (action, request, options = {}) =>
          self.execute(action, request, { ...options, view: viewName }),
        can: (action) => self.can(action, viewName),
        actions: () => self.actions(viewName)
      };
    }

    async init() {
      if (this.ready) return this.me();
      if (this._initPromise) return this._initPromise;

      this._initPromise = (async () => {
        const material = await this._loadOrCreateDeviceKey();
        this._privateKey = material.privateKey;
        const deviceName = String(this.deviceName || "Unnamed browser").trim().slice(0, 80) || "Unnamed browser";

        const challengeResponse = await this._request("/register/challenge", {
          auth: false,
          body: { publicKeyJwk: material.publicJwk, deviceName }
        });
        const signed = protocol.registrationProofString(
          challengeResponse.challenge,
          challengeResponse.jkt,
          challengeResponse.deviceNameHash
        );
        const proof = await this._signText(signed);

        const registered = await this._request("/register", {
          auth: false,
          body: {
            publicKeyJwk: material.publicJwk,
            deviceName,
            challenge: challengeResponse.challenge,
            proof
          }
        });
        this.device = {
          userId: registered.userId,
          deviceId: registered.deviceId,
          deviceJkt: registered.deviceJkt,
          deviceToken: registered.deviceToken,
          deviceName
        };
        this.user = registered.user;
        this.ready = true;
        this._emit("ready", this.me());
        return this.me();
      })();

      try {
        return await this._initPromise;
      } catch (error) {
        this._initPromise = null;
        this._emit("error", error);
        throw error;
      }
    }

    me() {
      const { user, device } = this;
      return {
        user,
        device: device
          ? {
              deviceId: device.deviceId,
              userId: device.userId,
              deviceJkt: device.deviceJkt,
              deviceName: device.deviceName
            }
          : null
      };
    }

    async reconnect() {
      this.ready = false;
      this.device = null;
      this.user = null;
      this._initPromise = null;
      return this.init();
    }

    async execute(action, request = {}, options = {}) {
      try {
        return await this._execute(action, request, options);
      } catch (error) {
        this._emit("error", error);
        throw error;
      }
    }

    async _execute(action, request, options) {
      if (!this.ready) throw new SecrecyError("NOT_READY", "Call secrecy.init() first");
      const config = this.policy.actions[action];
      if (!config) throw new SecrecyError("UNKNOWN_ACTION", `Unknown action: ${action}`);
      const viewName = options.view || this.currentView;
      if (!this.can(action, viewName)) {
        throw new SecrecyError(
          "ACTION_NOT_ALLOWED_IN_VIEW",
          `Action ${action} is not allowed in view ${viewName}`
        );
      }

      const { scope, body } = this._normalizeRequest(action, config, request);
      const scopeHash = await protocol.sha256Hex(scope);
      const bodyHash = await protocol.sha256Hex(body);
      let presenceToken;

      if (config.presence) {
        const provider = options.presence || this.presenceProvider;
        if (!provider || typeof provider.requestPresence !== "function") {
          throw new SecrecyError(
            "PRESENCE_PROVIDER_MISSING",
            "This action requires a PresenceProvider"
          );
        }
        const challenge = await this._request("/presence/challenge", {
          body: { action, view: viewName, scope, body }
        });
        const provided = await provider.requestPresence({
          action,
          view: viewName,
          scope,
          body,
          scopeHash: challenge.scopeHash || scopeHash,
          bodyHash: challenge.bodyHash || bodyHash,
          challenge: challenge.challenge,
          exp: challenge.exp
        });
        let proof;
        if (typeof provided === "string") {
          proof = { kind: "oob", code: provided.trim() };
        } else if (provided?.code) {
          proof = { kind: "oob", code: String(provided.code).trim() };
        } else if (provided?.assertion) {
          proof = { kind: "webauthn", assertion: provided.assertion };
        } else {
          throw new SecrecyError("PRESENCE_CANCELLED", "Presence was not provided");
        }
        const verified = await this._request("/presence/verify", {
          body: { challenge: challenge.challenge, proof }
        });
        presenceToken = verified.presenceToken;
      }

      const issueBody = { action, view: viewName, scope, body };
      if (presenceToken) issueBody.presenceToken = presenceToken;
      if (config.parent && this._links[action]) {
        issueBody.parentCap = this._links[action].parentCap;
        issueBody.prevHash = this._links[action].prevHash;
      }

      const issued = await this._request("/capabilities", { body: issueBody });
      const capability = issued.capability;
      const proof = await this._prove(capability, action, scope, body);
      const actionRequest = { capability, proof, action, view: viewName, scope, body };
      if (presenceToken) actionRequest.presenceToken = presenceToken;
      const response = await this._request("/action", { body: actionRequest });

      this.lastReceipt = response.receipt || null;
      this._lastUse = {
        capability,
        proof,
        action,
        view: viewName,
        scope,
        body,
        consumed: true,
        at: Date.now()
      };
      if (config.parent) delete this._links[action];
      if (response.sequence?.nextAction) {
        this._links[response.sequence.nextAction] = {
          parentCap: response.sequence.parentCap,
          prevHash: response.sequence.prevHash,
          nextScope: response.sequence.nextScope || null
        };
      }
      return response.result;
    }

    getState() {
      return this._request("/state", { method: "GET" });
    }

    getAudit(limit = 100) {
      return this._request(`/audit?limit=${encodeURIComponent(limit)}`, { method: "GET" });
    }

    async revokeDevice() {
      const result = await this._request("/revoke", { body: {} });
      this._emit("revoked", result);
      return result;
    }

    async resetDevice() {
      try {
        await idb(this.dbName, "delete", "device");
      } catch {
        // Best effort.
      }
      this.ready = false;
      this.device = null;
      this.user = null;
      this._privateKey = null;
      this._initPromise = null;
      this._links = {};
      this._lastUse = null;
      this._emit("reset", null);
    }

    _assertView(viewName) {
      if (!viewName || !Object.hasOwn(this.policy.views, viewName)) {
        throw new SecrecyError("UNKNOWN_VIEW", `Unknown view: ${viewName}`);
      }
    }

    _normalizeRequest(action, config, request) {
      if (!protocol.isPlainObject(request)) {
        throw new SecrecyError("INVALID_REQUEST", "execute request must be an object");
      }
      const explicit = Object.hasOwn(request, "scope") || Object.hasOwn(request, "body");
      const scope = explicit ? request.scope || {} : {};
      const body = explicit ? request.body || {} : {};
      if (!explicit) {
        // Backwards compatibility with execute(action, params).
        for (const key of Object.keys(config.scope)) {
          if (!Object.hasOwn(request, key)) {
            throw new SecrecyError("SCOPE_DENIED", `Missing scope field ${key}`);
          }
          scope[key] = request[key];
        }
        for (const key of Object.keys(config.body)) {
          if (!Object.hasOwn(request, key)) {
            throw new SecrecyError("INVALID_BODY", `Missing body field ${key}`);
          }
          body[key] = request[key];
        }
      }
      if (!protocol.isPlainObject(scope) || !protocol.isPlainObject(body)) {
        throw new SecrecyError("INVALID_REQUEST", "scope and body must be plain objects");
      }
      const expectedScope = Object.keys(config.scope).sort();
      const actualScope = Object.keys(scope).sort();
      if (expectedScope.join("|") !== actualScope.join("|")) {
        throw new SecrecyError("SCOPE_DENIED", `scope must contain exactly ${expectedScope.join(", ")}`);
      }
      const expectedBody = Object.keys(config.body).sort();
      const actualBody = Object.keys(body).sort();
      if (expectedBody.join("|") !== actualBody.join("|")) {
        throw new SecrecyError("INVALID_BODY", `body must contain exactly ${expectedBody.join(", ") || "(none)"}`);
      }
      if (Array.isArray(scope.userIds)) {
        scope.userIds = [...new Set(scope.userIds)].sort();
      }
      return { scope: { ...scope }, body: { ...body } };
    }

    async _prove(capability, action, scope, body) {
      const scopeHash = await protocol.sha256Hex(scope);
      const bodyHash = await protocol.sha256Hex(body);
      const text = protocol.proofString(capability.payload, action, scopeHash, bodyHash);
      return this._signText(text);
    }

    async _signText(text) {
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        this._privateKey,
        encoder.encode(text)
      );
      return protocol.b64urlEncode(new Uint8Array(signature));
    }

    async _loadOrCreateDeviceKey() {
      try {
        const stored = await idb(this.dbName, "get", "device");
        if (stored?.privateKey && stored.publicJwk && stored.privateKey.extractable === false) {
          return stored;
        }
      } catch (error) {
        this._emit("warning", { code: "INDEXEDDB_UNAVAILABLE", message: error.message });
      }
      const material = await generateDeviceKey();
      try {
        await idb(this.dbName, "put", "device", material);
      } catch (error) {
        this._emit("warning", { code: "DEVICE_KEY_NOT_PERSISTED", message: error.message });
      }
      return material;
    }

    async _request(path, { method = "POST", body, auth = true } = {}) {
      const headers = {};
      if (body !== undefined) headers["content-type"] = "application/json";
      if (auth && this.device?.deviceToken) headers["x-device-token"] = this.device.deviceToken;
      let response;
      try {
        response = await fetch(this.api + path, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body)
        });
      } catch (cause) {
        throw new SecrecyError("NETWORK_ERROR", "Server is unreachable", {
          source: "client",
          retryable: true,
          cause
        });
      }
      let data = null;
      try {
        data = await response.json();
      } catch {
        // Reported below.
      }
      if (!response.ok) {
        const details = data?.error || {};
        throw new SecrecyError(
          details.code || `HTTP_${response.status}`,
          details.message || `Request failed with ${response.status}`,
          {
            ...details,
            status: response.status,
            source: "server",
            retryable: response.status === 429 || response.status >= 500,
            details
          }
        );
      }
      return data;
    }

  }

  global.Secrecy = Secrecy;
  global.SecrecyError = SecrecyError;
})(typeof globalThis !== "undefined" ? globalThis : window);
