/*
 * Demo-only attack surface for the XSS lab. It is instantiated only when the
 * Secrecy client is created with demoHooks:true (the app enables that only for
 * ?demo=1). It exposes a signing oracle and raw capability helpers; never ship
 * this code enabled in production.
 */
(function (global) {
  "use strict";

  class DemoHooks {
    constructor(secrecy) {
      this.secrecy = secrecy;
    }

    issue(action, request, viewName = this.secrecy.currentView) {
      return this._issue(action, request, viewName);
    }

    sign(capability, action, request) {
      return this._sign(capability, action, request);
    }

    call(capability, proof, action, request, viewName) {
      return this._call(capability, proof, action, request, viewName);
    }

    tryIssue(action, request, viewName) {
      return this._tryIssue(action, request, viewName);
    }

    tryPresenceBypass(action, request, viewName) {
      return this._tryPresenceBypass(action, request, viewName);
    }

    lastUse() {
      return this.secrecy._lastUse;
    }

    async _issue(action, request, viewName) {
      const config = this.secrecy.policy.actions[action];
      if (!config) throw new Error(`Unknown action: ${action}`);
      const { scope, body } = this.secrecy._normalizeRequest(action, config, request);
      const response = await this.secrecy._request("/capabilities", {
        body: { action, view: viewName, scope, body }
      });
      return response.capability;
    }

    async _sign(capability, action, request) {
      const config = this.secrecy.policy.actions[action];
      if (!config) throw new Error(`Unknown action: ${action}`);
      const { scope, body } = this.secrecy._normalizeRequest(action, config, request);
      return this.secrecy._prove(capability, action, scope, body);
    }

    async _call(capability, proof, action, request, viewName) {
      const config = this.secrecy.policy.actions[action];
      if (!config) throw new Error(`Unknown action: ${action}`);
      const { scope, body } = this.secrecy._normalizeRequest(action, config, request);
      try {
        return {
          ok: true,
          status: 200,
          data: await this.secrecy._request("/action", {
            body: { capability, proof, action, view: viewName, scope, body }
          })
        };
      } catch (error) {
        return { ok: false, status: error.status, code: error.code, data: error.details };
      }
    }

    async _tryIssue(action, request, viewName) {
      const config = this.secrecy.policy.actions[action];
      if (!config) throw new Error(`Unknown action: ${action}`);
      const { scope, body } = this.secrecy._normalizeRequest(action, config, request);
      try {
        return {
          ok: true,
          status: 200,
          data: await this.secrecy._request("/capabilities", {
            body: { action, view: viewName, scope, body }
          })
        };
      } catch (error) {
        return { ok: false, status: error.status, code: error.code, data: error.details };
      }
    }

    async _tryPresenceBypass(action, request, viewName) {
      const config = this.secrecy.policy.actions[action];
      if (!config) throw new Error(`Unknown action: ${action}`);
      const { scope, body } = this.secrecy._normalizeRequest(action, config, request);
      try {
        const challenge = await this.secrecy._request("/presence/challenge", {
          body: { action, view: viewName, scope, body }
        });
        await this.secrecy._request("/presence/verify", {
          body: {
            challenge: challenge.challenge,
            proof: { kind: "oob", code: "00000" } // invalid length, never matches
          }
        });
        return { ok: true, status: 200, code: "UNEXPECTED_PRESENCE_SUCCESS" };
      } catch (error) {
        return { ok: false, status: error.status, code: error.code, data: error.details };
      }
    }
  }

  global.DemoHooks = DemoHooks;
})(typeof globalThis !== "undefined" ? globalThis : window);
