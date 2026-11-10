/*
 * Presence-provider interface.
 *
 * In v2 the browser obtains an out-of-band six-digit code from a separate channel
 * (here: the server console) and exchanges it for a presence token bound to
 * device + action + view + scopeHash + bodyHash.
 *
 * This is a real server-side check in the sense that a caller that cannot read
 * the channel cannot mint the token. It is still not WebAuthn user verification:
 * same-page XSS can read the code after the user types it, and a compromised
 * server console defeats it. See DESIGN.md.
 *
 * Production should implement WebAuthnPresenceProvider with navigator.credentials
 * .get({ publicKey: { userVerification: "required", ... } }) and verify the
 * assertion server-side (challenge, origin, rpIdHash, UP, UV, signature, counter).
 */
(function (global) {
  "use strict";

  class PresenceProvider {
    // Return either:
    //   { code: "123456" }                       // demo OOB provider
    //   { assertion: PublicKeyCredentialJSON }   // production WebAuthn provider
    // A plain string is accepted as a demo code for convenience.
    // eslint-disable-next-line no-unused-vars
    async requestPresence(request) {
      const error = new Error("No presence provider is configured");
      error.code = "PRESENCE_PROVIDER_MISSING";
      throw error;
    }
  }

  class WebAuthnPresenceProvider extends PresenceProvider {
    constructor(options = {}) {
      super();
      this.options = options;
    }

    async requestPresence(request) {
      // This is an intentionally explicit stub so the seam is visible.
      // A production provider would:
      //   1. call navigator.credentials.get() with a SHA-256 challenge;
      //   2. require userVerification: "required";
      //   3. return a WebAuthn assertion for server-side verification.
      const error = new Error(
        "WebAuthnPresenceProvider is a stub. Implement server-side WebAuthn UV " +
          "verification before relying on presence as a security control."
      );
      error.code = "PRESENCE_PROVIDER_UNAVAILABLE";
      error.request = request;
      throw error;
    }
  }

  class StaticCodePresenceProvider extends PresenceProvider {
    // Useful for local experiments where a trusted out-of-band code is supplied.
    constructor(code) {
      super();
      this.code = String(code || "");
    }

    async requestPresence() {
      return this.code;
    }
  }

  global.PresenceProvider = PresenceProvider;
  global.WebAuthnPresenceProvider = WebAuthnPresenceProvider;
  global.StaticCodePresenceProvider = StaticCodePresenceProvider;
})(typeof globalThis !== "undefined" ? globalThis : window);
