"use strict";

/*
 * Minimal static MVC client.
 *
 * Model: `state` (a small projection of GET /api/state) plus the server as the
 * authoritative model. Views are pure-ish HTML render functions. Controllers
 * are the event handlers below; importantly, they only call secrecy.execute()
 * and never see capability tokens, proofs or cryptographic keys.
 */

(function () {
  const policy = window.SECRECY_POLICY;
  const protocol = window.SECRECY_PROTOCOL;
  if (!policy || !window.Secrecy || !protocol || !window.PresenceProvider) {
    document.getElementById("app").textContent =
      "Failed to load protocol.js, policy.js, presence.js or secrecy.js";
    return;
  }

  const demoMode =
    new URLSearchParams(location.search).get("demo") === "1" &&
    Boolean(window.DemoHooks);

  class ModalCodePresenceProvider extends window.PresenceProvider {
    async requestPresence(request) {
      return showPresenceCodeModal(request);
    }
  }

  const secrecy = new Secrecy({
    api: "/api",
    policy,
    deviceName: "Secrecy demo browser",
    demoHooks: demoMode,
    presenceProvider: new ModalCodePresenceProvider()
  });

  // The signing-oracle demo hook and global handle exist only in ?demo=1 mode.
  if (demoMode) window.secrecy = secrecy;

  const state = {
    view: "login",
    data: null,
    lastError: null,
    audit: [],
    xssLog: [],
    xssRunning: false,
    xssFinished: false
  };

  // -----------------------------------------------------------------------
  // Tiny DOM / formatting helpers
  // -----------------------------------------------------------------------

  const $ = (selector) => document.querySelector(selector);

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function short(value, length = 10) {
    const text = String(value || "");
    return text.length > length ? `${text.slice(0, length)}…` : text;
  }

  function timeOf(value) {
    try {
      return new Date(value).toLocaleTimeString();
    } catch {
      return String(value);
    }
  }

  function toast(message, kind = "info") {
    const root = $("#toast");
    if (!root) return;
    const item = document.createElement("div");
    item.className = `toast toast-${kind}`;
    item.textContent = message;
    root.appendChild(item);
    setTimeout(() => item.remove(), 6000);
  }

  function showError(error) {
    const code = error?.code || "ERROR";
    const message = error?.message || String(error);
    toast(`${code}: ${message}`, "error");
    console.warn("[secrecy]", error);
  }

  function bind(id, event, handler) {
    const element = document.getElementById(id);
    if (element) element.addEventListener(event, handler);
  }

  async function runButton(button, task) {
    if (!button || button.disabled) return;
    const original = button.textContent;
    button.disabled = true;
    button.textContent = "Working…";
    try {
      await task();
    } finally {
      if (button.isConnected) {
        button.disabled = false;
        button.textContent = original;
      }
    }
  }

  function userById(userId) {
    return state.data?.users?.find((user) => user.userId === userId) || null;
  }

  function userName(userId) {
    return userById(userId)?.name || short(userId, 12);
  }

  function currentMe() {
    return state.data?.me || secrecy.me();
  }

  // -----------------------------------------------------------------------
  // Router
  // -----------------------------------------------------------------------

  const VIEWS = ["login", "home", "chat", "profile"];

  function navigate(view) {
    if (location.hash === `#/${view}`) {
      render();
    } else {
      location.hash = `#/${view}`;
    }
  }

  function route() {
    const requested = (location.hash.replace(/^#\/?/, "") || "login").trim();
    const view = VIEWS.includes(requested) ? requested : "login";
    state.view = view;

    if (view !== "login" && !secrecy.ready) {
      location.hash = "#/login";
      return;
    }

    try {
      secrecy.enterView(view);
    } catch (error) {
      console.warn(error);
    }

    render();

    if (view !== "login" && secrecy.ready) {
      refreshState({ rerender: false });
    }
  }

  // -----------------------------------------------------------------------
  // Model sync
  // -----------------------------------------------------------------------

  async function refreshState({ rerender = true } = {}) {
    if (!secrecy.ready) return null;
    const viewAtStart = state.view;
    try {
      state.data = await secrecy.getState();
      if (rerender && state.view === viewAtStart) render();
      return state.data;
    } catch (error) {
      if (error.code === "UNAUTHENTICATED") {
        state.lastError = error.code;
        toast("Server session expired — sign in again", "warn");
        state.data = null;
        navigate("login");
      } else {
        showError(error);
      }
      return null;
    }
  }

  // -----------------------------------------------------------------------
  // Views
  // -----------------------------------------------------------------------

  function loginView() {
    const me = secrecy.me();
    const ready = secrecy.ready && me.device;
    const revoked = state.lastError === "DEVICE_REVOKED";

    return `
      <section class="view login-view">
        <div class="hero">
          <p class="eyebrow">MVC + S</p>
          <h1>Capabilities, not ambient authority</h1>
          <p class="lede">
            This browser holds a non-extractable ECDSA P-256 device key. The server
            issues short-lived, one-use capabilities bound to that device, an action
            and its scope. Business code just calls <code>secrecy.execute()</code>.
          </p>
        </div>

        <div class="grid two">
          <article class="card">
            <h2>1. Register this browser</h2>
            <p class="muted">
              A private key is generated with <code>extractable: false</code> and
              persisted as a <code>CryptoKey</code> in IndexedDB. Only the public JWK
              is sent to the server.
            </p>
            ${
              ready
                ? `
                  <div class="device-box">
                    <div><span class="label">User</span> <code>${esc(me.user?.userId)}</code></div>
                    <div><span class="label">Device</span> <code>${esc(me.device.deviceId)}</code></div>
                    <div><span class="label">Thumbprint</span> <code>${esc(short(me.device.deviceJkt, 22))}</code></div>
                  </div>
                  <div class="actions">
                    <button id="continue-btn" class="primary">Continue to home</button>
                    <button id="reset-device" class="ghost">Forget local key</button>
                  </div>
                `
                : `
                  <button id="login-btn" class="primary">Generate / load device key</button>
                  ${
                    revoked
                      ? `<p class="error-text">This device key was revoked. Generate a fresh device key to continue.</p>
                         <button id="reset-device" class="ghost">Forget revoked key</button>`
                      : ""
                  }
                `
            }
          </article>

          <article class="card">
            <h2>What is enforced</h2>
            <ul class="checklist">
              <li>One action per capability</li>
              <li>Exact scope match on every use</li>
              <li>Single use, server-side consumption</li>
              <li>Device-bound proof signature</li>
              <li>Server-side ACL authorization at issue and use</li>
              <li>Out-of-band presence channel for high-risk actions</li>
              <li>Authenticated audit + device revocation</li>
            </ul>
            <p class="hint">
              Presence here is a demo out-of-band console code, not WebAuthn user
              verification. Same-page XSS can steal the code after you type it.
              See <code>DESIGN.md</code>.
            </p>
          </article>
        </div>
      </section>
    `;
  }

  function homeView() {
    const data = state.data;
    const me = currentMe();
    const feed = [...(data?.feed || [])].reverse();
    const drafts = data?.drafts || [];
    const draft = drafts[drafts.length - 1] || null;
    const revoked = Boolean(me?.device?.revokedAt);

    return `
      <section class="view">
        <div class="view-head">
          <div>
            <p class="eyebrow">Home</p>
            <h1>Feed and write paths</h1>
          </div>
          <div class="device-chip" title="${esc(me?.device?.deviceId || "")}">
            device ${esc(short(me?.device?.deviceId, 14))}
            ${revoked ? '<span class="badge danger">revoked</span>' : '<span class="badge ok">active</span>'}
          </div>
        </div>

        ${revoked ? `<div class="banner danger">This device is revoked. All capabilities fail with <code>DEVICE_REVOKED</code>. <button id="reset-device" class="link-button">Rotate device key</button></div>` : ""}

        <div class="grid main-grid">
          <div class="stack">
            <article class="card">
              <div class="card-head">
                <h2>Feed</h2>
                <div class="card-actions">
                  <button id="open-chat" class="ghost small">Open chat</button>
                  <button id="refresh-state" class="ghost small">Refresh</button>
                </div>
              </div>
              <div class="feed">
                ${
                  feed.length
                    ? feed
                        .map(
                          (post) => `
                            <article class="post">
                              <div class="post-meta">
                                <strong>${esc(userName(post.userId))}</strong>
                                <span>${esc(post.boardId)}</span>
                                <span>${esc(timeOf(post.createdAt))}</span>
                              </div>
                              <p>${esc(post.text)}</p>
                              <div class="post-foot">via ${esc(short(post.viaCap || "seed", 18))}</div>
                            </article>
                          `
                        )
                        .join("")
                    : `<p class="muted">No posts yet.</p>`
                }
              </div>
            </article>

            <article class="card">
              <h2>Create post <span class="badge">createPost</span></h2>
              <p class="muted">Controller calls <code>secrecy.execute("createPost", …)</code>. A fresh one-use capability is issued automatically.</p>
              <form id="create-post-form" class="form">
                <label>Board
                  <select name="boardId">
                    <option value="b1">b1 — general</option>
                    <option value="b2">b2 — random</option>
                  </select>
                </label>
                <label>Text
                  <textarea name="text" rows="3" maxlength="2000" required placeholder="Say something that will be signed into the proof body hash…"></textarea>
                </label>
                <button class="primary" type="submit">Create post</button>
              </form>
            </article>

            <article class="card">
              <h2>Two-step post <span class="badge">post:edit → post:submit</span></h2>
              <p class="muted">
                The edit step issues a root capability. Its consumed state and
                <code>prevHash</code> authorize exactly one linked submit capability.
              </p>
              ${
                draft
                  ? `
                    <div class="draft">
                      <div class="post-meta"><strong>Draft</strong><span>${esc(draft.boardId)}</span><span>${esc(timeOf(draft.createdAt))}</span></div>
                      <p>${esc(draft.text)}</p>
                      <p class="post-foot">draftHash ${esc(short(draft.draftHash, 22))}</p>
                      <button id="publish-draft" class="primary"
                        data-board="${esc(draft.boardId)}"
                        data-draft-id="${esc(draft.draftId)}"
                        data-draft-hash="${esc(draft.draftHash)}">Execute post:submit</button>
                      <p class="hint">The submit capability is bound to the draft ID and exact text hash. Reloading loses the in-memory sequence link, so a new edit step is needed.</p>
                    </div>
                  `
                  : `
                    <form id="draft-form" class="form compact">
                      <label>Board
                        <select name="boardId"><option value="b1">b1</option><option value="b2">b2</option></select>
                      </label>
                      <label>Draft text
                        <textarea name="text" rows="2" maxlength="2000" required></textarea>
                      </label>
                      <button class="primary" type="submit">Save edit step</button>
                    </form>
                  `
              }
            </article>
          </div>

          <aside class="stack">
            ${
              demoMode
                ? `
                  <article class="card" id="xss-card">
                    <div class="card-head">
                      <h2>XSS simulation</h2>
                      <span class="badge warn">?demo=1 only</span>
                    </div>
                    <p class="muted">
                      Injects a script tag. The script uses the deliberately exposed demo
                      handle to try cross-action use, replay, direct presence bypass and
                      one legitimate use. Results are shown below.
                    </p>
                    <button id="simulate-xss" class="danger" ${state.xssRunning ? "disabled" : ""}>
                      ${state.xssRunning ? "Attack running…" : "Simulate XSS"}
                    </button>
                    <div id="xss-log" class="log">${xssLogHtml()}</div>
                    ${state.xssFinished ? `<p class="hint">Audit and revocation are in the security panel below.</p>` : ""}
                  </article>
                `
                : `<article class="card"><h2>Demo hooks disabled</h2><p class="muted">The lab requires server <code>DEMO=1</code> plus <code>?demo=1</code>. The gate hides the instance/global; it is not a security boundary.</p></article>`
            }

            <article class="card" id="security-card">
              <h2>Security controls</h2>
              <div class="kv"><span>User</span><code>${esc(me?.user?.userId)}</code></div>
              <div class="kv"><span>Device</span><code>${esc(me?.device?.deviceId)}</code></div>
              <div class="kv"><span>Key thumbprint</span><code>${esc(short(me?.device?.deviceJkt, 26))}</code></div>
              <div class="actions wrap">
                <button id="refresh-audit" class="ghost">Refresh audit</button>
                ${
                  revoked
                    ? `<button id="reset-device" class="primary">Rotate device key</button>`
                    : `<button id="revoke-device" class="danger">Revoke this device</button>`
                }
              </div>
              <p class="hint">Revocation is one-way for this key. Rotation creates a new device identity.</p>
            </article>

            <article class="card">
              <div class="card-head">
                <h2>Audit log</h2>
                <span class="muted small">newest first</span>
              </div>
              <div id="audit-list" class="audit-list">Loading…</div>
            </article>
          </aside>
        </div>
      </section>
    `;
  }

  function chatView() {
    const data = state.data;
    const me = currentMe();
    const messages = data?.messages || [];
    const others = (data?.users || []).filter(
      (user) => user.userId !== me?.user?.userId
    );

    return `
      <section class="view">
        <div class="view-head">
          <div><p class="eyebrow">Chat</p><h1>c_general</h1></div>
          <div class="device-chip">device ${esc(short(me?.device?.deviceId, 14))}</div>
        </div>

        <div class="grid main-grid">
          <article class="card">
            <div class="card-head">
              <h2>Messages</h2>
              <button id="refresh-state" class="ghost small">Refresh</button>
            </div>
            <div class="messages">
              ${
                messages.length
                  ? messages
                      .map(
                        (message) => `
                          <div class="message">
                            <div class="post-meta">
                              <strong>${esc(userName(message.userId))}</strong>
                              <span>${esc(timeOf(message.createdAt))}</span>
                            </div>
                            <p>${esc(message.text)}</p>
                            ${
                              message.mentions?.length
                                ? `<div class="mentions">${message.mentions
                                    .map((id) => `<span class="mention">@${esc(userName(id))}</span>`)
                                    .join("")}</div>`
                                : ""
                            }
                            <div class="post-foot">via ${esc(short(message.viaCap || "seed", 18))}</div>
                          </div>
                        `
                      )
                      .join("")
                  : `<p class="muted">No messages yet.</p>`
              }
            </div>
          </article>

          <aside class="stack">
            <article class="card">
              <h2>Send message</h2>
              <p class="muted">
                No mentions uses <code>sendMessage</code>. Selecting users uses the
                medium-risk <code>mention</code> capability with
                <code>{ chatId, userIds }</code> scope.
              </p>
              <form id="chat-form" class="form">
                <label>Message
                  <textarea name="text" rows="3" maxlength="2000" required></textarea>
                </label>
                <fieldset class="mentions-picker">
                  <legend>Mention users (optional)</legend>
                  ${
                    others.length
                      ? others
                          .map(
                            (user) => `
                              <label class="check">
                                <input type="checkbox" name="mention" value="${esc(user.userId)}">
                                ${esc(user.name)}
                              </label>
                            `
                          )
                          .join("")
                      : `<span class="muted">No other users.</span>`
                  }
                </fieldset>
                <button class="primary" type="submit">Send</button>
              </form>
            </article>

            <article class="card">
              <h2>Why two actions?</h2>
              <p class="muted">
                <code>sendMessage</code> is scoped only to the chat. A mention can
                notify more users, so it has a different, broader scope and a medium
                risk label. A chat capability cannot silently become a mention.
              </p>
            </article>
          </aside>
        </div>
      </section>
    `;
  }

  function profileView() {
    const me = currentMe();
    const avatar = me?.user?.avatar;
    const revoked = Boolean(me?.device?.revokedAt);

    return `
      <section class="view">
        <div class="view-head">
          <div><p class="eyebrow">Profile</p><h1>High-risk action</h1></div>
          <div class="device-chip">device ${esc(short(me?.device?.deviceId, 14))}</div>
        </div>

        <div class="grid two">
          <article class="card profile-card">
            <div class="avatar-large">${esc((me?.user?.name || "?").slice(0, 1).toUpperCase())}</div>
            <h2>${esc(me?.user?.name || "Unknown")}</h2>
            <p class="muted"><code>${esc(me?.user?.userId)}</code></p>
            ${
              avatar
                ? `<p class="pill">Avatar metadata: ${esc(avatar.mime)} · max ${esc(avatar.maxSize)} bytes</p>`
                : `<p class="muted">No avatar set.</p>`
            }
            <p class="hint">
              This demo stores avatar metadata only (MIME + size limit). The
              capability is high risk and requires out-of-band confirmation.
            </p>
          </article>

          <article class="card">
            <h2>Change avatar <span class="badge high">high risk</span></h2>
            <p class="muted">
              The server prints a six-digit code to the terminal. Enter it into the
              modal: the code is exchanged for a single-use presence token bound to
              this device, action, view, scope hash and body hash.
            </p>
            <form id="avatar-form" class="form">
              <label>MIME type
                <select name="mime">
                  <option value="image/png">image/png</option>
                  <option value="image/jpeg">image/jpeg</option>
                </select>
              </label>
              <label>Max size (bytes)
                <input name="maxSize" type="number" min="1" max="104857600" value="1048576" required>
              </label>
              <label>Reason recorded in the signed body
                <input name="reason" type="text" maxlength="200" value="Profile avatar update" required>
              </label>
              <button class="primary" type="submit" ${revoked ? "disabled" : ""}>Request OOB code &amp; change</button>
            </form>
            <pre class="code-note">scope = { mime, maxSize }
body  = { reason }
risk  = high
channel = server console (demo OOB)</pre>
          </article>
        </div>
      </section>
    `;
  }

  const views = {
    login: loginView,
    home: homeView,
    chat: chatView,
    profile: profileView
  };

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  function render() {
    const app = document.getElementById("app");
    app.innerHTML = views[state.view]();

    for (const link of document.querySelectorAll("[data-nav]")) {
      link.classList.toggle("active", link.dataset.nav === state.view);
    }

    const after = afterRender[state.view];
    if (after) after();
  }

  // -----------------------------------------------------------------------
  // Login controller
  // -----------------------------------------------------------------------

  async function login() {
    state.lastError = null;
    try {
      const me = await secrecy.init();
      state.data = await secrecy.getState();
      toast(`Device ${short(me.device.deviceId, 16)} registered`, "ok");
      navigate("home");
    } catch (error) {
      state.lastError = error.code || "ERROR";
      showError(error);
      render();
    }
  }

  async function continueSession() {
    try {
      await secrecy.reconnect();
      state.data = await secrecy.getState();
      state.lastError = null;
      navigate("home");
    } catch (error) {
      state.lastError = error.code || "ERROR";
      showError(error);
      render();
    }
  }

  async function resetLocalDevice() {
    if (
      !confirm(
        "Forget the local device key? This does not revoke server-side capabilities; " +
          "revoke the device first if it is compromised. A new identity will be created."
      )
    ) {
      return;
    }
    await secrecy.resetDevice();
    state.data = null;
    state.lastError = null;
    state.xssLog = [];
    state.xssFinished = false;
    toast("Local device key forgotten", "info");
    navigate("login");
  }

  // -----------------------------------------------------------------------
  // Home / post controllers
  // -----------------------------------------------------------------------

  async function createPost(form, button) {
    const boardId = form.elements.boardId.value;
    const text = form.elements.text.value;

    await runButton(button, async () => {
      try {
        await secrecy.execute("createPost", {
          scope: { boardId },
          body: { text }
        });
        form.reset();
        toast("Post created with server-authorized one-use capability", "ok");
        await refreshState();
        await refreshAuditPanel();
      } catch (error) {
        showError(error);
      }
    });
  }

  async function saveDraft(form, button) {
    const boardId = form.elements.boardId.value;
    const text = form.elements.text.value;

    await runButton(button, async () => {
      try {
        await secrecy.execute("post:edit", {
          scope: { boardId },
          body: { text }
        });
        toast("Edit step consumed; submit must bind the same draft hash", "ok");
        await refreshState();
        await refreshAuditPanel();
      } catch (error) {
        showError(error);
      }
    });
  }

  async function publishDraft(button) {
    const boardId = button.dataset.board;
    const draftId = button.dataset.draftId;
    const draftHash = button.dataset.draftHash;

    await runButton(button, async () => {
      try {
        await secrecy.execute("post:submit", {
          scope: { boardId, draftId, draftHash },
          body: {}
        });
        toast("Two-step post submitted; draft hash matched", "ok");
        await refreshState();
        await refreshAuditPanel();
      } catch (error) {
        showError(error);
      }
    });
  }

  // -----------------------------------------------------------------------
  // Chat controller
  // -----------------------------------------------------------------------

  async function sendMessage(form, button) {
    const text = form.elements.text.value;
    const mentions = [
      ...form.querySelectorAll('input[name="mention"]:checked')
    ].map((input) => input.value);
    const action = mentions.length > 0 ? "mention" : "sendMessage";
    const scope =
      mentions.length > 0
        ? { chatId: "c_general", userIds: mentions }
        : { chatId: "c_general" };

    await runButton(button, async () => {
      try {
        await secrecy.execute(action, { scope, body: { text } });
        form.reset();
        toast(`${action} sent`, "ok");
        await refreshState();
        await refreshAuditPanel();
      } catch (error) {
        showError(error);
      }
    });
  }

  // -----------------------------------------------------------------------
  // Profile / presence controller
  // -----------------------------------------------------------------------

  async function changeAvatar(form, button) {
    const scope = {
      mime: form.elements.mime.value,
      maxSize: Number(form.elements.maxSize.value)
    };
    const body = { reason: form.elements.reason.value };

    await runButton(button, async () => {
      try {
        await secrecy.execute("changeAvatar", { scope, body });
        toast("Avatar changed after OOB presence confirmation", "ok");
        await refreshState();
        await refreshAuditPanel();
      } catch (error) {
        showError(error);
      }
    });
  }

  /**
   * Demo PresenceProvider: display the exact transaction and ask for the code
   * printed on the server console. This is an out-of-band channel in the demo,
   * not WebAuthn. See presence.js and DESIGN.md.
   */
  function showPresenceCodeModal(request) {
    return new Promise((resolve, reject) => {
      const root = document.getElementById("modal-root");
      root.innerHTML = `
        <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="presence-title">
          <div class="modal">
            <p class="eyebrow">High-risk action · out-of-band confirmation</p>
            <h2 id="presence-title">Read the code from the server console</h2>
            <p>
              Approve this exact transaction for <code>${esc(request.action)}</code>.
              The server printed a six-digit code for challenge
              <code>${esc(short(request.challenge, 18))}</code>. It is valid once and expires at
              ${esc(new Date(request.exp).toLocaleTimeString())}.
            </p>
            <div class="code-note">
              <div><strong>scope</strong> <code>${esc(JSON.stringify(request.scope))}</code></div>
              <div><strong>body</strong> <code>${esc(JSON.stringify(request.body))}</code></div>
              <div><strong>scopeHash</strong> <code>${esc(short(request.scopeHash, 24))}</code></div>
              <div><strong>bodyHash</strong> <code>${esc(short(request.bodyHash, 24))}</code></div>
            </div>
            <label class="form">Console code
              <input id="presence-code" inputmode="numeric" autocomplete="one-time-code"
                pattern="[0-9]{6}" maxlength="6" placeholder="000000">
            </label>
            <p class="hint">
              If you change the scope or body, this approval no longer applies. The
              server rejects mismatched scopeHash/bodyHash. WebAuthn UV is the
              production provider; this console code is a demo OOB channel.
            </p>
            <div class="actions">
              <button id="presence-confirm" class="primary">Verify code &amp; continue</button>
              <button id="presence-cancel" class="ghost">Cancel</button>
            </div>
          </div>
        </div>
      `;

      const input = document.getElementById("presence-code");
      setTimeout(() => input?.focus(), 0);

      const cancel = (error) => {
        hidePresenceModal();
        reject(error);
      };

      document.getElementById("presence-confirm").addEventListener("click", () => {
        const code = input.value.trim();
        if (!/^\d{6}$/.test(code)) {
          toast("Enter the six-digit code from the server console", "warn");
          return;
        }
        hidePresenceModal();
        resolve(code);
      });

      input?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") document.getElementById("presence-confirm").click();
      });

      document.getElementById("presence-cancel").addEventListener("click", () => {
        const error = new Error("Presence confirmation cancelled");
        error.code = "PRESENCE_CANCELLED";
        cancel(error);
      });
    });
  }

  function hidePresenceModal() {
    document.getElementById("modal-root").innerHTML = "";
  }

  // -----------------------------------------------------------------------
  // Audit / revocation controllers
  // -----------------------------------------------------------------------

  async function refreshAuditPanel() {
    try {
      const result = await secrecy.getAudit(80);
      state.audit = result.events || [];
      const list = document.getElementById("audit-list");
      if (list) list.innerHTML = auditHtml(state.audit);
    } catch (error) {
      const list = document.getElementById("audit-list");
      if (list) list.innerHTML = `<p class="error-text">${esc(error.message)}</p>`;
    }
  }

  function auditHtml(events) {
    if (!events.length) return `<p class="muted">No audit events yet.</p>`;
    return events
      .map(
        (event) => `
          <div class="audit-row audit-${esc(event.type)}">
            <span class="audit-time">${esc(timeOf(event.time))}</span>
            <span class="audit-type">${esc(event.type)}</span>
            <span class="audit-action" title="${esc(event.auditId || "")}">${esc(event.action || "—")}${event.outcome ? ` · ${esc(event.outcome)}` : ""}</span>
            <span class="audit-reason" title="scope ${esc(event.scopeHash || "—")} / body ${esc(event.bodyHash || "—")}">${esc(event.reason || "")}</span>
            <span class="audit-cap">${esc(short(event.capId || "—", 14))}</span>
          </div>
        `
      )
      .join("");
  }

  async function revokeDevice() {
    if (!confirm("Revoke this device? All its capabilities will fail immediately.")) {
      return;
    }
    try {
      const result = await secrecy.revokeDevice();
      toast(
        `Device revoked; ${result.revokedCapabilities} capabilities invalidated`,
        "warn"
      );
      await refreshState();
      await refreshAuditPanel();
    } catch (error) {
      showError(error);
    }
  }

  // -----------------------------------------------------------------------
  // XSS simulation
  // -----------------------------------------------------------------------

  function xssLogHtml() {
    if (!state.xssLog.length) {
      return `<p class="muted">Not run. The script will be injected as a &lt;script&gt; element.</p>`;
    }
    return state.xssLog
      .map(
        (entry) => `
          <div class="log-row">
            <span class="log-time">${esc(entry.time)}</span>
            <span class="log-label">${esc(entry.label)}</span>
            <span class="log-detail">${esc(entry.detail)}</span>
          </div>
        `
      )
      .join("");
  }

  function xssLog(label, detail) {
    state.xssLog.push({
      time: new Date().toLocaleTimeString(),
      label,
      detail
    });
    const box = document.getElementById("xss-log");
    if (box) box.innerHTML = xssLogHtml();
  }

  async function xssDone() {
    state.xssRunning = false;
    state.xssFinished = true;
    delete window.__secrecyXssLab;
    delete window.__secrecyXssLog;
    delete window.__secrecyXssDone;

    await refreshState({ rerender: false });
    render();
    await refreshAuditPanel();
    toast("XSS simulation complete — review the audit and revoke if needed", "warn");
    document.getElementById("security-card")?.scrollIntoView({
      behavior: "smooth",
      block: "center"
    });
  }

  /*
   * This function is never called directly in the page. It is stringified and
   * executed as an injected <script>, simulating attacker-controlled script.
   * The demo hook is deliberately exposed so the attacker can read the current
   * capability and ask the page's own non-extractable CryptoKey to sign.
   */
  function injectedXssPayload(lab, log, done) {
    return (async () => {
      const describe = (result) =>
        result.ok
          ? `SUCCESS${result.data?.result ? " (write applied)" : ""}`
          : `BLOCKED ${result.code || result.status}${result.data?.message ? " — " + result.data.message : ""}`;

      try {
        // Make sure a consumed capability exists for the replay attempt.
        let consumed = lab.lastUse();
        if (!consumed || consumed.action !== "createPost") {
          const setupRequest = {
            scope: { boardId: "b1" },
            body: { text: "XSS setup: consume a capability for the replay test" }
          };
          const setupCap = await lab.issue("createPost", setupRequest, "home");
          const setupProof = await lab.sign(setupCap, "createPost", setupRequest);
          const setupResult = await lab.call(
            setupCap,
            setupProof,
            "createPost",
            setupRequest,
            "home"
          );
          log("setup · consume one capability", describe(setupResult));
          consumed = {
            capability: setupCap,
            proof: setupProof,
            action: "createPost",
            request: setupRequest,
            view: "home"
          };
        }

        // Obtain a fresh, unconsumed capability through the exposed demo hook.
        const currentRequest = {
          scope: { boardId: "b1" },
          body: { text: "Posted by a capability obtained by script (XSS demo)" }
        };
        const current = await lab.issue("createPost", currentRequest, "home");
        const avatarRequest = {
          scope: { mime: "image/png", maxSize: 1048576 },
          body: { reason: "XSS demo substitution" }
        };

        // 1. Try to change avatar with a createPost capability from home.
        const crossProof = await lab.sign(current, "changeAvatar", avatarRequest);
        log(
          "1 · post cap → changeAvatar from home",
          describe(
            await lab.call(
              current,
              crossProof,
              "changeAvatar",
              avatarRequest,
              "home"
            )
          )
        );

        // 1b. Try lying about the view too.
        log(
          "1b · lie and claim profile view",
          describe(
            await lab.call(
              current,
              crossProof,
              "changeAvatar",
              avatarRequest,
              "profile"
            )
          )
        );

        // 2. Replay a consumed capability.
        const consumedRequest =
          consumed.request || { scope: consumed.scope, body: consumed.body };
        log(
          "2 · reuse a consumed capability",
          describe(
            await lab.call(
              consumed.capability,
              consumed.proof,
              consumed.action,
              consumedRequest,
              consumed.view
            )
          )
        );

        // 3. Mint a high-risk capability without a presence token.
        log(
          "3 · mint high-risk cap without presence",
          describe(await lab.tryIssue("changeAvatar", avatarRequest, "profile"))
        );

        // 3b. Obtain a challenge and attempt verification without the console code.
        log(
          "3b · direct presence bypass with wrong code",
          describe(await lab.tryPresenceBypass("changeAvatar", avatarRequest, "profile"))
        );

        // 4. Use the current capability for its allowed action once.
        const goodProof = await lab.sign(current, "createPost", currentRequest);
        log(
          "4 · use current cap for createPost",
          describe(
            await lab.call(current, goodProof, "createPost", currentRequest, "home")
          )
        );
      } catch (error) {
        log("script error", error.message || String(error));
      } finally {
        await done();
      }
    })();
  }

  function runXssSimulation() {
    if (!demoMode || !secrecy.demo) {
      toast("XSS lab is disabled; open with ?demo=1", "warn");
      return;
    }
    if (state.xssRunning) return;
    state.xssRunning = true;
    state.xssFinished = false;
    state.xssLog = [];

    const box = document.getElementById("xss-log");
    if (box) box.innerHTML = xssLogHtml();
    const button = document.getElementById("simulate-xss");
    if (button) {
      button.disabled = true;
      button.textContent = "Attack running…";
    }

    window.__secrecyXssLab = secrecy.demo;
    window.__secrecyXssLog = xssLog;
    window.__secrecyXssDone = xssDone;

    // The actual injection: a new script element with attacker-style code.
    const script = document.createElement("script");
    script.textContent = `(${injectedXssPayload.toString()})(window.__secrecyXssLab, window.__secrecyXssLog, window.__secrecyXssDone);`;
    document.body.appendChild(script);
    script.remove();
  }

  // -----------------------------------------------------------------------
  // View bindings
  // -----------------------------------------------------------------------

  const afterRender = {
    login() {
      bind("login-btn", "click", (event) =>
        runButton(event.currentTarget, login)
      );
      bind("continue-btn", "click", (event) =>
        runButton(event.currentTarget, continueSession)
      );
      bind("reset-device", "click", resetLocalDevice);
    },

    home() {
      const createForm = document.getElementById("create-post-form");
      createForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        createPost(event.currentTarget, event.currentTarget.querySelector("button"));
      });

      const draftForm = document.getElementById("draft-form");
      draftForm?.addEventListener("submit", (event) => {
        event.preventDefault();
        saveDraft(event.currentTarget, event.currentTarget.querySelector("button"));
      });

      bind("publish-draft", "click", (event) =>
        publishDraft(event.currentTarget)
      );
      bind("open-chat", "click", () => navigate("chat"));
      bind("simulate-xss", "click", runXssSimulation);
      bind("refresh-state", "click", async (event) =>
        runButton(event.currentTarget, async () => {
          await refreshState();
          await refreshAuditPanel();
        })
      );
      bind("refresh-audit", "click", (event) =>
        runButton(event.currentTarget, refreshAuditPanel)
      );
      bind("revoke-device", "click", revokeDevice);
      bind("reset-device", "click", resetLocalDevice);

      refreshAuditPanel();
    },

    chat() {
      const form = document.getElementById("chat-form");
      form?.addEventListener("submit", (event) => {
        event.preventDefault();
        sendMessage(event.currentTarget, event.currentTarget.querySelector("button"));
      });
      bind("refresh-state", "click", (event) =>
        runButton(event.currentTarget, refreshState)
      );
    },

    profile() {
      const form = document.getElementById("avatar-form");
      form?.addEventListener("submit", (event) => {
        event.preventDefault();
        changeAvatar(event.currentTarget, event.currentTarget.querySelector("button"));
      });
      bind("reset-device", "click", resetLocalDevice);
    }
  };

  // -----------------------------------------------------------------------
  // Boot
  // -----------------------------------------------------------------------

  secrecy.on("error", (error) => {
    // A single place to observe every library error (including local denials).
    console.warn(`[secrecy:${error.code || "ERROR"}]`, error.message);
  });

  secrecy.on("warning", (warning) => {
    console.warn(`[secrecy:${warning.code}]`, warning.message);
    toast(`${warning.code}: ${warning.message}`, "warn");
  });

  secrecy.on("revoked", () => {
    toast("Device revoked. All further capability attempts fail.", "warn");
  });

  // window.secrecy is installed only in ?demo=1 mode at the top of this file.

  if (!location.hash) location.hash = "#/login";
  window.addEventListener("hashchange", route);
  route();
})();
