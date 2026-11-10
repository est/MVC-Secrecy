# Browser tests (optional)

These Playwright tests exercise the real UI and the XSS lab. They are optional;
the main regression suites are `src/test/smoke.mjs` and `src/test/security.mjs`.

## Requirements

- Node.js 22+
- Playwright (`npm i -D playwright`, then `npx playwright install chromium`)
- A browser channel. The scripts default to `msedge`; set
  `PLAYWRIGHT_CHANNEL=chromium` to use Playwright's bundled Chromium, or
  `PLAYWRIGHT_CHANNEL=` (empty) to let Playwright choose.

If Playwright is installed globally, use:

```bash
NODE_PATH=$(npm root -g) node src/test/browser/browser.mjs
```

## Start the server with a log

The high-risk presence flow prints a six-digit code to the server console. The
browser tests read it from a log file.

```bash
mkdir -p tmp
PORT=8787 DEMO=1 node src/server.js > tmp/server.log 2>&1 &
```

## Run

```bash
BASE_URL=http://127.0.0.1:8787 \
SERVER_LOG=tmp/server.log \
PLAYWRIGHT_CHANNEL=chromium \
node src/test/browser/browser.mjs

BASE_URL=http://127.0.0.1:8787 \
SERVER_LOG=tmp/server.log \
PLAYWRIGHT_CHANNEL=chromium \
node src/test/browser/adversarial.mjs
```

- `browser.mjs` — 18 UI checks: login, post, reuse, cross-action, ACL, OOB
  presence, chat, mention, cross-device, XSS lab, audit, revoke.
- `adversarial.mjs` — 5 checks: concurrent double-spend, removed old presence
  endpoint, wrong OOB code, presence token scope substitution, anonymous audit.

The server is in-memory; restart it for a clean run.
