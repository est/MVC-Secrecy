import fs from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const BASE = process.env.BASE_URL || 'http://127.0.0.1:8787';
const LOG = process.env.SERVER_LOG || 'tmp/server.log';
const results = [];
const check = (name, ok, detail='') => { results.push({name,ok,detail}); console.log(`${ok?'PASS':'FAIL'}  ${name}${detail?'  — '+detail:''}`); };
function lastCode() {
  const text = fs.readFileSync(LOG, 'utf8');
  const m = [...text.matchAll(/\[presence\][^\n]*code=(\d{6})/g)];
  return m.length ? m[m.length-1][1] : null;
}

const channel = process.env.PLAYWRIGHT_CHANNEL || 'msedge';
const browser = await chromium.launch({ ...(channel ? { channel } : {}), headless:true });
const ctxA = await browser.newContext();
const pageA = await ctxA.newPage();
pageA.on('console', m => { if (m.type()==='error') console.log('[A console]', m.text()); });
pageA.on('pageerror', e => console.log('[A pageerror]', e.message));

async function login(page) {
  await page.goto(BASE + '/?demo=1');
  await page.waitForSelector('#login-btn', { timeout: 15000 });
  await page.click('#login-btn');
  await page.waitForSelector('#create-post-form', { timeout: 20000 });
  await page.waitForFunction(() => window.secrecy?.ready === true, null, { timeout: 15000 });
}

try {
  await login(pageA);
  const meA = await pageA.evaluate(() => window.secrecy.me());
  check('login: device registered', !!meA.device?.deviceId, meA.device?.deviceId);

  // createPost
  await pageA.selectOption('#create-post-form select[name=boardId]', 'b1');
  await pageA.fill('#create-post-form textarea[name=text]', 'hello v2 from playwright');
  await pageA.click('#create-post-form button[type=submit]');
  await pageA.waitForFunction(() => document.body.innerText.includes('hello v2 from playwright'), null, { timeout: 15000 });
  check('createPost: visible in feed', true);

  // reuse
  const last = await pageA.evaluate(() => window.secrecy.demo.lastUse());
  const reuse = await pageA.evaluate(async (l) => window.secrecy.demo.call(l.capability, l.proof, l.action, { scope:l.scope, body:l.body }, l.view), last);
  check('reuse: consumed rejected', !reuse.ok && reuse.code === 'CAPABILITY_CONSUMED', reuse.code);

  // cross-action
  const crossAction = await pageA.evaluate(async () => {
    const cap = await window.secrecy.demo.issue('createPost', { scope:{boardId:'b1'}, body:{text:'x'} }, 'home');
    const req = { scope:{mime:'image/png',maxSize:1000}, body:{reason:'x'} };
    const proof = await window.secrecy.demo.sign(cap, 'changeAvatar', req);
    return window.secrecy.demo.call(cap, proof, 'changeAvatar', req, 'home');
  });
  check('scope: post cap cannot changeAvatar', !crossAction.ok && ['ACTION_NOT_ALLOWED_IN_VIEW','ACTION_MISMATCH'].includes(crossAction.code), crossAction.code);

  // unauthorized board
  const acl = await pageA.evaluate(() => window.secrecy.demo.tryIssue('createPost', { scope:{boardId:'b_secret'}, body:{text:'x'} }, 'home'));
  check('authorizer: unauthorized board denied', !acl.ok && ['FORBIDDEN','SCOPE_DENIED'].includes(acl.code), acl.code);

  // view guard
  const viewGuard = await pageA.evaluate(() => window.secrecy.demo.tryIssue('changeAvatar', { scope:{mime:'image/png',maxSize:1000}, body:{reason:'x'} }, 'home'));
  check('view: changeAvatar denied in home', !viewGuard.ok && viewGuard.code === 'ACTION_NOT_ALLOWED_IN_VIEW', viewGuard.code);

  // presence via OOB console code
  await pageA.evaluate(() => { location.hash = '#/profile'; });
  await pageA.waitForSelector('#avatar-form', { timeout: 10000 });
  await pageA.selectOption('#avatar-form select[name=mime]', 'image/png');
  await pageA.fill('#avatar-form input[name=maxSize]', '1048576');
  await pageA.fill('#avatar-form input[name=reason]', 'playwright avatar');
  await pageA.click('#avatar-form button[type=submit]');
  await pageA.waitForSelector('#presence-code', { timeout: 10000 });
  const code = lastCode();
  check('presence: server printed a 6-digit code', !!code, code || 'none');
  if (code) {
    await pageA.fill('#presence-code', code);
    await pageA.click('#presence-confirm');
    await pageA.waitForFunction(() => document.body.innerText.includes('Avatar metadata'), null, { timeout: 15000 });
    check('presence: OOB code changes avatar', true);
  } else {
    check('presence: OOB code changes avatar', false, 'no code');
  }

  // chat
  await pageA.evaluate(() => { location.hash = '#/chat'; });
  await pageA.waitForSelector('#chat-form', { timeout: 10000 });
  await pageA.fill('#chat-form textarea[name=text]', 'hello chat v2');
  await pageA.click('#chat-form button[type=submit]');
  await pageA.waitForFunction(() => document.body.innerText.includes('hello chat v2'), null, { timeout: 15000 });
  check('chat: sendMessage works', true);
  const mentionBox = await pageA.$('#chat-form input[name=mention]');
  if (mentionBox) {
    await pageA.fill('#chat-form textarea[name=text]', 'mention v2');
    await mentionBox.check();
    await pageA.click('#chat-form button[type=submit]');
    await pageA.waitForFunction(() => document.body.innerText.includes('mention v2'), null, { timeout: 15000 });
    check('chat: mention works', true);
  } else check('chat: mention works', false, 'no mention checkbox');

  // cross-device
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  await login(pageB);
  const meB = await pageB.evaluate(() => window.secrecy.me());
  check('login: second device distinct', !!meB.device?.deviceId && meB.device.deviceId !== meA.device.deviceId, meB.device?.deviceId);
  const freshA = await pageA.evaluate(async () => {
    const req = { scope:{boardId:'b1'}, body:{text:'cross-device'} };
    const cap = await window.secrecy.demo.issue('createPost', req, 'home');
    const proof = await window.secrecy.demo.sign(cap, 'createPost', req);
    return { cap, proof, req };
  });
  const crossDevice = await pageB.evaluate(async (l) => {
    const token = window.secrecy.device.deviceToken;
    const r = await fetch('/api/action', { method:'POST', headers:{'content-type':'application/json','x-device-token':token}, body: JSON.stringify({ capability:l.cap, proof:l.proof, action:'createPost', view:'home', scope:l.req.scope, body:l.req.body }) });
    const j = await r.json().catch(()=>({}));
    return { status:r.status, code:j?.error?.code };
  }, freshA);
  check('device binding: B cannot use A capability', crossDevice.status >= 400, `${crossDevice.status} ${crossDevice.code}`);

  // XSS demo
  await pageA.evaluate(() => { location.hash = '#/home'; });
  await pageA.waitForSelector('#simulate-xss', { timeout: 10000 });
  await pageA.click('#simulate-xss');
  await pageA.waitForFunction(() => {
    const t = document.querySelector('#xss-log')?.innerText || '';
    return t.includes('3b ·') || t.includes('4 ·') || t.includes('script error');
  }, null, { timeout: 25000 });
  const xssText = await pageA.evaluate(() => document.querySelector('#xss-log')?.innerText || '');
  check('xss: cross-action blocked', /1 ·.*BLOCKED/s.test(xssText));
  check('xss: reuse blocked', /2 ·.*BLOCKED CAPABILITY_CONSUMED/s.test(xssText));
  check('xss: presence bypass blocked', /3b ·.*BLOCKED PRESENCE_CODE_INVALID/s.test(xssText), xssText.slice(-300));
  check('xss: allowed action succeeds once', /4 ·.*SUCCESS/s.test(xssText));

  // audit
  const audit = await pageA.evaluate(() => window.secrecy.getAudit(100));
  const types = new Set((audit.events||[]).map(e=>e.type));
  check('audit: issued/consumed/denied/presence present', ['issued','consumed','denied','presence'].every(t=>types.has(t)), [...types].join(','));

  // revoke
  await pageA.evaluate(() => { window.confirm = () => true; });
  const revokeBtn = await pageA.$('#revoke-device');
  if (revokeBtn) {
    await pageA.click('#revoke-device');
    await pageA.waitForFunction(() => document.body.innerText.includes('revoked'), null, { timeout: 10000 });
    const after = await pageA.evaluate(async () => {
      try { await window.secrecy.execute('createPost', { scope:{boardId:'b1'}, body:{text:'after revoke'} }); return { ok:true }; }
      catch (e) { return { ok:false, code:e.code }; }
    });
    check('revoke: subsequent action fails DEVICE_REVOKED', !after.ok && after.code === 'DEVICE_REVOKED', after.code);
  } else check('revoke: subsequent action fails DEVICE_REVOKED', false, 'no revoke button');

  await ctxB.close();
} catch (e) {
  console.error('FATAL', e);
  results.push({ name:'fatal', ok:false, detail:String(e) });
} finally {
  await browser.close();
  const failed = results.filter(r=>!r.ok);
  console.log(`\n${results.length-failed.length} passed, ${failed.length} failed`);
  process.exit(failed.length ? 1 : 0);
}
