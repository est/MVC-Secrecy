import fs from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const BASE = process.env.BASE_URL || 'http://127.0.0.1:8787';
const LOG = process.env.SERVER_LOG || 'tmp/server.log';
const results=[];
const check=(n,ok,d='')=>{results.push({n,ok,d});console.log(`${ok?'PASS':'FAIL'}  ${n}${d?'  — '+d:''}`);};
function lastCode(){const t=fs.readFileSync(LOG,'utf8');const m=[...t.matchAll(/\[presence\][^\n]*code=(\d{6})/g)];return m.length?m[m.length-1][1]:null;}

const channel = process.env.PLAYWRIGHT_CHANNEL || 'msedge';
const browser=await chromium.launch({ ...(channel ? { channel } : {}), headless:true});
const ctx=await browser.newContext();
const page=await ctx.newPage();
await page.goto(BASE+'/?demo=1');
await page.waitForSelector('#login-btn',{timeout:15000});
await page.click('#login-btn');
await page.waitForSelector('#create-post-form',{timeout:20000});
await page.waitForFunction(()=>window.secrecy?.ready===true);

// 1) concurrency: one capability, two parallel actions
const race=await page.evaluate(async()=>{
  const req={scope:{boardId:'b1'},body:{text:'race-v2-'+Date.now()}};
  const cap=await window.secrecy.demo.issue('createPost',req,'home');
  const proof=await window.secrecy.demo.sign(cap,'createPost',req);
  const token=window.secrecy.device.deviceToken;
  const body=JSON.stringify({capability:cap,proof,action:'createPost',view:'home',scope:req.scope,body:req.body});
  const call=()=>fetch('/api/action',{method:'POST',headers:{'content-type':'application/json','x-device-token':token},body});
  const [r1,r2]=await Promise.all([call(),call()]);
  const [j1,j2]=await Promise.all([r1.json().catch(()=>({})),r2.json().catch(()=>({}))]);
  return {s1:r1.status,s2:r2.status,ok1:j1?.ok,ok2:j2?.ok,c1:j1?.error?.code,c2:j2?.error?.code};
});
check('concurrency: exactly one success', (race.ok1?1:0)+(race.ok2?1:0)===1, JSON.stringify(race));

// 2) old /api/presence endpoint gone
const oldPresence=await page.evaluate(async()=>{
  const r=await fetch('/api/presence',{method:'POST',headers:{'content-type':'application/json','x-device-token':window.secrecy.device.deviceToken},body:JSON.stringify({challenge:'x'})});
  return {status:r.status};
});
check('presence: old click endpoint removed',  [404,410].includes(oldPresence.status), String(oldPresence.status));

// 3) direct presence bypass with wrong code
const bypass=await page.evaluate(async()=>{
  const req={scope:{mime:'image/png',maxSize:1000},body:{reason:'x'}};
  return window.secrecy.demo.tryPresenceBypass('changeAvatar',req,'profile');
});
check('presence: wrong code cannot mint high-risk capability', !bypass.ok && bypass.code==='PRESENCE_CODE_INVALID', bypass.code);

// 4) presence token scope substitution
const substitution=await page.evaluate(async()=>{
  const token=window.secrecy.device.deviceToken;
  const benign={scope:{mime:'image/png',maxSize:1000},body:{reason:'benign'}};
  const ch=await fetch('/api/presence/challenge',{method:'POST',headers:{'content-type':'application/json','x-device-token':token},body:JSON.stringify({action:'changeAvatar',view:'profile',...benign})});
  const cj=await ch.json().catch(()=>({}));
  if(!cj.challenge) return {err:'no challenge',status:ch.status,cj};
  // code is read by the Node side; expose challenge to caller
  return {challenge:cj.challenge};
});
const code=lastCode();
if(!substitution.challenge || !code){check('presence: token bound to scope/body',false,JSON.stringify(substitution));}
else {
  const sub=await page.evaluate(async({challenge,code})=>{
    const token=window.secrecy.device.deviceToken;
    const vr=await fetch('/api/presence/verify',{method:'POST',headers:{'content-type':'application/json','x-device-token':token},body:JSON.stringify({challenge,code})});
    const vj=await vr.json().catch(()=>({}));
    if(!vj.presenceToken) return {err:'no presence token',status:vr.status,vj};
    // substitute a different scope/body with the same presence token
    const evil={scope:{mime:'image/jpeg',maxSize:104857600},body:{reason:'evil'}};
    const cr=await fetch('/api/capabilities',{method:'POST',headers:{'content-type':'application/json','x-device-token':token},body:JSON.stringify({action:'changeAvatar',view:'profile',...evil,presenceToken:vj.presenceToken})});
    const cj=await cr.json().catch(()=>({}));
    return {status:cr.status,code:cj?.error?.code,ok:!!cj?.capability};
  },{challenge:substitution.challenge,code});
  check('presence: token bound to scope/body', !sub.ok && ['PRESENCE_SCOPE_MISMATCH','PRESENCE_REQUIRED','SCOPE_DENIED'].includes(sub.code), JSON.stringify(sub));
}

// 5) anonymous audit
const anon=await browser.newContext();
const anonPage=await anon.newPage();
await anonPage.goto(BASE+'/');
const audit=await anonPage.evaluate(async()=>{
  const r=await fetch('/api/audit?limit=3');
  return {status:r.status};
});
check('audit: anonymous request denied', audit.status===401, String(audit.status));
await anon.close();

await browser.close();
const failed=results.filter(r=>!r.ok);
console.log(`\n${results.length-failed.length} passed, ${failed.length} failed`);
process.exit(failed.length?1:0);
