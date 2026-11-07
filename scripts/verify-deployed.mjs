import assert from 'node:assert/strict';
const base=(process.env.WORKER_URL||'https://wallet-risk-checker.trantanlong2411.workers.dev').replace(/\/$/,'');
const expected='wallet-risk-pharos-2026-11-07-v1';
async function get(path){const r=await fetch(base+path,{signal:AbortSignal.timeout(22000),cache:'no-store'});return {status:r.status,data:await r.json()};}
async function post(path,body){const r=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(95000)});return {status:r.status,data:await r.json()};}
let h;
for(let i=0;i<22;i++){try{h=await get('/api/health');if(h.status===200&&h.data.version===expected)break;
 console.log('DEPLOY_PENDING',i,h.status,h.data.version||'unknown');}catch(e){console.log('DEPLOY_PENDING',i,String(e.message||e));}
 await new Promise(r=>setTimeout(r,4000));}
assert.equal(h?.status,200,'Worker not publicly accessible');
assert.equal(h.data.version,expected);
assert.equal(h.data.readOnly,true);
const invalid=await post('/api/analyze',{address:'not-a-wallet'});
assert.equal(invalid.status,400);
const real=await post('/api/analyze',{address:'0xfaC0718D882E5f07e1972D617bd430CD72A55D84'});
assert.equal(real.status,200,JSON.stringify(real.data).slice(0,450));
assert.equal(real.data.ok,true);
assert.equal(real.data.chainId,1672);
assert.equal(real.data.coverage.totalWindows,9);
assert.ok(real.data.coverage.windowsSucceeded>=1);
assert.ok(real.data.assessment.indexName.includes('not a trust'));
assert.equal(real.data.readOnly,true);
const page=await fetch(base,{signal:AbortSignal.timeout(14000)});
assert.equal(page.status,200);assert.match(await page.text(),/Wallet Risk Checker/);
console.log('WALLET_RISK_DEPLOYED_VERIFIED',JSON.stringify({
 url:base,version:expected,wallet:real.data.owner,block:real.data.blockNumber,
 windowsSucceeded:real.data.coverage.windowsSucceeded,
 approvalsFound:real.data.coverage.eventsFound,
 currentAllowancesChecked:real.data.coverage.spenderPairsChecked,
 score:real.data.assessment.score,coverage:real.data.assessment.confidence,
 privacy:'public address only; no wallet keys or signing'}));
