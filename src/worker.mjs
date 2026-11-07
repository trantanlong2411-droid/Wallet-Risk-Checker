import {analyze,TOKENS,KNOWN_SPENDERS} from './core.mjs';
import {HTML} from './page.mjs';
export const VERSION='wallet-risk-pharos-2026-11-07-v1';
const json=(body,status=200)=>Response.json(body,{status,headers:{'cache-control':'no-store','x-content-type-options':'nosniff'}});
const limiter=new Map();
function overLimit(request){
 const ip=(request.headers.get('cf-connecting-ip')||'anonymous').slice(0,80);
 const now=Date.now(),item=limiter.get(ip);
 if(!item||now-item.since>60000){limiter.set(ip,{since:now,n:1});return false;}
 item.n++;return item.n>7;
}
export default {
 async fetch(request){
  const u=new URL(request.url),path=u.pathname;
  if(request.method==='GET'&&path==='/')return new Response(HTML,{headers:{
   'content-type':'text/html;charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',
   'content-security-policy':"default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}});
  if(request.method==='GET'&&path==='/api/health')return json({ok:true,version:VERSION,
   network:'Pharos Mainnet',chainId:1672,source:'https://mcp.pharos.xyz/mcp',
   scope:'live wallet balance, nonce, contract code, sampled Approval events, verified current ERC-20 allowances',
   knownSpenders:KNOWN_SPENDERS.length,monitoredTokens:TOKENS.length,
   readOnly:true,requiresWalletConnection:false,requiresPrivateKey:false,
   note:'Local endpoint health only; actual MCP must be checked with POST /api/analyze'});
  if(request.method==='GET'&&path==='/api/method')return json({ok:true,
   monitoredTokens:TOKENS,knownSpenders:KNOWN_SPENDERS,
   sampleWindowCount:3,sampleBlockSpan:1000,completeHistory:false,
   scoring:'Risk exposure due to current ERC-20 allowances, not criminality or wallet trustworthiness',
   disclaimers:['Does not enumerate all approvals','A zero risk index is not a safety certification',
    'No keys, writes or revocations on this website']});
  if(request.method==='POST'&&path==='/api/analyze'){
   if(overLimit(request))return json({ok:false,error:'Rate limit reached. Retry in one minute.'},429);
   try{
    const payload=await request.text();if(payload.length>800)return json({ok:false,error:'Request too long'},400);
    const input=JSON.parse(payload),data=await analyze(input);return json(data);
   }catch(e){
    const message=String(e.message||e);
    const inputError=/valid Pharos EVM wallet address|Invalid JSON|Unexpected token|is not valid JSON/i.test(message);
    return json({ok:false,error:message.slice(0,320),
     note:'No risk assessment was fabricated. This application reads on-chain data only.'},inputError?400:502);
   }
  }
  return json({ok:false,error:'Not found'},404);
 }
};
