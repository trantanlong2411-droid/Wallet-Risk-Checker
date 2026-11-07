// Fixed official Pharos MCP endpoint; never accepts user-defined RPC URLs.
export const ENDPOINT='https://mcp.pharos.xyz/mcp';
const DEFAULT_PROTOCOL='2025-03-26';
function sse(text,id){
 for(const part of text.replace(/\r\n/g,'\n').split(/\n\n+/)){
  const payload=part.split('\n').filter(x=>x.startsWith('data:')).map(x=>x.slice(5).trim()).join('\n');
  if(!payload)continue;
  try{const parsed=JSON.parse(payload);if(parsed.id===id)return parsed}catch{}
 }
 throw Error('MCP response missing JSON-RPC ID '+id);
}
export function unpack(out,tool){
 if(!out||out.isError)throw Error(tool+' returned MCP failure '+JSON.stringify(out?.content||[]).slice(0,180));
 const v=out.structuredContent;
 if(v&&typeof v==='object'){
  if(v.error||v.mcpError)throw Error(tool+' returned RPC error '+JSON.stringify(v.error||v.mcpError).slice(0,200));
  if(v.chainId!==undefined||v.balanceWei!==undefined||v.nonce!==undefined||v.code!==undefined||v.result!==undefined||Array.isArray(v))return v;
 }
 const entry=out.content?.find(x=>x.type==='text'&&typeof x.text==='string');
 if(!entry)throw Error(tool+' returned no JSON text');
 const result=JSON.parse(entry.text);
 if(result?.error||result?.mcpError)throw Error(tool+' returned RPC error '+String(result.error?.message||result.mcpError?.message||result.error||'Unknown'));
 return result;
}
export async function connect(fetcher=fetch){
 let version=DEFAULT_PROTOCOL,session='',count=0,closed=false;
 async function rpc(method,params={},notify=false){
  if(closed)throw Error('MCP session closed');
  const id=notify?null:++count;
  const req={jsonrpc:'2.0',...(!notify?{id}:{}),method,...(!notify?{params}:{})};
  const response=await fetcher(ENDPOINT,{method:'POST',headers:{
   'content-type':'application/json','accept':'application/json, text/event-stream',
   'mcp-protocol-version':version,...(session?{'mcp-session-id':session}:{})
  },body:JSON.stringify(req),signal:AbortSignal.timeout(25000)});
  if(!response.ok)throw Error('Pharos Chain MCP HTTP '+response.status+': '+(await response.text()).slice(0,130));
  session=response.headers.get('mcp-session-id')||session;
  if(notify){await response.text();return null;}
  const raw=await response.text();
  if(raw.length>1200000)throw Error('MCP response oversized');
  const data=(response.headers.get('content-type')||'').includes('event-stream')?sse(raw,id):JSON.parse(raw);
  if(data.id!==id)throw Error('MCP response ID mismatch');
  if(data.error)throw Error('MCP protocol: '+String(data.error.message||data.error));
  return data.result;
 }
 const init=await rpc('initialize',{protocolVersion:version,capabilities:{},clientInfo:{name:'wallet-risk-checker',version:'1.0.0'}});
 if(init?.protocolVersion)version=String(init.protocolVersion);
 await rpc('notifications/initialized',{},true);
 return {list:async()=>{const x=await rpc('tools/list');return x.tools||[];},
  tool:async(name,args={})=>unpack(await rpc('tools/call',{name,arguments:args}),name),
  close:async()=>{closed=true;if(session)try{await fetcher(ENDPOINT,{method:'DELETE',
    headers:{'mcp-session-id':session,'mcp-protocol-version':version},signal:AbortSignal.timeout(2300)})}catch{}}};
}
