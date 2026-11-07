import {isAddress,getAddress,Interface,id as hashEvent,formatUnits} from 'ethers';
import {connect,ENDPOINT} from './mcp.mjs';
export const CHAIN_ID=1672;
export const EXPLORER='https://pharosscan.xyz';
export const TOKENS=Object.freeze([
 {symbol:'USDC',address:'0xc879c018db60520f4355c26ed1a6d572cdac1815',decimals:6},
 {symbol:'WPROS',address:'0x52c48d4213107b20bc583832b0d951fb9ca8f0b0',decimals:18},
 {symbol:'WETH',address:'0x1f4b7011ee3d53969bb67f59428a9ec0477856e9',decimals:18}
]);
export const KNOWN_SPENDERS=Object.freeze([
 {name:'R25 Axil Credit Vault',address:'0x1c2bc8b553d9a7e61f7531a3a4bf2162f4569268',token:'USDC'},
 {name:'Zona Lending Pool',address:'0xda464e68208A3083Eb65FE5c522a72AeD1C1372a',token:'USDC'}
]);
const iface=new Interface(['function allowance(address,address) view returns (uint256)',
 'function balanceOf(address) view returns (uint256)']);
const approvalTopic=hashEvent('Approval(address,address,uint256)').toLowerCase();
const MAX=(1n<<256n)-1n;
const HALF=1n<<255n;
function hexValue(v){if(typeof v!=='string'||!/^0x[0-9a-fA-F]+$/.test(v))throw Error('Invalid blockchain hex result');return BigInt(v);}
export function normalized(address){
 if(typeof address!=='string'||!isAddress(address))throw Error('Enter a valid Pharos EVM wallet address (0x + 40 hexadecimal characters)');
 return getAddress(address);
}
export function ownerTopic(address){return '0x'+normalized(address).slice(2).toLowerCase().padStart(64,'0');}
export function windows(head){
 const tip=Number(head);if(!Number.isSafeInteger(tip)||tip<10)throw Error('Invalid Pharos latest block');
 // Three intentionally DISJOINT 1000-block samples over the last ~7d.
 // We do not imply that approvals between these windows were scanned.
 const endPoints=[tip,Math.max(1,tip-150000),Math.max(1,tip-500000)];
 return endPoints.map(end=>({fromBlock:Math.max(1,end-999),toBlock:end}));
}
export function parseApproval(log,token,owner){
 if(!log||!Array.isArray(log.topics)||log.topics.length<3)return null;
 if(log.topics[0].toLowerCase()!==approvalTopic)return null;
 if(log.topics[1].toLowerCase()!==ownerTopic(owner))return null;
 const spender='0x'+log.topics[2].slice(-40);
 if(!isAddress(spender))return null;
 if(typeof log.data!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(log.data))return null;
 const block=hexValue(log.blockNumber);
 if(block>BigInt(Number.MAX_SAFE_INTEGER))return null;
 return {token:token.symbol,tokenAddress:token.address,spender:getAddress(spender),
  loggedAmount:BigInt(log.data).toString(),blockNumber:Number(block),
  transactionHash:typeof log.transactionHash==='string'&&/^0x[0-9a-fA-F]{64}$/.test(log.transactionHash)?log.transactionHash:null,
  source:'ERC-20 Approval event in sampled block window'};
}
export function mergeApprovals(events,owner){
 const byPair=new Map();
 const sorted=[...events].sort((a,b)=>b.blockNumber-a.blockNumber);
 for(const event of sorted){
  const key=event.tokenAddress.toLowerCase()+'|'+event.spender.toLowerCase();
  if(!byPair.has(key))byPair.set(key,event);
 }
 for(const known of KNOWN_SPENDERS){
  const token=TOKENS.find(t=>t.symbol===known.token);
  const key=token.address.toLowerCase()+'|'+known.address.toLowerCase();
  if(!byPair.has(key))byPair.set(key,{token:token.symbol,tokenAddress:token.address,
   spender:getAddress(known.address),blockNumber:null,transactionHash:null,
   source:'Explicit current-allowance check of a published protocol address',label:known.name});
 }
 return [...byPair.values()].sort((a,b)=>Number(b.blockNumber||0)-Number(a.blockNumber||0))
  .slice(0,10);
}
export function assessExposure(permissions,{nonce,balancePROS,contractAccount,errors=[]}={}){
 let score=0,active=0,unlimited=0,unknown=0,eoas=0;
 const signals=[],actions=[];
 for(const p of permissions){
  if(p.verification==='unavailable'){unknown++;continue;}
  if(!p.active)continue;
  active++;
  const unlimitedPermission=p.unlimited===true;
  if(unlimitedPermission){unlimited++;score+=p.spenderType==='EOA'?52:34;
   signals.push({level:p.spenderType==='EOA'?'high':'medium',name:'Unlimited '+p.token+' allowance',
    detail:'The spender currently has an extremely large allowance. This is not proof of malicious behavior, but exposes more tokens if the spender is compromised.',
    token:p.token,spender:p.spender,evidence:p.allowanceSource});}
  else if(p.spenderType==='EOA'){
   score+=24;signals.push({level:'medium',name:'Active allowance to externally owned address',
    detail:'An EOA spender has a currently nonzero ERC-20 allowance. Verify why this permission exists.',
    token:p.token,spender:p.spender,evidence:p.allowanceSource});}
  if(p.spenderType==='EOA'){eoas++;}
  if(p.spenderType==='unknown'&&unlimitedPermission)score+=8;
 }
 if(active===0)signals.push({level:'info',name:'No active monitored allowance found',
  detail:'This does NOT establish that the wallet is safe. Historical approvals and unmonitored assets may be missed.'});
 if(unlimited>0)actions.push('Review every unlimited allowance, especially contracts you no longer use. Consider a separate on-chain revocation with a trusted wallet.');
 if(eoas>0)actions.push('Check each active EOA spender and revoke permissions that are not necessary.');
 if(errors.length>0||unknown>0)actions.push('Some RPC checks failed; repeat the scan before relying on these results.');
 if(Number(balancePROS)===0&&Number(nonce)>0)actions.push('Wallet has no observed PROS for transaction gas at this block; fund gas only through trusted channels if you need to transact.');
 actions.push('Review other tokens, older approvals, NFTs, Permit2 and off-chain signatures with a full-history tool before making security decisions.');
 score=Math.min(100,score);
 return {score,grade:score>=60?'ELEVATED':score>=20?'REVIEW RECOMMENDED':'NO MAJOR SIGNAL OBSERVED',
  indexName:'Observed allowance-exposure index (not a trust or scam score)',
  activePermissions:active,unlimitedPermissions:unlimited,unknownChecks:unknown,
  signals,actions,confidence:errors.length||unknown>0?'PARTIAL': 'LIMITED SCOPE',
  method:'Deterministic heuristic on verified live allowances; 34 points per unlimited contract allowance, 52 for unlimited EOA, 24 for finite EOA. Unknown/spender-unclear readings may add caveats. Capped at 100.',
  cautions:['No full-history index. Three small 1000-block approval-event windows are sampled only.',
   'Allowance is checked at current chain state; an old Approval event is not itself evidence of a current permission.',
   'A zero score means no detected high-risk approval signal in the covered scope, not a safe or legitimate wallet.',
   'This report does not identify scammers, assess user identity, token audits, NFT approvals or off-chain signatures.']};
}
async function allowanceCheck(client,owner,token,spender){
 const data=iface.encodeFunctionData('allowance',[owner,spender]);
 const r=await client.tool('eth_call',{transaction:{to:token.address,data},block:'latest'});
 const raw=r?.result;if(typeof raw!=='string')throw Error('Missing live allowance');
 const [amount]=iface.decodeFunctionResult('allowance',raw);
 return amount;
}
async function typeOfSpender(client,address){
 const result=await client.tool('get_code',{address});
 if(typeof result.code!=='string'||!/^0x[0-9a-fA-F]*$/.test(result.code))return 'unknown';
 return result.code==='0x'?'EOA':'contract';
}
export async function analyze(input,connectFn=connect){
 const owner=normalized(input?.address);
 let client;const checkedAtUtc=new Date().toISOString(),notes=[],events=[];
 try{
  client=await connectFn();
  const list=(await client.list()).map(t=>t.name);
  for(const name of ['get_chain_info','get_balance','get_transaction_count','get_code','eth_call','get_logs'])
   if(!list.includes(name))throw Error('Pharos Chain MCP missing '+name);
  const chain=await client.tool('get_chain_info',{});
  if(Number(chain.chainId)!==CHAIN_ID||chain.chainIdMatches===false)throw Error('Expected Pharos Mainnet chain ID 1672');
  const latest=Number(chain.latestBlock),scope=windows(latest);
  const balance=await client.tool('get_balance',{address:owner,block:String(latest)});
  const nonce=await client.tool('get_transaction_count',{address:owner,block:String(latest)});
  const accountCode=await client.tool('get_code',{address:owner,block:String(latest)});
  const balancePROS=typeof balance.balance==='string'?balance.balance:formatUnits(BigInt(balance.balanceWei||0),18);
  const nonceCount=Number(nonce.nonce);
  if(!Number.isSafeInteger(nonceCount)||nonceCount<0)throw Error('Invalid chain nonce');
  const contractAccount=accountCode.code!=='0x';
  // Fixed token allowlist and 3 noncontiguous windows, <= 9 filtered log calls.
  let windowsSucceeded=0;
  for(const token of TOKENS)for(const w of scope){
   try{
    const logs=await client.tool('get_logs',{address:token.address,
     topics:[approvalTopic,ownerTopic(owner)],fromBlock:String(w.fromBlock),toBlock:String(w.toBlock)});
    if(!Array.isArray(logs))throw Error('MCP get_logs did not return array');
    windowsSucceeded++;
    for(const log of logs.slice(0,180)){
     const found=parseApproval(log,token,owner);
     if(found)events.push(found);
    }
   }catch(e){notes.push(token.symbol+' blocks '+w.fromBlock+'-'+w.toBlock+': '+String(e.message||e).slice(0,120));}
  }
  const candidates=mergeApprovals(events,owner);
  const permissions=[];
  for(const candidate of candidates){
   const token=TOKENS.find(t=>t.symbol===candidate.token);
   let amount=null,spenderType='unknown',reason=null;
   try{
    amount=await allowanceCheck(client,owner,token,candidate.spender);
    if(amount>0n)try{spenderType=await typeOfSpender(client,candidate.spender)}
     catch(e){notes.push('Could not check spender code: '+String(e.message||e).slice(0,100));}
   }catch(e){reason=String(e.message||e).slice(0,155);notes.push('Allowance check failed for '+candidate.token+' / '+candidate.spender);}
   const active=amount!==null&&amount>0n;
   const known=KNOWN_SPENDERS.find(x=>x.token===candidate.token&&x.address.toLowerCase()===candidate.spender.toLowerCase());
   permissions.push({
    token:candidate.token,tokenAddress:token.address,spender:candidate.spender,
    name:known?.name||null,spenderType,
    verification:amount===null?'unavailable':'current-on-chain',active,
    unlimited:active?amount>=HALF:false,
    allowanceRaw:amount===null?null:amount.toString(),
    allowanceDisplay:amount===null?null:active&&amount>=HALF?'Unlimited / near-uint256 maximum':formatUnits(amount,token.decimals),
    lastObservedApprovalBlock:candidate.blockNumber,
    observedTxHash:candidate.transactionHash,
    approvalEventSource:candidate.source,
    allowanceSource:'Chain MCP eth_call allowance(owner, spender) on '+token.symbol,
    reason
   });
  }
  const assessment=assessExposure(permissions,{nonce:nonceCount,balancePROS,contractAccount,errors:notes});
  return {ok:true,owner,chainId:CHAIN_ID,network:'Pharos Mainnet',blockNumber:latest,checkedAtUtc,
   account:{type:contractAccount?'Contract account':'Externally owned address (EOA)',nativeBalancePROS:balancePROS,nonce:nonceCount,
    note:'Nonce measures outgoing tx count, not wallet age or number of incoming transfers.'},
   coverage:{tokens:TOKENS,windows:scope,totalWindows:scope.length*TOKENS.length,windowsSucceeded,
    sampledBlocksPerToken:scope.reduce((sum,w)=>sum+w.toBlock-w.fromBlock+1,0),
    eventsFound:events.length,spenderPairsChecked:permissions.length,
    scope:'Sampled noncontiguous Approval event windows plus live allowance checks for R25 and Zona on USDC. Not full wallet history.'},
   permissions,assessment,errors:notes,source:{name:'Official Pharos Chain MCP',endpoint:ENDPOINT,
    tools:['get_chain_info','get_balance','get_transaction_count','get_code','get_logs','eth_call'],
    github:'https://github.com/PharosNetwork/pharos-mcp'},readOnly:true,
   explorer:EXPLORER+'/address/'+owner};
 }finally{if(client)await client.close().catch(()=>{});}
}
