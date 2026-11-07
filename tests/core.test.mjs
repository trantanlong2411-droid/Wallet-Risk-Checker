import test from 'node:test';import assert from 'node:assert/strict';
import {Interface} from 'ethers';
import {normalized,ownerTopic,windows,parseApproval,mergeApprovals,assessExposure,analyze,TOKENS,KNOWN_SPENDERS} from '../src/core.mjs';
const OWNER='0x00000000000000000000000000000000000000A1';
const EOA='0x000000000000000000000000000000000000bEEF';
const MAX=(1n<<256n)-1n;
const approvalTopic='0x8c5be1e5ebec7d5bd14f714f8e9d14f82b9f8983cc85c72e8c5c4fcd39a0a4f';// not used: computed from ethers below
const iface=new Interface(['function allowance(address,address) view returns (uint256)']);
const approveSig=iface.getEvent?.('Approval')?.topicHash||'';
const eventTopic=(await import('ethers')).id('Approval(address,address,uint256)');
const hex=n=>'0x'+BigInt(n).toString(16).padStart(64,'0');
const topic=a=>'0x'+a.toLowerCase().slice(2).padStart(64,'0');
const event=(token,spender,amount=MAX)=>({address:token.address,
 topics:[eventTopic,ownerTopic(OWNER),topic(spender)],data:hex(amount),blockNumber:'0x1550a01',
 transactionHash:'0x'+'a'.repeat(64)});
function client({breakWeth=false}={}){
 const known=KNOWN_SPENDERS[1].address.toLowerCase();
 return async()=>({list:async()=>['get_chain_info','get_balance','get_transaction_count','get_code','get_logs','eth_call'].map(name=>({name})),
 tool:async(name,args={})=>{
  if(name==='get_chain_info')return {chainId:1672,chainIdMatches:true,latestBlock:'22340000'};
  if(name==='get_balance')return {address:OWNER,balanceWei:'1200000000000000000',balance:'1.2',symbol:'PROS'};
  if(name==='get_transaction_count')return {nonce:'40'};
  if(name==='get_code')return {code:args.address.toLowerCase()===OWNER.toLowerCase()||args.address.toLowerCase()===EOA.toLowerCase()?'0x':'0x6000'};
  if(name==='get_logs'){
   if(breakWeth&&args.address.toLowerCase()===TOKENS[2].address.toLowerCase())throw Error('WETH log endpoint unavailable');
   if(args.address.toLowerCase()===TOKENS[0].address.toLowerCase() && Number(args.toBlock)===22340000)
    return [event(TOKENS[0],EOA)];
   return [];
  }
  if(name==='eth_call'){
   const parsed=iface.parseTransaction({data:args.transaction.data});
   if(parsed.name!=='allowance')throw Error('Unexpected method');
   const spender=parsed.args[1].toLowerCase();
   const amount=spender===EOA.toLowerCase()?MAX:spender===known?2000000n:0n;
   return {result:iface.encodeFunctionResult('allowance',[amount])};
  }
  throw Error('Unexpected method '+name);
 },close:async()=>{}});
}
test('validates EVM address without inventing wallet identity',()=>{
 assert.equal(normalized(OWNER.toLowerCase()).toLowerCase(),OWNER.toLowerCase());
 assert.throws(()=>normalized('12345'),/valid/);
 assert.equal(ownerTopic(OWNER).length,66);
});
test('bounded noncontiguous windows stay within 1000 blocks each',()=>{
 const w=windows(22340000);
 assert.equal(w.length,3);
 for(const i of w)assert.equal(i.toBlock-i.fromBlock+1,1000);
 assert.ok(w[0].fromBlock>w[1].toBlock);
});
test('decode indexed ERC20 approval event but do not equate it with current allowance',()=>{
 const a=parseApproval(event(TOKENS[0],EOA),TOKENS[0],OWNER);
 assert.equal(a.spender.toLowerCase(),EOA.toLowerCase());
 assert.equal(a.loggedAmount,MAX.toString());
 const wrong={...event(TOKENS[0],EOA),topics:[eventTopic,ownerTopic('0x00000000000000000000000000000000000000b0'),topic(EOA)]};
 assert.equal(parseApproval(wrong,TOKENS[0],OWNER),null);
});
test('include known spenders even without recent events',()=>{
 const v=mergeApprovals([],OWNER);assert.equal(v.length,2);
 assert.ok(v.every(x=>x.token==='USDC'));
});
test('score warns on active unlimited allowances to EOAs, not empty history',()=>{
 const p=[{token:'USDC',spender:EOA,active:true,unlimited:true,verification:'current-on-chain',spenderType:'EOA',allowanceSource:'live'}];
 const risk=assessExposure(p,{nonce:8,balancePROS:'1',errors:[]});
 assert.equal(risk.score,52);assert.equal(risk.grade,'REVIEW RECOMMENDED');
 assert.ok(risk.signals.some(s=>s.name.includes('Unlimited')));
 const empty=assessExposure([],{nonce:0,balancePROS:'0'});
 assert.equal(empty.score,0);assert.match(empty.cautions.join(' '),/not a safe/);
});
test('analyzes live nonce, balance, approvals, current allowances and spender code',async()=>{
 const v=await analyze({address:OWNER},client());
 assert.equal(v.ok,true);assert.equal(v.chainId,1672);
 assert.equal(v.account.nonce,40);
 assert.equal(v.coverage.windowsSucceeded,9);
 assert.equal(v.assessment.activePermissions,2);
 assert.equal(v.assessment.unlimitedPermissions,1);
 assert.ok(v.permissions.find(p=>p.spender.toLowerCase()===EOA.toLowerCase()).unlimited);
 assert.equal(v.assessment.score,52);
});
test('degraded log source is reported as partial instead of assuming no risk',async()=>{
 const v=await analyze({address:OWNER},client({breakWeth:true}));
 assert.equal(v.ok,true);assert.equal(v.coverage.windowsSucceeded,6);
 assert.equal(v.assessment.confidence,'PARTIAL');
 assert.equal(v.errors.length,3);
});
