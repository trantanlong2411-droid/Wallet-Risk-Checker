import {mkdir,writeFile} from 'node:fs/promises';
import {analyze} from '../src/core.mjs';
const wallet=process.env.DEMO_WALLET||'0xfaC0718D882E5f07e1972D617bd430CD72A55D84';
const report=await analyze({address:wallet});
const proof={schema:'pharos-wallet-risk-chain-mcp-v1',checkedAtUtc:new Date().toISOString(),wallet,
 chainId:report.chainId,blockNumber:report.blockNumber,
 balancePROS:report.account.nativeBalancePROS,nonce:report.account.nonce,
 accountType:report.account.type,
 monitoredTokens:report.coverage.tokens.map(x=>x.symbol),windows:report.coverage.windows,
 windowsSucceeded:report.coverage.windowsSucceeded,totalWindows:report.coverage.totalWindows,
 approvalsObserved:report.coverage.eventsFound,permissions:report.permissions.map(p=>({
 token:p.token,spender:p.spender,verification:p.verification,active:p.active,unlimited:p.unlimited,
 spenderType:p.spenderType,allowanceRaw:p.allowanceRaw
 })),exposureIndex:report.assessment.score,grade:report.assessment.grade,
 warning:'Read-only sampled analysis only; cannot certify safety or enumerate all past approvals.'};
if(report.chainId!==1672||report.coverage.windowsSucceeded===0)throw Error('No verified Pharos Mainnet log windows');
await mkdir('proof',{recursive:true});
await writeFile('proof/live-chain-proof.json',JSON.stringify(proof,null,2)+'\n');
console.log('WALLET_RISK_LIVE_MCP_SUCCESS',JSON.stringify(proof));
