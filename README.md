# Wallet Risk Checker — Pharos Agent Arena

**Live public Cloudflare Worker (verify after deployment):** https://wallet-risk-checker.trantanlong2411.workers.dev/
**Repository:** https://github.com/trantanlong2411-droid/Wallet-Risk-Checker

## What it does

A public, read-only wallet-security dashboard on **Pharos Mainnet (chain ID 1672)**. Enter an EVM wallet address to get an evidence-backed view of:

- Current native PROS balance, outgoing transaction nonce and EOA-versus-contract classification;
- Sampled **ERC-20 Approval** event history for **USDC, WPROS and WETH** using official Pharos **Chain MCP** `get_logs`;
- **Live** `allowance(owner, spender)` via `eth_call` for up to ten discovered/known token-spender pairs, rather than treating old events as proof of still-active permissions;
- Current approvals to two known public USDC venue contracts (R25 and Zona), checked even without a recent Approval event;
- Spender EOA-vs-contract classification via `get_code`;
- Explainable **0–100 observed allowance-exposure index**, associated risk signals, concrete review recommendations, and data provenance with block numbers / transaction hashes when found.

### Important: NOT a full wallet security audit

The server only examines **three disjoint sampled windows of 1,000 blocks each** (9 filtered `get_logs` calls, across 3 tokens), roughly spread over recent blockchain history, plus two directly queried known spender addresses. The scope can **miss years-old or even recent-but-unsampled approvals**. It does not check all tokens, NFTs, Permit2, offline signatures, bridge activity, high-risk counterparties or verified malware indicators.

A score of 0 is NOT an assertion that a wallet is safe or trustworthy. This is **a narrow allowance-exposure heuristic**, not a fraud detector, crime classifier, identity verification, phishing scanner or advice to transfer assets. No external malicious-wallet database is consulted. Some legitimate DeFi applications use unlimited approvals for convenience; flagged approvals warrant review, not an allegation.

## Real data and risk logic

All live observations use official [Pharos Chain MCP](https://github.com/PharosNetwork/pharos-mcp), hosted at `https://mcp.pharos.xyz/mcp`, with `get_chain_info`, `get_balance`, `get_transaction_count`, `get_code`, `get_logs`, and `eth_call`. No synthetic allowance results are inserted into production.

Signals:
- Active **unlimited** allowances verified by current state — higher exposure if spender is an externally owned address.
- Active **finite allowances** to EOAs — prompt user to verify why an EOA can spend their ERC-20.
- Failed/unavailable reads are marked **PARTIAL**, never silently treated as safe.
- Native PROS gas-funding warnings are informational, **not** an allegation of bad conduct.

Scoring illustration:
- +34 for active unlimited allowance to a contract;
- +52 for active unlimited allowance to an EOA;
- +24 for active finite allowance to an EOA;
- capped at 100; results reflect **observed permission exposure only**.

The UI links relevant verified Approval transactions (when observed in sampled windows) and lets reviewers **Copy JSON proof**. No keys, wallet connect, signing, approval or revocation transaction is used.

## How to review

1. Open the public Worker; paste any EVM 0x-address, or select **Use example address** (a third-party public example address whose safety is *not* claimed).
2. Click **Analyze live on-chain risk**. Verify the chain ID, block, balance, nonce, risk index, event coverage and current spender allowance checks.
3. Inspect the two known current USDC spender allowances (R25 and Zona) and any observed token-spender pairs. `No current allowance` is distinct from `Unverified`.
4. Click **Copy JSON proof** to inspect the data and its acknowledged coverage limitations.
5. Read [ARCHITECTURE.md](ARCHITECTURE.md), [reviewer mapping](proof/README.md) and [GitHub Actions evidence](https://github.com/trantanlong2411-droid/Wallet-Risk-Checker/actions).
6. A simulated high-risk allowance test is available in `tests/core.test.mjs`, but this is **explicitly a unit fixture**, never presented as a real risky wallet on production.

## API

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Public dashboard |
| `/api/health` | GET | App metadata and source (doesn't prove upstream availability) |
| `/api/method` | GET | Monitored tokens, known spenders, methodology and limitations |
| `/api/analyze` | POST | `{"address":"0x..."}` → real Chain MCP wallet risk analysis, no writes |

## Local test and Cloudflare deployment

```sh
npm install
npm test
npm run build       # Wrangler dry-run only
npm run smoke       # live Pharos Chain MCP; no wallet or gas needed
npx wrangler deploy # Cloudflare production
```

Cloudflare Workers & Pages → **wallet-risk-checker** → Settings → Builds: connect GitHub repo `trantanlong2411-droid/Wallet-Risk-Checker`, branch `main`, deployment command `npx wrangler deploy`. Check `/api/health` for version `wallet-risk-pharos-2026-11-07-v1`, then use live on-chain verification to confirm actual availability.

## Sources
- [Official hosted Pharos Chain MCP](https://github.com/PharosNetwork/pharos-mcp)
- [Ethereum.org: review and revoke token permissions](https://ethereum.org/guides/how-to-revoke-token-access/)
- [OWASP: approval and allowance security](https://scs.owasp.org/handbooks/09-ux-security/part1-foundations/)
- [Pharos Mainnet token address registry cross-reference](https://github.com/hosein-ul/pharos-rwa-yield-router/blob/main/assets/tokens.json)

No demo video has been created. A real video recording may be provided by the repository owner if the challenge awards optional video points.
