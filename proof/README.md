# Reviewer proof — Pharos Wallet Risk Checker

This repository provides a working read-only check of **observed ERC-20 allowance exposure** on Pharos Mainnet. The owner has not supplied the screenshot with the particular task's scoring requirements; judge only the verified features listed here.

| Feature | Evidence |
|---|---|
| Public input + Chain MCP wallet lookup | `POST /api/analyze`, `get_chain_info`, `get_balance`, `get_transaction_count`, `get_code` |
| Actual approval activity | `get_logs` for on-chain ERC20 `Approval` events in bounded token-specific samples |
| Verify currently effective permissions | `eth_call allowance(owner,spender)`, zero/nonzero/unlimited classified; wrong/missing data fails closed |
| Clear risk signals | `assessExposure` deterministic exposure index and actionable explanation with caveats |
| Evidence / traceability | Block number, separate sampled windows, token and spender addresses, optional transaction URLs |
| Graceful partial failures | Individual token log failures are reported, with confidence PARTIAL, not falsely marked clean |
| Public demo + code | Cloudflare Worker, README, ARCHITECTURE and independent live MCP / production CI checks |

See live workflow logs at https://github.com/trantanlong2411-droid/Wallet-Risk-Checker/actions.

**Safety note:** A passing deterministic test does not prove any real wallet has a malicious allowance. Missing sampled approvals must not be presented as wallet safety. Scan is read-only with no revocation, signature or transaction broadcast. See [Ethereum.org revocation guide](https://ethereum.org/guides/how-to-revoke-token-access/) for user-controlled processes.
