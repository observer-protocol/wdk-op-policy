# Conformance report — @observer-protocol/wdk-op-policy

**Engine under test:** **`@tetherto/wdk@1.0.0-beta.11`** (npm, `dist.shasum 3739ad7`) — the
first published release carrying PR #55 ("Phase 1 local transaction policy engine").
**Parity confirmed, not assumed:** the same 26 cases were run against the PR #55 merge commit
`tetherto/wdk@a00b391d5d40188db258ee3cf2db248ff915b47d` (github) immediately before re-pinning
to npm beta.11 — **per-case identical, no divergence** (beta.11 carries no behavior change vs
the merge). **Not stubbed:** every case drives a real `PolicyEngine`, a real `applyPoliciesTo`
Proxy, the real OP `ALLOW+DENY` condition pair, and a real signed `ObserverDelegationCredential`
(eddsa-jcs-2022). Reproduce: `npm install && npm test`. Watch one mandate end-to-end:
`npm run verify`.

**Result: 26 / 26 passed (identical on a00b391 and beta.11).**

Mandate under test: ≤ 100 USDC per tx · only to the allowlisted merchant · ≤ 150 USDC/day ·
rail `ethereum-mainnet` (`eip155:1`).

## Core enforcement (per operation)
| # | Case | Expect | Result |
|---|---|---|---|
| 1 | sendTransaction ERC-20 USDC 50 → merchant | ALLOW | PASS |
| 2 | sendTransaction ERC-20 USDC 150 (over ceiling) | BLOCK | PASS |
| 3 | sendTransaction ERC-20 USDC 50 → non-allowlisted | BLOCK | PASS |
| 4 | transfer USDC 50 → merchant | ALLOW | PASS |
| 5 | transfer USDC 50 → non-allowlisted | BLOCK | PASS |
| 6 | approve USDC 50, spender = merchant | ALLOW | PASS |
| 7 | approve USDC 50, spender = non-allowlisted | BLOCK | PASS |
| 8 | signTypedData EIP-2612 Permit USDC 50, spender = merchant | ALLOW | PASS |
| 9 | signTypedData non-Permit (undecodable) | BLOCK | PASS |

## Velocity (cross-tx, counter + replay + concurrency)
| # | Case | Expect | Result |
|---|---|---|---|
| 10 | transfer USDC 80 (#1, under daily cap) | ALLOW | PASS |
| 11 | transfer USDC 80 (#2, trips 150/day cap) | BLOCK | PASS |
| 12 | velocity recovered from audit-log replay (100 + 60 > 150) | BLOCK | PASS |
| 13 | 5 concurrent 40-USDC txs under a 150 cap → exactly 3 allowed (serialized) | 3 ALLOW | PASS |

## Credential integrity
| # | Case | Expect | Result |
|---|---|---|---|
| 14 | expired credential | BLOCK | PASS |
| 15 | tampered credential (signature mismatch) | BLOCK | PASS |
| 16 | revoked credential (status list) | BLOCK | PASS |

## Fail-closed construction (H-3, outage, config)
| # | Case | Expect | Result |
|---|---|---|---|
| 17 | H-3: OP ALLOW+DENY + a broader permissive ALLOW, with a DID-resolver outage | BLOCK (no leak) | PASS |
| 18 | H-3 + a valid in-mandate tx (permissive present) | ALLOW (no false-block) | PASS |
| 19 | runtime: account governed under a wallet label not in `wallets` map | BLOCK (fail closed) | PASS |
| 20 | registration-time: wallet label → CAIP-2 that has no rail | throws `ObserverConfigError` | PASS |
| 21 | fail-closed: base method NOT invoked on a denied op | base not called | PASS |

## signTypedData fail-closed (Permit2 / undecodable)
| # | Case | Expect | Result |
|---|---|---|---|
| 22 | Permit2 `PermitSingle` (verifyingContract = Permit2, amount in `message.details`) | BLOCK (pending decode) | PASS |
| 23 | unknown-contract typed data with `spender`+`value` | BLOCK | PASS |

## Mutex release on throw / timeout (no queue wedge)
| # | Case | Expect | Result |
|---|---|---|---|
| 24 | 4 concurrent evals that THROW (malformed ceiling → enforce throws) | all BLOCK, batch settles | PASS |
| 25 | a tx after the throw-batch still evaluates (lock recovered) | BLOCK promptly (no hang) | PASS |
| 26 | 4 concurrent evals that TIME OUT (150ms resolution vs 30ms cap) | all BLOCK, batch settles | PASS |

## Notes
- The per-subject mutex **releases on a rejected or timed-out evaluation** (the lock advances
  on both resolve and reject), so a throwing/slow tx cannot wedge the queue behind it — every
  following tx still evaluates and fails closed (cases 24–26). Hang-guarded in the test.
- Permit2 / undecodable typed data are **blocked pending decode**, never passed unbounded
  (cases 22–23). EIP-2612 Permit is decoded today (case 8).
- Velocity is **serialized per subject** (promise-chain mutex) so concurrent txs cannot race
  past the cap (case 13). Recovery via shared-path audit-log replay (case 12); fail-closed if
  the log is unreadable.
- The DENY companion is the mandatory fail-closed backbone: uncertainty (case 17) blocks even
  with a permissive baseline present, because DENY-wins and DENY conditions fail closed on
  throw. See `docs/SUPPORT-MATRIX.md` and the cited verification addendum
  (`op-at-specs/feasibility/wdk-op-policy-design-note-2026-06-12.md`).
