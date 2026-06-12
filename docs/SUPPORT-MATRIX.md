# Support matrix — what this engine enforces, and exactly how

Same discipline as the OWS and mppx engines: nothing claimed that a conformance case does
not prove; partial/inherited enforcement is stated. Validated against the **real merged WDK
policy engine** (`tetherto/wdk` @ `a00b391`) + a real `applyPoliciesTo` Proxy + the real OP
condition — **20 conformance cases pass**.

## Construction — the DENY companion is the backbone
The public API (`registerObserverPolicy` / `buildObserverPolicies`) **always emits an
ALLOW + DENY pair**; there is no exported path to a lone ALLOW. Why (proven against the
engine, see `op-at-specs/feasibility/wdk-failclose-proof/`):
- On a governed (default-deny) account, an **ALLOW** condition that returns false, throws,
  or times out yields a `governed-but-unmatched` BLOCK — fail-closed **on its own**.
- **But** if the consumer also registers a broader permissive ALLOW on the same op (H-3),
  ALLOW-only **leaks**. The **DENY** rule closes it: DENY conditions fail closed on
  throw/timeout and **DENY-wins** regardless of any other rule. Hence DENY is mandatory
  and primary.
- **The DENY condition never swallows uncertainty into a silent false.** It returns `false`
  (does not block) **only** on a confident, fully-verified in-mandate result; every other
  outcome — violation, or any verification uncertainty (DID/status outage, thrown error) —
  returns `true` or propagates the throw → BLOCK. (Conformance: "H-3 + DID outage → BLOCKED".)

## Operations decoded (scoped deliberately)
`params = structuredClone(args[0])` (engine `policy-context.js:47-56`). Shapes confirmed @
`a00b391` vs `tests/wdk-policy.test.js` + `@tetherto/wdk-wallet(-evm)@beta.13`:

| Operation | `params` | Decode |
|---|---|---|
| `sendTransaction` / `signTransaction` | `{ to, value, data? }` | core EVM resolver (native + ERC-20 + EIP-3009) |
| `transfer` | `{ token, recipient, amount }` | token via `evmTokens` registry → amount/recipient |
| `approve` | `{ token, spender, amount }` | allowance = spend authorization to `spender` |
| `signTypedData` | `{ domain, types, message }` | **EIP-2612 Permit** (`verifyingContract`=token, `message.{spender,value}`) |

Anything undecodable (unknown token, missing fields, non-Permit typed data) → `unenforceable`
→ the mandate engine **DENYs** under any binding amount/counterparty constraint.

**Coverage:** OP gates only the operations above. On a governed account every *unaddressed*
write op (`swap`/`bridge`/etc.) is denied by default — register your own rules for those, or
scope OP's `ops` accordingly (default = the decoded set, so they aren't bricked silently).

## Rail resolution (config-by-label, fail-closed)
The WDK read-only account exposes `getAddress()` but **no chainId** (base interface), so OP
resolves the rail from `config.wallets[label] → CAIP-2 → policy.rails`. Guarantees:
- **Registration-time:** a label whose CAIP-2 has no rail throws `ObserverConfigError` —
  refuses to construct (can't silently check against the wrong rail).
- **Runtime:** a `context.wallet` not in the map → fail closed (deny).
- **Defense-in-depth:** if an (EVM) account exposes `chainId` and it disagrees with the
  configured rail → fail closed.

## Velocity counter
- `(subject-DID, UTC-day)` per asset; recovered at startup by replaying the shared
  append-only JSONL audit log; fail-closed if the log is unreadable (a velocity-bearing
  mandate then denies).
- **Per-transaction dedup:** the engine evaluates both rules per tx (each calls a condition
  with the same frozen context); OP snapshots the daily total per context and records the
  spend exactly once — so velocity isn't double-counted and audit replay isn't inflated.
- **Concurrency-safe:** verify+enforce is **serialized per subject** (a promise-chain mutex
  in the condition closure), so two concurrent txs cannot each snapshot under the cap and
  race past it. Proven: 5 concurrent 40-USDC txs under a 150 cap → exactly 3 allowed.
  (Cost: a single subject's txs serialize — correctness over parallelism for a money gate.)
- **No queue wedge:** the mutex lock advances on both resolve **and reject**, so a thrown or
  timed-out evaluation does not block the txs behind it — each still evaluates and fails
  closed, and the lock recovers. Proven: 4 concurrent throwing evals and 4 concurrent
  timed-out evals (150ms vs a 30ms cap) all BLOCK, hang-guarded.
- Monthly caps: deny-side lower-bound only (vendored-core behavior).
- Conservative edge: if a *foreign* DENY blocks a tx OP already counted as allowed, the
  count is not rolled back (over-counts → caps trip earlier; fail-safe direction).

## Timeout
Engine default `conditionTimeoutMs = 30000` (`policy-engine.js:161`); the template sets
`5000`. OP bounds each network fetch at `revocation.fetchTimeoutMs` (default 1500ms), so a
cold DID+status fetch (~3s) fits; pre-warm or use offline paths for the hot path. An
ALLOW-rule timeout resolves to BLOCK (proven).

## Limitations (stated)
- **Permit2 / undecodable signTypedData → BLOCKED pending decode.** `signTypedData` decodes
  **EIP-2612 Permit** only (`verifyingContract` = a known token, `message.{spender,value}`).
  A Permit2 `PermitSingle` (verifyingContract = the Permit2 contract; amount nested in
  `message.details`) and any other/undecodable typed data are treated as `unenforceable` and
  **denied** — never passed unbounded. Proven (conformance: "Permit2 … fails closed",
  "unknown-contract w/ spender+value fails closed"). Permit2-aware decode is a follow-up
  that will *widen* what's allowed, never what's blocked.
- Non-EVM WDK rails (TON/TRON/BTC) are identity/unparsed → fail-closed under a binding
  amount/counterparty constraint (consistent with the core resolver).

## Provenance
Engine surface, default-deny path, ALLOW/DENY fail modes, `conditionTimeoutMs`, and the
`params`/account shapes are cited to `tetherto/wdk@a00b391` and `@tetherto/wdk-wallet(-evm)`
in `op-at-specs/feasibility/wdk-op-policy-design-note-2026-06-12.md` (VERIFICATION ADDENDUM).
Vendored core is byte-identical to `ows-op-verify` (`npm run check:core-sync`).
