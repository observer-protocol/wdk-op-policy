# Scope & non-goals

## In scope (v1)
- An **ALLOW + DENY policy pair** for the Tether WDK transaction policy engine (PR #55),
  shipped as one unit, enforcing a signed ObserverDelegationCredential (schema v2.1) at the
  signer boundary, fail-closed, before any write op runs.
- **Credential verification** reused verbatim from `@observer-protocol/ows-op-verify`
  (vendored core): issuer pin, schema allowlist, `eddsa-jcs-2022` proof, `did:web`
  resolution, Bitstring status-list revocation.
- **Operations decoded:** `sendTransaction`, `signTransaction`, `transfer`, `approve`,
  `signTypedData` (EIP-2612 Permit).
- **Mandate enforcement:** per-rail ceiling, `maxNotionalPerOrder`, counterparty allow/block,
  temporal windows, and a cross-tx velocity counter (audit-log-recoverable, fail-closed).
- **Fail-closed construction:** DENY backbone (uncertainty → throw/true, never silent
  false), default-deny aware, registration-time + runtime rail-resolution checks.

## Out of scope (v1) — stated, not hidden
- **Not a payment rail, identity registry, or custodian** — the enforcement step between
  "agent decides" and "key signs".
- **signTypedData beyond EIP-2612 Permit** (Permit2, arbitrary typed-data spend) → treated
  as `unenforceable` (deny). Permit2 decode is a follow-up.
- **Non-EVM WDK rails** (TON/TRON/BTC) → identity/unparsed; fail-closed under a binding
  amount/counterparty constraint.
- **Operations OP does not decode** (`swap`/`bridge`/lending/fiat/etc.) — left to the
  consumer's own rules; default-deny blocks them on a governed account unless addressed.
- **Allow-side monthly velocity** (deny-side lower bound only) and **roll-back of an
  OP-counted spend that a foreign DENY later blocks** (conservative over-count instead).
- **Signed audit credential** — v0.1 records decisions to an unsigned local JSONL audit log.
  A cryptographically-signed `PolicyEvaluationCredential` audit artifact (issued by the
  Observer Protocol evaluator, bound to the proposal + delegation hashes) is **roadmap**, not
  yet shipped.
- **Per-trade / live-funds enforcement** — out of scope; a separate concern, neither
  blocked nor opened by this package.

## Relationship to the other engines
The chain-agnostic enforcement core is **vendored byte-identical** from `ows-op-verify`
(drift-guarded). Long-term: extract a shared `@observer-protocol/op-verify-core` consumed by
all three engines (OWS executable, mppx account, WDK policy) — deliberately deferred so each
engine ships without restructuring the published OWS package.

## Release
Built against the PR #55 merge commit and validated against the published
`@tetherto/wdk@1.0.0-beta.11` (parity-identical), 26 conformance cases. The peer dependency
targets the first published build that carries #55 (`>=1.0.0-beta.11`);
develop against the `main` pin until then.
