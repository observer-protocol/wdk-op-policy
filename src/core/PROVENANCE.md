# Vendored core — provenance

The files in `src/core/` are vendored **verbatim** from the launched verifier
`@observer-protocol/ows-op-verify` (repo `ows-op-policy`):

- **Source commit:** `6a5df2e203e438355fee7b3615229a28dfc4990c`
- **Vendored:** 2026-06-11

These modules are the chain-agnostic enforcement core — credential structure, DID
resolution, eddsa-jcs-2022 proof verification, revocation, the mandate engine, and the
EVM/Solana transfer resolver. They are **security-critical and must not diverge** between
the two engines (OWS executable and this mppx account).

`soltx.ts` is vendored **inert**: it is imported by `resolve-transfer.ts` so that module
ports with zero edits, but this engine only exercises the EVM (Tempo) path. The Solana
resolver path is unreachable here.

## Drift guard
`npm run check:core-sync` diffs every file in `src/core/` against the same file in a
sibling `../ows-op-policy/src/` checkout and **fails on any difference**. Run it before
publish (`prepublishOnly` does). If the sibling repo is absent, the check warns and skips
(CI must run it where the sibling is present).

## Long-term fix (recommended, post-v1)
Extract these modules into a shared package `@observer-protocol/op-verify-core` consumed
by **both** engines, eliminating the vendored copy. Tracked as a launch-note follow-up —
deliberately deferred so the v1 second-engine artifact ships without restructuring the
already-published OWS package.
