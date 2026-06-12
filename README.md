# @observer-protocol/wdk-op-policy

Enforce a **signed Observer Protocol delegation credential** on a Tether **WDK** account —
at the signer boundary, fail-closed — via the WDK transaction policy engine
([tetherto/wdk #55](https://github.com/tetherto/wdk/pull/55)).

The third Observer Protocol enforcement engine. Same credential, same mandate vocabulary,
same vendored core as the OWS verifier and the mppx account — here as a pair of WDK
policy rules. **The API always registers an ALLOW + DENY pair together**: the DENY
companion is the mandatory fail-closed backbone (DENY-wins + fail-closed-on-throw), so it
holds regardless of what else the consumer registered.

## Install
```sh
npm install @observer-protocol/wdk-op-policy @tetherto/wdk
```
Requires `@tetherto/wdk >= 1.0.0-beta.11` — the first published release carrying the
transaction policy engine (PR #55). Verified against `1.0.0-beta.11` (see
[`docs/CONFORMANCE.md`](docs/CONFORMANCE.md)).

## Use
```ts
import { registerObserverPolicy } from '@observer-protocol/wdk-op-policy';

registerObserverPolicy(wdk, {
  policy: {
    credentialPath: '~/.op/agent-delegation.json',     // the signed ObserverDelegationCredential
    issuerDid: 'did:web:observerprotocol.org',
    schemaAllowlist: ['https://observerprotocol.org/schemas/delegation/v2.1.json'],
    agentDid: 'did:web:observerprotocol.org:agents:my-agent',
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    auditLog: '~/.op/decisions.jsonl',
    // evmTokens / rails as needed; defaults cover mainnet USDC/USDT
  },
  wallets: { ethereum: 'eip155:1' },                   // wallet label -> CAIP-2 (MUST resolve to a rail)
}, { wallet: 'ethereum' });

// Every write op on the governed account now verifies the mandate before signing.
// Out-of-mandate / unverifiable -> PolicyViolationError; the key never signs.
```

`registerObserverPolicy` emits two rules — an **ALLOW** (in-mandate) and a **DENY**
(violation/uncertainty). Do **not** hand-author a lone ALLOW, and **never** pair OP with a
broad permissive wildcard `ALLOW` on the same operations without the DENY — that reopens a
fail-open hole (proven; see SUPPORT-MATRIX).

## What it enforces
Gates `sendTransaction`, `signTransaction`, `transfer`, `approve`, `signTypedData` against
per-rail ceiling, counterparty, temporal window, and cross-tx velocity. Exact decode per
operation, the fail-closed construction, rail resolution, and limitations are in
[`docs/SUPPORT-MATRIX.md`](docs/SUPPORT-MATRIX.md); scope/non-goals in
[`docs/SCOPE.md`](docs/SCOPE.md).

## Security model
- **Fail-closed:** uncertainty (DID/status outage, thrown verification, timeout) blocks —
  the DENY condition never resolves uncertainty to a silent allow.
- **Default-deny aware:** OP relies on the engine's default-deny on governed accounts, and
  the DENY backbone holds even alongside a permissive baseline.
- **Enforcement locus:** the signer boundary, from the actual operation params — portable
  across OWS, mppx, and WDK. *The binding layer is contested; the enforcement locus is not.*
- Validated against the **published engine** (`@tetherto/wdk@1.0.0-beta.11`), 26 conformance cases.

## Develop
```sh
npm test                  # typecheck + build + fixtures + 26 conformance cases (real engine)
npm run check:core-sync   # vendored core must match ows-op-verify byte-for-byte
```
MIT.
