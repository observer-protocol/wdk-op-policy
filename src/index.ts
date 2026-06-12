// @observer-protocol/wdk-op-policy — public API.
//
// Enforce a signed Observer Protocol delegation credential on a Tether WDK
// account, at the signer boundary, fail-closed, via the WDK transaction policy
// engine (PR #55). The API ALWAYS registers an ALLOW + DENY pair together — the
// DENY companion is the mandatory fail-closed backbone.
//
//   import { registerObserverPolicy } from '@observer-protocol/wdk-op-policy';
//   registerObserverPolicy(wdk, {
//     policy: { credentialPath, issuerDid, schemaAllowlist, rails, evmTokens, auditLog },
//     wallets: { ethereum: 'eip155:1' },   // wallet label -> CAIP-2 (must resolve to a rail)
//   }, { wallet: 'ethereum' });

export { buildObserverPolicies, registerObserverPolicy } from './policy.js';
export type { ObserverPolicyOptions } from './policy.js';
export { OP_DECODED_OPERATIONS, ObserverConfigError } from './adapter-types.js';
export type { ObserverWdkConfig, OpOperation, WdkPolicyContext } from './adapter-types.js';
