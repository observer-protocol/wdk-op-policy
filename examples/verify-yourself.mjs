// Verify it yourself — watch an Observer Protocol mandate enforced through the
// REAL Tether WDK policy engine (PR #55, merge commit a00b391), end to end.
//
//   npm install && npm run verify
//
// No mocks of the engine: this registers the OP ALLOW+DENY pair via the public
// API onto a real PolicyEngine, wraps a real account in the real policy Proxy,
// and signs a REAL ObserverDelegationCredential's mandate. An in-mandate payment
// is allowed; an over-mandate payment is blocked before the key is reached.
import PolicyEngine from '../node_modules/@tetherto/wdk/src/policy/policy-engine.js';
import PolicyViolationError from '../node_modules/@tetherto/wdk/src/policy/policy-error.js';
import { registerObserverPolicy } from '../dist/index.mjs';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { erc20TransferData } from '../test/fixtures/lib.mjs';
import { OUT, ISSUER, AGENT, SCHEMA_URL, MERCHANT_ADDR, OTHER_ADDR, USDT_CONTRACT, USDT } from '../test/fixtures/consts.mjs';

const g = '\x1b[1;32m', r = '\x1b[1;31m', d = '\x1b[2m', b = '\x1b[1m', x = '\x1b[0m';

// A real WDK account (minimal IWalletAccount): the underlying signer.
const account = {
  path: "0'/0/0",
  async toReadOnlyAccount () { return { getAddress: async () => '0xAGENT', chainId: 1 }; },
  async transfer () { return '0xREAL_SIGNATURE'; }, // the key signs here, only if OP allows
};

// A tiny shim so registerObserverPolicy can target the standalone PolicyEngine
// (the full WDK class wraps engine.register as registerPolicy).
const engine = new PolicyEngine();
const wdkShim = { registerPolicy: (policies, options) => engine.register(policies, options) };

console.log(`${b}Observer Protocol × Tether WDK — verify it yourself${x}`);
console.log(`${d}engine: tetherto/wdk @ a00b391 (PR #55) · credential: signed ObserverDelegationCredential (v2.1)${x}\n`);

// Register OP enforcement. ONE call emits the ALLOW + DENY pair (DENY is the
// mandatory fail-closed backbone). The mandate: <=100 USDT per tx, only to the
// allowlisted merchant, <=150 USDT/day.
registerObserverPolicy(wdkShim, {
  policy: {
    credentialPath: join(OUT, 'cred-wdk-usdt.json'),
    issuerDid: ISSUER, schemaAllowlist: [SCHEMA_URL], agentDid: AGENT,
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 }, cacheDir: join(OUT, 'cache'),
    auditLog: join(mkdtempSync(join(tmpdir(), 'wdk-op-verify-')), 'decisions.jsonl'),
    offline: { didDocumentPath: join(OUT, 'issuer-did.json'), statusListPath: join(OUT, 'status-clean.json') },
  },
  wallets: { ethereum: 'eip155:1' },
}, { wallet: 'ethereum' });

const proxy = await engine.applyPoliciesTo(account, { blockchain: 'ethereum', path: account.path, index: 0 });
const usdtTransfer = (to, whole) => proxy.transfer({ token: USDT_CONTRACT, recipient: to, amount: USDT(whole) });

async function show(label, fn) {
  try { const sig = await fn(); console.log(`${g}ALLOWED${x}  ${label}  ${d}→ key signed: ${sig}${x}`); }
  catch (e) { const why = e instanceof PolicyViolationError ? e.reason : e.message; console.log(`${r}BLOCKED${x}  ${label}  ${d}→ ${why}${x}`); }
}

await show('transfer 50 USDT → allowlisted merchant (in mandate)', () => usdtTransfer(MERCHANT_ADDR, 50));
await show('transfer 150 USDT → merchant (over the 100 ceiling)', () => usdtTransfer(MERCHANT_ADDR, 150));
await show('transfer 50 USDT → a non-allowlisted address', () => usdtTransfer(OTHER_ADDR, 50));

console.log(`\n${d}The enforcement happened inside account.transfer, before the signature — at the key.${x}`);
console.log(`${d}Out-of-mandate and unverifiable calls throw PolicyViolationError; the key never signs.${x}`);
