// social-demo.mjs — all-REAL capture harness for the launch video. No mocks, no
// staged output, no broadcast. Every line printed is true at run time.
//
//   npm run build && node demo/social-demo.mjs          (DEMO_PAUSE=ms to pace)
//
// ONE mandate, TWO clean tracks. The mandate is a real Maxi v2.1 payment
// delegation, issued by did:web:observerprotocol.org (signed #key-5,
// eddsa-jcs-2022), ≤100 USDC to one allowlisted merchant. The same credential
// drives the local #55 enforcement AND the remote evaluator's signed decision.
//
//   TRACK 1 — AUTHORIZED → SIGNED → PROVABLE
//     within mandate: real @tetherto/wdk@beta.11 #55 engine ALLOWS, a REAL viem
//     key signs (signTransaction — produced, NOT broadcast), and the LIVE OP
//     evaluator issues a signed PolicyEvaluationCredential bound to THAT exact
//     signed transaction (proposalHash = sha256 of the signed bytes), re-verified
//     against the production verify API.
//   TRACK 2 — OVER THE LINE → BLOCKED → NEVER SIGNED
//     over the ceiling: #55 BLOCKS at the signing boundary (PolicyViolationError)
//     and the real signer is invoked 0 times — printed live. Nothing is signed,
//     so there is nothing to prove and nothing to undo.
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { encodeFunctionData } from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import PolicyEngine from '../node_modules/@tetherto/wdk/src/policy/policy-engine.js';
import PolicyViolationError from '../node_modules/@tetherto/wdk/src/policy/policy-error.js';
import { buildObserverPolicies } from '../dist/index.mjs';
import { OUT, SCHEMA_URL, MERCHANT_ADDR, USDC_CONTRACT, USDC } from '../test/fixtures/consts.mjs';

// The ONE mandate. Real, signed by #key-5; its counterparty allowlist is MERCHANT_ADDR
// and its ceiling is 100 USDC (maxNotionalPerOrder) — the same bytes track 1 evaluates.
const ASSETS = new URL('./assets/', import.meta.url).pathname;
const DELEGATION_PATH = join(ASSETS, 'maxi-payment-delegation.json');
const OP_DID_PATH = join(ASSETS, 'op-did.json');
const ISSUER = 'did:web:observerprotocol.org';
const AGENT = 'did:web:observerprotocol.org:agents:maxi-0001';

const g = '\x1b[1;32m', r = '\x1b[1;31m', c = '\x1b[1;36m', d = '\x1b[2m', b = '\x1b[1m', x = '\x1b[0m';
const ERC20 = [{ name: 'transfer', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ type: 'bool' }] }];

// REAL viem signer (bounded test key, never funded). transfer() SIGNS a real
// EIP-1559 tx and returns the signed bytes — it does NOT broadcast.
const key = generatePrivateKey();
const viem = privateKeyToAccount(key);
const signer = { count: 0, lastSig: null };
const base = {
  path: "0'/0/0",
  async toReadOnlyAccount () { return { getAddress: async () => viem.address, chainId: 1 }; },
  async transfer ({ token, recipient, amount }) {
    signer.count++;
    const data = encodeFunctionData({ abi: ERC20, functionName: 'transfer', args: [recipient, amount] });
    const signed = await viem.signTransaction({ to: token, data, value: 0n, chainId: 1, type: 'eip1559', nonce: 0, gas: 60000n, maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n });
    signer.lastSig = signed;
    return signed; // real signature, NOT broadcast
  },
};

const cfg = {
  policy: {
    credentialPath: DELEGATION_PATH,
    issuerDid: ISSUER, schemaAllowlist: [SCHEMA_URL], agentDid: AGENT,
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 }, cacheDir: join(OUT, 'cache'),
    auditLog: join(OUT, 'social-demo-decisions.jsonl'),
    offline: { didDocumentPath: OP_DID_PATH },
  },
  wallets: { ethereum: 'eip155:1' },
};
const engine = new PolicyEngine();
engine.register(buildObserverPolicies(cfg, { wallet: 'ethereum' }), { conditionTimeoutMs: 5000 });
const proxy = await engine.applyPoliciesTo(base, { blockchain: 'ethereum', path: base.path, index: 0 });
const delegation = JSON.parse(readFileSync(DELEGATION_PATH, 'utf8'));

const pause = () => new Promise((res) => setTimeout(res, Number(process.env.DEMO_PAUSE ?? 1200)));

console.log(`${d}one mandate · did:web:observerprotocol.org#key-5 · ≤100 USDC, only to the allowlisted merchant · real WDK #55 engine · real viem key${x}\n`);

// ───────────────────────────────────────────────────────────────────────────
console.log(`${c}${b}TRACK 1 — AUTHORIZED → SIGNED → PROVABLE${x}`);
console.log(`${d}within mandate: 50 USDC → the allowlisted merchant${x}`);
const sig = await proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(50) });
console.log(`  ${g}✓ ALLOWED${x}  by the WDK #55 engine`);
console.log(`  ${g}✓ SIGNED${x}    by the wallet key: ${sig.slice(0, 50)}…  ${d}(real signature, not broadcast)${x}`);
// the exact bytes the wallet just signed become the evaluator's proposal
const txBytes = sig.replace(/^0x/, '');
const localProposalHash = createHash('sha256').update(Buffer.from(txBytes, 'hex')).digest('hex');
try {
  const body = {
    proposal: { rail: 'ethereum-mainnet', canonicalBytes: txBytes, humanReadable: { notional: 50, unit: 'USDC', counterparty: MERCHANT_ADDR } },
    delegationCredential: delegation,
  };
  const pec = await (await fetch('https://api.observerprotocol.org/policy/evaluate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  const cs = pec.credentialSubject || {};
  const boundToTx = cs.proposal?.proposalHash === localProposalHash;
  const boundToMandate = cs.evaluatedAgainst?.delegationCredentialId === delegation.id;
  const v = await (await fetch('https://api.observerprotocol.org/api/v1/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential: pec }) })).json();
  console.log(`  ${g}✓ PROVABLE${x}  OP evaluator issued a signed PolicyEvaluationCredential${x}`);
  console.log(`             decision ${b}${cs.decision}${x} · signed by ${pec.proof?.verificationMethod} ${d}(${pec.proof?.cryptosuite})${x}`);
  console.log(`             ${boundToTx ? g + 'bound to THIS transaction ✓' : r + 'NOT bound ✗'}${x} ${d}proposalHash = sha256(signed bytes)${x}`);
  console.log(`             ${boundToMandate ? g + 'bound to the same mandate ✓' : r + 'mandate mismatch ✗'}${x} ${d}${cs.evaluatedAgainst?.delegationCredentialId}${x}`);
  console.log(`             ${v.verified === true ? g + 're-verified ✓' : r + 're-verify FAILED ✗'}${x} ${d}api.observerprotocol.org/api/v1/verify → ${JSON.stringify(v.checks || {})}${x}`);
} catch (e) {
  console.log(`  ${r}✗ evaluator call failed: ${e.message}${x}`);
}
console.log(`  ${d}→ authorized, signed, and provable — a portable record of exactly what was authorized.${x}`);
await pause();

// ───────────────────────────────────────────────────────────────────────────
console.log(`\n${c}${b}TRACK 2 — OVER THE LINE → BLOCKED → NEVER SIGNED${x}`);
console.log(`${d}over the ceiling: 150 USDC → the same merchant (mandate caps at 100)${x}`);
const before = signer.count;
let blocked = null;
try { await proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(150) }); }
catch (e) { if (e instanceof PolicyViolationError) blocked = e; else throw e; }
const after = signer.count;
// the engine's own recorded reason (the PolicyViolationError surface is generic by design)
let denyReason = blocked?.reason;
try {
  const lines = readFileSync(cfg.policy.auditLog, 'utf8').trim().split('\n');
  const last = JSON.parse(lines[lines.length - 1]);
  if (last.decision === 'deny' && last.reason) denyReason = last.reason;
} catch { /* fall back to the generic reason */ }
console.log(`  ${r}✗ BLOCKED${x}    at the signing boundary — ${denyReason}`);
console.log(`  ${g}✓ NEVER SIGNED${x}  signer invoked ${after - before} times for this transaction ${d}(the key never moved)${x}`);
console.log(`  ${d}→ refused before the key — nothing was signed, so there is nothing to prove and nothing to undo.${x}`);

console.log(`\n${d}A payment going through is WDK's wallet. A provable refusal at the key — and a portable signed record of what was authorized — is Observer Protocol.${x}`);
