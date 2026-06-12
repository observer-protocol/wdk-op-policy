// Conformance runner — drives the REAL merged WDK policy engine (a00b391) + a
// real applyPoliciesTo Proxy + the REAL OP condition pair (buildObserverPolicies)
// + a real signed credential. Engine/proxy are not stubbed; the account is a
// minimal real IWalletAccount.
import PolicyEngine from '../node_modules/@tetherto/wdk/src/policy/policy-engine.js';
import PolicyViolationError from '../node_modules/@tetherto/wdk/src/policy/policy-error.js';
import { buildObserverPolicies, ObserverConfigError } from '../dist/index.mjs';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { erc20TransferData } from './fixtures/lib.mjs';
import { OUT, ISSUER, AGENT, SCHEMA_URL, MERCHANT_ADDR, OTHER_ADDR, USDC_CONTRACT, USDC } from './fixtures/consts.mjs';

let pass = 0, fail = 0; const failures = [];
const freshLog = () => join(mkdtempSync(join(tmpdir(), 'wdk-op-')), 'decisions.jsonl');

function makeConfig(cred, { auditLog, statusList = 'status-clean.json', didPath, wallets } = {}) {
  return {
    policy: {
      credentialPath: join(OUT, `cred-${cred}.json`),
      issuerDid: ISSUER, schemaAllowlist: [SCHEMA_URL], agentDid: AGENT,
      revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
      didCache: { maxStalenessHours: 24 }, cacheDir: join(OUT, 'cache'),
      auditLog: auditLog ?? freshLog(),
      offline: { didDocumentPath: didPath ?? join(OUT, 'issuer-did.json'), statusListPath: join(OUT, statusList) },
    },
    wallets: wallets ?? { ethereum: 'eip155:1' },
  };
}
function makeAccount(blockchain = 'ethereum', slowMs = 0) {
  const calls = { n: 0 };
  const sign = async () => { calls.n++; return '0xSIGNED'; };
  const getAddress = async () => { if (slowMs) await new Promise((r) => setTimeout(r, slowMs)); return '0xabc0000000000000000000000000000000000009'; };
  return { calls, blockchain, account: { path: "0'/0/0", async toReadOnlyAccount () { return { getAddress, chainId: 1 }; }, sendTransaction: sign, transfer: sign, approve: sign, signTypedData: sign } };
}
async function governed(cfg, { wallet = 'ethereum', blockchain = 'ethereum', extraPolicies = [], timeout = 5000, slowMs = 0 } = {}) {
  const engine = new PolicyEngine();
  engine.register([...buildObserverPolicies(cfg, { wallet }), ...extraPolicies], { conditionTimeoutMs: timeout });
  const m = makeAccount(blockchain, slowMs);
  const proxy = await engine.applyPoliciesTo(m.account, { blockchain, path: m.account.path, index: 0 });
  return { proxy, calls: m.calls };
}
// fail the test if a batch doesn't settle in `ms` (i.e. the queue wedged behind a throw/timeout)
const withHangGuard = (p, ms, label) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`HANG: ${label} did not settle in ${ms}ms — queue wedged`)), ms))]);
const erc20 = (to, amt) => '0x' + erc20TransferData(to, amt).toString('hex');
const permitTD = (spender, value) => ({ domain: { verifyingContract: USDC_CONTRACT }, types: { Permit: [{ name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }] }, primaryType: 'Permit', message: { spender, value } });

async function allow(name, fn) {
  try { const r = await fn(); if (r === '0xSIGNED') { pass++; console.log(`PASS  allow: ${name}`); } else { fail++; failures.push(`${name}: expected signed, got ${JSON.stringify(r)}`); console.log(`FAIL  allow: ${name}`); } }
  catch (e) { fail++; failures.push(`${name}: expected ALLOW threw ${e.message}`); console.log(`FAIL  allow: ${name}`); }
}
async function deny(name, fn) {
  try { await fn(); fail++; failures.push(`${name}: expected BLOCK but allowed`); console.log(`FAIL  deny:  ${name}`); }
  catch (e) { if (e instanceof PolicyViolationError) { pass++; console.log(`PASS  deny:  ${name}`); } else { fail++; failures.push(`${name}: non-policy error ${e.message}`); console.log(`FAIL  deny:  ${name}`); } }
}

console.log('=== WDK OP adapter — real engine + proxy + condition ===');
// sendTransaction (ERC-20 USDC, resolver path)
await allow('sendTransaction USDC 50 -> merchant', async () => (await governed(makeConfig('wdk-usdc'))).proxy.sendTransaction({ to: USDC_CONTRACT, value: 0n, data: erc20(MERCHANT_ADDR, USDC(50)) }));
await deny('sendTransaction USDC 150 over ceiling', async () => (await governed(makeConfig('wdk-usdc'))).proxy.sendTransaction({ to: USDC_CONTRACT, value: 0n, data: erc20(MERCHANT_ADDR, USDC(150)) }));
await deny('sendTransaction USDC 50 -> non-allowlisted', async () => (await governed(makeConfig('wdk-usdc'))).proxy.sendTransaction({ to: USDC_CONTRACT, value: 0n, data: erc20(OTHER_ADDR, USDC(50)) }));
// transfer
await allow('transfer USDC 50 -> merchant', async () => (await governed(makeConfig('wdk-usdc'))).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(50) }));
await deny('transfer USDC 50 -> non-allowlisted', async () => (await governed(makeConfig('wdk-usdc'))).proxy.transfer({ token: USDC_CONTRACT, recipient: OTHER_ADDR, amount: USDC(50) }));
// approve
await allow('approve USDC 50 spender=merchant', async () => (await governed(makeConfig('wdk-usdc'))).proxy.approve({ token: USDC_CONTRACT, spender: MERCHANT_ADDR, amount: USDC(50) }));
await deny('approve USDC 50 spender=non-allowlisted', async () => (await governed(makeConfig('wdk-usdc'))).proxy.approve({ token: USDC_CONTRACT, spender: OTHER_ADDR, amount: USDC(50) }));
// signTypedData (EIP-2612 Permit)
await allow('signTypedData Permit USDC 50 spender=merchant', async () => (await governed(makeConfig('wdk-usdc'))).proxy.signTypedData(permitTD(MERCHANT_ADDR, USDC(50))));
await deny('signTypedData non-Permit (undecodable) fails closed', async () => (await governed(makeConfig('wdk-usdc'))).proxy.signTypedData({ domain: {}, types: {}, message: {} }));
// velocity (counter) + recovery
await (async () => { const g = await governed(makeConfig('wdk-usdc')); await allow('velocity transfer #1 (80)', () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(80) })); await deny('velocity transfer #2 (80) trips dailyVolumeCap', () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(80) })); })();
await (async () => { const log = freshLog(); const today = new Date().toISOString().slice(0, 10); mkdirSync(join(log, '..'), { recursive: true }); appendFileSync(log, JSON.stringify({ ts: new Date().toISOString(), decision: 'allow', notes: [], kind: 'op-allow', subject_did: AGENT, asset: 'USDC', amount: USDC(100).toString(), utc_day: today }) + '\n'); const g = await governed(makeConfig('wdk-usdc', { auditLog: log })); await deny('velocity recovered from audit-log replay (100+60>150)', () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(60) })); })();
// credential integrity
await deny('expired credential', async () => (await governed(makeConfig('expired'))).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }));
await deny('tampered credential', async () => (await governed(makeConfig('tampered'))).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }));
await deny('revoked credential', async () => (await governed(makeConfig('wdk-usdc', { statusList: 'status-revoked.json' }))).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }));

console.log('\n=== H-3 / outage / fail-closed construction ===');
const permissive = { id: 'permissive', name: 'permissive baseline', scope: 'project', wallet: 'ethereum', rules: [{ name: 'allow-all-sends', operation: ['sendTransaction', 'transfer'], action: 'ALLOW', conditions: [] }] };
// H-3 + verification OUTAGE (missing DID doc): DENY companion must block despite the permissive ALLOW
await deny('H-3 + DID outage -> BLOCKED (no leak)', async () => (await governed(makeConfig('wdk-usdc', { didPath: join(OUT, 'MISSING-did.json') }), { extraPolicies: [permissive] })).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }));
// H-3 + valid in-mandate tx + permissive present -> still ALLOWED (DENY doesn't false-block)
await allow('H-3 + valid in-mandate -> ALLOWED', async () => (await governed(makeConfig('wdk-usdc'), { extraPolicies: [permissive] })).proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(50) }));
// runtime: account governed under a wallet label not in cfg.wallets -> fail closed
await deny('runtime unmapped wallet label -> fail closed', async () => {
  const cfg = makeConfig('wdk-usdc', { wallets: { ethereum: 'eip155:1' } });
  const g = await governed(cfg, { wallet: ['ethereum', 'polygon'], blockchain: 'polygon' });
  return g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) });
});
// registration-time: label -> rail that doesn't resolve -> construction throws
{
  let threw = false;
  try { buildObserverPolicies(makeConfig('wdk-usdc', { wallets: { ethereum: 'eip155:999999' } }), { wallet: 'ethereum' }); }
  catch (e) { threw = e instanceof ObserverConfigError; }
  threw ? pass++ : (fail++, failures.push('registration-time label->rail mismatch did not throw ObserverConfigError'));
  console.log(`${threw ? 'PASS' : 'FAIL'}  registration-time label->rail mismatch -> throws ObserverConfigError`);
}
// fail-closed: base method NOT called on a denied op
await (async () => { const g = await governed(makeConfig('wdk-usdc')); try { await g.proxy.transfer({ token: USDC_CONTRACT, recipient: OTHER_ADDR, amount: USDC(50) }); } catch { /* deny */ } g.calls.n === 0 ? pass++ : (fail++, failures.push('fail-closed: base method ran on a denied op')); console.log(`${g.calls.n === 0 ? 'PASS' : 'FAIL'}  fail-closed: base method NOT called on deny`); })();

console.log('\n=== signTypedData: Permit2 / undecodable must fail closed ===');
// Permit2 PermitSingle: verifyingContract is the Permit2 contract (not a token);
// amount lives in message.details, not message.value -> must NOT pass unbounded.
const permit2TD = {
  domain: { name: 'Permit2', chainId: 1, verifyingContract: '0x000000000022d473030f116ddee9f6b43ac78ba3' },
  types: { PermitDetails: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint160' }], PermitSingle: [{ name: 'details', type: 'PermitDetails' }, { name: 'spender', type: 'address' }] },
  primaryType: 'PermitSingle',
  message: { details: { token: USDC_CONTRACT, amount: USDC(1_000_000).toString() }, spender: OTHER_ADDR },
};
await deny('signTypedData Permit2 (verifyingContract != token) fails closed', async () => (await governed(makeConfig('wdk-usdc'))).proxy.signTypedData(permit2TD));
await deny('signTypedData unknown-contract w/ spender+value fails closed', async () => (await governed(makeConfig('wdk-usdc'))).proxy.signTypedData({ domain: { verifyingContract: '0xdeadbeef00000000000000000000000000000000' }, types: { X: [] }, primaryType: 'X', message: { spender: MERCHANT_ADDR, value: USDC(1).toString() } }));

console.log('\n=== velocity under concurrency ===');
// cap 150; FIVE concurrent 40-USDC txs on the same subject. Serialized
// accumulation => exactly 3 pass (40+40+40=120<=150; 4th=160>150 denied).
await (async () => {
  const g = await governed(makeConfig('wdk-usdc'));
  const settled = await Promise.allSettled(
    Array.from({ length: 5 }, () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(40) })),
  );
  const allowed = settled.filter((s) => s.status === 'fulfilled' && s.value === '0xSIGNED').length;
  if (allowed === 3) pass++;
  else { fail++; failures.push(`concurrency: ${allowed} of 5 concurrent 40-USDC txs allowed under a 150 cap (expected 3 — counter raced)`); }
  console.log(`${allowed === 3 ? 'PASS' : 'FAIL'}  velocity accumulates correctly under concurrency (3 of 5 concurrent 40s, got ${allowed})`);
})();

console.log('\n=== mutex release on throw / timeout (no queue wedge) ===');
// (a) verifyAndEnforce THROWS (malformed ceiling amount -> parseDecimalScaled throws):
//     4 concurrent txs must each BLOCK and the batch must settle (lock releases on reject).
await (async () => {
  const g = await governed(makeConfig('bad-amount'));
  const txs = Array.from({ length: 4 }, () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }).then(() => 'ALLOWED', (e) => (e instanceof PolicyViolationError ? 'BLOCKED' : `ERR:${e.message}`)));
  let results;
  try { results = await withHangGuard(Promise.all(txs), 4000, 'throw-batch'); }
  catch (e) { fail++; failures.push(e.message); console.log(`FAIL  ${e.message}`); return; }
  const allBlocked = results.every((r) => r === 'BLOCKED');
  if (allBlocked) pass++; else { fail++; failures.push(`throw-batch: not all blocked: ${results.join(',')}`); }
  console.log(`${allBlocked ? 'PASS' : 'FAIL'}  mutex releases on THROW: 4 concurrent throwing evals all BLOCK, none hang (${results.join(',')})`);
  // recovery: a subsequent tx on the same proxy still evaluates promptly (lock free)
  try { const r = await withHangGuard(g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }).then(() => 'ALLOWED', (e) => (e instanceof PolicyViolationError ? 'BLOCKED' : `ERR`)), 2000, 'post-throw recovery'); (r === 'BLOCKED') ? pass++ : (fail++, failures.push(`recovery: ${r}`)); console.log(`${r === 'BLOCKED' ? 'PASS' : 'FAIL'}  lock recovers: a tx after the throw-batch still evaluates (got ${r})`); }
  catch (e) { fail++; failures.push(e.message); console.log(`FAIL  ${e.message}`); }
})();
// (b) evaluation TIMES OUT (slow resolution vs a low conditionTimeoutMs): the engine
//     blocks each, and our queue must not wedge — all concurrent txs settle to BLOCK.
await (async () => {
  const g = await governed(makeConfig('wdk-usdc'), { timeout: 30, slowMs: 150 });
  const txs = Array.from({ length: 4 }, () => g.proxy.transfer({ token: USDC_CONTRACT, recipient: MERCHANT_ADDR, amount: USDC(10) }).then(() => 'ALLOWED', (e) => (e instanceof PolicyViolationError ? 'BLOCKED' : `ERR:${e.message}`)));
  let results;
  try { results = await withHangGuard(Promise.all(txs), 5000, 'timeout-batch'); }
  catch (e) { fail++; failures.push(e.message); console.log(`FAIL  ${e.message}`); return; }
  const allBlocked = results.every((r) => r === 'BLOCKED');
  if (allBlocked) pass++; else { fail++; failures.push(`timeout-batch: not all blocked: ${results.join(',')}`); }
  console.log(`${allBlocked ? 'PASS' : 'FAIL'}  mutex releases on TIMEOUT: 4 concurrent slow evals (150ms vs 30ms cap) all BLOCK, none hang (${results.join(',')})`);
})();

console.log(`\nwdk-op-policy conformance: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error('\nFAILURES:'); failures.forEach((f) => console.error('  ✗ ' + f)); process.exit(1); }
