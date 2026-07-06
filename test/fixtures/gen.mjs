// Conformance fixtures for the WDK OP adapter. Issuer keys + DID doc + status
// lists + delegation credentials with an ethereum-mainnet / USDC mandate. All
// keys generated here; nothing derives from production.
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { newIssuerKeys, signEddsaJcs2022, makeDidDocument, makeStatusList } from './lib.mjs';
import { OUT, ISSUER, AGENT, SCHEMA_URL, SCHEMA_URL_V22, MERCHANT_ADDR, TRON_MERCHANT } from './consts.mjs';

rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, 'cache'), { recursive: true });

const key1 = newIssuerKeys();
const key2 = newIssuerKeys();
const didDoc = makeDidDocument(ISSUER, [
  { fragment: 'key-1', multikey: key1.multikey, assertion: true },
  { fragment: 'key-2', multikey: key2.multikey, assertion: false },
]);
writeFileSync(join(OUT, 'issuer-did.json'), JSON.stringify(didDoc, null, 2));
const VM1 = `${ISSUER}#key-1`, VM2 = `${ISSUER}#key-2`;
writeFileSync(join(OUT, 'status-clean.json'), JSON.stringify(makeStatusList({ issuer: ISSUER, privateKey: key1.privateKey, verificationMethod: VM1, setBits: [], url: 'https://issuer.example/status/1' }), null, 2));
writeFileSync(join(OUT, 'status-revoked.json'), JSON.stringify(makeStatusList({ issuer: ISSUER, privateKey: key1.privateKey, verificationMethod: VM1, setBits: [7], url: 'https://issuer.example/status/1' }), null, 2));

function baseCredential(overrides = {}) {
  const { subject = {}, top = {} } = overrides;
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: ISSUER, validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z',
    credentialSchema: { id: SCHEMA_URL, type: 'JsonSchema' },
    credentialStatus: [{ id: 'https://issuer.example/status/1#7', type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: 'https://issuer.example/status/1' }],
    ...top,
    credentialSubject: {
      id: AGENT, authorizationLevel: 'policy',
      authorizationConfig: { policy: { policy_id: 'wdk-001', rail_preference: ['ethereum-mainnet'] } },
      actionScope: { allowed_rails: ['ethereum-mainnet'], per_transaction_ceiling: { amount: '100', currency: 'USDC' } },
      delegationScope: { may_delegate_further: false }, enforcementMode: 'pre_transaction_check',
      tradingMandate: { unit: 'USDC', counterparty: { allowList: [MERCHANT_ADDR] }, velocity: { dailyVolumeCap: 150 } },
      ...subject,
    },
  };
}
const sign = (c, k = key1.privateKey, vm = VM1) => signEddsaJcs2022(c, k, vm);
const creds = {
  'wdk-usdc': sign(baseCredential()),
  // Public-facing demo credential: same mandate denominated in USDT (the
  // "× Tether WDK" page leads with USDT). Conformance fixtures stay USDC.
  'wdk-usdt': sign(baseCredential({ subject: {
    actionScope: { allowed_rails: ['ethereum-mainnet'], per_transaction_ceiling: { amount: '100', currency: 'USDT' } },
    tradingMandate: { unit: 'USDT', counterparty: { allowList: [MERCHANT_ADDR] }, velocity: { dailyVolumeCap: 150 } },
  } })),
  'no-velocity': sign(baseCredential({ subject: { tradingMandate: { unit: 'USDC', counterparty: { allowList: [MERCHANT_ADDR] } } } })),
  expired: sign(baseCredential({ top: { validUntil: '2026-02-01T00:00:00Z' } })),
  // malformed ceiling amount: passes structure, but parseDecimalScaled() THROWS
  // inside evaluateMandate -> verifyAndEnforce rejects (exercises mutex reject path).
  'bad-amount': sign(baseCredential({ subject: { actionScope: { allowed_rails: ['ethereum-mainnet'], per_transaction_ceiling: { amount: 'not-a-number', currency: 'USDC' } } } })),
  // TRON rail: USDT TRC-20 mandate (structured WDK transfer, exact-case base58 matching).
  'wdk-usdt-tron': sign(baseCredential({ subject: {
    authorizationConfig: { policy: { policy_id: 'wdk-tron', rail_preference: ['usdt-trc20'] } },
    actionScope: { allowed_rails: ['tron:mainnet'], per_transaction_ceiling: { amount: '100', currency: 'USDT' } },
    tradingMandate: { unit: 'USDT', counterparty: { allowList: [TRON_MERCHANT] }, velocity: { dailyVolumeCap: 150 } },
  } })),
  // Cross-rail budget (schema v2.3): one 24h USD budget across TRON + Ethereum +
  // Lightning at principal-attested rates (USDT explicitly 1 — its OWN entry,
  // no implicit peg-equivalence with USDC).
  'wdk-cross-rail': sign(baseCredential({ top: { credentialSchema: { id: SCHEMA_URL_V22, type: 'JsonSchema' } }, subject: {
    authorizationConfig: { policy: { policy_id: 'wdk-cross-rail', rail_preference: ['usdt-trc20'] } },
    actionScope: { allowed_rails: ['tron:mainnet', 'eip155:1', 'lightning'] },
    tradingMandate: { counterparty: { allowList: [TRON_MERCHANT, MERCHANT_ADDR] }, crossRailBudget: { amount: '5', currency: 'USD', window: 'P1D', rates: { USDT: '1', USDC: '1', sat: '0.0005' } } },
  } })),
};
const tampered = JSON.parse(JSON.stringify(creds['wdk-usdc']));
tampered.credentialSubject.actionScope.per_transaction_ceiling.amount = '999999';
creds.tampered = tampered;
for (const [n, c] of Object.entries(creds)) writeFileSync(join(OUT, `cred-${n}.json`), JSON.stringify(c, null, 2));
console.log(`wdk fixtures: ${Object.keys(creds).length} credentials -> ${OUT}`);
