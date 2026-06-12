// Fixture-side signing/encoding helpers. Mirrors the verifier's wire
// formats so fixtures are produced independently of the bundled code.
import { createHash, sign as cryptoSign, generateKeyPairSync } from 'node:crypto';
import { gzipSync } from 'node:zlib';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(buf) {
  let acc = 0n;
  for (const b of buf) acc = (acc << 8n) + BigInt(b);
  let out = '';
  while (acc > 0n) {
    out = B58[Number(acc % 58n)] + out;
    acc /= 58n;
  }
  for (const b of buf) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

export function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => jcs(v ?? null)).join(',') + ']';
  const keys = Object.keys(value).sort();
  return (
    '{' +
    keys
      .filter((k) => value[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + jcs(value[k]))
      .join(',') +
    '}'
  );
}

const sha256 = (data) => createHash('sha256').update(data).digest();

export function newIssuerKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const raw = spki.subarray(spki.length - 32);
  const multikey = 'z' + base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
  return { privateKey, raw, multikey };
}

export function signEddsaJcs2022(document, privateKey, verificationMethod) {
  const docNoProof = {};
  for (const [k, v] of Object.entries(document)) if (k !== 'proof') docNoProof[k] = v;
  const proofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2026-06-01T00:00:00Z',
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };
  if ('@context' in docNoProof) proofOptions['@context'] = docNoProof['@context'];
  const hashData = Buffer.concat([
    sha256(Buffer.from(jcs(proofOptions), 'utf8')),
    sha256(Buffer.from(jcs(docNoProof), 'utf8')),
  ]);
  const sig = cryptoSign(null, hashData, privateKey);
  return { ...docNoProof, proof: { ...proofOptions, proofValue: 'z' + base58Encode(sig) } };
}

export function makeDidDocument(did, keys) {
  // keys: [{fragment, multikey, assertion: bool}]
  return {
    id: did,
    verificationMethod: keys.map((k) => ({
      id: `${did}#${k.fragment}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: k.multikey,
    })),
    assertionMethod: keys.filter((k) => k.assertion).map((k) => `${did}#${k.fragment}`),
  };
}

export function makeStatusList({ issuer, privateKey, verificationMethod, setBits = [], url }) {
  const raw = Buffer.alloc(2048); // 16384 bits
  for (const i of setBits) raw[i >> 3] |= 1 << (7 - (i % 8));
  const encodedList = 'u' + gzipSync(raw).toString('base64url');
  const cred = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: url,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer,
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: {
      id: url + '#list',
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList,
    },
  };
  return signEddsaJcs2022(cred, privateKey, verificationMethod);
}

// Minimal RLP encoder + EIP-1559 unsigned-tx builder for raw_hex fixtures.
function rlpBytes(b) {
  if (b.length === 1 && b[0] < 0x80) return b;
  if (b.length < 56) return Buffer.concat([Buffer.from([0x80 + b.length]), b]);
  let lenHex = b.length.toString(16);
  if (lenHex.length % 2) lenHex = '0' + lenHex;
  const lb = Buffer.from(lenHex, 'hex');
  return Buffer.concat([Buffer.from([0xb7 + lb.length]), lb, b]);
}
function pad32hex(hexNoPrefix) { return Buffer.from(hexNoPrefix.padStart(64, '0'), 'hex'); }
export function erc20TransferData(toAddr, amount) {
  return Buffer.concat([Buffer.from('a9059cbb', 'hex'), pad32hex(toAddr.replace(/^0x/, '')), pad32hex(BigInt(amount).toString(16))]);
}
export function eip3009TransferWithAuthData(fromAddr, toAddr, value) {
  return Buffer.concat([Buffer.from('e3ee160e', 'hex'),
    pad32hex(fromAddr.replace(/^0x/, '')), pad32hex(toAddr.replace(/^0x/, '')), pad32hex(BigInt(value).toString(16)),
    pad32hex('0'), pad32hex('0'), pad32hex('0')]);
}
export const USDC_EVM_ETHEREUM = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
function rlpInt(n) {
  if (n === 0n) return rlpBytes(Buffer.alloc(0));
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return rlpBytes(Buffer.from(hex, 'hex'));
}
function rlpList(items) {
  const payload = Buffer.concat(items);
  if (payload.length < 56) return Buffer.concat([Buffer.from([0xc0 + payload.length]), payload]);
  let lenHex = payload.length.toString(16);
  if (lenHex.length % 2) lenHex = '0' + lenHex;
  const lb = Buffer.from(lenHex, 'hex');
  return Buffer.concat([Buffer.from([0xf7 + lb.length]), lb, payload]);
}

export function buildEip1559Tx({ chainId = 1n, to, valueWei, data = Buffer.alloc(0) }) {
  const toBuf = to ? Buffer.from(to.replace(/^0x/, ''), 'hex') : Buffer.alloc(0);
  const body = rlpList([
    rlpInt(chainId), rlpInt(0n), rlpInt(1000000000n), rlpInt(20000000000n), rlpInt(21000n),
    rlpBytes(toBuf), rlpInt(valueWei), rlpBytes(data), rlpList([]),
  ]);
  return '0x02' + body.toString('hex');
}

// --- Solana transaction builders (legacy + v0), zero-dep, for fixtures ------
const B58A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58Decode(s) {
  let n = 0n;
  for (const c of s) { const i = B58A.indexOf(c); if (i < 0) throw new Error('bad b58'); n = n * 58n + BigInt(i); }
  const bytes = [];
  while (n > 0n) { bytes.push(Number(n & 0xffn)); n >>= 8n; }
  bytes.reverse();
  let pad = 0; for (const c of s) { if (c === '1') pad++; else break; }
  return Buffer.concat([Buffer.alloc(pad), Buffer.from(bytes)]);
}
function shortvec(n) {
  const out = [];
  for (;;) { let b = n & 0x7f; n >>>= 7; if (n) { out.push(b | 0x80); } else { out.push(b); break; } }
  return Buffer.from(out);
}
// Known program pubkeys (32 bytes)
export const SOL_SYSTEM = Buffer.alloc(32);
export const SOL_TOKEN = base58Decode('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const SOL_COMPUTE_BUDGET = base58Decode('ComputeBudget111111111111111111111111111111');
export const USDC_MINT = base58Decode('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

function pad32(seedByte) { return Buffer.alloc(32, seedByte); }

// Build a Solana tx. opts.version: 'legacy'|'v0'. instructions: array of
// {programId: Buffer(32), accounts: [Buffer(32)|{alut:true}], data: Buffer}.
// Accounts are deduped into the static account list (signer first). An
// {alut:true} account is placed in the ALUT-loaded range (v0 only) so its
// instruction index points past staticCount.
export function buildSolanaTx({ version = 'legacy', signer, instructions, alutAccounts = [] }) {
  // assemble static account keys: signer, then all program ids + non-alut accounts (deduped)
  const staticKeys = [];
  const keyHex = new Map();
  const addStatic = (buf) => {
    const h = buf.toString('hex');
    if (!keyHex.has(h)) { keyHex.set(h, staticKeys.length); staticKeys.push(buf); }
    return keyHex.get(h);
  };
  addStatic(signer);
  // ALUT accounts occupy indices AFTER all static keys; assign them now (v0)
  const alutIndex = new Map();
  // First pass: register all static (non-alut) accounts + program ids
  for (const ix of instructions) {
    for (const a of ix.accounts) if (!a.alut) addStatic(a);
    addStatic(ix.programId);
  }
  const staticCount = staticKeys.length;
  alutAccounts.forEach((a, i) => alutIndex.set(a.toString('hex'), staticCount + i));

  const idxOf = (a) => {
    if (a.alut) { const h = a.key.toString('hex'); if (!alutIndex.has(h)) throw new Error('alut acct not registered'); return alutIndex.get(h); }
    return keyHex.get(a.toString('hex'));
  };

  const ixBufs = instructions.map((ix) => {
    const prog = keyHex.get(ix.programId.toString('hex'));
    const accIdx = ix.accounts.map(idxOf);
    return Buffer.concat([Buffer.from([prog]), shortvec(accIdx.length), Buffer.from(accIdx), shortvec(ix.data.length), ix.data]);
  });

  const header = Buffer.from([1, 0, staticKeys.length - 1 - /*writable signer*/0 >= 0 ? 1 : 0]); // numReq=1; readonly-unsigned≈1 (program). simplistic; parser ignores values.
  const acctsBuf = Buffer.concat([shortvec(staticKeys.length), ...staticKeys]);
  const blockhash = pad32(9);
  const ixSection = Buffer.concat([shortvec(instructions.length), ...ixBufs]);

  let message;
  if (version === 'v0') {
    // v0 ALUT lookups: one table, writable indexes = alutAccounts positions (dummy)
    const lookups = alutAccounts.length > 0
      ? Buffer.concat([shortvec(1), pad32(7), shortvec(alutAccounts.length), Buffer.from(alutAccounts.map((_, i) => i)), shortvec(0)])
      : shortvec(0);
    message = Buffer.concat([Buffer.from([0x80]), header, acctsBuf, blockhash, ixSection, lookups]);
  } else {
    message = Buffer.concat([header, acctsBuf, blockhash, ixSection]);
  }
  const tx = Buffer.concat([shortvec(1), Buffer.alloc(64), message]);
  return '0x' + tx.toString('hex');
}

export function ixSystemTransfer(from, to, lamports) {
  const data = Buffer.concat([Buffer.from([2, 0, 0, 0]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(lamports)); return b; })()]);
  return { programId: SOL_SYSTEM, accounts: [from, to], data };
}
export function ixSplTransferChecked(source, mint, dest, owner, amount, decimals) {
  const b = Buffer.alloc(10); b[0] = 12; b.writeBigUInt64LE(BigInt(amount), 1); b[9] = decimals;
  return { programId: SOL_TOKEN, accounts: [source, mint, dest, owner], data: b };
}
export function ixSplTransfer(source, dest, owner, amount) {
  const b = Buffer.alloc(9); b[0] = 3; b.writeBigUInt64LE(BigInt(amount), 1);
  return { programId: SOL_TOKEN, accounts: [source, dest, owner], data: b };
}
export function ixComputeBudget() {
  return { programId: SOL_COMPUTE_BUDGET, accounts: [], data: Buffer.from([2, 0x40, 0x42, 0x0f, 0x00]) }; // setComputeUnitLimit
}
export function ixOpaque() {
  return { programId: pad32(0x55), accounts: [], data: Buffer.from([1, 2, 3]) }; // unknown program
}
export const solPubkey = (seed) => pad32(seed);
