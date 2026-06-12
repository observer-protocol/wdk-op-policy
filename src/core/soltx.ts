import { base58Encode } from './base58.js';
import { SOLANA_PROGRAMS, SOLANA_BENIGN_PROGRAMS } from './tokens.js';

// Solana transaction parsing from raw_hex. Zero runtime dependencies.
//
// The released OWS engine hands the executable the full serialized
// transaction as raw_hex (verified empirically against ows v1.3.2):
//   [compact-u16 sigCount][sigCount × 64-byte sig][message]
//
// Message — LEGACY:
//   [u8 numRequiredSignatures][u8 numReadonlySigned][u8 numReadonlyUnsigned]
//   [compact-u16 acctCount][acctCount × 32-byte pubkey]
//   [32-byte recentBlockhash][compact-u16 ixCount][instructions]
//
// Message — VERSIONED (v0): identical, but prefixed with one byte whose high
// bit is set: (0x80 | version). After the instructions it carries address
// table lookups:
//   [compact-u16 lookupCount][lookups]
//   lookup = [32-byte tableAddr][compact-u16 nW][nW × u8][compact-u16 nR][nR × u8]
//
// Instruction:
//   [u8 programIdIndex][compact-u16 acctIdxCount][acctIdxCount × u8]
//   [compact-u16 dataLen][dataLen bytes]
//
// ALUT (address lookup table) accounts referenced by a v0 transaction are
// loaded from on-chain tables at runtime and are NOT present in the static
// message. The runtime account list is
//   [static keys][ALUT writable][ALUT readonly]
// so any instruction account index >= staticAccountCount refers to an
// account we cannot see. We surface that as `alutUnresolved` and the caller
// fails closed on any binding constraint that would depend on it (no on-chain
// reads in v1).

export interface SolTransfer {
  kind: 'system' | 'spl-transfer' | 'spl-transfer-checked';
  amount: bigint; // lamports (system) or raw token units (spl)
  destination: string; // base58: wallet (system) or token account (spl)
  source?: string;
  mint?: string; // base58 mint, only for transfer-checked
  decimals?: number; // only for transfer-checked
}

export interface ParsedSolTx {
  version: 'legacy' | 'v0';
  transfers: SolTransfer[]; // fully-resolved recognised value transfers
  benignCount: number; // ComputeBudget / Memo — do not defeat enforcement
  unknownCount: number; // opaque/unhandled instructions (may move value)
  alutUnresolved: number; // instructions needing ALUT-loaded (unseen) accounts
  instructionCount: number;
}

class Reader {
  constructor(private buf: Buffer, public pos = 0) {}
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error('solana: unexpected end of input');
    return this.buf[this.pos++] as number;
  }
  take(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('solana: unexpected end of input');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
  shortvec(): number {
    let val = 0;
    let shift = 0;
    for (;;) {
      const b = this.u8();
      val |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 21) throw new Error('solana: shortvec too long');
    }
    return val >>> 0;
  }
}

const SYSTEM_TRANSFER_IX = 2; // SystemInstruction::Transfer (u32 LE discriminator)
const TOKEN_TRANSFER_IX = 3; // SPL TokenInstruction::Transfer (u8)
const TOKEN_TRANSFER_CHECKED_IX = 12; // SPL TokenInstruction::TransferChecked (u8)

export function parseSolanaRawTx(rawHex: string): ParsedSolTx {
  const hex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) throw new Error('raw_hex is not byte-aligned hex');
  const r = new Reader(Buffer.from(hex, 'hex'));

  // signatures
  const sigCount = r.shortvec();
  r.take(sigCount * 64);

  // version detection
  const b0 = r.u8();
  let version: 'legacy' | 'v0';
  if ((b0 & 0x80) !== 0) {
    const v = b0 & 0x7f;
    if (v !== 0) throw new Error(`unsupported Solana message version ${v}`);
    version = 'v0';
    r.u8(); // numRequiredSignatures
  } else {
    version = 'legacy';
    // b0 was numRequiredSignatures
  }
  r.u8(); // numReadonlySignedAccounts
  r.u8(); // numReadonlyUnsignedAccounts

  // static account keys
  const acctCount = r.shortvec();
  const accounts: string[] = [];
  for (let i = 0; i < acctCount; i++) accounts.push(base58Encode(r.take(32)));
  const staticCount = accounts.length;

  // recent blockhash
  r.take(32);

  // instructions
  const ixCount = r.shortvec();
  const transfers: SolTransfer[] = [];
  let benignCount = 0;
  let unknownCount = 0;
  let alutUnresolved = 0;

  // index into the *static* account list, or null if it points into the
  // ALUT-loaded (unseen) range.
  const acct = (idx: number): string | null => (idx < staticCount ? (accounts[idx] as string) : null);

  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = r.u8();
    const nAccts = r.shortvec();
    const acctIdx: number[] = [];
    for (let j = 0; j < nAccts; j++) acctIdx.push(r.u8());
    const dataLen = r.shortvec();
    const data = r.take(dataLen);

    const programId = acct(programIdIndex);
    if (programId === null) {
      // program itself lives in an ALUT — cannot identify it
      alutUnresolved++;
      continue;
    }
    if (SOLANA_BENIGN_PROGRAMS.has(programId)) {
      benignCount++;
      continue;
    }

    if (programId === SOLANA_PROGRAMS.SYSTEM) {
      if (data.length >= 12 && data.readUInt32LE(0) === SYSTEM_TRANSFER_IX && acctIdx.length >= 2) {
        const from = acct(acctIdx[0] as number);
        const to = acct(acctIdx[1] as number);
        if (from === null || to === null) {
          alutUnresolved++;
          continue;
        }
        transfers.push({ kind: 'system', amount: data.readBigUInt64LE(4), source: from, destination: to });
        continue;
      }
      unknownCount++; // other System instructions (createAccount, transferWithSeed, …) can move lamports
      continue;
    }

    if (programId === SOLANA_PROGRAMS.TOKEN || programId === SOLANA_PROGRAMS.TOKEN_2022) {
      const disc = data.length > 0 ? (data[0] as number) : -1;
      if (disc === TOKEN_TRANSFER_CHECKED_IX && data.length >= 9 && acctIdx.length >= 4) {
        const src = acct(acctIdx[0] as number);
        const mint = acct(acctIdx[1] as number);
        const dest = acct(acctIdx[2] as number);
        if (src === null || mint === null || dest === null) {
          alutUnresolved++;
          continue;
        }
        transfers.push({
          kind: 'spl-transfer-checked',
          amount: data.readBigUInt64LE(1),
          decimals: data.length >= 10 ? (data[9] as number) : undefined,
          source: src,
          mint,
          destination: dest,
        });
        continue;
      }
      if (disc === TOKEN_TRANSFER_IX && data.length >= 9 && acctIdx.length >= 3) {
        const src = acct(acctIdx[0] as number);
        const dest = acct(acctIdx[1] as number);
        if (src === null || dest === null) {
          alutUnresolved++;
          continue;
        }
        transfers.push({ kind: 'spl-transfer', amount: data.readBigUInt64LE(1), source: src, destination: dest });
        continue;
      }
      unknownCount++; // mintTo / burn / approve / closeAccount / … — may move value
      continue;
    }

    unknownCount++; // unknown program
  }

  // v0 address table lookups (parsed to advance the reader + count dynamics)
  if (version === 'v0') {
    const nLookups = r.shortvec();
    for (let i = 0; i < nLookups; i++) {
      r.take(32); // table address
      const nW = r.shortvec();
      r.take(nW);
      const nR = r.shortvec();
      r.take(nR);
    }
  }

  return { version, transfers, benignCount, unknownCount, alutUnresolved, instructionCount: ixCount };
}
