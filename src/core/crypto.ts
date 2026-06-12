import { createPublicKey, verify as cryptoVerify, createHash } from 'node:crypto';
import { base58Decode } from './base58.js';

// SPKI DER prefix for a raw Ed25519 public key (RFC 8410).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// Multicodec prefix for ed25519-pub in a Multikey publicKeyMultibase.
const MULTICODEC_ED25519_PUB = Buffer.from([0xed, 0x01]);

/**
 * Decode a publicKeyMultibase string to raw 32-byte Ed25519 key material.
 * Accepts proper Multikey form (z + base58(0xed01 || key)) and, tolerantly,
 * a bare base58-encoded 32-byte key behind 'z' (some early DID documents
 * omitted the multicodec prefix). The tolerance is surfaced to the caller.
 */
export function decodeEd25519Multibase(s: string): { key: Buffer; note?: string } {
  if (!s.startsWith('z')) {
    throw new Error(`publicKeyMultibase must be multibase base58btc (prefix 'z'), got ${JSON.stringify(s.slice(0, 4))}…`);
  }
  const decoded = base58Decode(s.slice(1));
  if (decoded.length === 34 && decoded[0] === MULTICODEC_ED25519_PUB[0] && decoded[1] === MULTICODEC_ED25519_PUB[1]) {
    return { key: decoded.subarray(2) };
  }
  if (decoded.length === 32) {
    return { key: decoded, note: 'publicKeyMultibase lacked the ed25519-pub multicodec prefix; accepted bare 32-byte key' };
  }
  throw new Error(`publicKeyMultibase decodes to ${decoded.length} bytes; expected 34 (multicodec) or 32 (bare)`);
}

export function ed25519Verify(rawPublicKey: Buffer, data: Buffer, signature: Buffer): boolean {
  if (rawPublicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  const keyObject = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
  return cryptoVerify(null, data, keyObject, signature);
}

export function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data).digest();
}
