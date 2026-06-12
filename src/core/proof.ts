import { jcsBytes } from './jcs.js';
import { sha256, ed25519Verify, decodeEd25519Multibase } from './crypto.js';
import { base58Decode } from './base58.js';
import type { DataIntegrityProof } from './types.js';

const PROOF_TYPE = 'DataIntegrityProof';
const CRYPTOSUITE = 'eddsa-jcs-2022';

export interface ProofCheckResult {
  ok: boolean;
  reason: string;
  notes: string[];
}

/**
 * Verify a DataIntegrityProof / eddsa-jcs-2022 signature per W3C VC Data
 * Integrity (EdDSA Cryptosuites §3.3):
 *
 *   hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
 *
 * where proofConfig is the proof block minus proofValue. Implements the
 * spec's context-binding check: when the proof carries @context, the
 * document's @context must start with it in identical order and the
 * effective document @context for hashing becomes proof.@context.
 *
 * Legacy suites (Ed25519Signature2020/2026) are rejected outright — this
 * verifier implements the post-migration Observer Protocol signing surface
 * only.
 */
export function verifyEddsaJcs2022(
  document: Record<string, unknown>,
  rawPublicKey: Buffer,
): ProofCheckResult {
  const notes: string[] = [];
  const proof = document['proof'] as DataIntegrityProof | undefined;
  if (!proof || typeof proof !== 'object') {
    return { ok: false, reason: 'credential has no proof block', notes };
  }
  if (proof.type !== PROOF_TYPE) {
    return {
      ok: false,
      reason: `proof.type must be ${PROOF_TYPE} (got ${JSON.stringify(proof.type)}); legacy suites are not accepted`,
      notes,
    };
  }
  if (proof.cryptosuite !== CRYPTOSUITE) {
    return {
      ok: false,
      reason: `proof.cryptosuite must be ${CRYPTOSUITE} (got ${JSON.stringify(proof.cryptosuite)})`,
      notes,
    };
  }
  if (proof.proofPurpose !== 'assertionMethod') {
    return { ok: false, reason: `proof.proofPurpose must be assertionMethod (got ${JSON.stringify(proof.proofPurpose)})`, notes };
  }
  if (!proof.created || !proof.verificationMethod || typeof proof.proofValue !== 'string') {
    return { ok: false, reason: 'proof must carry created, verificationMethod, and proofValue', notes };
  }
  if (!proof.proofValue.startsWith('z')) {
    return { ok: false, reason: "proof.proofValue must be multibase base58btc (prefix 'z')", notes };
  }
  let signature: Buffer;
  try {
    signature = base58Decode(proof.proofValue.slice(1));
  } catch (e) {
    return { ok: false, reason: `proof.proofValue decode failed: ${(e as Error).message}`, notes };
  }
  if (signature.length !== 64) {
    return { ok: false, reason: `Ed25519 signature must be 64 bytes (got ${signature.length})`, notes };
  }

  const documentNoProof: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(document)) if (k !== 'proof') documentNoProof[k] = v;

  // Context binding (spec §3.3 verifier step 4).
  if ('@context' in proof) {
    const proofCtx = Array.isArray(proof['@context']) ? proof['@context'] : [proof['@context']];
    const docCtxRaw = documentNoProof['@context'];
    const docCtx = Array.isArray(docCtxRaw) ? docCtxRaw : docCtxRaw !== undefined ? [docCtxRaw] : [];
    if (docCtx.length < proofCtx.length) {
      return { ok: false, reason: 'document.@context does not start with proof.@context', notes };
    }
    for (let i = 0; i < proofCtx.length; i++) {
      if (docCtx[i] !== proofCtx[i]) {
        return { ok: false, reason: 'document.@context does not start with proof.@context', notes };
      }
    }
    documentNoProof['@context'] = proof['@context'];
  }

  const proofConfig: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(proof)) if (k !== 'proofValue') proofConfig[k] = v;

  const hashData = Buffer.concat([sha256(jcsBytes(proofConfig)), sha256(jcsBytes(documentNoProof))]);
  let valid: boolean;
  try {
    valid = ed25519Verify(rawPublicKey, hashData, signature);
  } catch (e) {
    return { ok: false, reason: `signature verification errored: ${(e as Error).message}`, notes };
  }
  return valid
    ? { ok: true, reason: 'ok', notes }
    : { ok: false, reason: 'eddsa-jcs-2022 signature does not verify against the issuer key', notes };
}

export { decodeEd25519Multibase };
