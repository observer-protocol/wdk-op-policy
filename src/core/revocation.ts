import { gunzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { cachedFetch, resolveDidDocument, findAssertionMethodKey } from './resolve.js';
import { verifyEddsaJcs2022, decodeEd25519Multibase } from './proof.js';
import type { BitstringStatusListEntry, VerifierConfig } from './types.js';

// W3C Bitstring Status List checking.
//
// Ratified behavior: refresh-first within the fetch timeout; on refresh
// failure serve from cache if younger than revocation.maxStalenessHours
// (default 24, always written explicitly by the policy template); DENY when
// older or absent. A set bit (revoked/suspended) always denies.

function decodeEncodedList(encoded: string): Buffer {
  // W3C encodes as multibase base64url-no-pad ('u' prefix); some issuers
  // emit bare base64url. Accept both, preferring the prefixed form.
  const candidates = encoded.startsWith('u') ? [encoded.slice(1), encoded] : [encoded];
  let lastError: Error | undefined;
  for (const candidate of candidates) {
    try {
      const compressed = Buffer.from(candidate, 'base64url');
      return gunzipSync(compressed);
    } catch (e) {
      lastError = e as Error;
    }
  }
  throw new Error(`encodedList decode failed: ${lastError?.message}`);
}

function getBit(raw: Buffer, index: number): number {
  const total = raw.length * 8;
  if (index < 0 || index >= total) {
    throw new Error(`status list index ${index} out of range [0, ${total})`);
  }
  // W3C bit ordering: bit 0 is the most significant bit of byte 0.
  const byte = raw[index >> 3] as number;
  return (byte >> (7 - (index % 8))) & 1;
}

export interface RevocationCheckOutcome {
  revoked: boolean;
  detail: string;
  notes: string[];
}

export async function checkStatusEntry(
  entry: BitstringStatusListEntry,
  config: VerifierConfig,
): Promise<RevocationCheckOutcome> {
  const notes: string[] = [];

  if (entry.type !== 'BitstringStatusListEntry') {
    throw new Error(`unsupported credentialStatus type ${JSON.stringify(entry.type)}`);
  }
  const index = Number.parseInt(entry.statusListIndex, 10);
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`statusListIndex must be a non-negative integer string, got ${JSON.stringify(entry.statusListIndex)}`);
  }

  let body: string;
  if (config.offline?.statusListPath) {
    body = readFileSync(config.offline.statusListPath, 'utf8');
    notes.push(`status list loaded from offline override ${config.offline.statusListPath}`);
  } else {
    const res = await cachedFetch(
      entry.statusListCredential,
      config.cacheDir,
      config.revocation.fetchTimeoutMs,
      config.revocation.maxStalenessHours,
    );
    if (res.note) notes.push(res.note);
    body = res.body;
  }

  const listCredential = JSON.parse(body) as Record<string, unknown>;

  const types = listCredential['type'];
  if (!Array.isArray(types) || !types.includes('BitstringStatusListCredential')) {
    throw new Error('status list credential type must include BitstringStatusListCredential');
  }
  const listIssuer = listCredential['issuer'];
  if (listIssuer !== config.issuerDid) {
    throw new Error(
      `status list credential issuer ${JSON.stringify(listIssuer)} does not match the pinned issuer ${config.issuerDid}`,
    );
  }

  // The status list credential is itself a signed VC — verify its proof
  // against the same pinned issuer's DID document.
  const { doc, note } = await resolveDidDocument(config.issuerDid, {
    cacheDir: config.cacheDir,
    timeoutMs: config.revocation.fetchTimeoutMs,
    maxStalenessHours: config.didCache.maxStalenessHours,
    offlinePath: config.offline?.didDocumentPath,
  });
  if (note) notes.push(note);
  const proof = listCredential['proof'] as { verificationMethod?: string } | undefined;
  if (!proof?.verificationMethod) {
    throw new Error('status list credential has no proof.verificationMethod');
  }
  const { entry: vm } = findAssertionMethodKey(doc, proof.verificationMethod);
  if (!vm.publicKeyMultibase) {
    throw new Error(`verification method ${vm.id} has no publicKeyMultibase`);
  }
  const { key, note: keyNote } = decodeEd25519Multibase(vm.publicKeyMultibase);
  if (keyNote) notes.push(`status list issuer key: ${keyNote}`);
  const proofResult = verifyEddsaJcs2022(listCredential, key);
  if (!proofResult.ok) {
    throw new Error(`status list credential proof invalid: ${proofResult.reason}`);
  }

  const subject = listCredential['credentialSubject'] as
    | { type?: string; statusPurpose?: string; encodedList?: string }
    | undefined;
  if (subject?.type !== 'BitstringStatusList') {
    throw new Error('status list credentialSubject.type must be BitstringStatusList');
  }
  if (subject.statusPurpose !== entry.statusPurpose) {
    throw new Error(
      `statusPurpose mismatch: entry says ${entry.statusPurpose}, list says ${String(subject.statusPurpose)}`,
    );
  }
  if (typeof subject.encodedList !== 'string') {
    throw new Error('status list credentialSubject.encodedList missing');
  }

  const raw = decodeEncodedList(subject.encodedList);
  const bit = getBit(raw, index);
  if (bit === 1) {
    return {
      revoked: true,
      detail: `credential is ${entry.statusPurpose === 'suspension' ? 'suspended' : 'revoked'} (status list index ${index})`,
      notes,
    };
  }
  return { revoked: false, detail: `status clear (purpose ${entry.statusPurpose}, index ${index})`, notes };
}
