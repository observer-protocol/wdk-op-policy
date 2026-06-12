import type { ObserverDelegationCredential, VerifierConfig } from './types.js';

// Structural validation derived from schemas/delegation/v2.1.json.
//
// Deliberate deviation, documented: the frozen v2.1 schema's `proof` block
// predates the eddsa-jcs-2022 migration (it pins the legacy suite name).
// This verifier validates the credential BODY against the v2.1 structure
// and verifies the proof cryptographically per W3C VC Data Integrity
// (eddsa-jcs-2022) instead of schema-validating the proof block. Tracked
// upstream in the AIP repo as a spec/implementation alignment item.

const W3C_VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

export function validateStructure(
  cred: ObserverDelegationCredential,
  config: VerifierConfig,
): { ok: true } | { ok: false; reason: string } {
  const fail = (reason: string) => ({ ok: false as const, reason: `structure: ${reason}` });

  if (!Array.isArray(cred['@context']) || !cred['@context'].includes(W3C_VC_V2_CONTEXT)) {
    return fail(`@context must include ${W3C_VC_V2_CONTEXT}`);
  }
  if (typeof cred.id !== 'string' || !(cred.id.startsWith('https://') || cred.id.startsWith('urn:uuid:'))) {
    return fail('id must be an https: or urn:uuid: URI');
  }
  if (!Array.isArray(cred.type) || !cred.type.includes('VerifiableCredential') || cred.type.length < 2) {
    return fail('type must be an array containing VerifiableCredential plus a concrete type');
  }
  if (typeof cred.issuer !== 'string' || !/^did:[a-z]+:.+/.test(cred.issuer)) {
    return fail('issuer must be a DID string');
  }
  if (cred.issuer !== config.issuerDid) {
    return fail(`issuer ${cred.issuer} does not match the pinned trusted issuer ${config.issuerDid}`);
  }
  if (typeof cred.validFrom !== 'string' || typeof cred.validUntil !== 'string') {
    return fail('validFrom and validUntil are required');
  }

  const schemaRef = cred.credentialSchema;
  if (!schemaRef || schemaRef.type !== 'JsonSchema' || typeof schemaRef.id !== 'string') {
    return fail('credentialSchema must be { id, type: "JsonSchema" }');
  }
  if (!config.schemaAllowlist.includes(schemaRef.id)) {
    return fail(
      `credentialSchema.id ${schemaRef.id} is not in the schema allowlist [${config.schemaAllowlist.join(', ')}]`,
    );
  }

  const subject = cred.credentialSubject;
  if (!subject || typeof subject !== 'object') return fail('credentialSubject missing');
  if (typeof subject.id !== 'string' || !/^did:[a-z]+:.+/.test(subject.id)) {
    return fail('credentialSubject.id must be a DID');
  }
  if (config.agentDid && subject.id !== config.agentDid) {
    return fail(`credentialSubject.id ${subject.id} does not match the pinned agent DID ${config.agentDid}`);
  }
  if (!subject.actionScope || typeof subject.actionScope !== 'object') {
    return fail('credentialSubject.actionScope is required');
  }
  if (!subject.delegationScope || typeof subject.delegationScope.may_delegate_further !== 'boolean') {
    return fail('credentialSubject.delegationScope.may_delegate_further is required');
  }
  if (subject.enforcementMode !== 'protocol_native' && subject.enforcementMode !== 'pre_transaction_check') {
    return fail('credentialSubject.enforcementMode must be protocol_native or pre_transaction_check');
  }
  if (subject.authorizationLevel) {
    const levelKey = { 'one-time': 'oneTime', recurring: 'recurring', policy: 'policy' }[subject.authorizationLevel];
    if (!levelKey) return fail(`unknown authorizationLevel ${String(subject.authorizationLevel)}`);
    const cfg = subject.authorizationConfig as Record<string, unknown> | undefined;
    if (!cfg || typeof cfg !== 'object' || !cfg[levelKey]) {
      return fail(`authorizationLevel ${subject.authorizationLevel} requires authorizationConfig.${levelKey}`);
    }
  }

  if (cred.credentialStatus !== undefined && !Array.isArray(cred.credentialStatus)) {
    return fail('credentialStatus must be an array of BitstringStatusListEntry when present');
  }

  return { ok: true };
}

export function checkValidityWindow(
  cred: ObserverDelegationCredential,
  nowMs: number,
): { ok: true } | { ok: false; reason: string } {
  const from = Date.parse(cred.validFrom);
  const until = Date.parse(cred.validUntil);
  if (Number.isNaN(from) || Number.isNaN(until)) {
    return { ok: false, reason: 'validity: validFrom/validUntil are not parseable timestamps' };
  }
  if (nowMs < from) return { ok: false, reason: `validity: credential not yet valid (validFrom ${cred.validFrom})` };
  if (nowMs > until) return { ok: false, reason: `validity: credential expired (validUntil ${cred.validUntil})` };
  return { ok: true };
}
