import { readFileSync } from 'node:fs';
import { validateStructure, checkValidityWindow } from './core/schema.js';
import { resolveDidDocument, findAssertionMethodKey } from './core/resolve.js';
import { verifyEddsaJcs2022, decodeEd25519Multibase } from './core/proof.js';
import { checkStatusEntry } from './core/revocation.js';
import { evaluateMandate } from './core/mandate.js';
import { resolveTransfer } from './core/resolve-transfer.js';
import type {
  ObserverDelegationCredential,
  PolicyContext,
  ResolvedTransfer,
  VerifierConfig,
} from './core/types.js';

// Shared credential-verification + mandate pipeline. Steps 1–5 (load, structure,
// validity, DID-resolve+proof, revocation) are the SAME flow the OWS executable
// runs in main.ts — chain-agnostic, reused unchanged here. Step 6 differs: the
// mppx adapter builds the ResolvedTransfer itself (escrow open) or asks the core
// resolver (generic Tempo tx), and injects the velocity counter via
// ctx.spending. The verdict shape mirrors the executable's.

export interface Verdict {
  allow: boolean;
  reason: string;
  notes: string[];
  cred?: ObserverDelegationCredential;
}

/** Steps 1–5: load + cryptographically verify the delegation credential. On
 * success returns the parsed credential; on failure a deny Verdict. */
export async function verifyCredential(config: VerifierConfig, nowMs: number): Promise<Verdict> {
  const notes: string[] = [];

  let cred: ObserverDelegationCredential;
  try {
    cred = JSON.parse(readFileSync(config.credentialPath, 'utf8')) as ObserverDelegationCredential;
  } catch (e) {
    return { allow: false, reason: `[credential] cannot read ${config.credentialPath}: ${(e as Error).message}`, notes };
  }

  const structure = validateStructure(cred, config);
  if (!structure.ok) return { allow: false, reason: `[schema] ${structure.reason}`, notes };

  const window = checkValidityWindow(cred, nowMs);
  if (!window.ok) return { allow: false, reason: window.reason ?? '[validity] credential not currently valid', notes };

  try {
    const { doc, note } = await resolveDidDocument(cred.issuer, {
      cacheDir: config.cacheDir,
      timeoutMs: config.revocation.fetchTimeoutMs,
      maxStalenessHours: config.didCache.maxStalenessHours,
      offlinePath: config.offline?.didDocumentPath,
    });
    if (note) notes.push(note);
    if (doc.id !== cred.issuer) {
      return { allow: false, reason: `[did] resolved DID document id ${doc.id} does not match issuer ${cred.issuer}`, notes };
    }
    const vmId = cred.proof?.verificationMethod;
    if (!vmId) return { allow: false, reason: '[proof] proof.verificationMethod missing', notes };
    if (!vmId.startsWith(cred.issuer + '#')) {
      return { allow: false, reason: `[proof] verificationMethod ${vmId} is not a key of the issuer ${cred.issuer}`, notes };
    }
    const { entry } = findAssertionMethodKey(doc, vmId);
    if (!entry.publicKeyMultibase) {
      return { allow: false, reason: `[did] verification method ${entry.id} has no publicKeyMultibase`, notes };
    }
    const { key, note: keyNote } = decodeEd25519Multibase(entry.publicKeyMultibase);
    if (keyNote) notes.push(keyNote);
    const proofResult = verifyEddsaJcs2022(cred as unknown as Record<string, unknown>, key);
    notes.push(...proofResult.notes);
    if (!proofResult.ok) return { allow: false, reason: `[proof] ${proofResult.reason}`, notes };
  } catch (e) {
    return { allow: false, reason: `[proof] ${(e as Error).message}`, notes };
  }

  if (cred.credentialStatus && cred.credentialStatus.length > 0) {
    for (const entry of cred.credentialStatus) {
      try {
        const outcome = await checkStatusEntry(entry, config);
        notes.push(...outcome.notes);
        if (outcome.revoked) return { allow: false, reason: `[revocation] ${outcome.detail}`, notes };
      } catch (e) {
        return { allow: false, reason: `[revocation] status could not be established: ${(e as Error).message}`, notes };
      }
    }
  } else {
    notes.push('credential carries no credentialStatus entry — revocation not checkable for this credential');
  }

  return { allow: true, reason: 'credential verified', notes, cred };
}

/** Step 6–7: enforce the mandate against a transfer. `resolvedOverride` is the
 * hand-built transfer for an escrow open; otherwise the core resolver decodes
 * ctx.transaction. `dailyTotalRaw` (raw units of the transfer asset) is injected
 * as ctx.spending so the vendored velocity check runs unchanged. */
export function enforceMandate(
  ctx: PolicyContext,
  cred: ObserverDelegationCredential,
  config: VerifierConfig,
  opts: { resolvedOverride?: ResolvedTransfer; dailyTotalRaw?: bigint },
): Verdict {
  const railDef = config.rails[ctx.chain_id];
  if (!railDef) {
    return { allow: false, reason: `[rails] chain ${ctx.chain_id} has no rail mapping in config.rails`, notes: [] };
  }
  if (opts.dailyTotalRaw !== undefined) {
    ctx = { ...ctx, spending: { daily_total: opts.dailyTotalRaw.toString(), date: ctx.timestamp.slice(0, 10) } };
  }
  const resolved = opts.resolvedOverride ?? resolveTransfer(ctx, railDef, config);
  const mandate = evaluateMandate(ctx, cred, config, resolved);
  if (!mandate.ok) return { allow: false, reason: mandate.reason, notes: mandate.notes };
  return { allow: true, reason: mandate.reason, notes: mandate.notes };
}
