import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditEntry } from './types.js';

// Unsigned append-only JSONL decision log (ratified v1 shape; signed
// PolicyEvaluationCredential emission with a published instance key is a
// v1.x candidate). Logging must never change the verdict: failures are
// swallowed and reported back to the caller as a note.

export function appendAudit(path: string, entry: AuditEntry): string | undefined {
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, JSON.stringify(entry) + '\n', { mode: 0o600 });
    return undefined;
  } catch (e) {
    return `audit log write failed: ${(e as Error).message}`;
  }
}
