import { readFileSync, existsSync } from 'node:fs';
import type { AuditEntry } from './core/types.js';

// Cross-transaction daily velocity counter (the only constraint that needs
// state). Mirrors the mppx engine's approach: an in-process counter recovered at
// startup by replaying the shared append-only JSONL audit log. WDK conditions
// may carry closure state, so the counter lives in the condition closure.
//
// Fail-closed: if the counter cannot be established (audit log unreadable), a
// mandate carrying a velocity cap is denied (the vendored core denies a velocity
// mandate when no spending.daily_total is supplied).

export interface VelocityAuditEntry extends AuditEntry {
  kind: 'op-allow' | 'op-deny';
  subject_did?: string;
  asset?: string;
  amount?: string; // raw token units of the allowed spend
  utc_day?: string;
}

export function utcDay(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10);
}

export class VelocityCounter {
  private readonly auditLog: string;
  private readonly subjectDid: string;
  private daily = new Map<string, bigint>(); // `${asset}|${day}` -> raw total
  private recovered = false;
  recoveryError?: string;

  constructor(auditLog: string, subjectDid: string) {
    this.auditLog = auditLog;
    this.subjectDid = subjectDid;
  }

  private key(asset: string, day: string): string {
    return `${asset}|${day}`;
  }

  recover(): void {
    if (this.recovered) return;
    this.recovered = true;
    if (!existsSync(this.auditLog)) return; // fresh deployment starts at zero
    let lines: string[];
    try {
      lines = readFileSync(this.auditLog, 'utf8').split('\n');
    } catch (e) {
      this.recoveryError = `audit-log replay failed (velocity counter incomplete): ${(e as Error).message}`;
      return;
    }
    for (const line of lines) {
      if (!line.trim()) continue;
      let e: VelocityAuditEntry;
      try {
        e = JSON.parse(line) as VelocityAuditEntry;
      } catch {
        continue;
      }
      if (e.subject_did !== this.subjectDid || e.decision !== 'allow') continue;
      if (e.kind !== 'op-allow' || !e.asset || !e.amount || !e.utc_day) continue;
      try {
        this.add(e.asset, e.utc_day, BigInt(e.amount));
      } catch {
        /* skip corrupt amount */
      }
    }
  }

  private add(asset: string, day: string, amount: bigint): void {
    const k = this.key(asset, day);
    this.daily.set(k, (this.daily.get(k) ?? 0n) + amount);
  }

  dailyTotal(asset: string, day: string): bigint {
    this.recover();
    return this.daily.get(this.key(asset, day)) ?? 0n;
  }

  record(asset: string, day: string, amount: bigint): void {
    this.recover();
    this.add(asset, day, amount);
  }
}
