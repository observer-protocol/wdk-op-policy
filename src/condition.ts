import { parseConfig, appendAudit, verifyCredential, enforceMandate, CrossRailLedger } from '@observer-protocol/policy-engine';
import type { ObserverDelegationCredential, PolicyContext, VerifierConfig } from '@observer-protocol/policy-engine';
import { resolveTransfer } from './core/resolve-transfer.js';
import { mapContext } from './map-context.js';
import { VelocityCounter, utcDay, type VelocityAuditEntry } from './counter.js';
import { type ObserverWdkConfig, ObserverConfigError, type WdkPolicyContext } from './adapter-types.js';

// The OP condition pair for the WDK policy engine.
//
// `deny` is the BACKBONE (mandatory, primary): it returns true (BLOCK) on any
// outcome that is not a confident, fully-verified in-mandate result — and it
// NEVER swallows uncertainty into a silent false. A thrown error (DID/status
// outage) propagates, which the engine treats as a DENY-rule match (fail-closed,
// DENY-wins) regardless of any other registered rule. `allow` permits only a
// confident in-mandate result. Ship them together (see policy.ts) — `allow`
// without `deny` is a fail-open gate.

export interface ObserverConditionPair {
  /** ALLOW-rule condition: true iff the credential verifies AND the tx is within mandate. */
  allow: (context: WdkPolicyContext) => Promise<boolean>;
  /** DENY-rule condition (primary): true on any violation/uncertainty; throws propagate. */
  deny: (context: WdkPolicyContext) => Promise<boolean>;
  /** Resolved verifier config (for policy.ts). */
  readonly config: VerifierConfig;
}

interface Outcome {
  allow: boolean;
  reason: string;
}

export function createObserverCondition(cfg: ObserverWdkConfig): ObserverConditionPair {
  const config: VerifierConfig = parseConfig(cfg.policy);

  // Registration-time fail-closed: every configured wallet label MUST resolve to
  // a rail. A label→rail that does not resolve is a misconfiguration that could
  // silently check a transfer against the wrong rail — refuse to construct.
  if (!cfg.wallets || Object.keys(cfg.wallets).length === 0) {
    throw new ObserverConfigError('wallets map is required: { <wdk wallet label>: <CAIP-2 chain id> }');
  }
  for (const [label, caip2] of Object.entries(cfg.wallets)) {
    if (!config.rails[caip2]) {
      throw new ObserverConfigError(`wallet label '${label}' maps to ${caip2}, which has no entry in policy.rails — cannot establish the rail; refusing to construct (fail closed).`);
    }
  }

  let counter: VelocityCounter | undefined;
  const counterFor = (subject: string): VelocityCounter => {
    if (!counter) counter = new VelocityCounter(config.auditLog, subject);
    return counter;
  };

  // Shared cross-rail spend ledger (same file the x402/l402 buyer gates use).
  // Absent ledger + crossRailBudget mandate = no counter = fail-closed deny
  // in the shared evaluator.
  const ledger = cfg.crossRailLedgerPath ? new CrossRailLedger(cfg.crossRailLedgerPath) : undefined;

  // The engine evaluates BOTH rules (ALLOW + DENY) per transaction, each calling
  // a condition with the SAME frozen context object. To avoid double-counting
  // velocity (and double-writing audit entries), snapshot the daily total once
  // per context so both conditions see the same pre-tx total, and record the
  // spend exactly once per context.
  const snapByCtx = new WeakMap<object, { total: bigint | undefined; cross?: { total: bigint } | { error: string } }>();
  const countedCtx = new WeakSet<object>();

  // Serialize verify+enforce per condition instance (= per credential = per
  // subject). Without this, two concurrent txs can each snapshot the daily total
  // before either records, racing past a velocity cap. JS is single-threaded but
  // the race window is across the `await` in verification (real network latency
  // widens it). A promise-chain mutex makes the snapshot→enforce→record region
  // atomic per subject, so the cap holds under any interleaving. (Throughput cost
  // is acceptable: a single agent's txs serialize; correctness > parallelism for
  // a money gate.)
  let lock: Promise<unknown> = Promise.resolve();
  const serialized = <T>(fn: () => Promise<T>): Promise<T> => {
    const result = lock.then(fn, fn);
    lock = result.then(() => undefined, () => undefined);
    return result;
  };

  const audit = (e: Partial<VelocityAuditEntry> & Pick<VelocityAuditEntry, 'kind' | 'decision' | 'reason'>): void => {
    appendAudit(config.auditLog, { ts: new Date().toISOString(), notes: [], ...e });
  };

  // Shared verify+enforce. Returns an Outcome. Lets genuine errors THROW
  // (uncertainty) rather than swallowing them — the deny condition relies on it.
  const verifyAndEnforce = (context: WdkPolicyContext): Promise<Outcome> => serialized(() => verifyAndEnforceInner(context));

  async function verifyAndEnforceInner(context: WdkPolicyContext): Promise<Outcome> {
    const caip2 = cfg.wallets[context.wallet];
    if (!caip2) return { allow: false, reason: `[wallet] context.wallet '${context.wallet}' is not in the configured wallets map — rail cannot be established (fail closed)` };
    const railDef = config.rails[caip2];
    if (!railDef) return { allow: false, reason: `[rails] ${caip2} has no rail mapping (fail closed)` };

    // Defense-in-depth: if the (EVM) account exposes a chainId, it must match the
    // configured rail's numeric chain id — else we may be checking the wrong rail.
    const acctChain = context.account?.chainId;
    if (acctChain !== undefined && caip2.startsWith('eip155:')) {
      const expected = caip2.slice('eip155:'.length);
      if (String(acctChain) !== expected) {
        return { allow: false, reason: `[chain-mismatch] account chainId ${acctChain} != configured rail ${caip2} for wallet '${context.wallet}' (fail closed)` };
      }
    }

    const nowIso = new Date().toISOString();
    const nowMs = Date.parse(nowIso);

    const cred = await verifyCredential(config, nowMs); // may throw on a hard internal error → propagates (uncertainty)
    if (!cred.allow || !cred.cred) return { allow: false, reason: cred.reason };
    const credential: ObserverDelegationCredential = cred.cred;
    const subject = credential.credentialSubject.id;

    const walletId = typeof context.account?.getAddress === 'function' ? await context.account.getAddress().catch(() => '') : '';
    const map = mapContext(context.operation, context.params, caip2, walletId ?? '', nowIso, config);
    const resolved = map.resolvedOverride ?? resolveTransfer(map.ctx, railDef, config);
    const asset = resolved.assetSymbol ?? railDef.currency;
    const day = utcDay(nowIso);

    const crb = credential.credentialSubject.tradingMandate?.crossRailBudget;

    const c = counterFor(subject);
    c.recover();
    // Per-context snapshot so the ALLOW and DENY evaluations of the same tx agree
    // and the spend isn't read after a sibling recorded it. The cross-rail total
    // is snapshotted for the same reason.
    let snap = snapByCtx.get(context);
    if (!snap) {
      snap = { total: c.recoveryError ? undefined : c.dailyTotal(asset, day) };
      if (crb && ledger && crb.rates && typeof crb.rates === 'object') {
        const sum = ledger.sumWindowConverted(crb.rates, nowMs);
        snap.cross = sum.ok ? { total: sum.total } : { error: sum.reason };
      }
      snapByCtx.set(context, snap);
    }
    const dailyTotalRaw = snap.total;

    // An unestablishable cross-rail total (unpriceable in-window spend) is an
    // established violation state, never an under-count.
    if (snap.cross && 'error' in snap.cross) {
      return { allow: false, reason: `[cross-rail] ${snap.cross.error}` };
    }

    // Inject velocity + cross-rail state into ctx before the shared enforceMandate.
    let ctxForMandate: PolicyContext = map.ctx;
    if (dailyTotalRaw !== undefined) {
      ctxForMandate = { ...ctxForMandate, spending: { daily_total: dailyTotalRaw.toString(), date: day } };
    }
    if (snap.cross && 'total' in snap.cross && crb) {
      ctxForMandate = { ...ctxForMandate, cross_rail: { total: snap.cross.total.toString(), currency: crb.currency } };
    }
    const verdict = enforceMandate(ctxForMandate, credential, config, resolved);

    if (verdict.allow) {
      // Record the spend ONCE per transaction (not once per condition eval).
      if (resolved.amount !== undefined && resolved.assetSymbol && !countedCtx.has(context)) {
        countedCtx.add(context);
        c.record(asset, day, resolved.amount);
        // Count into the shared cross-rail ledger too — the other rails' gates
        // must see this spend in their next evaluation.
        ledger?.record({ rail: `wdk:${caip2}`, asset: resolved.assetSymbol, amountRaw: resolved.amount.toString(), decimals: resolved.decimals ?? railDef.decimals });
        audit({ kind: 'op-allow', decision: 'allow', reason: verdict.reason, subject_did: subject, asset, amount: resolved.amount.toString(), utc_day: day });
      }
      return { allow: true, reason: verdict.reason };
    }
    return { allow: false, reason: verdict.reason };
  }

  return {
    config,
    allow: async (context) => {
      const o = await verifyAndEnforce(context); // throws propagate -> ALLOW no-match (DENY companion catches)
      return o.allow === true;
    },
    deny: async (context) => {
      // BACKBONE: block on anything that is not a confident allow. Uncertainty
      // (a thrown error) propagates -> DENY-rule fail-closed. Never a silent false.
      const o = await verifyAndEnforce(context);
      if (o.allow === true) return false; // confident in-mandate -> DENY does not fire
      audit({ kind: 'op-deny', decision: 'deny', reason: o.reason });
      return true; // violation OR established uncertainty -> BLOCK
    },
  };
}
