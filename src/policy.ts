import { createObserverCondition } from './condition.js';
import { OP_DECODED_OPERATIONS, type ObserverWdkConfig, type OpOperation } from './adapter-types.js';

// Public API. The ONLY way to wire OP into WDK — and it ALWAYS emits the
// ALLOW + DENY pair together. There is deliberately no exported path that yields
// a lone ALLOW rule: the DENY companion is the fail-closed backbone (DENY-wins +
// fail-closed-on-throw, robust regardless of what else the consumer registered),
// so shipping ALLOW without it would be a fail-open gate.

export interface ObserverPolicyOptions {
  /** WDK wallet label(s) to govern — the same string(s) passed to registerWallet. */
  wallet: string | string[];
  scope?: 'project' | 'account';
  /** account-scope targeting (derivation paths or indexes). */
  accounts?: Array<string | number>;
  /** operations to gate — defaults to the ops OP decodes (so swap/bridge/etc. are
   * left to the consumer's own rules and not bricked by default-deny). */
  ops?: OpOperation[];
  /** per-condition timeout; defaults to 5000ms (well inside the engine's 30000 default). */
  conditionTimeoutMs?: number;
  idPrefix?: string;
}

/** Build the ALLOW + DENY policy pair (as one array) for `wdk.registerPolicy`. */
export function buildObserverPolicies(cfg: ObserverWdkConfig, opts: ObserverPolicyOptions): unknown[] {
  const pair = createObserverCondition(cfg);
  const ops = opts.ops ?? [...OP_DECODED_OPERATIONS];
  const scope = opts.scope ?? 'project';
  const prefix = opts.idPrefix ?? 'op';
  const common: Record<string, unknown> = { scope, wallet: opts.wallet };
  if (opts.accounts) common.accounts = opts.accounts;

  return [
    {
      ...common,
      id: `${prefix}-delegation`,
      name: 'Observer Protocol delegation (ALLOW — in-mandate)',
      rules: [{ name: 'op-in-mandate', operation: ops, action: 'ALLOW', conditions: [pair.allow] }],
    },
    {
      ...common,
      id: `${prefix}-hardening`,
      name: 'Observer Protocol hardening (DENY — mandatory backbone)',
      rules: [{ name: 'op-violation', operation: ops, action: 'DENY', conditions: [pair.deny] }],
    },
  ];
}

/** Register OP enforcement on a WDK instance. Emits the ALLOW + DENY pair and
 * sets a sane conditionTimeoutMs. Returns the WDK instance for chaining. */
export function registerObserverPolicy<T extends { registerPolicy: (policies: unknown, options?: unknown) => unknown }>(
  wdk: T,
  cfg: ObserverWdkConfig,
  opts: ObserverPolicyOptions,
): T {
  wdk.registerPolicy(buildObserverPolicies(cfg, opts), { conditionTimeoutMs: opts.conditionTimeoutMs ?? 5000 });
  return wdk;
}
