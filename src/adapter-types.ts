// WDK-side adapter types. The runtime is dependency-free; `@tetherto/wdk` is a
// peer dependency used only for its policy types and at test time.

/** The operations OP decodes and gates. Scoped deliberately so a governed
 * account does not brick swap/bridge/etc. (those need the consumer's own rules). */
export const OP_DECODED_OPERATIONS = [
  'sendTransaction',
  'signTransaction',
  'transfer',
  'approve',
  'signTypedData',
] as const;
export type OpOperation = (typeof OP_DECODED_OPERATIONS)[number];

/** The read-only account view the engine passes on the context. Base WDK only
 * guarantees getAddress(); EVM accounts add an optional chainId (used only as a
 * defense-in-depth cross-check, never as the source of truth). */
export interface ReadOnlyAccountLike {
  getAddress?: () => Promise<string>;
  chainId?: number | bigint;
  [k: string]: unknown;
}

/** The frozen PolicyContext WDK hands every condition (policy-context.js:47-56
 * @ a00b391): params = structuredClone(args[0]). */
export interface WdkPolicyContext {
  operation: string;
  wallet: string;
  account: ReadOnlyAccountLike;
  params: unknown;
  args: readonly unknown[];
}

export interface ObserverWdkConfig {
  /** The OP verifier policy object — identical vocabulary to the OWS/mppx engines
   * (parsed by the vendored core parseConfig): credentialPath, issuerDid,
   * schemaAllowlist, rails, evmTokens, revocation, auditLog, etc. */
  policy: Record<string, unknown>;
  /** Map of WDK wallet label (the `context.wallet` registration identifier) →
   * CAIP-2 chain id. Each CAIP-2 MUST resolve to a rail in policy.rails — checked
   * at construction; a label/context with no resolvable rail FAILS CLOSED. */
  wallets: Record<string, string>;
  /** Path to the shared cross-rail spend ledger (CrossRailLedger JSONL — the
   * same file the x402 and l402 buyer gates use). When set, it feeds the
   * cross-rail budget counter before every evaluation and every ALLOWED spend
   * is recorded into it (rail label `wdk:<caip2>`). A mandate carrying
   * tradingMandate.crossRailBudget with no ledger configured fails closed
   * (no counter can be established). */
  crossRailLedgerPath?: string;
}

export class ObserverConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ObserverConfigError';
  }
}
