// OWS-side wire types — the executable contract.
// Per open-wallet-standard/core docs/03-policy-engine.md: full PolicyContext
// arrives as one JSON object on stdin; exactly one PolicyResult JSON object
// must be written to stdout. Non-zero exit, malformed output, or a 5-second
// timeout all deny.

export interface OwsTransaction {
  to?: string;
  value?: string; // wei (or rail-native integer) as decimal string — EVM parsed
  data?: string;
  raw_hex?: string;
}

export interface OwsSpending {
  daily_total?: string; // cumulative value signed today (wei), per API key
  date?: string;
}

export interface OwsTypedData {
  verifying_contract?: string;
  domain_chain_id?: string | number;
  primary_type?: string;
  domain_name?: string;
  domain_version?: string;
  raw_json?: unknown;
}

export interface PolicyContext {
  chain_id: string; // CAIP-2
  wallet_id: string;
  api_key_id: string;
  transaction: OwsTransaction;
  spending?: OwsSpending;
  timestamp: string;
  typed_data?: OwsTypedData;
  policy_config?: unknown;
}

export interface PolicyResult {
  allow: boolean;
  reason?: string;
}

// Observer Protocol credential shapes — mirrors
// @observer-protocol/policy-interface and schemas/delegation/v2.1.json.

export interface DataIntegrityProof {
  type: string; // "DataIntegrityProof"
  cryptosuite?: string; // "eddsa-jcs-2022"
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  '@context'?: unknown;
}

export interface BitstringStatusListEntry {
  id: string;
  type: string; // "BitstringStatusListEntry"
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
}

export interface PerTransactionCeiling {
  amount: string;
  currency: string;
}

export interface ActionScope {
  allowed_rails?: string[];
  per_transaction_ceiling?: PerTransactionCeiling;
  allowed_transaction_categories?: string[];
  cumulative_budget?: { amount: string; currency: string; window: string };
  allowed_counterparty_types?: string[];
  geographic_restriction?: { allowed?: string[]; disallowed?: string[] };
}

export interface AuthorizationConfig {
  oneTime?: {
    counterparty_did: string;
    amount: string;
    currency: string;
    rail: string;
    execution_deadline?: string;
    purchase_description?: string;
  };
  recurring?: {
    counterparty_did: string;
    ceiling_amount: string;
    ceiling_currency: string;
    per_transaction_max?: string;
    period: string;
    valid_until?: string;
    allowed_rails?: string[];
  };
  policy?: {
    policy_id: string;
    rail_preference: string[];
    per_rail_caps?: Record<
      string,
      { per_transaction?: string; aggregate?: string; period?: string; currency?: string }
    >;
    escalation_threshold?: { amount?: string; currency?: string };
  };
}

export interface TradingMandate {
  allowedVenues?: string[];
  allowedInstruments?: string[];
  maxNotionalPerOrder?: number;
  maxPosition?: number;
  unit?: string;
  dailyDrawdownCap?: { limit: number; type: 'percent' | 'absolute'; window: string };
  counterparty?: {
    allowList?: string[];
    blockList?: string[];
    requireIssuerClassIn?: string[];
  };
  temporal?: {
    allowedTimeWindows?: Array<{
      start: string;
      end: string;
      timezone: string;
      daysOfWeek?: string[];
    }>;
  };
  geographic?: {
    blockedJurisdictions?: string[];
    allowedJurisdictionsOnly?: string[];
  };
  velocity?: { dailyVolumeCap?: number; monthlyVolumeCap?: number };
}

export interface DelegationCredentialSubject {
  id: string;
  authorizationLevel?: 'one-time' | 'recurring' | 'policy';
  authorizationConfig?: AuthorizationConfig;
  actionScope: ActionScope;
  delegationScope: { may_delegate_further: boolean };
  acl?: unknown;
  enforcementMode: string;
  parentDelegationId?: string | null;
  kybCredentialId?: string | null;
  tradingMandate?: TradingMandate;
}

export interface ObserverDelegationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: DelegationCredentialSubject;
  credentialSchema: { id: string; type: string };
  credentialStatus?: BitstringStatusListEntry[];
  proof: DataIntegrityProof;
}

// Configuration injected via the OWS policy file's `config` object
// (arrives as PolicyContext.policy_config). Every behavioral knob is
// explicit here and documented in the README — no quiet defaults for
// staleness behavior: the shipped policy template always writes
// `revocation.maxStalenessHours` and `revocation.onUnreachable` out loud.

export interface RailDef {
  rail: string; // Observer Protocol rail name, e.g. "ethereum-mainnet"
  currency: string; // rail-native unit for transaction.value, e.g. "ETH"
  decimals: number; // scale of transaction.value relative to `currency`
  family: 'evm' | 'solana' | 'other'; // payload-parsing family
}

export interface TokenDefConfig {
  symbol: string;
  decimals: number;
}

// The single asset/amount/recipient view the mandate enforces against,
// resolved from either an EVM or Solana payload. `amount` is raw (unscaled)
// units of `assetSymbol`; `decimals` is that asset's scale.
export interface ResolvedTransfer {
  kind: 'native' | 'evm-token' | 'sol-system' | 'sol-spl-checked' | 'sol-spl' | 'unparsed';
  assetSymbol?: string; // e.g. "ETH", "SOL", "USDC" — undefined if undeterminable
  amount?: bigint; // raw units of assetSymbol
  decimals?: number;
  recipient?: string; // wallet (native/evm-token/sol-system) or token account (sol-spl*)
  recipientKind: 'wallet' | 'spl-token-account' | 'none';
  notes: string[];
  // Set when resolution itself establishes the transfer is unenforceable for
  // a binding amount/counterparty constraint (mandate turns this into a deny).
  unenforceable?: string;
}

export interface VerifierConfig {
  credentialPath: string;
  issuerDid: string;
  schemaAllowlist: string[];
  agentDid?: string;
  revocation: {
    maxStalenessHours: number;
    onUnreachable: 'cache-then-deny'; // refresh-first; cache under maxStalenessHours; deny otherwise
    fetchTimeoutMs: number;
  };
  didCache: { maxStalenessHours: number };
  cacheDir: string;
  auditLog: string;
  rails: Record<string, RailDef>;
  evmTokens?: Record<string, TokenDefConfig>; // lowercased ERC-20 contract → asset
  solanaMints?: Record<string, TokenDefConfig>; // base58 SPL mint → asset
  allowContractCalls: boolean;
  transactionCategory?: string;
  counterpartyAddressMap?: Record<string, string[]>; // DID -> rail addresses
  offline?: {
    didDocumentPath?: string; // air-gapped/test override for the issuer DID document
    statusListPath?: string; // air-gapped/test override for the status list credential
  };
}

export interface AuditEntry {
  ts: string;
  decision: 'allow' | 'deny';
  reason: string;
  notes: string[];
  chain_id?: string;
  wallet_id?: string;
  api_key_id?: string;
  credential_id?: string;
  credential_sha256?: string;
  tx_sha256?: string;
}
