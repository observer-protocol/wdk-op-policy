import { homedir } from 'node:os';
import { join } from 'node:path';
import type { RailDef, VerifierConfig } from './types.js';

// Default CAIP-2 → Observer Protocol rail mapping. `currency` is the
// rail-native unit that OWS's `transaction.value` denominates (scaled by
// `decimals`). Same-currency comparison only — no FX — so a mandate ceiling
// in any other currency cannot be verified on that rail and DENIES.
// Extend or override per deployment via config.rails.
export const DEFAULT_RAILS: Record<string, RailDef> = {
  'eip155:1': { rail: 'ethereum-mainnet', currency: 'ETH', decimals: 18, family: 'evm' },
  'eip155:8453': { rail: 'base-mainnet', currency: 'ETH', decimals: 18, family: 'evm' },
  'eip155:137': { rail: 'polygon-mainnet', currency: 'POL', decimals: 18, family: 'evm' },
  'eip155:42161': { rail: 'arbitrum-one', currency: 'ETH', decimals: 18, family: 'evm' },
  'eip155:10': { rail: 'optimism-mainnet', currency: 'ETH', decimals: 18, family: 'evm' },
  // Solana mainnet — CAIP-2 chain id IS the genesis-hash identifier. The
  // signed message carries a recentBlockhash, NOT the genesis hash, so the
  // cluster cannot be re-derived from the static payload offline; this
  // mapping is the source of truth for which cluster ctx.chain_id names.
  'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': { rail: 'solana-mainnet', currency: 'SOL', decimals: 9, family: 'solana' },
  // Solana devnet, for completeness (distinct genesis-hash CAIP-2).
  'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1': { rail: 'solana-devnet', currency: 'SOL', decimals: 9, family: 'solana' },
  'bip122:000000000019d6689c085ae165831e93': { rail: 'bitcoin-mainnet', currency: 'BTC', decimals: 8, family: 'other' },
  'tron:mainnet': { rail: 'usdt-trc20', currency: 'TRX', decimals: 6, family: 'other' },
};

function expandHome(p: string): string {
  return p.startsWith('~/') ? join(homedir(), p.slice(2)) : p;
}

export function parseConfig(raw: unknown): VerifierConfig {
  if (!raw || typeof raw !== 'object') {
    throw new Error(
      'policy_config missing — the OWS policy file must carry a `config` object (see README: Configuration)',
    );
  }
  const c = raw as Record<string, unknown>;

  const credentialPath = c['credentialPath'];
  if (typeof credentialPath !== 'string' || credentialPath.length === 0) {
    throw new Error('config.credentialPath is required (path to the agent ObserverDelegationCredential JSON)');
  }
  const issuerDid = c['issuerDid'];
  if (typeof issuerDid !== 'string' || !issuerDid.startsWith('did:')) {
    throw new Error('config.issuerDid is required and must be a DID (pinned trusted issuer)');
  }
  const schemaAllowlist = c['schemaAllowlist'];
  if (!Array.isArray(schemaAllowlist) || schemaAllowlist.length === 0 || !schemaAllowlist.every((s) => typeof s === 'string')) {
    throw new Error('config.schemaAllowlist is required and must be a non-empty array of schema URLs');
  }

  const revocationRaw = (c['revocation'] ?? {}) as Record<string, unknown>;
  const maxStalenessHours =
    typeof revocationRaw['maxStalenessHours'] === 'number' ? revocationRaw['maxStalenessHours'] : 24;
  const onUnreachable = revocationRaw['onUnreachable'] ?? 'cache-then-deny';
  if (onUnreachable !== 'cache-then-deny') {
    throw new Error(
      `config.revocation.onUnreachable: only 'cache-then-deny' is implemented (refresh-first; cache under the staleness window; deny otherwise)`,
    );
  }
  const fetchTimeoutMs =
    typeof revocationRaw['fetchTimeoutMs'] === 'number' ? revocationRaw['fetchTimeoutMs'] : 1500;

  const didCacheRaw = (c['didCache'] ?? {}) as Record<string, unknown>;
  const didStaleness =
    typeof didCacheRaw['maxStalenessHours'] === 'number' ? didCacheRaw['maxStalenessHours'] : maxStalenessHours;

  const railsOverride = (c['rails'] ?? {}) as Record<string, RailDef>;
  const offlineRaw = c['offline'] as { didDocumentPath?: string; statusListPath?: string } | undefined;

  return {
    credentialPath: expandHome(credentialPath),
    issuerDid,
    schemaAllowlist: schemaAllowlist as string[],
    agentDid: typeof c['agentDid'] === 'string' ? (c['agentDid'] as string) : undefined,
    revocation: { maxStalenessHours, onUnreachable: 'cache-then-deny', fetchTimeoutMs },
    didCache: { maxStalenessHours: didStaleness },
    cacheDir: expandHome(typeof c['cacheDir'] === 'string' ? (c['cacheDir'] as string) : '~/.cache/ows-op-policy'),
    auditLog: expandHome(typeof c['auditLog'] === 'string' ? (c['auditLog'] as string) : '~/.cache/ows-op-policy/decisions.jsonl'),
    rails: { ...DEFAULT_RAILS, ...railsOverride },
    evmTokens: (c['evmTokens'] as Record<string, { symbol: string; decimals: number }>) ?? undefined,
    solanaMints: (c['solanaMints'] as Record<string, { symbol: string; decimals: number }>) ?? undefined,
    allowContractCalls: c['allowContractCalls'] === true,
    transactionCategory: typeof c['transactionCategory'] === 'string' ? (c['transactionCategory'] as string) : undefined,
    counterpartyAddressMap: (c['counterpartyAddressMap'] as Record<string, string[]>) ?? undefined,
    offline: offlineRaw
      ? {
          didDocumentPath: offlineRaw.didDocumentPath ? expandHome(offlineRaw.didDocumentPath) : undefined,
          statusListPath: offlineRaw.statusListPath ? expandHome(offlineRaw.statusListPath) : undefined,
        }
      : undefined,
  };
}
