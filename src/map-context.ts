import type { PolicyContext, RailDef, ResolvedTransfer, TokenDefConfig, VerifierConfig } from '@observer-protocol/policy-engine';
import { DEFAULT_EVM_TOKENS, DEFAULT_SOLANA_MINTS } from '@observer-protocol/policy-engine';

// Map a WDK (operation, params) to the core PolicyContext + (for token ops) a
// hand-built ResolvedTransfer. params shapes confirmed @ a00b391 against
// tests/wdk-policy.test.js and @tetherto/wdk-wallet(-evm):
//   sendTransaction/signTransaction: { to, value, data? }   (EvmTransaction)
//   transfer: { token, recipient, amount }                  (EvmTransferOptions)
//   approve:  { token, spender, amount }                    (ApproveOptions)
//   signTypedData: { domain, types, message }               (TypedData; EIP-2612 Permit)
//
// Undecodable inputs (unknown token, missing fields, non-Permit typed data)
// resolve to `unenforceable` — the mandate engine turns that into a DENY under
// any binding amount/counterparty constraint. (This is a definitive "cannot
// establish", distinct from verification UNCERTAINTY, which throws in the
// condition layer.)

export interface Mapped {
  ctx: PolicyContext;
  resolvedOverride?: ResolvedTransfer;
}

/** Token lookup is rail-family-aware. EVM contract addresses fold case
 * (hex; EIP-55 is only a checksum). base58 identifiers (TRC-20 contracts,
 * SPL mints) are CASE-SENSITIVE and compare exact — folding base58 makes a
 * case-collision grindable. An address that misses its family's registry
 * resolves to unenforceable downstream (deny under binding constraints). */
function tokenOf(config: VerifierConfig, addr: unknown, family: RailDef['family']): TokenDefConfig | undefined {
  if (typeof addr !== 'string') return undefined;
  if (family === 'evm') {
    const map = { ...DEFAULT_EVM_TOKENS, ...(config.evmTokens ?? {}) };
    return map[addr.toLowerCase()];
  }
  if (family === 'solana') {
    return { ...DEFAULT_SOLANA_MINTS, ...(config.solanaMints ?? {}) }[addr];
  }
  // family 'other' (TRON et al): pinned per-deployment registry, exact-case.
  return (config.trc20Tokens ?? {})[addr];
}

function tokenKind(family: RailDef['family']): ResolvedTransfer['kind'] {
  return family === 'evm' ? 'evm-token' : family === 'solana' ? 'sol-spl' : 'trc20-token';
}
function asBigInt(v: unknown): bigint | undefined {
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
    if (typeof v === 'string' && /^\d+$/.test(v.trim())) return BigInt(v.trim());
    return undefined;
  } catch {
    return undefined;
  }
}
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

const unparsed = (reason: string): ResolvedTransfer => ({
  kind: 'unparsed',
  recipientKind: 'none',
  notes: [],
  unenforceable: reason,
});

export function mapContext(
  operation: string,
  params: unknown,
  caip2: string,
  walletId: string,
  nowIso: string,
  config: VerifierConfig,
): Mapped {
  const base = { chain_id: caip2, wallet_id: walletId, api_key_id: 'wdk', timestamp: nowIso };
  const p = (params ?? {}) as Record<string, unknown>;
  // condition.ts verifies the rail mapping exists before mapping; 'other' is
  // the safe default (case-exact registries, no calldata decode).
  const family = config.rails[caip2]?.family ?? 'other';

  switch (operation) {
    case 'sendTransaction':
    case 'signTransaction': {
      const tx = {
        to: str(p.to),
        value: p.value != null ? String(asBigInt(p.value) ?? '0') : '0',
        data: str(p.data),
      };
      return { ctx: { ...base, transaction: tx } }; // core resolver decodes native/ERC-20
    }
    case 'transfer': {
      const def = tokenOf(config, p.token, family);
      const recipient = str(p.recipient);
      const amount = asBigInt(p.amount);
      if (!def || amount === undefined) {
        return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed(`transfer token ${String(p.token)} not in the ${family} token registry (evmTokens/solanaMints/trc20Tokens), or amount missing — asset/amount cannot be established`) };
      }
      return {
        ctx: { ...base, transaction: { to: recipient, value: '0' } },
        resolvedOverride: { kind: tokenKind(family), assetSymbol: def.symbol, amount, decimals: def.decimals, recipient, recipientKind: recipient ? 'wallet' : 'none', notes: [`WDK transfer ${def.symbol}`] },
      };
    }
    case 'approve': {
      const def = tokenOf(config, p.token, family);
      const spender = str(p.spender);
      const amount = asBigInt(p.amount);
      if (!def || amount === undefined) {
        return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed(`approve token ${String(p.token)} not in the ${family} token registry, or amount missing — spend cannot be bounded`) };
      }
      return {
        ctx: { ...base, transaction: { to: spender, value: '0' } },
        resolvedOverride: { kind: tokenKind(family), assetSymbol: def.symbol, amount, decimals: def.decimals, recipient: spender, recipientKind: spender ? 'wallet' : 'none', notes: [`WDK approve ${def.symbol} to spender (allowance = spend authorization)`] },
      };
    }
    case 'signTypedData': {
      // EIP-2612 Permit: domain.verifyingContract = token; message {spender, value}.
      // EVM-only structure — on other families the token lookup misses and the
      // request resolves unenforceable (fail-closed under binding constraints).
      const domain = (p.domain ?? {}) as Record<string, unknown>;
      const message = (p.message ?? {}) as Record<string, unknown>;
      const def = tokenOf(config, domain.verifyingContract, family);
      const spender = str(message.spender);
      const value = asBigInt(message.value);
      if (def && spender && value !== undefined) {
        return {
          ctx: { ...base, transaction: { to: spender, value: '0' } },
          resolvedOverride: { kind: 'evm-token', assetSymbol: def.symbol, amount: value, decimals: def.decimals, recipient: spender, recipientKind: 'wallet', notes: ['WDK signTypedData EIP-2612 Permit decoded (spender/value)'] },
        };
      }
      return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed('signTypedData is not a decodable EIP-2612 Permit (verifyingContract not a known token, or no spender/value) — spend cannot be bounded') };
    }
    default:
      return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed(`operation ${operation} is not decoded by OP`) };
  }
}
