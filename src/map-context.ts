import type { PolicyContext, ResolvedTransfer, TokenDefConfig, VerifierConfig } from './core/types.js';
import { DEFAULT_EVM_TOKENS } from './core/tokens.js';

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

function tokenOf(config: VerifierConfig, addr: unknown): TokenDefConfig | undefined {
  if (typeof addr !== 'string') return undefined;
  const map = { ...DEFAULT_EVM_TOKENS, ...(config.evmTokens ?? {}) };
  return map[addr.toLowerCase()];
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
      const def = tokenOf(config, p.token);
      const recipient = str(p.recipient);
      const amount = asBigInt(p.amount);
      if (!def || amount === undefined) {
        return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed(`transfer token ${String(p.token)} not in evmTokens registry, or amount missing — asset/amount cannot be established`) };
      }
      return {
        ctx: { ...base, transaction: { to: recipient, value: '0' } },
        resolvedOverride: { kind: 'evm-token', assetSymbol: def.symbol, amount, decimals: def.decimals, recipient, recipientKind: recipient ? 'wallet' : 'none', notes: [`WDK transfer ${def.symbol}`] },
      };
    }
    case 'approve': {
      const def = tokenOf(config, p.token);
      const spender = str(p.spender);
      const amount = asBigInt(p.amount);
      if (!def || amount === undefined) {
        return { ctx: { ...base, transaction: {} }, resolvedOverride: unparsed(`approve token ${String(p.token)} not in evmTokens registry, or amount missing — spend cannot be bounded`) };
      }
      return {
        ctx: { ...base, transaction: { to: spender, value: '0' } },
        resolvedOverride: { kind: 'evm-token', assetSymbol: def.symbol, amount, decimals: def.decimals, recipient: spender, recipientKind: spender ? 'wallet' : 'none', notes: [`WDK approve ${def.symbol} to spender (allowance = spend authorization)`] },
      };
    }
    case 'signTypedData': {
      // EIP-2612 Permit: domain.verifyingContract = token; message {spender, value}.
      const domain = (p.domain ?? {}) as Record<string, unknown>;
      const message = (p.message ?? {}) as Record<string, unknown>;
      const def = tokenOf(config, domain.verifyingContract);
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
