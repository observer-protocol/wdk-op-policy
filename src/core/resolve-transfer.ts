import type { PolicyContext, RailDef, ResolvedTransfer, TokenDefConfig, VerifierConfig } from '@observer-protocol/policy-engine';
import { DEFAULT_EVM_TOKENS, DEFAULT_SOLANA_MINTS } from '@observer-protocol/policy-engine';
import { parseErc20Transfer } from './evmtx.js';
import { parseSolanaRawTx } from './soltx.js';

// Resolve the OWS transaction context into a single {asset, amount, recipient}
// view the mandate enforces against. This is where native-vs-token and
// EVM-vs-Solana differences are absorbed, so mandate.ts reasons in one model.
//
// Fail-closed principle: when a payload is recognised as value-bearing but the
// asset or recipient cannot be established (e.g. a plain SPL transfer whose
// mint isn't in the instruction), the resolver marks it `unenforceable` rather
// than guessing — mandate denies any binding amount/counterparty constraint on
// it. Native and fully-typed token transfers resolve cleanly.

function evmTokens(config: VerifierConfig): Record<string, TokenDefConfig> {
  return { ...DEFAULT_EVM_TOKENS, ...(config.evmTokens ?? {}) };
}
function solanaMints(config: VerifierConfig): Record<string, TokenDefConfig> {
  return { ...DEFAULT_SOLANA_MINTS, ...(config.solanaMints ?? {}) };
}

function resolveEvm(ctx: PolicyContext, railDef: RailDef, config: VerifierConfig): ResolvedTransfer {
  const tx = ctx.transaction ?? {};
  const value = typeof tx.value === 'string' ? BigInt(tx.value) : 0n;
  const hasCalldata = typeof tx.data === 'string' && tx.data !== '' && tx.data !== '0x';

  if (!hasCalldata) {
    return {
      kind: 'native',
      assetSymbol: railDef.currency,
      amount: value,
      decimals: railDef.decimals,
      recipient: typeof tx.to === 'string' ? tx.to : undefined,
      recipientKind: typeof tx.to === 'string' ? 'wallet' : 'none',
      notes: [],
    };
  }

  // Calldata present. If `to` is a known token contract and the calldata is a
  // recognised transfer, this is a clean token payment.
  const contract = typeof tx.to === 'string' ? tx.to.toLowerCase() : undefined;
  const token = contract ? evmTokens(config)[contract] : undefined;
  const decoded = parseErc20Transfer(tx.data as string);

  if (token && decoded) {
    return {
      kind: 'evm-token',
      assetSymbol: token.symbol,
      amount: decoded.amount,
      decimals: token.decimals,
      recipient: decoded.recipient,
      recipientKind: 'wallet',
      notes: [`EVM ${token.symbol} transfer decoded (${decoded.selector}); native value ${value} ignored`],
    };
  }
  if (token && !decoded) {
    return {
      kind: 'unparsed',
      recipientKind: 'none',
      notes: [],
      unenforceable: `call to known token contract ${contract} uses unrecognised calldata — amount/recipient cannot be established`,
    };
  }
  // Calldata to an unknown contract: the native value is not a reliable
  // measure of spend (could be a token transfer, swap, etc.). Fail closed
  // under a binding amount/counterparty constraint — mandate's explicit
  // allowContractCalls knob is the only escape (native-value measurement).
  return {
    kind: 'unparsed',
    recipientKind: 'none',
    notes: [],
    unenforceable:
      'transaction carries calldata (contract call); native value is not a reliable measure of spend under a binding amount constraint. Set allowContractCalls=true to accept native-value-only measurement',
  };
}

function resolveSolana(ctx: PolicyContext, railDef: RailDef, config: VerifierConfig): ResolvedTransfer {
  const raw = ctx.transaction?.raw_hex;
  if (typeof raw !== 'string') {
    return { kind: 'unparsed', recipientKind: 'none', notes: [], unenforceable: 'no raw_hex on the Solana transaction' };
  }
  let parsed;
  try {
    parsed = parseSolanaRawTx(raw);
  } catch (e) {
    return { kind: 'unparsed', recipientKind: 'none', notes: [], unenforceable: `Solana parse failed: ${(e as Error).message}` };
  }

  const valueTransfers = parsed.transfers;
  const note = `Solana ${parsed.version} tx: ${parsed.instructionCount} instruction(s) — ${valueTransfers.length} transfer, ${parsed.benignCount} benign, ${parsed.unknownCount} opaque, ${parsed.alutUnresolved} ALUT-unresolved`;

  // Fail-closed boundaries (each denies only a BINDING amount/counterparty
  // constraint; identity/temporal/revocation-scoped mandates still pass).
  if (parsed.alutUnresolved > 0) {
    return {
      kind: 'unparsed',
      recipientKind: 'none',
      notes: [note],
      unenforceable: `Solana v0 transaction references ${parsed.alutUnresolved} address-lookup-table account(s) not present in the static message — cannot prove amount/counterparty without on-chain table reads (not done in v1)`,
    };
  }
  if (parsed.unknownCount > 0) {
    return {
      kind: 'unparsed',
      recipientKind: 'none',
      notes: [note],
      unenforceable: `Solana tx contains ${parsed.unknownCount} opaque/unhandled instruction(s) that may move value — every instruction must satisfy the mandate, so this fails closed`,
    };
  }
  if (valueTransfers.length === 0) {
    return {
      kind: 'unparsed',
      recipientKind: 'none',
      notes: [note],
      unenforceable: 'no recognised SOL/SPL transfer instruction to enforce amount/counterparty against',
    };
  }
  if (valueTransfers.length > 1) {
    return {
      kind: 'unparsed',
      recipientKind: 'none',
      notes: [note],
      unenforceable: `Solana tx contains ${valueTransfers.length} transfer instructions — multi-transfer attribution is not supported; fails closed`,
    };
  }

  const t = valueTransfers[0]!;
  if (t.kind === 'system') {
    return {
      kind: 'sol-system',
      assetSymbol: railDef.currency, // SOL
      amount: t.amount,
      decimals: railDef.decimals, // 9
      recipient: t.destination,
      recipientKind: 'wallet',
      notes: [],
    };
  }
  if (t.kind === 'spl-transfer-checked') {
    const mintDef = t.mint ? solanaMints(config)[t.mint] : undefined;
    if (!mintDef) {
      return {
        kind: 'sol-spl-checked',
        recipient: t.destination,
        recipientKind: 'spl-token-account',
        notes: [],
        unenforceable: `SPL TransferChecked mint ${t.mint} is not in the token registry — asset cannot be identified`,
      };
    }
    // Cross-check the on-chain decimals against the registry when present.
    if (t.decimals !== undefined && t.decimals !== mintDef.decimals) {
      return {
        kind: 'sol-spl-checked',
        recipient: t.destination,
        recipientKind: 'spl-token-account',
        notes: [],
        unenforceable: `SPL TransferChecked decimals ${t.decimals} disagree with registry ${mintDef.symbol}=${mintDef.decimals}`,
      };
    }
    return {
      kind: 'sol-spl-checked',
      assetSymbol: mintDef.symbol,
      amount: t.amount,
      decimals: mintDef.decimals,
      recipient: t.destination,
      recipientKind: 'spl-token-account',
      notes: [`SPL ${mintDef.symbol} TransferChecked decoded; recipient is a token account`],
    };
  }
  // plain SPL Transfer — mint is NOT in the instruction, asset undeterminable offline
  return {
    kind: 'sol-spl',
    amount: t.amount,
    recipient: t.destination,
    recipientKind: 'spl-token-account',
    notes: [],
    unenforceable:
      'SPL Transfer (non-checked) does not carry the mint — asset cannot be identified offline. Use TransferChecked for enforceable token payments, or this fails closed under a binding token ceiling.',
  };
}

export function resolveTransfer(ctx: PolicyContext, railDef: RailDef, config: VerifierConfig): ResolvedTransfer {
  if (railDef.family === 'evm') return resolveEvm(ctx, railDef, config);
  if (railDef.family === 'solana') return resolveSolana(ctx, railDef, config);
  // Non-EVM/Solana families (Bitcoin, Tron, …) are not payload-parsed here.
  return {
    kind: 'unparsed',
    recipientKind: 'none',
    notes: [`rail family '${railDef.family}' is not payload-parsed by this verifier`],
    unenforceable: `${railDef.rail} payloads are not parsed — amount/counterparty enforcement unavailable on this rail`,
  };
}
