// Token + program registry for asset-aware enforcement.
//
// USDC and USDT are 6-decimal tokens on every chain we support — NOT the
// chain-native unit. A mandate ceiling denominated in "USDC" must compare
// against the token's transferred amount at 6 decimals, never the native
// value at 18 (ETH) or 9 (SOL). Misreading a USDC transfer as native value
// is a silent under-enforcement, so token transfers are resolved explicitly
// and pinned by contract/mint address.

export interface TokenDef {
  symbol: string;
  decimals: number;
}

// EVM ERC-20 contracts (lowercased) → asset. Extend per deployment via
// config.evmTokens.
export const DEFAULT_EVM_TOKENS: Record<string, TokenDef> = {
  // USDC
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6 }, // Ethereum
  '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', decimals: 6 }, // Base
  '0xaf88d065e77c8cc2239327c5edb3a432268e5831': { symbol: 'USDC', decimals: 6 }, // Arbitrum
  '0x0b2c639c533813f4aa9d7837caf62653d097ff85': { symbol: 'USDC', decimals: 6 }, // Optimism
  '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': { symbol: 'USDC', decimals: 6 }, // Polygon
  // USDT
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { symbol: 'USDT', decimals: 6 }, // Ethereum
};

// Solana SPL mints (base58) → asset.
export const DEFAULT_SOLANA_MINTS: Record<string, TokenDef> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: { symbol: 'USDC', decimals: 6 },
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: { symbol: 'USDT', decimals: 6 },
};

// Solana program IDs (base58). System program is the all-zero key.
export const SOLANA_PROGRAMS = {
  SYSTEM: '11111111111111111111111111111111',
  TOKEN: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  TOKEN_2022: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
} as const;

// Programs that cannot move an agent's tokens or change a counterparty, so
// their presence alongside a transfer does not defeat enforcement. Compute
// budget sets fee/CU only; Memo carries opaque note bytes but moves nothing.
// Everything NOT in this set, and not a recognised transfer, is treated as
// opaque → fail closed under any binding amount/counterparty constraint.
export const SOLANA_BENIGN_PROGRAMS = new Set<string>([
  'ComputeBudget111111111111111111111111111111',
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', // SPL Memo v2
  'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo', // SPL Memo v1
]);
