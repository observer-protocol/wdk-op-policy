import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
export const OUT = join(dirname(fileURLToPath(import.meta.url)), 'out');
export const ISSUER = 'did:web:issuer.example';
export const AGENT = 'did:web:issuer.example:agents:wdk-agent';
export const SCHEMA_URL = 'https://observerprotocol.org/schemas/delegation/v2.1.json';
export const MERCHANT_ADDR = '0xa11ce00000000000000000000000000000000001';
export const OTHER_ADDR = '0xb0b0000000000000000000000000000000000002';
export const USDC_CONTRACT = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'; // DEFAULT_EVM_TOKENS ethereum USDC (6dec) — internal conformance only
export const USDC = (whole) => BigInt(Math.round(whole * 1e6));
// Public-facing demo instrument: USDT (the "× Tether WDK" page leads with USDT, never USDC).
export const USDT_CONTRACT = '0xdac17f958d2ee523a2206206994597c13d831ec7'; // DEFAULT_EVM_TOKENS ethereum USDT (6dec)
export const USDT = (whole) => BigInt(Math.round(whole * 1e6));
// TRON (TRC-20) conformance fixtures. Addresses are base58 and CASE-SENSITIVE —
// the case-twiddled variant below MUST be rejected by the exact-case compare.
export const SCHEMA_URL_V22 = 'https://observerprotocol.org/schemas/delegation/v2.3.json';
export const USDT_TRC20 = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // mainnet USDT TRC-20 (6dec)
export const TRON_MERCHANT = 'TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9';
export const TRON_OTHER = 'TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy';
