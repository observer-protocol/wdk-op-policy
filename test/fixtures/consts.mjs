import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
export const OUT = join(dirname(fileURLToPath(import.meta.url)), 'out');
export const ISSUER = 'did:web:issuer.example';
export const AGENT = 'did:web:issuer.example:agents:wdk-agent';
export const SCHEMA_URL = 'https://observerprotocol.org/schemas/delegation/v2.1.json';
export const MERCHANT_ADDR = '0xa11ce00000000000000000000000000000000001';
export const OTHER_ADDR = '0xb0b0000000000000000000000000000000000002';
export const USDC_CONTRACT = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'; // DEFAULT_EVM_TOKENS ethereum USDC (6dec)
export const USDC = (whole) => BigInt(Math.round(whole * 1e6));
