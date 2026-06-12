// EVM unsigned-transaction parsing from raw_hex.
//
// The released OWS engine (v1.3.2) hands executables `transaction.raw_hex`
// only — the parsed to/value/data fields described in the main-branch docs
// are newer than the latest release. We therefore decode EVM payloads
// ourselves: EIP-1559 (type 2), EIP-2930 (type 1), and legacy RLP. When the
// engine does provide parsed fields, those are used as-is.

export interface ParsedEvmTx {
  chainId?: bigint;
  to?: string; // 0x… or undefined for contract creation
  value: bigint;
  data: string; // 0x…
}

export interface EvmTokenTransfer {
  selector: string;
  recipient: string; // 0x… wallet address being paid
  amount: bigint; // raw token units (scale by the token's own decimals)
}

// ERC-20 / EIP-3009 transfer selectors. For USDC the canonical agent-payment
// path is EIP-3009 transferWithAuthorization (x402); plain transfer/transferFrom
// are also decoded.
const SEL_TRANSFER = 'a9059cbb'; // transfer(address,uint256)
const SEL_TRANSFER_FROM = '23b872dd'; // transferFrom(address,address,uint256)
const SEL_TRANSFER_WITH_AUTH = 'e3ee160e'; // transferWithAuthorization(address,address,uint256,...)
const SEL_RECEIVE_WITH_AUTH = 'ef55bec6'; // receiveWithAuthorization(address,address,uint256,...)

function word(data: Buffer, wordIndex: number): Buffer {
  const start = 4 + wordIndex * 32;
  if (start + 32 > data.length) throw new Error(`token calldata too short for word ${wordIndex}`);
  return data.subarray(start, start + 32);
}
const addrFromWord = (w: Buffer): string => '0x' + w.subarray(12).toString('hex'); // last 20 bytes
const uintFromWord = (w: Buffer): bigint => BigInt('0x' + w.toString('hex'));

/**
 * Decode a known ERC-20 / EIP-3009 token transfer from calldata. Returns null
 * for any selector we don't recognise (caller treats unknown calldata per its
 * contract-call policy). Recipient is the wallet being paid; amount is in the
 * token's own raw units.
 */
export function parseErc20Transfer(dataHex: string): EvmTokenTransfer | null {
  const hex = dataHex.startsWith('0x') ? dataHex.slice(2) : dataHex;
  if (hex.length < 8) return null;
  const data = Buffer.from(hex, 'hex');
  const selector = hex.slice(0, 8).toLowerCase();
  try {
    switch (selector) {
      case SEL_TRANSFER: // transfer(to, amount)
        return { selector, recipient: addrFromWord(word(data, 0)), amount: uintFromWord(word(data, 1)) };
      case SEL_TRANSFER_FROM: // transferFrom(from, to, amount)
        return { selector, recipient: addrFromWord(word(data, 1)), amount: uintFromWord(word(data, 2)) };
      case SEL_TRANSFER_WITH_AUTH: // transferWithAuthorization(from, to, value, ...)
      case SEL_RECEIVE_WITH_AUTH: // receiveWithAuthorization(from, to, value, ...)
        return { selector, recipient: addrFromWord(word(data, 1)), amount: uintFromWord(word(data, 2)) };
      default:
        return null;
    }
  } catch {
    // a recognised selector with truncated/malformed args → treat as
    // undecodable (caller fails closed under a binding constraint)
    return null;
  }
}

interface RlpItem {
  bytes?: Buffer;
  list?: RlpItem[];
}

function rlpDecode(buf: Buffer, offset = 0): { item: RlpItem; next: number } {
  if (offset >= buf.length) throw new Error('rlp: unexpected end of input');
  const b = buf[offset] as number;
  if (b < 0x80) return { item: { bytes: buf.subarray(offset, offset + 1) }, next: offset + 1 };
  if (b <= 0xb7) {
    const len = b - 0x80;
    return { item: { bytes: buf.subarray(offset + 1, offset + 1 + len) }, next: offset + 1 + len };
  }
  if (b <= 0xbf) {
    const lenLen = b - 0xb7;
    const len = Number(BigInt('0x' + buf.subarray(offset + 1, offset + 1 + lenLen).toString('hex')));
    const start = offset + 1 + lenLen;
    return { item: { bytes: buf.subarray(start, start + len) }, next: start + len };
  }
  let payloadLen: number;
  let start: number;
  if (b <= 0xf7) {
    payloadLen = b - 0xc0;
    start = offset + 1;
  } else {
    const lenLen = b - 0xf7;
    payloadLen = Number(BigInt('0x' + buf.subarray(offset + 1, offset + 1 + lenLen).toString('hex')));
    start = offset + 1 + lenLen;
  }
  const end = start + payloadLen;
  const list: RlpItem[] = [];
  let pos = start;
  while (pos < end) {
    const { item, next } = rlpDecode(buf, pos);
    list.push(item);
    pos = next;
  }
  if (pos !== end) throw new Error('rlp: list payload length mismatch');
  return { item: { list }, next: end };
}

const toBigInt = (item: RlpItem): bigint => {
  const b = item.bytes ?? Buffer.alloc(0);
  return b.length === 0 ? 0n : BigInt('0x' + b.toString('hex'));
};
const toAddress = (item: RlpItem): string | undefined => {
  const b = item.bytes ?? Buffer.alloc(0);
  if (b.length === 0) return undefined; // contract creation
  if (b.length !== 20) throw new Error(`rlp: address field is ${b.length} bytes, expected 20`);
  return '0x' + b.toString('hex');
};
const toData = (item: RlpItem): string => '0x' + (item.bytes ?? Buffer.alloc(0)).toString('hex');

export function parseEvmRawTx(rawHex: string): ParsedEvmTx {
  const hex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length === 0) throw new Error('raw_hex is not hex');
  const buf = Buffer.from(hex, 'hex');
  const typeByte = buf[0] as number;

  if (typeByte === 0x02 || typeByte === 0x01) {
    const { item } = rlpDecode(buf.subarray(1));
    const fields = item.list;
    if (!fields) throw new Error('typed tx payload is not an RLP list');
    if (typeByte === 0x02) {
      // [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, ...]
      if (fields.length < 9) throw new Error(`EIP-1559 tx has ${fields.length} fields, expected ≥9`);
      return {
        chainId: toBigInt(fields[0] as RlpItem),
        to: toAddress(fields[5] as RlpItem),
        value: toBigInt(fields[6] as RlpItem),
        data: toData(fields[7] as RlpItem),
      };
    }
    // type 1: [chainId, nonce, gasPrice, gas, to, value, data, accessList, ...]
    if (fields.length < 8) throw new Error(`EIP-2930 tx has ${fields.length} fields, expected ≥8`);
    return {
      chainId: toBigInt(fields[0] as RlpItem),
      to: toAddress(fields[4] as RlpItem),
      value: toBigInt(fields[5] as RlpItem),
      data: toData(fields[6] as RlpItem),
    };
  }

  if (typeByte >= 0xc0) {
    // Legacy RLP list: [nonce, gasPrice, gas, to, value, data] with optional
    // EIP-155 trailer [chainId, 0, 0] on unsigned transactions.
    const { item } = rlpDecode(buf);
    const fields = item.list;
    if (!fields || fields.length < 6) throw new Error('legacy tx is not a ≥6-field RLP list');
    return {
      chainId: fields.length >= 9 ? toBigInt(fields[6] as RlpItem) : undefined,
      to: toAddress(fields[3] as RlpItem),
      value: toBigInt(fields[4] as RlpItem),
      data: toData(fields[5] as RlpItem),
    };
  }

  throw new Error(`unsupported EVM transaction type byte 0x${typeByte.toString(16)}`);
}
