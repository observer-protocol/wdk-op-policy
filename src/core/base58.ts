// base58btc (Bitcoin alphabet) — used by multibase 'z' encodings.

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) INDEX[ALPHABET[i] as string] = i;

export function base58Decode(s: string): Buffer {
  if (s.length === 0) return Buffer.alloc(0);
  let acc = 0n;
  for (const ch of s) {
    const d = INDEX[ch];
    if (d === undefined) throw new Error(`base58: invalid character ${JSON.stringify(ch)}`);
    acc = acc * 58n + BigInt(d);
  }
  const bytes: number[] = [];
  while (acc > 0n) {
    bytes.push(Number(acc & 0xffn));
    acc >>= 8n;
  }
  bytes.reverse();
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === '1') leadingZeros++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), Buffer.from(bytes)]);
}

export function base58Encode(buf: Buffer): string {
  let acc = 0n;
  for (const b of buf) acc = (acc << 8n) + BigInt(b);
  let out = '';
  while (acc > 0n) {
    out = ALPHABET[Number(acc % 58n)] + out;
    acc /= 58n;
  }
  for (const b of buf) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}
