// RFC 8785 JSON Canonicalization Scheme.
//
// Inputs here are always values freshly parsed from JSON text, so numbers
// are finite and strings are well-formed; JSON.stringify's serialization of
// strings and numbers matches RFC 8785 (which defers to ECMAScript's
// JSON.stringify for primitives). Object members are sorted by UTF-16 code
// units, which is the default Array.prototype.sort() comparison.

export function jcsCanonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new Error('JCS: non-finite numbers are not representable in JSON');
    }
    if (value === undefined) {
      throw new Error('JCS: undefined is not representable in JSON');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => jcsCanonicalize(v === undefined ? null : v)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue; // mirror JSON.stringify: undefined members are omitted
    parts.push(JSON.stringify(k) + ':' + jcsCanonicalize(v));
  }
  return '{' + parts.join(',') + '}';
}

export function jcsBytes(value: unknown): Buffer {
  return Buffer.from(jcsCanonicalize(value), 'utf8');
}
