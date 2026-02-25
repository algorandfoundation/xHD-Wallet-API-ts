// Small utilities to operate on Uint8Array without Buffer
export function concatUint8Arrays(arrs: Uint8Array[]): Uint8Array {
  const totalLength = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const a of arrs) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function writeUInt32LE(target: Uint8Array, value: number, offset: number) {
  const dv = new DataView(target.buffer, target.byteOffset, target.byteLength);
  dv.setUint32(offset, value, true);
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const h = bytes[i].toString(16).padStart(2, '0');
    s += h;
  }
  return s;
}

export function base64Encode(bytesOrString: Uint8Array | string): string {
  let bytes: Uint8Array;
  if (typeof bytesOrString === 'string') {
    bytes = new TextEncoder().encode(bytesOrString);
  } else {
    bytes = bytesOrString;
  }

  const enc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  let i = 0;
  while (i + 2 < bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    result += enc[(n >> 18) & 63] + enc[(n >> 12) & 63] + enc[(n >> 6) & 63] + enc[n & 63];
    i += 3;
  }
  if (i < bytes.length) {
    if (bytes.length - i === 1) {
      const n = bytes[i] << 16;
      result += enc[(n >> 18) & 63] + enc[(n >> 12) & 63] + '==';
    } else {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
      result += enc[(n >> 18) & 63] + enc[(n >> 12) & 63] + enc[(n >> 6) & 63] + '=';
    }
  }
  return result.replace(/=+$/, '');
}

export function base64Decode(b64: string): Uint8Array {
  // remove padding
  const s = b64.replace(/=+$/, '');
  const lookup: number[] = new Array(256).fill(-1);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;

  const outLen = Math.floor((s.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let outIndex = 0;
  let i = 0;
  while (i < s.length) {
    const a = lookup[s.charCodeAt(i++)];
    const b = lookup[s.charCodeAt(i++)];
    const c = lookup[s.charCodeAt(i++)] ?? 0;
    const d = lookup[s.charCodeAt(i++)] ?? 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    if (outIndex < outLen) out[outIndex++] = (n >> 16) & 0xff;
    if (outIndex < outLen) out[outIndex++] = (n >> 8) & 0xff;
    if (outIndex < outLen) out[outIndex++] = n & 0xff;
  }
  return out;
}

export function uint8FromStringUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
