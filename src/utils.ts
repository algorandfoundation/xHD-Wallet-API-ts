// Byte and bigint helpers in plain JavaScript, so the library imports @noble only for
// cryptography that WebCrypto can't provide. Behaviour, including the errors thrown,
// matches the @noble/curves and @noble/hashes helpers they replace (see utils.spec.ts).

function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name}: Uint8Array expected`);
  }
}

/** Concatenate byte arrays into a new Uint8Array */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const array of arrays) {
    assertBytes(array, "concatBytes");
    length += array.length;
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

/** Interpret bytes as an unsigned little-endian integer */
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  assertBytes(bytes, "bytesToNumberLE");
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Encode a non-negative integer as exactly `length` little-endian bytes */
export function numberToBytesLE(n: bigint, length: number): Uint8Array {
  if (typeof n !== "bigint" || n < 0n) {
    throw new RangeError(`numberToBytesLE: non-negative bigint expected, got ${n}`);
  }
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError(`numberToBytesLE: positive length expected, got ${length}`);
  }
  if (n >> BigInt(8 * length) !== 0n) {
    throw new RangeError("numberToBytesLE: number is too large");
  }
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    result[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return result;
}

/** Modular reduction with a non-negative result */
export function mod(a: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) {
    throw new RangeError(`mod: positive modulus expected, got ${modulus}`);
  }
  const result = a % modulus;
  return result >= 0n ? result : result + modulus;
}
