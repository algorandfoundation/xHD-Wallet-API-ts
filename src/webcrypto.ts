// Every cryptographic operation that WebCrypto (crypto.subtle) can perform goes through here,
// so the library binds to the platform interface rather than a library where it can.
// @noble/curves is used only for what WebCrypto lacks: unclamped Ed25519 point arithmetic
// (BIP32-Ed25519) and Ed25519 -> X25519 key conversion; @noble/hashes only for BLAKE2b.

import { bytesToNumberLE, concatBytes } from "./utils.js";

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error(
      "WebCrypto (crypto.subtle) is unavailable. It requires a secure context (HTTPS or localhost) in browsers, " +
        "and a polyfill in React Native."
    );
  }
  return s;
}

// WebCrypto copies its inputs before the call returns, and the library never passes
// SharedArrayBuffer-backed views, so narrowing the buffer type is safe.
const source = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => bytes as Uint8Array<ArrayBuffer>;

export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-512", source(data)));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", source(data)));
}

export async function hmacSha512(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey("raw", source(key), { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", cryptoKey, source(data)));
}

// PKCS#8 wrapper for a raw 32-byte X25519 private key (RFC 8410)
const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * X25519 (RFC 7748). The scalar is clamped as RFC 7748 requires. Throws if the shared secret is
 * all zeros, i.e. the public key has small order, as libsodium's crypto_scalarmult does.
 */
export async function x25519(scalar: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  const privateKey = await subtle().importKey("pkcs8", source(concatBytes(X25519_PKCS8_PREFIX, scalar)), { name: "X25519" }, false, ["deriveBits"]);
  const peer = await subtle().importKey("raw", source(publicKey), { name: "X25519" }, false, []);
  return new Uint8Array(await subtle().deriveBits({ name: "X25519", public: peer }, privateKey, 256));
}

// ===========================
// Ed25519 verification
// ===========================

// Ed25519 group order L and field prime p
export const ED25519_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const FIELD_PRIME = 2n ** 255n - 19n;

// Encodings of the small-order points, with the sign bit cleared, plus the non-canonical
// encodings of 0 and 1. The same list as libsodium's ge25519_has_small_order.
const SMALL_ORDER_ENCODINGS: Uint8Array[] = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => Uint8Array.from(hex.match(/../g)!, (byte) => parseInt(byte, 16)));

/** The encoded y-coordinate (sign bit cleared) is below the field prime */
function isCanonicalPoint(encoding: Uint8Array): boolean {
  const masked = encoding.slice();
  masked[31] &= 0x7f;
  return bytesToNumberLE(masked) < FIELD_PRIME;
}

function hasSmallOrder(encoding: Uint8Array): boolean {
  return SMALL_ORDER_ENCODINGS.some((blocked) =>
    blocked.every((byte, i) => (i === 31 ? encoding[i] & 0x7f : encoding[i]) === byte)
  );
}

/**
 * Ed25519 signature verification with libsodium's strict rules (as in xHD-Wallet-API 1.x).
 * WebCrypto implementations differ on edge cases (RFC 8032 leaves them open), so signatures
 * that libsodium rejects are rejected here before WebCrypto is consulted: a non-canonical S,
 * a non-canonical or small-order public key, or a non-canonical or small-order R.
 */
export async function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const R = signature.subarray(0, 32);
  const S = signature.subarray(32, 64);
  if (bytesToNumberLE(S) >= ED25519_ORDER) return false;
  if (!isCanonicalPoint(publicKey) || hasSmallOrder(publicKey)) return false;
  if (!isCanonicalPoint(R) || hasSmallOrder(R)) return false;

  try {
    const key = await subtle().importKey("raw", source(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await subtle().verify({ name: "Ed25519" }, key, source(signature), source(message));
  } catch {
    // e.g. a public key that isn't a valid curve point
    return false;
  }
}
