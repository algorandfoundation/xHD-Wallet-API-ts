import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha512 } from "@noble/hashes/sha2.js";

// ===========================
// Libsodium Constants
// ===========================

const crypto_scalarmult_ed25519_SCALARBYTES = 32;
const crypto_scalarmult_x25519_SCALARBYTES = 32;
const crypto_scalarmult_x25519_PKBYTES = 32;
const crypto_generichash_BYTES_MIN = 16;
const crypto_generichash_BYTES_MAX = 64;
const crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64;

// ===========================
// Ed25519 Signature Functions
// ===========================

/**
 * Verify a detached signature
 */
export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch (error) {
    return false;
  }
}

// ===========================
// Ed25519 Point Operations
// ===========================

/**
 * Scalar multiplication with base point (no clamping)
 */
export function crypto_scalarmult_ed25519_base_noclamp(
  scalar: Uint8Array
): Uint8Array {
  // Input validation - only validate length
  if (scalar.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  // Convert scalar bytes to bigint (little-endian)
  const scalarBigint = bytesToNumberLE(scalar);

  // Always clear top bit and call reduce modulo curve order, for constant time.
  // This maintains compatibility with libsodium's noclamp behavior

  // Clear top bit from scalar using bitwise AND with bitmask:
  // 1n << 255n creates a bigint with only bit 255 set
  // Subtracting 1n gives you all bits 0-254 set (0x7FFF...FFFF)
  // Bitwise & operation with the resulting mask clears bit 255
  const clearedTopBitScalar = scalarBigint & ((1n << 255n) - 1n);
  const reducedScalar = mod(clearedTopBitScalar, ed25519.Point.Fn.ORDER);

  // Reject zero scalars to match libsodium behavior
  if (reducedScalar === 0n) {
    throw new Error("scalar is 0");
  }

  // Perform scalar multiplication with base point
  const point = ed25519.Point.BASE.multiply(reducedScalar);
  return point.toBytes();
}

/**
 * Add two Ed25519 points
 */
export function crypto_core_ed25519_add(
  pointA: Uint8Array,
  pointB: Uint8Array
): Uint8Array {
  try {
    const a = ed25519.Point.fromBytes(pointA);
    const b = ed25519.Point.fromBytes(pointB);
    const result = a.add(b);
    return result.toBytes();
  } catch (error) {
    throw new Error("invalid point");
  }
}

// ===========================
// Ed25519 Scalar Operations
// ===========================

/**
 * Add two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_add(
  scalarA: Uint8Array,
  scalarB: Uint8Array
): Uint8Array {
  // Input validation - ensure both scalars are correct length
  if (scalarA.length !== crypto_scalarmult_ed25519_SCALARBYTES ||
    scalarB.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalars must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  // Convert little-endian bytes to bigint
  const a = bytesToNumberLE(scalarA);
  const b = bytesToNumberLE(scalarB);
  const sum = a + b;

  // Safety check: ensure sum fits into 64 bytes maximum. If
  // bytesToNumberLE ever misbehaves and returns something larger,
  // this will catch it before we try to serialize.
  if (sum < 0n || sum > (1n << (64n * 8n)) - 1n) {
    throw new Error("resulting sum scalar is invalid");
  }

  const reduced = mod(sum, ed25519.Point.Fn.ORDER);
  const result = numberToBytesLE(reduced, crypto_scalarmult_ed25519_SCALARBYTES);

  // Final length check
  if (result.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error("resulting scalar has invalid length");
  }

  return result
}

/**
 * Multiply two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_mul(
  scalarA: Uint8Array,
  scalarB: Uint8Array
): Uint8Array {

  // Input validation - ensure both scalars are correct length
  if (scalarA.length !== crypto_scalarmult_ed25519_SCALARBYTES ||
    scalarB.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalars must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  const a = bytesToNumberLE(scalarA);
  const b = bytesToNumberLE(scalarB);
  const reduced = mod(a * b, ed25519.Point.Fn.ORDER);
  const result = numberToBytesLE(reduced, crypto_scalarmult_ed25519_SCALARBYTES);

  // Final length check
  if (result.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error("resulting scalar has invalid length");
  }

  return result;
}

/**
 * Reduce a scalar modulo the curve order
 */
export function crypto_core_ed25519_scalar_reduce(
  scalar: Uint8Array
): Uint8Array {
  if (scalar.length > crypto_core_ed25519_NONREDUCEDSCALARBYTES) {
    throw new Error(`scalar must be at most ${crypto_core_ed25519_NONREDUCEDSCALARBYTES} bytes`);
  }

  const scalarNum = bytesToNumberLE(scalar);
  const reduced = mod(scalarNum, ed25519.Point.Fn.ORDER);

  const result = numberToBytesLE(reduced, crypto_scalarmult_ed25519_SCALARBYTES);

  // Final length check
  if (result.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error("resulting scalar has invalid length");
  }

  return result;
}

// ===========================
// X25519 ECDH Operations
// ===========================

/**
 * X25519 scalar multiplication
 */
export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  if (privateKey.length !== crypto_scalarmult_x25519_SCALARBYTES || publicKey.length !== crypto_scalarmult_x25519_PKBYTES) {
    throw new Error("x25519 private and public keys must be 32 bytes each");
  }

  // Clamp the private key as per X25519 specification
  const clampedKey = new Uint8Array(privateKey);
  clampedKey[0] &= 248;
  clampedKey[31] &= 127;
  clampedKey[31] |= 64;

  return x25519.getSharedSecret(clampedKey, publicKey);
}

/**
 * Convert Ed25519 public key to X25519 public key
 */
export function crypto_sign_ed25519_pk_to_curve25519(
  edPubKey: Uint8Array
): Uint8Array {
  return ed25519.utils.toMontgomery(edPubKey);
}

// ===========================
// Hash Functions
// ===========================

/**
 * SHA-512 hash function
 */
export function crypto_hash_sha512(message: Uint8Array): Uint8Array {
  return sha512(message);
}

/**
 * BLAKE2b hash function (generic hash)
 * Matches libsodium signature: crypto_generichash(outputLength, message, key?)
 */
export function crypto_generichash(
  outputLength: number,
  message: Uint8Array,
  key: Uint8Array | null = null
): Uint8Array {
  // Input validation
  if (
    outputLength < crypto_generichash_BYTES_MIN ||
    outputLength > crypto_generichash_BYTES_MAX
  ) {
    throw new Error(
      `output length must be between ${crypto_generichash_BYTES_MIN} and ${crypto_generichash_BYTES_MAX} bytes`
    );
  }

  if (key) {
    return blake2b(message, { key, dkLen: outputLength });
  }
  return blake2b(message, { dkLen: outputLength });
}
