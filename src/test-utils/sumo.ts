// Test-only: libsodium-style helpers the library itself doesn't use. The specs use them to
// check parity with libsodium-wrappers-sumo. They use @noble directly (a dev dependency) and
// live outside the published library (src/test-utils is excluded in tsconfig.build.json).
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { crypto_generichash } from "../sumo.facade.js";

const crypto_sign_SECRETKEYBYTES = 64;
const crypto_scalarmult_ed25519_SCALARBYTES = 32;
const crypto_generichash_blake2b_BYTES_MAX = 64;
const crypto_kx_SESSIONKEYBYTES = 32;
const crypto_kx_PUBLICKEYBYTES = 32;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  keyType: string;
}

export interface CryptoKX {
  sharedRx: Uint8Array;
  sharedTx: Uint8Array;
}

/**
 * Generate an Ed25519 keypair
 * @param seed 32-byte seed which to use to generate public key. Optional, generates random value if not provided.
 */
export function crypto_sign_keypair(seed?: Uint8Array): KeyPair {
  seed ??= ed25519.utils.randomSecretKey(); // Use random 32-byte seed if not provided
  const publicKey = ed25519.getPublicKey(seed); // 32-byte public key

  // Create 64-byte secret key: seed (32 bytes) + public key (32 bytes)
  // "secretKey" in Noble terminology is equivalent to "seed" in LibSodium.
  // "secretKey" in LibSodium terminology refers to the concatenation of seed || publicKey.
  const secretKey = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  secretKey.set(seed, 0); // First 32 bytes: seed
  secretKey.set(publicKey, 32); // Last 32 bytes: public key

  return {
    publicKey: new Uint8Array(publicKey),
    secretKey: secretKey,
    keyType: "ed25519",
  };
}

/**
 * Convert Ed25519 secret key to X25519 secret key
 */
export function crypto_sign_ed25519_sk_to_curve25519(
  edSecretKey: Uint8Array
): Uint8Array {
  // Extract just the seed (first 32 bytes) since edwardsToMontgomeryPriv expects 32 bytes
  const seed = edSecretKey.slice(0, crypto_scalarmult_ed25519_SCALARBYTES);
  return ed25519.utils.toMontgomerySecret(seed);
}

/**
 * Synchronous X25519 with libsodium's clamping, as used by crypto_kx_* below.
 * Noble clamps too, so the explicit clamp is redundant crypto-wise; it is kept so this helper
 * mirrors libsodium's `crypto_scalarmult` (including its input length checks) one-to-one.
 */
function scalarmult(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32 || publicKey.length !== 32) {
    throw new Error("x25519 private and public keys must be 32 bytes each");
  }
  const clampedKey = new Uint8Array(privateKey);
  clampedKey[0] &= 248;
  clampedKey[31] &= 127;
  clampedKey[31] |= 64;
  return x25519.getSharedSecret(clampedKey, publicKey);
}

// ===========================
// Key Exchange Functions
// ===========================

/**
 * Generate client session keys for key exchange
 */
export function crypto_kx_client_session_keys(
  clientPub: Uint8Array,
  clientPriv: Uint8Array,
  serverPub: Uint8Array
): CryptoKX {

  // Step 1: Perform X25519 ECDH to get shared secret
  // Calling crypto_scalarmult rather than x25519.getSharedSecret to match facade function naming
  // as crypto_scalarmult handles clamping
  const sharedSecret = scalarmult(clientPriv, serverPub);

  if (sharedSecret.length !== crypto_kx_SESSIONKEYBYTES) {
    throw new Error(`shared secret must be ${crypto_kx_SESSIONKEYBYTES} bytes`);
  }

  // Step 2: Create key material = shared_secret + client_pk + server_pk (96 bytes)
  // This matches libsodium's exact concatenation order
  const keyMaterial = new Uint8Array(crypto_kx_SESSIONKEYBYTES + 2 * crypto_kx_PUBLICKEYBYTES);
  keyMaterial.set(sharedSecret, 0); // shared_secret (32 bytes)
  keyMaterial.set(clientPub, crypto_kx_PUBLICKEYBYTES); // client_pk (32 bytes)
  keyMaterial.set(serverPub, 2 * crypto_kx_PUBLICKEYBYTES); // server_pk (32 bytes)

  // Step 3: BLAKE2B-512 hash to get 64-byte result
  const hash = crypto_generichash(crypto_generichash_blake2b_BYTES_MAX, keyMaterial);

  // Step 4: Split into rx (first 32 bytes) and tx (last 32 bytes) for client
  const sharedRx = hash.slice(0, crypto_kx_SESSIONKEYBYTES);
  const sharedTx = hash.slice(crypto_kx_SESSIONKEYBYTES, 2 * crypto_kx_SESSIONKEYBYTES);

  return {
    sharedRx: sharedRx,
    sharedTx: sharedTx,
  };
}

/**
 * Generate server session keys for key exchange
 */
export function crypto_kx_server_session_keys(
  serverPub: Uint8Array,
  serverPriv: Uint8Array,
  clientPub: Uint8Array
): CryptoKX {

  // Step 1: Perform X25519 ECDH to get shared secret
  // Calling crypto_scalarmult rather than x25519.getSharedSecret to match facade function naming
  // and as crypto_scalarmult handles clamping
  const sharedSecret = scalarmult(serverPriv, clientPub);

  // Step 2: Create key material = shared_secret + client_pk + server_pk (96 bytes)
  // Same concatenation order as client (libsodium specification)
  const keyMaterial = new Uint8Array(crypto_kx_SESSIONKEYBYTES + 2 * crypto_kx_PUBLICKEYBYTES);
  keyMaterial.set(sharedSecret, 0); // shared_secret (32 bytes)
  keyMaterial.set(clientPub, crypto_kx_PUBLICKEYBYTES); // client_pk (32 bytes)
  keyMaterial.set(serverPub, 2 * crypto_kx_PUBLICKEYBYTES); // server_pk (32 bytes)

  // Step 3: BLAKE2B-512 hash to get 64-byte result
  const hash = crypto_generichash(crypto_generichash_blake2b_BYTES_MAX, keyMaterial);

  // Step 5: Server swaps rx/tx (server rx = client tx, server tx = client rx)
  const sharedRx = hash.slice(crypto_kx_SESSIONKEYBYTES, 2 * crypto_kx_SESSIONKEYBYTES); // Server rx = client tx (last 32 bytes)
  const sharedTx = hash.slice(0, crypto_kx_SESSIONKEYBYTES); // Server tx = client rx (first 32 bytes)

  return {
    sharedRx: sharedRx,
    sharedTx: sharedTx,
  };
}

// ===========================
// Utility Functions
// ===========================

/**
 * Convert bytes or string to base64 string (without padding to match libsodium)
 */
export function to_base64(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);

  // Remove padding to match libsodium's to_base64 behavior
  return base64.replace(/=+$/, "");
}
