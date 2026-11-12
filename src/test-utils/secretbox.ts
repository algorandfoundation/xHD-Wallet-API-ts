// Test-only: libsodium-compatible secretbox (XSalsa20-Poly1305), used by the specs to check
// that ECDH shared secrets work as encryption keys. It lives outside the published library so
// that @noble/ciphers is a dev dependency only (excluded in tsconfig.build.json).
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";

/**
 * Encrypt a message using XSalsa20Poly1305
 */
export function crypto_secretbox_easy(
  message: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  // Encrypt the message using XSalsa20Poly1305
  // crypto_secretbox_MESSAGEBYTES_MAX is not enforced here, as noble-ciphers can handle larger messages
  const encrypted = xsalsa20poly1305(key, nonce).encrypt(message);

  return encrypted;
}

/**
 * Decrypt a message using XSalsa20Poly1305
 */
export function crypto_secretbox_open_easy(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  try {
    // Decrypt the message using XSalsa20Poly1305
    const decrypted = xsalsa20poly1305(key, nonce).decrypt(ciphertext);
    return decrypted;
  } catch (error) {
    // Keep the original failure as the cause (authentication failure, bad nonce/key length, ...)
    throw new Error("decryption failed", { cause: error });
  }
}
