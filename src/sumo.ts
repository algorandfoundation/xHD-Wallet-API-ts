import pkg from 'libsodium-wrappers-sumo'

await pkg.ready;

export const crypto_core_ed25519_add = pkg.crypto_core_ed25519_add;
export const crypto_core_ed25519_scalar_add = pkg.crypto_core_ed25519_scalar_add
export const crypto_core_ed25519_scalar_mul = pkg.crypto_core_ed25519_scalar_mul
export const crypto_core_ed25519_scalar_reduce = pkg.crypto_core_ed25519_scalar_reduce
export const crypto_hash_sha512 = pkg.crypto_hash_sha512
export const crypto_scalarmult_ed25519_base_noclamp = pkg.crypto_scalarmult_ed25519_base_noclamp
export const crypto_sign_verify_detached = pkg.crypto_sign_verify_detached
export const crypto_sign_ed25519_pk_to_curve25519 = pkg.crypto_sign_ed25519_pk_to_curve25519
export const crypto_scalarmult = pkg.crypto_scalarmult
export const crypto_generichash = pkg.crypto_generichash
export const crypto_sign_keypair = pkg.crypto_sign_keypair
export const crypto_sign_ed25519_sk_to_curve25519 = pkg.crypto_sign_ed25519_sk_to_curve25519
export const crypto_secretbox_open_easy = pkg.crypto_secretbox_open_easy
export const crypto_secretbox_easy = pkg.crypto_secretbox_easy
export const crypto_kx_client_session_keys = pkg.crypto_kx_client_session_keys
export const crypto_kx_server_session_keys = pkg.crypto_kx_server_session_keys
export const to_base64 = pkg.to_base64
