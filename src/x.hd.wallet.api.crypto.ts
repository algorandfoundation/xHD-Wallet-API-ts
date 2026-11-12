import {
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_hash_sha512,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_sign_verify_detached,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_scalarmult,
    crypto_generichash,
} from './sumo.facade.js';
import { deriveChildNodePrivate } from './bip32-ed25519.js';
import { FIRST_HARDENED_INDEX } from './constants.js';

/**
 *
 */
export enum KeyContext {
    Address = 0,
    Identity = 1
}

export type ECDHCallback = (sharedPoint: Uint8Array, ourPubCurve25519: Uint8Array, otherPartyPubCurve25519: Uint8Array) => Promise<Uint8Array>;
export function computeSharedBlake2bSecret(meFirst: boolean): ECDHCallback {
    return async (sharedPoint: Uint8Array, ourPubCurve25519: Uint8Array, otherPartyPubCurve25519: Uint8Array): Promise<Uint8Array> => {
        let concatenation: Uint8Array
        if (meFirst) {
            concatenation = Buffer.concat([sharedPoint, ourPubCurve25519, otherPartyPubCurve25519])
        } else {
            concatenation = Buffer.concat([sharedPoint, otherPartyPubCurve25519, ourPubCurve25519])
        }

        return crypto_generichash(32, new Uint8Array(concatenation))
    }
}

export enum BIP32DerivationType {
    // standard Ed25519 bip32 derivations based of: https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a
    // Defines 32 bits to be zeroed from each derived zL
    Khovratovich = 32,
    // Derivations based on Peikert's ammendments to the original BIP32-Ed25519
    // Picking only 9 bits to be zeroed from each derived zL
    Peikert = 9
}

export interface ChannelKeys {
    tx: Uint8Array
    rx: Uint8Array
}

/**
 * Rejects values that can't be used as a non-hardened BIP44 level.
 * @throws RangeError if level is not an integer in [0, 2^31)
 */
function assertBip44Level(level: number, name: string): void {
    if (!Number.isInteger(level) || level < 0 || level >= FIRST_HARDENED_INDEX) {
        throw new RangeError(`${name} must be an integer in [0, ${FIRST_HARDENED_INDEX}), got ${level}`)
    }
}

/**
 * Turns a BIP44 path level into its hardened form (2^31 + num).
 * @throws RangeError if num is not an integer in [0, 2^31)
 */
export const harden = (num: number): number => {
    assertBip44Level(num, "harden() level")
    return FIRST_HARDENED_INDEX + num
};

/**
 * Rejects unknown derivation types, so a wrong value (e.g. a leftover `metadata` argument
 * from 1.x passed to signData) can't silently fall back to Khovratovich derivation.
 * @throws RangeError if derivationType is not a BIP32DerivationType member
 */
function assertValidDerivationType(derivationType: BIP32DerivationType): void {
    if (derivationType !== BIP32DerivationType.Peikert && derivationType !== BIP32DerivationType.Khovratovich) {
        throw new RangeError(`derivationType must be BIP32DerivationType.Peikert (${BIP32DerivationType.Peikert}) or BIP32DerivationType.Khovratovich (${BIP32DerivationType.Khovratovich}), got ${String(derivationType)}`)
    }
}

const TX_TAG: Uint8Array = new TextEncoder().encode("TX")

function startsWith(message: Uint8Array, prefix: Uint8Array): boolean {
    return message.length >= prefix.length && prefix.every((byte, i) => message[i] === byte)
}

function GetBIP44PathFromContext(context: KeyContext, account:number, key_index: number): number[] {
    // account is hardened below and keyIndex is a soft level, so both must fit below the hardened range.
    // Checking account here names it in the error, instead of harden()'s generic "level".
    assertBip44Level(account, "account")
    assertBip44Level(key_index, "keyIndex")

    switch (context) {
        case KeyContext.Address:
            return [harden(44), harden(283), harden(account), 0, key_index]
        case KeyContext.Identity:
            return [harden(44), harden(0), harden(account), 0, key_index]
        default:
            throw Error("Invalid context")
    }
}

/**
 * Thrown by signAlgoTransaction when its input does not start with "TX". Usually the encoded
 * transaction was passed instead of its bytes to sign ("TX" || encoded transaction).
 */
export class TxTagMissingError extends Error {
    constructor() {
        super('Transaction is not prefixed with the "TX" tag: pass the bytes to sign (e.g. algosdk\'s txn.bytesToSign()), not the encoded transaction')
        this.name = "TxTagMissingError"
    }
}

export class XHDWalletAPI {

    constructor() {}

    /**
     * Derives a child key from the root key based on BIP44 path
     *
     * @param rootKey - root key in extended format (kL, kR, c). It should be 96 bytes long
     * @param bip44Path - BIP44 path (m / purpose' / coin_type' / account' / change / address_index). The ' indicates that the value is hardened
     * @param isPrivate  - if true, return the private key, otherwise return the public key
     * @param derivationType - required; unlike the context-based methods there is no default
     * @returns - The extended private key (kL, kR, chainCode) or the extended public key (pub, chainCode)
     * @throws RangeError if derivationType is missing or not a BIP32DerivationType member
     */
    async deriveKey(rootKey: Uint8Array, bip44Path: number[], isPrivate: boolean = true, derivationType: BIP32DerivationType): Promise<Uint8Array> {
        assertValidDerivationType(derivationType)

        // Pick `g`, which is amount of bits zeroed from each derived node
        const g: number = derivationType === BIP32DerivationType.Peikert ? 9 : 32

        for (let i = 0; i < bip44Path.length; i++) {
            rootKey = await deriveChildNodePrivate(rootKey, bip44Path[i], g)
        }

        if (isPrivate) return rootKey

        // extended public key
        // [public] [nodeCC]
        return new Uint8Array(Buffer.concat([crypto_scalarmult_ed25519_base_noclamp(rootKey.subarray(0, 32)), rootKey.subarray(64, 96)]))
    }

    /**
     *
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @returns - public key 32 bytes
     */
    async keyGen(rootKey: Uint8Array, context: KeyContext, account:number, keyIndex: number, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)

        const extendedKey: Uint8Array = await this.deriveKey(rootKey, bip44Path, false, derivationType)
        return extendedKey.subarray(0, 32) // only public key
    }

    /**
     * Raw Signing function called by signData and signTransaction
     *
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     * Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param bip44Path
     * - BIP44 path (m / purpose' / coin_type' / account' / change / address_index)
     * @param data
     * - data to be signed in raw bytes
     *
     * @returns
     * - signature holding R and S, totally 64 bytes
     */
    private async rawSign(rootKey: Uint8Array, bip44Path: number[], data: Uint8Array, derivationType: BIP32DerivationType): Promise<Uint8Array> {
        const raw: Uint8Array = await this.deriveKey(rootKey, bip44Path, true, derivationType)

        const scalar: Uint8Array = raw.slice(0, 32);
        const kR: Uint8Array = raw.slice(32, 64);

        // \(1): pubKey = scalar * G (base point, no clamp)
        const publicKey = crypto_scalarmult_ed25519_base_noclamp(scalar);

        // \(2): h = hash(c || msg) mod q
        const r = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(Buffer.concat([kR, data])))

        // \(4):  R = r * G (base point, no clamp)
        const R = crypto_scalarmult_ed25519_base_noclamp(r)

        // h = hash(R || pubKey || msg) mod q
        let h = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(Buffer.concat([R, publicKey, data])));

        // \(5): S = (r + h * k) mod q
        const S = crypto_core_ed25519_scalar_add(r, crypto_core_ed25519_scalar_mul(h, scalar))

        return Buffer.concat([R, S]);
    }

    /**
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     *  Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @param data - data to be signed in raw bytes, signed exactly as given. If passed a transaction
     * or other Algorand protocol message, it signs that too. Callers signing data from an untrusted
     * source must domain-separate it so it can't form such a message, for example by signing a hash
     * of it, as ARC-60 does. Use signAlgoTransaction to sign transactions.
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns - signature holding R and S, totally 64 bytes
     * */
    async signData(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, data: Uint8Array, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        return await this.rawSign(rootKey, bip44Path, data, derivationType)
    }

    /**
     * Sign Algorand transaction
     * @param context
     * - context of the key (i.e Address, Identity)
     * @param account
     * - account number. This value will be hardened as part of BIP44
     * @param keyIndex
     * - key index. This value will be a SOFT derivation as part of BIP44.
     * @param prefixEncodedTx
     * - Bytes to sign: the encoded transaction prefixed with the "TX" tag (algosdk's txn.bytesToSign()).
     * Rejected with TxTagMissingError otherwise, to catch an encoded transaction passed without its prefix
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns sig
     * - Raw bytes signature
     */
    async signAlgoTransaction(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, prefixEncodedTx: Uint8Array, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        if (!startsWith(prefixEncodedTx, TX_TAG)) {
            throw new TxTagMissingError()
        }

        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)

        const sig =  await this.rawSign(rootKey, bip44Path, prefixEncodedTx, derivationType)

        return sig
    }



    /**
     * Wrapper around libsodium basica signature verification
     *
     * Any lib or system that can verify EdDSA signatures can be used
     *
     * @param signature - raw 64 bytes signature (R, S)
     * @param message - raw bytes of the message
     * @param publicKey - raw 32 bytes public key (x,y)
     * @returns true if signature is valid, false otherwise
     */
    async verifyWithPublicKey(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
        return crypto_sign_verify_detached(signature, message, publicKey)
    }


    /**
     * Function to perform ECDH against a provided ed25519 public key. 
     *
     * ECDH reference link: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
     *
     * It creates a shared secret between two parties. Each party only needs to be aware of the other's public key.
     * This symmetric secret can be used to derive a symmetric key for encryption and decryption, creating a private channel between the two parties.
     *
     * # Safety
     *
     * Without a callback function, the ECDH shared point is NOT uniformly distributed. It is recommended to provide a callback function that derives a final shared secret from the shared point. This functionality should only be called without a callback if the caller is doing KDF themselves.
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @param otherPartyEd25519Pub - raw 32 byte ed25519 public key of the other party. This key will be converted to montgomery format (curve25519) internally.
     * @param ecdhCallback - callback function that receives the shared point and both public keys in curve25519 format, and returns the final shared secret. This is typically a KDF.
     * @returns - If no ecdhCallback is provided, it returns the raw shared point. Otherwise, it returns the result of the ecdhCallback function. 
     */
    async ECDH(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, otherPartyEd25519Pub: Uint8Array, ecdhCallback?: ECDHCallback, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)
        const childKey: Uint8Array = await this.deriveKey(rootKey, bip44Path, true, derivationType)

        const scalar: Uint8Array = childKey.slice(0, 32)

        // our public key is derived from the private key
        const ourPub: Uint8Array = crypto_scalarmult_ed25519_base_noclamp(scalar)

        // convert from ed25519 to curve25519
        const ourPubCurve25519: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(ourPub)
        const otherPartyPubCurve25519: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(otherPartyEd25519Pub)

        // find common point
        const sharedPoint: Uint8Array = crypto_scalarmult(scalar, otherPartyPubCurve25519)

        if (ecdhCallback === undefined) {
            return sharedPoint
        }

        return ecdhCallback(sharedPoint, ourPubCurve25519, otherPartyPubCurve25519)
    }
}
