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
import * as msgpack from "algo-msgpack-with-bigint"
import Ajv from "ajv"
//@ts-expect-error, we handle this with ts-alias
import { deriveChildNodePrivate } from './bip32-ed25519';
import { concatUint8Arrays, base64Decode } from './uint8.js';

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
            concatenation = concatUint8Arrays([sharedPoint, ourPubCurve25519, otherPartyPubCurve25519])
        } else {
            concatenation = concatUint8Arrays([sharedPoint, otherPartyPubCurve25519, ourPubCurve25519])
        }

        return crypto_generichash(32, concatenation)
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

export enum Encoding {
    MSGPACK = "msgpack",
    BASE64 = "base64",
    NONE = "none"
}

export interface SignMetadata {
    encoding: Encoding
    schema: Object
}

export const harden = (num: number): number => 0x80_00_00_00 + num;

function GetBIP44PathFromContext(context: KeyContext, account: number, key_index: number): number[] {
    switch (context) {
        case KeyContext.Address:
            return [harden(44), harden(283), harden(account), 0, key_index]
        case KeyContext.Identity:
            return [harden(44), harden(0), harden(account), 0, key_index]
        default:
            throw Error("Invalid context")
    }
}

export const ERROR_BAD_DATA: Error = Error("Invalid Data")
export const ERROR_TAGS_FOUND: Error = Error("Transactions tags found")

export class XHDWalletAPI {

    constructor() { }

    /**
     * Derives a child key from the root key based on BIP44 path
     *
     * @param rootKey - root key in extended format (kL, kR, c). It should be 96 bytes long
     * @param bip44Path - BIP44 path (m / purpose' / coin_type' / account' / change / address_index). The ' indicates that the value is hardened
     * @param isPrivate  - if true, return the private key, otherwise return the public key
     * @returns - The extended private key (kL, kR, chainCode) or the extended public key (pub, chainCode)
     */
    async deriveKey(rootKey: Uint8Array, bip44Path: number[], isPrivate: boolean = true, derivationType: BIP32DerivationType): Promise<Uint8Array> {
        // Pick `g`, which is amount of bits zeroed from each derived node
        const g: number = derivationType === BIP32DerivationType.Peikert ? 9 : 32

        for (let i = 0; i < bip44Path.length; i++) {
            rootKey = await deriveChildNodePrivate(rootKey, bip44Path[i], g)
        }

        if (isPrivate) return rootKey

        // extended public key
        // [public] [nodeCC]
        return concatUint8Arrays([crypto_scalarmult_ed25519_base_noclamp(rootKey.subarray(0, 32)), rootKey.subarray(64, 96)])
    }

    /**
     *
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @returns - public key 32 bytes
     */
    async keyGen(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
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
        const r = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(concatUint8Arrays([kR, data])))

        // \(4):  R = r * G (base point, no clamp)
        const R = crypto_scalarmult_ed25519_base_noclamp(r)

        // h = hash(R || pubKey || msg) mod q
        let h = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(concatUint8Arrays([R, publicKey, data])));

        // \(5): S = (r + h * k) mod q
        const S = crypto_core_ed25519_scalar_add(r, crypto_core_ed25519_scalar_mul(h, scalar))

        return concatUint8Arrays([R, S]);
    }

    /**
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     *  Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @param data - data to be signed in raw bytes
     * @param metadata - metadata object that describes how `data` was encoded and what schema to use to validate against
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns - signature holding R and S, totally 64 bytes
     * */
    async signData(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, data: Uint8Array, metadata: SignMetadata, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        // validate data
        const result: boolean | Error = this.validateData(data, metadata)

        if (result instanceof Error) { // decoding errors
            throw result
        }

        if (!result) { // failed schema validation
            throw ERROR_BAD_DATA
        }

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
     * - Encoded transaction object
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns sig
     * - Raw bytes signature
     */
    async signAlgoTransaction(rootKey: Uint8Array, context: KeyContext, account: number, keyIndex: number, prefixEncodedTx: Uint8Array, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<Uint8Array> {
        const bip44Path: number[] = GetBIP44PathFromContext(context, account, keyIndex)

        const sig = await this.rawSign(rootKey, bip44Path, prefixEncodedTx, derivationType)

        return sig
    }


    /**
     * SAMPLE IMPLEMENTATION to show how to validate data with encoding and schema, using base64 as an example
     *
     * @param message
     * @param metadata
     * @returns
     */
    private validateData(message: Uint8Array, metadata: SignMetadata): boolean | Error {

        // First, perform an early check on the raw message bytes for Algorand protocol tags.
        // This prevents attempting to decode a buffer that already includes a reserved prefix
        // (e.g., "TX" + msgpack payload) which would cause msgpack to throw a decode error.
        if (this.hasAlgorandTags(message)) {
            return ERROR_TAGS_FOUND
        }

        let decoded: Uint8Array
        switch (metadata.encoding) {
            case Encoding.BASE64:
                decoded = base64Decode(new TextDecoder().decode(message))
                break
            case Encoding.MSGPACK:
                // algo-msgpack-with-bigint expects a Buffer-like input in Node.js
                decoded = msgpack.decode<Uint8Array>(Buffer.from(message)) as Uint8Array
                break

            case Encoding.NONE:
                decoded = message
                break
            default:
                throw Error("Invalid encoding")
        }

        // normalize binary/Buffer decoded payloads into plain JS objects that AJV can validate
        let toValidate: any = decoded
        // Buffer detection (Node) — Buffer may expose prototype methods that AJV treats as properties
        // Convert Buffer/Uint8Array into an object with numeric string keys to match the schema shape
        // (e.g. {"0": 12, "1": 34, ...})
        // eslint-disable-next-line no-undef
        if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(decoded)) {
            const obj: Record<string, number> = {}
            for (let i = 0; i < decoded.length; i++) obj[i] = (decoded as any)[i]
            toValidate = obj
        } else if (decoded instanceof Uint8Array) {
            const obj: Record<string, number> = {}
            for (let i = 0; i < decoded.length; i++) obj[i] = (decoded as any)[i]
            toValidate = obj
        }

        //@ts-expect-error, this is constructable
        const ajv = new Ajv()
        const validate = ajv.compile(metadata.schema)
        return validate(toValidate)
    }

    /**
     * Detect if the message has Algorand protocol specific tags
     *
     * @param message - raw bytes of the message
     * @returns - true if message has Algorand protocol specific tags, false otherwise
     */
    private hasAlgorandTags(message: Uint8Array): boolean {

        // Check that decoded doesn't include the following prefixes
        // Prefixes taken from go-algorand node software code
        // https://github.com/algorand/go-algorand/blob/master/protocol/hash.go
        const prefixes: string[] = [
            "appID", "arc", "aB", "aD", "aO", "aP", "aS", "AS", "B256", "BH", "BR", "CR", "GE", "KP", "MA", "MB",
            "MX", "NIC", "NIR", "NIV", "NPR", "OT1", "OT2", "PF", "PL", "Program", "ProgData", "PS", "PK", "SD",
            "SpecialAddr", "STIB", "spc", "spm", "spp", "sps", "spv", "TE", "TG", "TL", "TX", "VO"
        ]
        for (const prefix of prefixes) {
            if (new TextDecoder().decode(message.subarray(0, prefix.length)) === prefix) {
                return true
            }
        }

        return false
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
