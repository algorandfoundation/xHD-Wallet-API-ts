import { ed25519 } from "@noble/curves/ed25519.js"
import { sha512 as nobleSha512 } from "@noble/hashes/sha2.js"
import _sodium from "libsodium-wrappers-sumo"
import { bytesToNumberLE, concatBytes, numberToBytesLE } from "./utils.js"
import { ED25519_ORDER, ed25519Verify, x25519 } from "./webcrypto.js"

const Point = ed25519.Point
const FIELD_PRIME = 2n ** 255n - 19n
const message = new TextEncoder().encode("edge case")
const randomScalar = (): bigint => bytesToNumberLE(crypto.getRandomValues(new Uint8Array(64))) % ED25519_ORDER

let sodium: typeof _sodium
beforeAll(async () => {
    await _sodium.ready
    sodium = _sodium
})

const libsodiumVerify = (signature: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean => {
    try { return sodium.crypto_sign_verify_detached(signature, msg, publicKey) } catch { return false }
}

// ed25519Verify must reach the same verdict as libsodium (the 1.x verifier) on every case,
// including those where WebCrypto implementations and @noble's default (ZIP-215) differ.
describe("Ed25519 verification matches libsodium's strict rules", () => {
    const identity: Uint8Array = Point.ZERO.toBytes()
    const nonCanonicalIdentity: Uint8Array = numberToBytesLE(FIELD_PRIME + 1n, 32)

    // An order-8 point; its multiples are every small-order point
    const torsion = Point.fromBytes(Uint8Array.from(Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex")))

    const expectSameAsLibsodium = async (signature: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, expected: boolean) => {
        expect(libsodiumVerify(signature, msg, publicKey)).toBe(expected)
        expect(await ed25519Verify(signature, msg, publicKey)).toBe(expected)
    }

    it("\(OK) torsion point has order 8", () => {
        expect(torsion.double().double().double().equals(Point.ZERO)).toBe(true)
        expect(torsion.double().double().equals(Point.ZERO)).toBe(false)
    })

    it("\(OK) accepts a valid signature", async () => {
        const secretKey = ed25519.utils.randomSecretKey()
        await expectSameAsLibsodium(ed25519.sign(message, secretKey), message, ed25519.getPublicKey(secretKey), true)
    })

    it("\(FAIL) rejects a tampered message", async () => {
        const secretKey = ed25519.utils.randomSecretKey()
        await expectSameAsLibsodium(ed25519.sign(message, secretKey), new TextEncoder().encode("other"), ed25519.getPublicKey(secretKey), false)
    })

    it("\(FAIL) rejects a non-canonical S (S + L)", async () => {
        const secretKey = ed25519.utils.randomSecretKey()
        const signature = ed25519.sign(message, secretKey)
        const malleated = concatBytes(signature.subarray(0, 32), numberToBytesLE(bytesToNumberLE(signature.subarray(32)) + ED25519_ORDER, 32))
        await expectSameAsLibsodium(malleated, message, ed25519.getPublicKey(secretKey), false)
    })

    it("\(FAIL) rejects every small-order public key and R, with either sign bit", async () => {
        let point = Point.ZERO
        for (let k = 0; k < 8; k++, point = point.add(torsion)) {
            for (const signBit of [0, 0x80]) {
                const encoding = point.toBytes()
                encoding[31] |= signBit
                // R = identity, S = 0 satisfies the verification equation for any small-order key
                await expectSameAsLibsodium(concatBytes(identity, new Uint8Array(32)), message, encoding, false)
                await expectSameAsLibsodium(concatBytes(encoding, new Uint8Array(32)), message, identity, false)
            }
        }
    })

    it("\(FAIL) rejects non-canonical public key and R encodings", async () => {
        await expectSameAsLibsodium(concatBytes(identity, new Uint8Array(32)), message, nonCanonicalIdentity, false)
        await expectSameAsLibsodium(concatBytes(nonCanonicalIdentity, new Uint8Array(32)), message, identity, false)

        // y = p + 3 (non-canonical) on an otherwise valid-looking key
        const secretKey = ed25519.utils.randomSecretKey()
        await expectSameAsLibsodium(ed25519.sign(message, secretKey), message, numberToBytesLE(FIELD_PRIME + 3n, 32), false)
    })

    it("\(OK) mixed-order public keys: cofactorless verification, as libsodium", async () => {
        // A' = aB + T. A signature over A' satisfies the cofactorless equation only when
        // k = H(R || A' || M) is a multiple of 8, so libsodium accepts exactly those.
        let sawReject = false, sawAccept = false
        for (let i = 0; i < 200 && !(sawReject && sawAccept); i++) {
            const a = randomScalar(), r = randomScalar()
            const mixedPublicKey = Point.BASE.multiply(a).add(torsion).toBytes()
            const R = Point.BASE.multiply(r).toBytes()
            const msg = concatBytes(message, new Uint8Array([i]))
            const k = bytesToNumberLE(nobleSha512(concatBytes(R, mixedPublicKey, msg))) % ED25519_ORDER
            const signature = concatBytes(R, numberToBytesLE((r + k * a) % ED25519_ORDER, 32))
            const expected = k % 8n === 0n
            if (expected ? sawAccept : sawReject) continue
            await expectSameAsLibsodium(signature, msg, mixedPublicKey, expected)
            if (expected) sawAccept = true; else sawReject = true
        }
        expect(sawReject && sawAccept).toBe(true)
    })

    it("\(FAIL) rejects wrong lengths and invalid points", async () => {
        const secretKey = ed25519.utils.randomSecretKey()
        const publicKey = ed25519.getPublicKey(secretKey), signature = ed25519.sign(message, secretKey)
        expect(await ed25519Verify(signature.subarray(0, 63), message, publicKey)).toBe(false)
        expect(await ed25519Verify(signature, message, publicKey.subarray(0, 31))).toBe(false)
        // y = 2 is not on the curve
        await expectSameAsLibsodium(signature, message, numberToBytesLE(2n, 32), false)
    })
})

describe("X25519 matches libsodium", () => {
    const libsodiumScalarmult = (scalar: Uint8Array, publicKey: Uint8Array): Uint8Array | "reject" => {
        try { return sodium.crypto_scalarmult(scalar, publicKey) } catch { return "reject" }
    }
    const ours = async (scalar: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array | "reject"> => {
        try { return await x25519(scalar, publicKey) } catch { return "reject" }
    }

    it("\(OK) same shared secret, including unclamped scalars and a set high bit in the public key", async () => {
        for (let i = 0; i < 50; i++) {
            const scalar = crypto.getRandomValues(new Uint8Array(32))
            const publicKey = sodium.crypto_scalarmult_base(crypto.getRandomValues(new Uint8Array(32)))
            if (i % 2) publicKey[31] |= 0x80
            expect(await ours(scalar, publicKey)).toEqual(libsodiumScalarmult(scalar, publicKey))
        }
    })

    it("\(FAIL) rejects small-order and non-canonical public keys, as libsodium", async () => {
        const scalar = crypto.getRandomValues(new Uint8Array(32))
        for (const u of [0n, 1n, FIELD_PRIME, FIELD_PRIME + 1n]) {
            const publicKey = numberToBytesLE(u, 32)
            expect(libsodiumScalarmult(scalar, publicKey)).toBe("reject")
            expect(await ours(scalar, publicKey)).toBe("reject")
        }
    })
})
