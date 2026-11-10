import { randomBytes } from "crypto"
import { mod as nobleMod } from "@noble/curves/abstract/modular.js"
import { ed25519 } from "@noble/curves/ed25519.js"
import { bytesToNumberLE as nobleBytesToNumberLE, numberToBytesLE as nobleNumberToBytesLE } from "@noble/curves/utils.js"
import { concatBytes as nobleConcatBytes } from "@noble/hashes/utils.js"
import { bytesToNumberLE, concatBytes, mod, numberToBytesLE } from "./utils.js"

// These helpers replaced @noble's in the library, so they must behave identically
describe("Native byte/bigint helpers match @noble", () => {
    const randomLength = (max: number): number => Math.floor(Math.random() * (max + 1))
    const ITERATIONS = 2000

    it("\(OK) concatBytes", () => {
        expect(concatBytes()).toEqual(nobleConcatBytes())
        for (let i = 0; i < ITERATIONS; i++) {
            const parts = Array.from({ length: randomLength(4) }, () => new Uint8Array(randomBytes(randomLength(40))))
            expect(concatBytes(...parts)).toEqual(nobleConcatBytes(...parts))
        }
    })

    it("\(OK) concatBytes returns a copy", () => {
        const a = new Uint8Array([1, 2, 3])
        const result = concatBytes(a)
        result[0] = 9
        expect(a[0]).toBe(1)
    })

    it("\(OK) bytesToNumberLE", () => {
        for (const bytes of [new Uint8Array(0), new Uint8Array(32), new Uint8Array(32).fill(0xff)]) {
            expect(bytesToNumberLE(bytes)).toBe(nobleBytesToNumberLE(bytes))
        }
        for (let i = 0; i < ITERATIONS; i++) {
            const bytes = new Uint8Array(randomBytes(randomLength(64)))
            expect(bytesToNumberLE(bytes)).toBe(nobleBytesToNumberLE(bytes))
        }
    })

    it("\(OK) numberToBytesLE", () => {
        for (let i = 0; i < ITERATIONS; i++) {
            const length = 1 + randomLength(63)
            const n = nobleBytesToNumberLE(new Uint8Array(randomBytes(length)))
            expect(numberToBytesLE(n, length)).toEqual(nobleNumberToBytesLE(n, length))
        }
        expect(numberToBytesLE(0n, 32)).toEqual(nobleNumberToBytesLE(0n, 32))
        expect(numberToBytesLE((1n << 256n) - 1n, 32)).toEqual(nobleNumberToBytesLE((1n << 256n) - 1n, 32))
    })

    it("\(FAIL) numberToBytesLE rejects what @noble rejects", () => {
        for (const [n, length] of [[1n << 256n, 32], [256n, 1], [-1n, 32], [1n, 0]] as const) {
            expect(() => nobleNumberToBytesLE(n, length)).toThrow()
            expect(() => numberToBytesLE(n, length)).toThrow(RangeError)
        }
    })

    it("\(OK) mod", () => {
        const order = ed25519.Point.Fn.ORDER
        for (let i = 0; i < ITERATIONS; i++) {
            const a = nobleBytesToNumberLE(new Uint8Array(randomBytes(64))) * (Math.random() < 0.5 ? -1n : 1n)
            expect(mod(a, order)).toBe(nobleMod(a, order))
        }
        expect(mod(-1n, order)).toBe(order - 1n)
        expect(mod(0n, order)).toBe(0n)
    })

    it("\(FAIL) mod rejects a non-positive modulus", () => {
        expect(() => mod(5n, 0n)).toThrow(RangeError)
        expect(() => mod(5n, -7n)).toThrow(RangeError)
    })

    it("\(FAIL) byte helpers reject non-Uint8Array input", () => {
        expect(() => concatBytes([1, 2] as unknown as Uint8Array)).toThrow(TypeError)
        expect(() => bytesToNumberLE("00" as unknown as Uint8Array)).toThrow(TypeError)
    })
})
