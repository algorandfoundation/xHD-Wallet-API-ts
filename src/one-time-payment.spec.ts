import * as bip39 from "@scure/bip39"
import { deriveChildNodePublic, fromSeed } from "./bip32-ed25519.js"
import { BIP32DerivationType, XHDWalletAPI, harden } from "./x.hd.wallet.api.crypto.js"
import base32 from "hi-base32"
import { sha512_256 } from "js-sha512"

function encodeAddress(publicKey: Buffer): string {
    const keyHash: string = sha512_256.create().update(publicKey).hex()

    // last 4 bytes of the hash
    const checksum: string = keyHash.slice(-8)

    return base32.encode(ConcatArrays(publicKey, Buffer.from(checksum, "hex"))).slice(0, 58)
}

function ConcatArrays(...arrs: ArrayLike<number>[]) {
    const size = arrs.reduce((sum, arr) => sum + arr.length, 0)
    const c = new Uint8Array(size)

    let offset = 0
    for (let i = 0; i < arrs.length; i++) {
        c.set(arrs[i], offset)
        offset += arrs[i].length
    }

    return c
}


describe("One time Payment Flows", () => {

  let cryptoService: XHDWalletAPI
  let bip39Mnemonic: string = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
  let rootKey: Uint8Array
  const derivationType: BIP32DerivationType = BIP32DerivationType.Peikert

  beforeAll(() => {
    rootKey = fromSeed( Buffer.from(bip39.mnemonicToSeedSync(bip39Mnemonic, "")))
  })

  beforeEach(() => {
    cryptoService = new XHDWalletAPI()
    })

	afterEach(() => {})

  it("Derive 4th path node extended key and soft derive a child public key", async () => {
    // Derivation path m/44'/283'/0'/0
    // Purposely missing the last index so that we can soft derive a child public key
    const path = [harden(44), harden(283), harden(0), 0]

    // Pick `g`, which is amount of bits zeroed from each derived node
    const g: number = derivationType === BIP32DerivationType.Peikert ? 9 : 32

    // 4 level derivation to get extended key
    const node: Uint8Array = await cryptoService.deriveKey(rootKey, path, false, g)

    // Check length of node extended key
    expect(node.length).toBe(64)

    // Soft derive a child public key at index 5
    const childIndex: number = 5
    const childNode: Uint8Array = await deriveChildNodePublic(node, childIndex, g)

    // Check length of child node extended key
    expect(childNode.length).toBe(64)

    // Cross check with a a full bip44 path derivation
    // Full derivation path m/44'/283'/0'/0/5
    const fullPath = [harden(44), harden(283), harden(0), 0, childIndex]

    const fullNode: Uint8Array = await cryptoService.deriveKey(rootKey, fullPath, false, g)

    // Check that the public keys are the same
    const childPublicKey: Uint8Array = childNode.subarray(0, 32)
    const fullPublicKey: Uint8Array = fullNode.subarray(0, 32)

    expect(Buffer.from(childPublicKey).toString('hex')).toBe(Buffer.from(fullPublicKey).toString('hex'))

    // Check that the chain codes are the same
    const childChainCode: Uint8Array = childNode.subarray(32, 64)
    const fullChainCode: Uint8Array = fullNode.subarray(32, 64)

    expect(Buffer.from(childChainCode).toString('hex')).toBe(Buffer.from(fullChainCode).toString('hex'))
  })

  describe("Alice & Bob Share 4th level nodes and guess child public keys", () => {

    it("Alice derives m/44'/283'/0'/0 and derives child public keys", async () => {
      // Alice's derivation path m/44'/283'/0'/0
      // derive 5 keys
      for (let index = 0; index < 5; index++) {
        const alicePath = [harden(44), harden(283), harden(0), 0, index]

        // Pick `g`, which is amount of bits zeroed from each derived node
        const g: number = derivationType === BIP32DerivationType.Peikert ? 9 : 32

        // Alice derives her child node
        const aliceChildNode: Uint8Array = await cryptoService.deriveKey(rootKey, alicePath, false, g)

        const aliceChildPub: Uint8Array = aliceChildNode.subarray(0, 32)
        const aliceChildChainCode: Uint8Array = aliceChildNode.subarray(32, 64)

        console.log(`Alice derived child index ${index}: public Key: [${Buffer.from(aliceChildPub).toString('hex')}], algorand address: ${encodeAddress(Buffer.from(aliceChildPub))}  , chain Code: [${Buffer.from(aliceChildChainCode).toString('hex')}]`)
      }
    })

    it("Alice derives m/44'/283'/0'/0 and shares with Bob. Bob derives child public keys", async () => {
      // Alice's derivation path m/44'/283'/0'/0
      const alicePath = [harden(44), harden(283), harden(0), 0]

      // Pick `g`, which is amount of bits zeroed from each derived node
      const g: number = derivationType === BIP32DerivationType.Peikert ? 9 : 32

      // Alice derives her node
      const aliceNode: Uint8Array = await cryptoService.deriveKey(rootKey, alicePath, false, g)

      // log alice's extended key, first 32 bytes is public key, last 32 bytes is chain code
      console.log(`Alice's public node key: [${Buffer.from(aliceNode.subarray(0, 32)).toString('hex')}] chain Code: [${Buffer.from(aliceNode.subarray(32, 64)).toString('hex')}]`)

      // Alice shares her extended key with Bob (aliceNode)
     
      console.log(`Alice shares her extended key with Bob.`)

// Bob derives the first 20 keys and logs them
      for (let index = 0; index < 5; index++) {
        const aliceChildNode: Uint8Array = await deriveChildNodePublic(aliceNode, index, g)

        const aliceChildPub: Uint8Array = aliceChildNode.subarray(0, 32)
        const aliceChildChainCode: Uint8Array = aliceChildNode.subarray(32, 64)

        console.log(`Bob derived Alice's child index ${index}: public Key: [${Buffer.from(aliceChildPub).toString('hex')}], algorand address: ${encodeAddress(Buffer.from(aliceChildPub))}  , chain Code: [${Buffer.from(aliceChildChainCode).toString('hex')}]`)
      
        // cross check with Alice's derivation
        const fullAlicePath = [harden(44), harden(283), harden(0), 0, index]
        const fullAliceChildNode: Uint8Array = await cryptoService.deriveKey(rootKey, fullAlicePath, false, g)

        const fullAliceChildPub: Uint8Array = fullAliceChildNode.subarray(0, 32)
        const fullAliceChildChainCode: Uint8Array = fullAliceChildNode.subarray(32, 64)

        expect(Buffer.from(aliceChildPub).toString('hex')).toBe(Buffer.from(fullAliceChildPub).toString('hex'))
        expect(Buffer.from(aliceChildChainCode).toString('hex')).toBe(Buffer.from(fullAliceChildChainCode).toString('hex'))
      }
      
    
    })
  })
})
