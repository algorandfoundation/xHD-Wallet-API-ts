[![semantic-release: angular](https://img.shields.io/badge/semantic--release-angular-e10079?logo=semantic-release)](https://github.com/semantic-release/semantic-release)


# xHD Wallet API Typescript

Typescript implementation of BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace for Algorand's ARC-52 ([BIP32-ed25519 spec](https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a)).

---

## Changes from 1.x to 2.x

Due to issues related to importing a library reliant on WASM into the browser environment as well as in React-Native, we decided to migrate away from libsodium-wrappers-sumo (a WASM-based libsodium wrapper) to Noble cryptography. See [PR #22](https://github.com/algorandfoundation/xHD-Wallet-API-ts/pull/22) for more details.


## Installation

```bash
yarn add @algorandfoundation/xhd-wallet-api
```

## Usage

### 1. Initialize

```ts
import { XHDWalletAPI, fromSeed, KeyContext } from '@algorandfoundation/xhd-wallet-api';

const cryptoService = new XHDWalletAPI();
const seed = getSeed(); // Your secure seed-retrieval API
const rootKey = cryptoService.fromSeed(seed);
seed.fill(0); // Zero out the seed after it has been used

// ... use rootKey
rootKey.fill(0); // Zero out the rootKey after it has been used
```

### Buffer for Binary Operations

This library uses Buffer for all binary operations (concatenation, encoding, base64, etc.) in both Node.js and React Native. The Buffer API is available everywhere via the [buffer](https://www.npmjs.com/package/buffer) polyfill.

You can use Buffer just as you would in Node.js:

```js
// Concatenate binary data
const result = Buffer.concat([Buffer.from(a), Buffer.from(b)]);

// Convert to string
const str = Buffer.from(a).toString('utf8');

// Base64 encode/decode
const base64 = Buffer.from(a).toString('base64');
const bytes = Buffer.from(base64, 'base64');
```

All cryptographic APIs still use Uint8Array for compatibility, but you can always convert between Buffer and Uint8Array using Buffer.from().

### 2. Generate Public Key (BIP44 path)

```ts
const pk = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0);
```
`KeyContext.Address` is Algorand's cointype `283'`. Use `KeyContext.Identity` for identity keys (`0'`).

### 3. Sign Algorand Transactions

```ts
const prefixEncodedTx = new Uint8Array(/* ... */); // Algorand SDK-encoded tx
const signature = await cryptoService.signAlgoTransaction(
  rootKey, KeyContext.Address, 0, 0, prefixEncodedTx
);
const isValid = await cryptoService.verifyWithPublicKey(signature, prefixEncodedTx, pk);
```

### 4. Sign Arbitrary Data

```ts
const challenge = new Uint8Array(32); // e.g. random challenge
const metadata = { encoding: Encoding.BASE64, schema: authSchema };
const encoded = /* encode challenge as needed */;
const signature = await cryptoService.signData(
  rootKey, KeyContext.Address, 0, 0, encoded, metadata
);
const isValid = await cryptoService.verifyWithPublicKey(
  signature, encoded, await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0)
);
```

### 5. ECDH (Shared Secret)

```ts
// On Alice's end
const sharedSecret = await cryptoService.ECDH(
  aliceRootKey, KeyContext.Identity, 0, 0, bobPublicKey, true
);
// On Bob's end:
const sharedSecretBob = await cryptoService.ECDH(
  bobRootKey, KeyContext.Identity, 0, 0, alicePublicKey, false
);
```

### 6. Derive Child Public Keys

```ts
const xPk = await cryptoService.deriveKey(
  rootKey, [harden(44), harden(283), harden(0), 0], false, BIP32DerivationType.Peikert
);
const derivedKey = await deriveChildNodePublic(xPk, 1);
const pk = derivedKey.slice(0, 32); // 32-byte public key
```

---

## API

- `fromSeed(seed: Buffer | Uint8Array): Uint8Array` — Generate extended root key from seed
- `keyGen(rootKey, context, account, keyIndex): Promise<Uint8Array>` — Derive public key (32 bytes)
- `signAlgoTransaction(rootKey, context, account, keyIndex, prefixEncodedTx[, derivationType]): Promise<Uint8Array>` — Sign Algorand tx
- `signData(rootKey, context, account, keyIndex, data, metadata[, derivationType]): Promise<Uint8Array>` — Sign arbitrary data
- `verifyWithPublicKey(signature, message, publicKey): Promise<boolean>` — Verify signature
- `ECDH(rootKey, context, account, keyIndex, otherPk, ecdhCallback?): Promise<Uint8Array>` — Shared secret (optionally derive final secret via callback)
- `deriveKey(rootKey, path, isPrivate, type): Promise<Uint8Array>` — Derive extended key
- `deriveChildNodePublic(xpk, index): Promise<Uint8Array>` — Derive child public key

---

## CJS / Node.js Usage

This library can be used in CommonJS via dynamic import:

```js
;(async function () {
  const hd = await import("@algorandfoundation/xhd-wallet-api");
})();
```
Set your `tsconfig.json`:
```json
{
  "target": "es2020",
  "module": "Node16",
  "moduleResolution": "Node16"
}
```

# Test

## Output

```shell
 PASS  ./contextual.api.crypto.spec.ts
  Contextual Derivation & Signing
    ✓ (OK) Root Key (2 ms)
    (JS Library) Reference Implementation alignment with known BIP32-Ed25519 JS LIB
      ✓ (OK) BIP32-Ed25519 derive key m'/44'/283'/0'/0/0 (135 ms)
      ✓ (OK) BIP32-Ed25519 derive key m'/44'/283'/0'/0/1 (120 ms)
      ✓ (OK) BIP32-Ed25519 derive PUBLIC key m'/44'/283'/1'/0/1 (284 ms)
      ✓ (OK) BIP32-Ed25519 derive PUBLIC key m'/44'/0'/1'/0/2 (277 ms)
    (Derivations) Context
      ✓ (OK) ECDH (4 ms)
      ✓ (OK) ECDH, Encrypt and Decrypt (5 ms)
      ✓ Libsodium example ECDH (8 ms)
      Addresses
        Soft Derivations
          ✓ (OK) Derive m'/44'/283'/0'/0/0 Algorand Address Key (1 ms)
          ✓ (OK) Derive m'/44'/283'/0'/0/1 Algorand Address Key (1 ms)
          ✓ (OK) Derive m'/44'/283'/0'/0/2 Algorand Address Key (2 ms)
        Hard Derivations
          ✓ (OK) Derive m'/44'/283'/1'/0/0 Algorand Address Key (3 ms)
          ✓ (OK) Derive m'/44'/283'/2'/0/1 Algorand Address Key (2 ms)
          ✓ (OK) Derive m'/44'/283'/3'/0/0 Algorand Address Key (1 ms)
      Identities
        Soft Derivations
          ✓ (OK) Derive m'/44'/0'/0'/0/0 Identity Key (1 ms)
          ✓ (OK) Derive m'/44'/0'/0'/0/1 Identity Key (2 ms)
          ✓ (OK) Derive m'/44'/0'/0'/0/2 Identity Key (1 ms)
        Hard Derivations
          ✓ (OK) Derive m'/44'/0'/1'/0/0 Identity Key (2 ms)
          ✓ (OK) Derive m'/44'/0'/2'/0/1 Identity Key (1 ms)
      Signing Typed Data
        ✓ (OK) Sign Arbitrary Message against Schem (54 ms)
        ✓ (FAIL) Signing attempt fails because of invalid data against Schema (33 ms)
        Reject Regular Transaction Signing. IF TAG Prexies are present signing must fail
          ✓ (FAIL) [TX] Tag
          ✓ (FAIL) [MX] Tag (1 ms)
          ✓ (FAIL) [Program] Tag
          ✓ (FAIL) [progData] Tag (1 ms)
          Reject tags present in the encoded payload
            ✓ (FAIL) [TX] Tag (2 ms)
            ✓ (FAIL) [MX] Tag
            ✓ (FAIL) [Program] Tag (1 ms)
            ✓ (FAIL) [progData] Tag


```

## BIP39 / BIP32-ed25519 / BIP44 Test Vectors

All keys are in extended format: [kl][kr][chaincode]

Public key = kl \* Ed25519GeneratorPoint

- `BIP39 mnemonic`: _salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice_

- `root key (hex)`: a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946

### BIP44 paths

#### Child Private Derivation

- `m'/44'/283'/0'/0/0`: 70982049eeea743cbd4139fc198be4f277ece99188be5834aeb3a97ac2c53d5a79ef3bc0121991bc02eb52c99055dff273348b157ee21ab6c03d4632bd6ba2ff7755309210496c3415d40372d94abd8a831906a30f57247a8c4aa101b204ba94
  - corresponding public key: 8ad0bbc42326ac64eb4dbbe40a77518a7fc1d39504b618a4dc85f03b3a921a02 (kl \* Ed25519GeneratorPoint)
- `m'/44'/283'/0'/0/1`: e8a8ca7ee58ddfcecaff18a2adb2fbe691bcd20b618c9fc32e8950d074ad3c59f7303f20f0054a91996bb5cec26e36a4cc1da352762a276a73e61843e97a5b24ad172bfd9435e6b0bb42bbe5fbded4220ccb14d733e9aa2c75346ded752f134f

  - public key: 2d3f9e31232bd36e6c0f37597e19c4c0154e58c41bc2b737c7700b683e85d0af

- `m'/44'/283'/0'/0/2`: 1885ded7f457f85c6060f44140cca497863b644d0e1662cb650e9c506688ea59644b97313410ed41acdb106512ea6600083417c1d782e5a22f18094a623f3dacdcc6a5447a10b67e8fde5b0b36a7d011c7678de0b558af725292d114b7665383

  - public key: 96acc17f0c34f6c640d5466988ce59c4da5423b5ec233b7ad2e5c5a3b1b80782

- `m'/44'/283'/1'/0/0`: 883345270edf5bd2bfdd744acd2a318b16d01a4668d7b467c14c1597658c75516e286a0311e8098e548581f315d2ac67d51661ded951349aedbd649e003794860cdfdf296711c7f40531f9dc4f1dd099b784c9a92bfbb749c8a7fe71c6f395b0

  - public key: fd56577456794efb91e05dc947d26d4864b346d139dfa8fff9b0e1def84b9078

- `m'/44'/283'/2'/0/1`: c06f6219dfe978ebcbe4a4834fa57af7a9ebb92cfe966be120e98778cd600f59f3f19fc39b32ef51bb3c7344b3484c5fdcbea206e24dac0cad5da022fb18cb394863b9e03e8d5b290b82453dc0bd6fce65eafdd455df642614b7c80fbb8b067e

  - public key: aa03d62057744f4422d70c3a421deae838d8f7546a15f2ada59287569911144c

- `m'/44'/283'/3'/0/0`: 48a9ed4203303292926a208811a19fa3fbd6480e92c03327d2e43b2596015e5e0dc91a410e5b9ddd2bef2008a702b54ff1ba58c698bb0271f047dcd2617c35024b36efc42fc48c932a6eeff1625e58382f302f4b3f069675e5ca8efc88e2f176

  - public key: 303718c23846fdd0f7d9cded69d95c5a72fbb1ccbbea50c865c00c050bb0e68b

- `m'/44'/0'/0'/0/0`: 589478bedb7983b1de5926129223d21e1628f12ac018caff5942c9bb8b956557529ca2ed4e97b945ec5325d5f456ebaa537c557adb3767f2b749582a46dfc1ce7826ab1d98f7bb2ab9a6004f4c6aa1b1360bfd95a8748c38c90ec906bab9acb4

  - public key: 844cda69c4ef7c212befaa6733f5e3c0317fc173cb9f14c6cf66a48263e722ec

- `m'/44'/0'/0'/0/1`: 68094a077a8e025766c4456f306f91fcada3098b09993e45b4eb0fde191b955c1d709e0875931b98cbd045972e6d38f76ca49295cee24385d3eee8e5350db31d0e84012a142d233514f178b55b5b6b63dafaae9ceebe7d2bcc8872740213bbe9

  - public key: a8c6de4e6d2672ad5a804994cf6e481ea7c2c3b1cedc5f51c63b2d0819d503f0

- `m'/44'/0'/0'/0/2`: 20c050bce9e69a37bbad8bf50ec7c8c54a3a34e9cdfec902d477a32a20b543572629e59fd3aa7d284396668e891d2d8476b43d370811aaf56194c36bdc8bc30e8211880e939e0cbe6a252b828fc7faf46eec236ef967ebdf115d380194a93bd3
  - public key: 88e493675894f0ba8472037da40a61a7ed356fd0f24c312a1ec9bb7c052f5d8c