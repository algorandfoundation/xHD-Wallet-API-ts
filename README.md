# xHD Wallet API Typescript

Typescript implementation of BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace for Algorand's ARC-52

The implementation is based on the [BIP32-ed25519](https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a) specification.

## Changes from 1.x to 2.x

Due to issues related to importing a library reliant on WASM into the browser environment as well as in React-Native, we decided to migrate away from LibSodium.js (sumo version). See [PR #22](https://github.com/algorandfoundation/xHD-Wallet-API-ts/pull/22) for more details.

2.x binds to the platform's [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) interface for SHA-512, SHA-256, HMAC, X25519 and Ed25519 signature verification. It uses [Noble](https://paulmillr.com/noble/) only for what WebCrypto can't do: the unclamped Ed25519 point arithmetic BIP32-Ed25519 needs, Ed25519 to X25519 key conversion, and BLAKE2b.

Breaking changes:

- `fromSeed` is now async (it hashes with WebCrypto) and accepts any `Uint8Array`.
- `signData` no longer takes a `metadata` argument; the encoding and JSON-schema validation (and the `SignMetadata`, `Encoding` and `ERROR_BAD_DATA` exports) were removed.
- `signData` no longer rejects data that starts with an Algorand protocol tag (`TX`, `MX`, `Program`, ...), and the `ERROR_TAGS_FOUND` export was removed. It signs exactly what it's given. **When signing data from an untrusted source, domain-separate it** so it can't form a transaction or other protocol message, for example by signing a hash of it, as [ARC-60](https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0060.md) does. The 1.x prefix check didn't provide that protection: it rejected harmless data that happened to start with a short tag (`"TEST"`, `"PSA"`, about 1 in 2,700 hashes), and it couldn't make raw untrusted bytes safe to sign.
- `signAlgoTransaction` now rejects data that is not prefixed with the `TX` tag (throws `TxTagMissingError`). This catches an encoded transaction passed instead of its bytes to sign (algosdk's `txn.bytesToSign()`). In 1.x it signed any bytes.
- `deriveChildNodePublic` now rejects the hardened index `harden(0)`. In 1.x it returned an incorrect key for it.
- Only the package root can be imported; paths inside the package (e.g. `dist/...`) are no longer reachable.

`verifyWithPublicKey` applies libsodium's strict rules, as 1.x did: it rejects non-canonical signatures and small-order or non-canonical public keys, whatever the platform's WebCrypto implementation would accept.

## Requirements

A WebCrypto implementation (`globalThis.crypto.subtle`) with Ed25519 and X25519 support:

- **Node.js**: 22 or later.
- **Browsers**: current Chrome, Edge, Firefox and Safari. `crypto.subtle` is only available in a secure context (HTTPS or `localhost`).
- **React Native**: has no `crypto.subtle`; install a WebCrypto polyfill that supports Ed25519 and X25519.

## Variants

It offers 2 modes to derive keys.

- Khovratovich: Standard mode according to the paper above.
- Peikert's: Amendment to the standard mode to allow for a more secure derivation of keys by giving more entropy to `zL`. This is the **default** mode of this library

## Sensitive Data

Instances of the `XHDWalletAPI` class do not persist sensitive data. However, many methods of the class require the `rootKey` be passed as a parameter. The responsibility of handling the `seed` and derived `rootKey` in a secure manner is on the developer of the consuming application. Variables used to hold these sensitive values should be zeroed as soon as they are no longer needed.

```ts
import { fromSeed, KeyContext, XHDWalletAPI } from "@algorandfoundation/xhd-wallet-api";

async function example() {
  const seed = getSeed();
  const rootKey = await fromSeed(seed);
  const cryptoService = new XHDWalletAPI();
  const key = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0);
}
```

## Run

```shell
$ pnpm install
$ pnpm test
```

## Regarding CJS

This library can be used in a CommonJS environment as a dynamic import:

```ts
;(async function () {
  const hd = await import("@algorandfoundation/xhd-wallet-api");
})();
```

Make sure to set your tsconfig.json so it is at least:

```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "Node16",
    "moduleResolution": "Node16"
  }
}
```

## BIP39 / BIP32-ed25519 / BIP44 Test Vectors

These vectors are checked by the test suite against this README, so they always match the library's output. The Khovratovich vectors also match the reference [bip32-ed25519](https://www.npmjs.com/package/bip32-ed25519) JS library.

Private keys are in extended format: [kl][kr][chaincode]

Public key = kl \* Ed25519GeneratorPoint

- `BIP39 mnemonic`: _salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice_

- `root key (hex)`: a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946

### Peikert (default)

- `m'/44'/283'/0'/0/0`
  - private: 00cc7480c8edf9f64a680957e05cd0908f3b682a9ffdbafa2a61c43b6df6705095a7d0d2f9afd1f472e855a0f6fe967ccb12f497cf3c8d3213c156e72c0de37a27f9b4be231765ad6fb4a7d93bdf16e8d9ae87bf20662c8c21fb6acf1ce65325
  - public: 7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9

- `m'/44'/283'/0'/0/1`
  - private: b0cb47103426b932d562ff6f14e99ecc26b26aec080259e1190c869d6ac9c84fecff83895eb2f9ea75cad60044090cd8f386cff87715059a28a86765db2e3b134e90b59e711981eb6d9c0809c35da23726b997d5731c706309d9c8b3daa5f12c
  - public: 5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519

- `m'/44'/283'/0'/0/2`
  - private: a07edb23e4faf30f59cbb26f4213d8dd11220534f027a1075311c96a89d1284ff0d90e3916fb278d86bf043118b681c2e557c9935205f466bcf8cb9420aa5104a12b973d2ff014081d65307a373c2538554106ce0fb53101f879bd1dde98b29b
  - public: 00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3

- `m'/44'/283'/1'/0/0`
  - private: e0aa644b2c36661db958c909ab8b93d0d6a0b6eb9d0bbe485941760e7462464cd5e022ec5ea44b1a7d1a27d609b487acf42b44a363692a5326866ea0648855b4c4e6d8adaf35b81cdbc462be16c6fd75da3119d98e81e04337799eabb880408b
  - public: 358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9

- `m'/44'/283'/2'/0/1`
  - private: 00e8a72836b4a1f729a2f7e85f375d1584e39ea8ab8cfb72f6b7a23ef09a934da9a7d81def1cb7a06b81b31b4ab8726c1af90fb3be287f500f6147b41132ac38a0456285f909ef4ed79edadd1c8eec884d418bef891c83670287cb555040d7d9
  - public: 1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0

- `m'/44'/283'/3'/0/0`
  - private: d09fce5c98494bb76ddde59c64b10cb9180334e6022d5446ab87bb13ba30fa4fab2365a9eefc187fc2bdca40f46dd0b6556342f41ce8d1781336d9d135874c514b07ff453850dcc8df10345d1e17460216005532351a36616e84ecf845f03d34
  - public: f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b

- `m'/44'/0'/0'/0/0`
  - private: 70b91d1dbcf9cbb4486fddbececa0dcd2b898cfb0ce676fc1e18ce6fba169d4f040706f4c965b6f0a72683332c64f4420c422c760fd8bc574a8886fd79edd8b98c3d61188964a420564560ef79219fc69df4279ecc71031df2fe53092feb9563
  - public: ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a

- `m'/44'/0'/0'/0/1`
  - private: 1004d0dbfcc3ba84a005226629f542dde8f9c7679798b888fa661cdfa048834e9bd15949b14e12668114e91851b7ce629c354bb4228b31496b0e65f4b9c20e62fcfd18dcc56550b7798bb5faf1054f1fcda60451cf3a03fd95f1379eeb0297b8
  - public: 2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97

- `m'/44'/0'/0'/0/2`
  - private: 384db2b6e652e7d7022fd1388ec16a3765bd5d6b5e88be10df092eeafa05cd4e60e018b9409664bbdf645ed32642d506ef1f83c5bde2b963d4c1f8cc475b71ee1cab705ce60267c12d9ddf08aee97129e5d8e3c3ff7f3207267b779c355b4de0
  - public: 2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d

### Khovratovich

- `m'/44'/283'/0'/0/0`
  - private: 80102bb98faac3fd1789c2c6c559d3715cd9cac228d6d4b0f76a2346eaec8f4601ae14284089243e936be91b2823cc142f753135eaff1bae20d3eec77870c5449f92c790d7abaee0e00a4ec1fb78a1d438e8ccf7c2bad9a018a5bf9a5d510075
  - public: 62fe832b7ad10544be8337a670435e5064ae4a66e77bd78909765b46b576a6f3

- `m'/44'/283'/0'/0/1`
  - private: e85753ef080f08c803cc262f55608087d1a7bb7441ed9fb49c0db527e7ec8f460f12a9fe7388ee2b208984d0ef5a0f305650833e8317a3caa3ced7a9665737ce665fa7ba3dddf6bd6c092b0ea091b6062d085ceea30e521d422fd04e5a2f4551
  - public: 530461002eaccec0c7b5795925aa104a7fb45f85ef0aa95bbb5be93b6f8537ad

- `m'/44'/283'/0'/0/2`
  - private: 10c5c957f286e57057159a0192a371ea9a2b2a13dc329b96315c937febec8f46637904af2f161b8762d5ac265e53e87d9ffdd05bac2b74d95c74ae6947cb9b2a9002f399f1d754523898643cbe32b05bbb7e6fca6b46ffa6935fa3026b20a493
  - public: 2281c81bee04ee039fa482c283541c6ab06c8324db6f1cc59c68252e1d58bcb3

- `m'/44'/283'/1'/0/0`
  - private: 78ac4eed7f4240a917024c81efb7943d97b568451bab7411bb41c0b1e6ec8f46be0fb00d32d534aa12d88892e2235b32915db07fd4f6885a114f945ee323cb80242d3aea41d4b42e7fc6ac4c18ef928555130d260a7868eb1dcea76baeb3c1e4
  - public: 9e12643f6c0068dcf53b04daced6f8c1a90ad21c954a66df4140d79303166a67

- `m'/44'/283'/2'/0/1`
  - private: c018d31c0e50d114050e43eb1fd992b5785c9ed8bc8d002eb50141e7efec8f46ab9f28e754f0f69236085aab08e129f767ba3ec1552bd4ee5d0e39bcf3a17e9515cd142cf6b0ee617749968470be5e370ad8d302f7764bbb53dadd3a303c11ed
  - public: 8a5ddf62d51a2c50e51dbad4634356cc72314a81edd917ac91da96477a9fb5b0

- `m'/44'/283'/3'/0/0`
  - private: 003d917ace754d61099c5d2ba1c6cdef3a2c683bf253dba1b79503c7ebec8f46f0ffc0f4ca053a1edd33eb6dbdb53cade78cfc4f762d9b751bdbb0958b2d5e47dc95c15c22bf9bcab4fcf884d5489e4b8e2f3d5dc79a895ee41cede75428c5a2
  - public: 2358e0f2b465ab3e8f55139d8316654d4be39ebb22367d36409fd02a20b0e017

- `m'/44'/0'/0'/0/0`
  - private: b8e1f7364bb0c7e04259ba54b3b4205e655da6260d0945955c655ca1e3ec8f46566c25ae584a598f5538bc1125db0374a46e73cf2c0b9a7e01c27c88fa3686bcbc6ba8649a131a8d730dfc3c77ebd7d5214f18d80ab16a3362e4f3c1293857cb
  - public: b6d7eea5af0ad83edf4340659e72f0ea2b4566de1fc3b63a40a425aabebe5e49

- `m'/44'/0'/0'/0/1`
  - private: e89fcb676280e1d81e17a506ab7f5acd31f8fa65d5d417a036eb07cee4ec8f466a471d5f3886f98460869ce28cedef7154dc639a669218ebbf9bb0088ca0f8e803df34c23ab4f0a2fdbb86235f1cb4c540f5c7674e5d45d4661e7e159816fd9b
  - public: b5cec676c5a2129ed1be4223a2702439bbb2462fd77b43f27e2f79fd194a30a2

- `m'/44'/0'/0'/0/2`
  - private: 30edb5d785bdf343523f5ec498c867d6b79c53be5ac566e36e3cccd3e8ec8f46a64042c2a0dd05ecb41ef93eb5790c6ec38fa9186c668433cc509f6f87d32b0c47d06b42463fb520045da406fff183814c22c021659e1af176ebe3f6eca59aa2
  - public: 435e5e3446431d462572abee1b8badb88608906a6af27b8497bccfd503edb6fe
