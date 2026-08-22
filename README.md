# xHD Wallet API Typescript

Typescript implementation of BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace for Algorand's ARC-52

The implementation is based on the [BIP32-ed25519](https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a) specification.

## Changes from 1.x to 2.x

Due to issues related to importing a library reliant on WASM into the browser environment as well as in React-Native, we decided to migrate away from LibSodium.js (sudo version) to Noble cryptography. See (PR #22)[https://github.com/algorandfoundation/xHD-Wallet-API-ts/pull/22] for more details.

## Variants

It offers 2 modes to derive keys.

- Khovratovich; Standard mode according to the paper above.
- Peikert's: Ammendment to the standard mode to allow for a more secure derivation of keys by giving more entropy to `zL`. This is the **default** mode of this library

## Sensitive Data

Instances of the `XHDWalletAPI` class do not persist sensitive data. However, many methods of the class require the `rootKey` be passed as a parameter. The responsibility of handling the `seed` and derived `rootKey` in a secure manner is on the developer of the consuming application. Variables used to hold these sensitive values should be zeroed as soon as they are no longer needed.

```ts
async function example() {
  const seed = getSeed();
  const rootKey = fromSeed(seed);
  const cryptoService = new XHDWalletAPI();
  const key = await cryptoService.keyGen(rootKey, KeyContext.Address, 0, 0);
}
```

## Run

```shell
$ yarn
$ yarn test
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

These vectors are **Peikert mode (g=9)**, the library default used by `keyGen()` when no derivation type is passed. Khovratovich (g=32) produces different child keys.

Extended private keys are 96 bytes: `[kL][kR][chaincode]`. `keyGen()` returns the 32-byte public key `kL * Ed25519BasePoint` (noclamp). Values below were produced by this library and match `src/x.hd.wallet.api.crypto.spec.ts`.

- `BIP39 mnemonic`: _salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice_

- `root key (hex)`: a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946

### BIP44 paths (Peikert / default)

#### Address context (`coin_type=283`)

- `m'/44'/283'/0'/0/0`: 00cc7480c8edf9f64a680957e05cd0908f3b682a9ffdbafa2a61c43b6df6705095a7d0d2f9afd1f472e855a0f6fe967ccb12f497cf3c8d3213c156e72c0de37a27f9b4be231765ad6fb4a7d93bdf16e8d9ae87bf20662c8c21fb6acf1ce65325
  - public key: 7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9
- `m'/44'/283'/0'/0/1`: b0cb47103426b932d562ff6f14e99ecc26b26aec080259e1190c869d6ac9c84fecff83895eb2f9ea75cad60044090cd8f386cff87715059a28a86765db2e3b134e90b59e711981eb6d9c0809c35da23726b997d5731c706309d9c8b3daa5f12c
  - public key: 5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519
- `m'/44'/283'/0'/0/2`: a07edb23e4faf30f59cbb26f4213d8dd11220534f027a1075311c96a89d1284ff0d90e3916fb278d86bf043118b681c2e557c9935205f466bcf8cb9420aa5104a12b973d2ff014081d65307a373c2538554106ce0fb53101f879bd1dde98b29b
  - public key: 00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3
- `m'/44'/283'/1'/0/0`: e0aa644b2c36661db958c909ab8b93d0d6a0b6eb9d0bbe485941760e7462464cd5e022ec5ea44b1a7d1a27d609b487acf42b44a363692a5326866ea0648855b4c4e6d8adaf35b81cdbc462be16c6fd75da3119d98e81e04337799eabb880408b
  - public key: 358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9
- `m'/44'/283'/2'/0/1`: 00e8a72836b4a1f729a2f7e85f375d1584e39ea8ab8cfb72f6b7a23ef09a934da9a7d81def1cb7a06b81b31b4ab8726c1af90fb3be287f500f6147b41132ac38a0456285f909ef4ed79edadd1c8eec884d418bef891c83670287cb555040d7d9
  - public key: 1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0
- `m'/44'/283'/3'/0/0`: d09fce5c98494bb76ddde59c64b10cb9180334e6022d5446ab87bb13ba30fa4fab2365a9eefc187fc2bdca40f46dd0b6556342f41ce8d1781336d9d135874c514b07ff453850dcc8df10345d1e17460216005532351a36616e84ecf845f03d34
  - public key: f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b

#### Identity context (`coin_type=0`)

- `m'/44'/0'/0'/0/0`: 70b91d1dbcf9cbb4486fddbececa0dcd2b898cfb0ce676fc1e18ce6fba169d4f040706f4c965b6f0a72683332c64f4420c422c760fd8bc574a8886fd79edd8b98c3d61188964a420564560ef79219fc69df4279ecc71031df2fe53092feb9563
  - public key: ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a
- `m'/44'/0'/0'/0/1`: 1004d0dbfcc3ba84a005226629f542dde8f9c7679798b888fa661cdfa048834e9bd15949b14e12668114e91851b7ce629c354bb4228b31496b0e65f4b9c20e62fcfd18dcc56550b7798bb5faf1054f1fcda60451cf3a03fd95f1379eeb0297b8
  - public key: 2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97
- `m'/44'/0'/0'/0/2`: 384db2b6e652e7d7022fd1388ec16a3765bd5d6b5e88be10df092eeafa05cd4e60e018b9409664bbdf645ed32642d506ef1f83c5bde2b963d4c1f8cc475b71ee1cab705ce60267c12d9ddf08aee97129e5d8e3c3ff7f3207267b779c355b4de0
  - public key: 2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d
- `m'/44'/0'/1'/0/0`: 1896afe83f07e21924a52f39ed53b05060e232a4b107b234cd83e31cad2ca54e5154b8400a6bfb8840f62fce04c3024991f233dded48b36b9b1dfb8aa3e05f9483021b88eb9f990ac7b4e3b66c6f2d40398ba8a3b67bf5aa6a630ac36f84ce94
  - public key: 232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a
- `m'/44'/0'/2'/0/1`: e80da09a6df712c3fa52df566e1a92b1326ebeb866b2646e6a10971893b0f54df4f4d19d852c758eee3c4f1072d0169bd6dfb1fbbbdde82c5ae50ad68064174a1c2e4a65666419b9875c9da8bf84a40d69ee06a3dd273cf85107cf1192b99913
  - public key: 8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e
