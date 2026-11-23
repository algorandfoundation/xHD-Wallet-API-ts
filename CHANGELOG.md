# [2.0.0-canary.3](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v2.0.0-canary.2...v2.0.0-canary.3) (2026-11-23)


### Bug Fixes

* index validation for writeUint32LE ([2a1755a](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/2a1755a7cb0f1ada020b283e1006950b269d0ada))

# [2.0.0-canary.2](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v2.0.0-canary.1...v2.0.0-canary.2) (2026-11-16)


### Bug Fixes

* enhance error handling for derivation methods and update README for clarity ([eefc21b](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/eefc21b623c296bd2bd410bd98a5e0af01fa0ee8))
* remove unnecessary util ([15e6f19](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/15e6f1990f93dcccb21a1ff7c7f1cea8792b8733))
* simplify signing policy, fix public derivation and README vectors, switch to pnpm ([24e1ce1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/24e1ce11486d8c40841f1a145f80fb8dfe6bd181))
* validate derivation indexes, decouple build from test tooling ([8b46887](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/8b46887c02f88f26d3487ceab7dfcb8bf551d14d))
* validate derivation type and soft key index ([dfd6d0d](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/dfd6d0d5fa42a3d5be8c58f2687281ca1f007cf1))

# [2.0.0-canary.1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.3...v2.0.0-canary.1) (2026-01-12)


* feat!: replace libsodium with @noble/* libs to remove wasm-unsafe-eval CSP requirement ([9849fb3](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/9849fb3e90cecfb6348e188ff445b55806bfde00))


### BREAKING CHANGES

* replaced libsodium dependencies with nobile cryptography dependencies

## [1.0.3](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.2...v1.0.3) (2025-01-21)


### Bug Fixes

* include instructions for CJS ([7cbdf23](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/7cbdf2375782c57b6a4bff99e68d326494849d99))

## [1.0.3-canary.1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.2...v1.0.3-canary.1) (2025-01-21)


### Bug Fixes

* include instructions for CJS ([7cbdf23](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/7cbdf2375782c57b6a4bff99e68d326494849d99))

## [1.0.2](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.1...v1.0.2) (2024-10-18)


### Bug Fixes

* ensure module is loaded before consuming as imports ([39131e1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/39131e1645bdaaf2ce0d57152b9bdc90e429dcd5))

## [1.0.2-canary.1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.1...v1.0.2-canary.1) (2024-10-16)


### Bug Fixes

* ensure module is loaded before consuming as imports ([39131e1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/39131e1645bdaaf2ce0d57152b9bdc90e429dcd5))

## [1.0.1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.0...v1.0.1) (2024-10-15)


### Bug Fixes

* remove other KeyContexts ([e0c4626](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/e0c46267f832a0fd1e2ebef9b20817e333e94505))

## [1.0.1-canary.1](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.0...v1.0.1-canary.1) (2024-10-15)


### Bug Fixes

* remove other KeyContexts ([e0c4626](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/e0c46267f832a0fd1e2ebef9b20817e333e94505))

# 1.0.0 (2024-10-15)


### Bug Fixes

* fixes tsc-alias build command ([7b7e1a6](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/7b7e1a6b3958479b7c6fd3516ecda550936cb7f8))
* package name scope ([d4f68ee](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/d4f68eea19a82b6cf2d47123a6819ad5c49938f0))
* updated CI and semantic-release ([e64acdf](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/e64acdfe72dbfb137189ae1ef4eb83566e41e3bd))


### Features

* adds everything from ARC-52 PR ([5177334](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/517733458b7e9a10c059c2ddd265956c7127bde2))
* rename, add semantic release ([84f2576](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/84f2576f7d37fc0bfd48dd266f8623e2f7c9beef))

# [1.0.0-canary.2](https://github.com/algorandfoundation/xHD-Wallet-API-ts/compare/v1.0.0-canary.1...v1.0.0-canary.2) (2024-10-15)


### Bug Fixes

* package name scope ([d4f68ee](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/d4f68eea19a82b6cf2d47123a6819ad5c49938f0))

# 1.0.0-canary.1 (2024-10-15)


### Bug Fixes

* fixes tsc-alias build command ([7b7e1a6](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/7b7e1a6b3958479b7c6fd3516ecda550936cb7f8))
* updated CI and semantic-release ([e64acdf](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/e64acdfe72dbfb137189ae1ef4eb83566e41e3bd))


### Features

* adds everything from ARC-52 PR ([5177334](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/517733458b7e9a10c059c2ddd265956c7127bde2))
* rename, add semantic release ([84f2576](https://github.com/algorandfoundation/xHD-Wallet-API-ts/commit/84f2576f7d37fc0bfd48dd266f8623e2f7c9beef))
