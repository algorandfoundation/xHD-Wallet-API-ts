# Privacy? kinda...

With small effort, with tools we already have available, we get arguably enough privacy to make hard to disern who is who and be "compliance friendly", since if  you know a specific pieace of information, you can link multiple addresses to the same owner. 

## xpub (pub + chain code) and soft derivations

Using xpubs and soft derivations, we can create multiple addresses from a single public key. This means that while all addresses can be traced back to the same xpub, they appear as distinct entities on the blockchain. This method provides a layer of obfuscation, making it harder to link transactions directly to a single user.

## Alice & Bob

Instead of sharing a public key with Bob, alice will share an xpub derived from 4 levels of BIP32-ed25519 derivation (i.e `m'/44'/283'/0'/0`).

The information available in the xpub is: [public key (32 bytes), chain code(32 bytes)].

Bob can then take Alice's xpub and non-interactively "guess" or derive all Alice's future potential public keys (and thus addresses) by performing soft derivations on the xpub. 

1 address == 1 payment == `private enough?`

## Tests
command: `yarn test`
file: `one-time-payment.spec.ts`


### Sample output

```shell

      Alice derived child index 0: public Key: [7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9], algorand address: PPNHVQJGE6ZMEWPR35UHLUYMCCZV6VNTHLJMZDVCONXKUPV47K4WGQJWGI  , chain Code: [27f9b4be231765ad6fb4a7d93bdf16e8d9ae87bf20662c8c21fb6acf1ce65325]


      Alice derived child index 1: public Key: [5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519], algorand address: LOXIQKHRCEDEMN5MKBQ32Y54J7H6JKBTEURQL4S65K44MTWN6UMTU2WNBM  , chain Code: [4e90b59e711981eb6d9c0809c35da23726b997d5731c706309d9c8b3daa5f12c]


      Alice derived child index 2: public Key: [00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3], algorand address: ACTSMNPJPS5JMZJJ5G73JOXUUMWXXDGS7TMOER3M4W7BC54ERSZ4KPSMHM  , chain Code: [a12b973d2ff014081d65307a373c2538554106ce0fb53101f879bd1dde98b29b]


      Alice derived child index 3: public Key: [54b7431af55ee9c9e6f9f486bb8e499791b340fc3fbab3046571072179874062], algorand address: KS3UGGXVL3U4TZXZ6SDLXDSJS6I3GQH4H65LGBDFOEDSC6MHIBRPC6CDYI  , chain Code: [5d4404e0d07313c0ad21c47f9257f3b82c9691f16cbd0e17f029c4d122a8cc45]


      Alice derived child index 4: public Key: [b3c231a1bca384434e2407cec19106af11dc0f996380c3c625817280105c30d8], algorand address: WPBDDIN4UOCEGTREA7HMDEIGV4I5YD4ZMOAMHRRFQFZIAEC4GDMFWKUWLQ  , chain Code: [60185fa195a06caa70ab59b1bd42ecd1531906efd01ab0d6b0180f1778d377dd]


    Alice's public node key: [563cc1c633ea99efbddf272eb5ed81b9d85af5b5f32ea93ea5de6fb9297788e0] chain Code: [6e7ee2b9886883fcf29ef4b98e0023503b9bb1c883d6e861b6953d3e17976df8]
```

Alice's `xpub`: `563cc1c633ea99efbddf272eb5ed81b9d85af5b5f32ea93ea5de6fb9297788e06e7ee2b9886883fcf29ef4b98e0023503b9bb1c883d6e861b6953d3e17976df8`


Sharing with bob:
```shell

      Alice shares her extended key with Bob.

      Bob derived Alice's child index 0: public Key: [7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9], algorand address: PPNHVQJGE6ZMEWPR35UHLUYMCCZV6VNTHLJMZDVCONXKUPV47K4WGQJWGI  , chain Code: [27f9b4be231765ad6fb4a7d93bdf16e8d9ae87bf20662c8c21fb6acf1ce65325]

      Bob derived Alice's child index 1: public Key: [5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519], algorand address: LOXIQKHRCEDEMN5MKBQ32Y54J7H6JKBTEURQL4S65K44MTWN6UMTU2WNBM  , chain Code: [4e90b59e711981eb6d9c0809c35da23726b997d5731c706309d9c8b3daa5f12c]

      Bob derived Alice's child index 2: public Key: [00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3], algorand address: ACTSMNPJPS5JMZJJ5G73JOXUUMWXXDGS7TMOER3M4W7BC54ERSZ4KPSMHM  , chain Code: [a12b973d2ff014081d65307a373c2538554106ce0fb53101f879bd1dde98b29b]

      Bob derived Alice's child index 3: public Key: [54b7431af55ee9c9e6f9f486bb8e499791b340fc3fbab3046571072179874062], algorand address: KS3UGGXVL3U4TZXZ6SDLXDSJS6I3GQH4H65LGBDFOEDSC6MHIBRPC6CDYI  , chain Code: [5d4404e0d07313c0ad21c47f9257f3b82c9691f16cbd0e17f029c4d122a8cc45]

      Bob derived Alice's child index 4: public Key: [b3c231a1bca384434e2407cec19106af11dc0f996380c3c625817280105c30d8], algorand address: WPBDDIN4UOCEGTREA7HMDEIGV4I5YD4ZMOAMHRRFQFZIAEC4GDMFWKUWLQ  , chain Code: [60185fa195a06caa70ab59b1bd42ecd1531906efd01ab0d6b0180f1778d377dd]
```
