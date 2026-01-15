export default {
  preset: "ts-jest/presets/default-esm",
  testPathIgnorePatterns: ["dist", ".*cjs-only.*"],
  extensionsToTreatAsEsm: [".ts"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        useESM: true,
        diagnostics: { ignoreCodes: [151002] },
        tsconfig: "tsconfig.esm.json",
      },
    ],
  },
  moduleNameMapper: {
    "^\.\/bip32-ed25519\.js$": "<rootDir>/src/bip32-ed25519.ts",
    "^\.\/sumo\.facade\.js$": "<rootDir>/src/sumo.facade.ts",
    "^\.\/x\.hd\.wallet\.api\.crypto\.js$":
      "<rootDir>/src/x.hd.wallet.api.crypto.ts",
    "^\.\/index\.js$": "<rootDir>/src/index.ts",
    // test files
    "^\.\/sumo\.facade\.spec\.js$": "<rootDir>/src/sumo.facade.spec.ts",
    "^\.\/x\.hd\.wallet\.api\.crypto\.spec\.js$":
      "<rootDir>/src/x.hd.wallet.api.crypto.spec.ts",
  },
};