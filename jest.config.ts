import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
    preset: 'ts-jest/presets/default-esm',
    testPathIgnorePatterns: ["src"],
    // Tests are compiled to dist/ first; this is the config `pnpm test` compiles them with,
    // which is also the one that includes the jest types (`tsconfig.json` is build-only).
    transform: {
        // Same as the preset's transform (`defaultsESM`), with the spec tsconfig made explicit
        '^.+\\.m?tsx?$': ['ts-jest', { useESM: true, tsconfig: '<rootDir>/tsconfig.spec.json' }],
    },
};

export default jestConfig;
