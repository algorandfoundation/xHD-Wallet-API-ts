import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
    preset: 'ts-jest/presets/default-esm',
    // `pnpm test` compiles the specs to dist/ with tsconfig.spec.json first, and jest runs the
    // compiled .js files; the .ts sources are ignored, so ts-jest never transforms a test file.
    testPathIgnorePatterns: ["src"],
};

export default jestConfig;
