// The runtime package report (src/runtime-packages.ts) starts with every init()
// that has a URL and key; tests that init the SDK must not send one after they
// end. Its own tests pass the environment explicitly.
process.env.SHIELD360_RUNTIME_PACKAGES ??= 'off';

export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/src/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  roots: ['<rootDir>/src/'],
};
