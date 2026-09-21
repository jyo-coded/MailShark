import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['engine/test/**/*.test.ts', 'extension/test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20000,
  },
});
