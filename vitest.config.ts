import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', 'build/**'],
    fileParallelism: false,
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});
