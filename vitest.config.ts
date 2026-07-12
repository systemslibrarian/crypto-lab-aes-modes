import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests live next to the crypto modules (src/*.test.ts). The Playwright
    // accessibility + functional suite in e2e/ is driven by `npm run test:a11y`
    // and must NOT be collected by vitest.
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
