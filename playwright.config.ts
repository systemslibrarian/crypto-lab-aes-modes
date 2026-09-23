import { defineConfig, devices } from '@playwright/test';

const PORT = 4360;
const BASE_PATH = '/crypto-lab-aes-modes/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE_PATH}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    /* chromium runs everything, including the axe sweep over every state. */
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    /* firefox and webkit run the FUNCTIONAL specs only.
     *
     * The exhibit's behaviour is a claim about a browser, so the functional tests
     * belong in all three. The accessibility sweep is a different kind of check and
     * a far heavier one — it drives every state and runs axe at each — and putting
     * it in three engines tripled the gate and made it fail on a runner sharing
     * three browsers: `.oracle-byte` reached 1 of 16 inside its auto-retry window at
     * 380px in WebKit. Driven directly against the deployed build, that count is 16
     * in all three engines at both 380px and 1280px, so what the runner measured was
     * its own load, not the page.
     *
     * Raising that timeout would have made the gate pass without making anything
     * truer. The scan stays where it was, and the engine coverage goes where the
     * engine claims are. */
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
      testIgnore: /a11y\.spec\.ts/,
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
      testIgnore: /a11y\.spec\.ts/,
    },
  ],
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE_PATH}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
