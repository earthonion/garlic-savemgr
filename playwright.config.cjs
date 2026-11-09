const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://savemgr.local',
    browserName: 'chromium',
    headless: true,
    viewport: { width: 1440, height: 1000 },
  },
});
