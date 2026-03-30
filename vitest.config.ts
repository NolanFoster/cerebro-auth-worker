import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node', // Changed from 'miniflare' to fix timeout issues
    // environmentOptions: {
    //   wranglerConfigPath: './wrangler.toml',
    //   packagePath: true,
    //   wranglerConfigEnv: 'preview'
    // },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'tests/',
        'src/types/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData.ts',
        '**/*.js',
        'run-test.js'
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      }
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      'cloudflare:email': path.resolve(__dirname, './tests/mocks/cloudflare-email.ts')
    }
  }
});