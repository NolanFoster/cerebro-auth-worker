#!/usr/bin/env node

/**
 * Comprehensive test runner for auth-worker
 * Tests multiple environments and generates reports
 * 
 * Usage: node run-tests.js [options]
 * 
 * Options:
 *   --env <environment>     Test specific environment (local, preview, staging, production)
 *   --all                   Test all environments
 *   --email <email>         Email address to use for testing
 *   --report                Generate detailed test report
 *   --help                  Show this help message
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

/** Override base URL: `AUTH_WORKER_TEST_URL=https://my-worker.workers.dev node run-tests.js` */
function getAllConfigs() {
  return [
    {
      key: 'local',
      name: 'Local (wrangler dev)',
      baseUrl: process.env.AUTH_WORKER_TEST_URL || 'http://127.0.0.1:8787'
    }
  ];
}

// Test results storage
const testResults = {
  timestamp: new Date().toISOString(),
  environments: {},
  summary: {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0
  }
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logHeader(message) {
  console.log('\n' + '='.repeat(60));
  log(message, 'bright');
  console.log('='.repeat(60));
}

function logSection(message) {
  console.log('\n' + '-'.repeat(40));
  log(message, 'cyan');
  console.log('-'.repeat(40));
}

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    env: null,
    all: false,
    email: 'test@example.com',
    report: false,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--env':
        options.env = args[++i];
        break;
      case '--all':
        options.all = true;
        break;
      case '--email':
        options.email = args[++i];
        break;
      case '--report':
        options.report = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
    }
  }

  return options;
}

function showHelp() {
  console.log(`
${colors.bright}Auth Worker Test Runner${colors.reset}

Usage: node run-tests.js [options]

Options:
  --env <environment>     Test environment key (default: local; see getAllConfigs in this file)
  --all                   Run against every configured environment
  --email <email>         Email address to use for testing (default: test@example.com)
  --report                Generate detailed test report
  --help                  Show this help message

Examples:
  node run-tests.js --env local --email test@example.com
  node run-tests.js --all --email developer@company.com
  node run-tests.js --env production --report

Available Environments:
${getAllConfigs().map(env => `  ${env.key}: ${env.name}`).join('\n')}
`);
}

async function runEnvironmentTest(envKey, email) {
  logSection(`Testing ${envKey} environment`);
  
  const config = getAllConfigs().find(e => e.key === envKey);
  if (!config) {
    log(`❌ Unknown environment: ${envKey}`, 'red');
    return { success: false, error: 'Unknown environment' };
  }

  log(`🌍 Environment: ${config.name}`, 'blue');
  log(`🔗 Base URL: ${config.baseUrl}`, 'blue');
  log(`📧 Test Email: ${email}`, 'blue');

  try {
    // Set environment variable for the test
    process.env.TEST_ENV = envKey;
    
    // Run the test script
    const result = execSync(`node test-email.js "${email}" "TEST${Date.now()}" 15`, {
      encoding: 'utf8',
      stdio: 'pipe',
      env: { ...process.env, AUTH_WORKER_BASE_URL: config.baseUrl }
    });

    log('✅ Test completed successfully', 'green');
    
    return {
      success: true,
      output: result,
      config: config
    };

  } catch (error) {
    log('❌ Test failed', 'red');
    log(`Error: ${error.message}`, 'red');
    
    return {
      success: false,
      error: error.message,
      config: config
    };
  }
}

async function runAllTests(options) {
  logHeader('Starting Comprehensive Test Suite');
  
  const environments = options.all ? getAllConfigs().map(e => e.key) : [options.env || 'local'];
  const email = options.email;

  log(`📧 Test Email: ${email}`, 'blue');
  log(`🌍 Environments to Test: ${environments.join(', ')}`, 'blue');
  log(`📊 Generate Report: ${options.report ? 'Yes' : 'No'}`, 'blue');

  for (const envKey of environments) {
    const result = await runEnvironmentTest(envKey, email);
    
    // Store results
    testResults.environments[envKey] = {
      ...result,
      timestamp: new Date().toISOString()
    };

    // Update summary
    testResults.summary.total++;
    if (result.success) {
      testResults.summary.passed++;
    } else {
      testResults.summary.failed++;
    }

    // Wait a bit between tests
    if (environments.length > 1) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Generate summary
  logHeader('Test Summary');
  log(`📊 Total Tests: ${testResults.summary.total}`, 'bright');
  log(`✅ Passed: ${testResults.summary.passed}`, 'green');
  log(`❌ Failed: ${testResults.summary.failed}`, 'red');
  log(`⏭️  Skipped: ${testResults.summary.skipped}`, 'yellow');

  // Generate detailed report if requested
  if (options.report) {
    generateReport();
  }

  return testResults;
}

function generateReport() {
  logSection('Generating Test Report');
  
  const reportDir = 'test-reports';
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir);
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = path.join(reportDir, `test-report-${timestamp}.json`);
  
  try {
    fs.writeFileSync(reportFile, JSON.stringify(testResults, null, 2));
    log(`📄 Report saved to: ${reportFile}`, 'green');
  } catch (error) {
    log(`❌ Failed to save report: ${error.message}`, 'red');
  }
}

async function main() {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    return;
  }

  try {
    await runAllTests(options);
    
    if (testResults.summary.failed > 0) {
      process.exit(1);
    }
  } catch (error) {
    log(`💥 Test runner failed: ${error.message}`, 'red');
    process.exit(1);
  }
}

// Run the test runner
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { runAllTests, generateReport };
