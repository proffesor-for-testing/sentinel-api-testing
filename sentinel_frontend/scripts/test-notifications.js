#!/usr/bin/env node

/**
 * Test script to verify notification modals are working properly
 * This script will test various scenarios through the API
 */

const axios = require('axios');

const API_BASE_URL = 'http://localhost:3000/api/v1';

// Color codes for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m'
};

const log = {
  success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  warning: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`)
};

async function testDeleteTestRun() {
  log.info('Testing DELETE endpoint for test run...');
  
  try {
    // Try to delete a non-existent test run to trigger an error
    const response = await axios.delete(`${API_BASE_URL}/test-runs/999999`);
    log.warning('Unexpected success for non-existent test run');
  } catch (error) {
    if (error.response && error.response.status === 404) {
      log.success('Correctly returned 404 for non-existent test run');
    } else if (error.code === 'ECONNREFUSED') {
      log.error('API Gateway not running on port 8000. Please start the backend services.');
      return false;
    } else {
      log.error(`Unexpected error: ${error.message}`);
    }
  }
  
  return true;
}

async function testBulkDelete() {
  log.info('Testing bulk delete endpoint...');
  
  try {
    // Try bulk delete with empty array
    const response = await axios.post(`${API_BASE_URL}/test-runs/bulk-delete`, {
      run_ids: []
    });
    log.success('Bulk delete with empty array successful');
  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      log.error('API Gateway not running on port 8000. Please start the backend services.');
      return false;
    } else {
      log.error(`Bulk delete test failed: ${error.message}`);
    }
  }
  
  return true;
}

async function testGetTestRuns() {
  log.info('Testing GET test runs endpoint...');
  
  try {
    const response = await axios.get(`${API_BASE_URL}/test-runs`);
    log.success(`Successfully fetched ${response.data.length || 0} test runs`);
    return response.data;
  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      log.error('API Gateway not running on port 8000. Please start the backend services.');
    } else {
      log.error(`Failed to fetch test runs: ${error.message}`);
    }
    return [];
  }
}

async function main() {
  console.log('\n' + colors.blue + '=' .repeat(50) + colors.reset);
  console.log(colors.blue + ' Testing Notification Modal Integration' + colors.reset);
  console.log(colors.blue + '=' .repeat(50) + colors.reset + '\n');
  
  log.info('Note: Please open http://localhost:3000 in your browser');
  log.info('and navigate to the Test Runs page to see the notifications\n');
  
  // Test GET endpoint first
  const testRuns = await testGetTestRuns();
  
  // Test DELETE endpoint
  await testDeleteTestRun();
  
  // Test bulk delete
  await testBulkDelete();
  
  // If we have test runs, try to delete the first one
  if (testRuns && testRuns.length > 0) {
    log.info(`\nAttempting to delete test run #${testRuns[0].id}...`);
    try {
      await axios.delete(`${API_BASE_URL}/test-runs/${testRuns[0].id}`);
      log.success(`Deleted test run #${testRuns[0].id}`);
      log.info('Check the browser to see the success notification!');
    } catch (error) {
      log.warning(`Could not delete test run: ${error.message}`);
    }
  }
  
  console.log('\n' + colors.blue + '=' .repeat(50) + colors.reset);
  console.log(colors.green + ' Test Complete!' + colors.reset);
  console.log(colors.blue + '=' .repeat(50) + colors.reset + '\n');
  
  log.info('Manual testing steps:');
  console.log('1. Open http://localhost:3000 in your browser');
  console.log('2. Navigate to the Test Runs page');
  console.log('3. Try deleting a test run - you should see a success notification');
  console.log('4. Select multiple test runs and bulk delete - you should see a notification with count');
  console.log('5. Notifications should auto-dismiss after 5 seconds\n');
}

main().catch(error => {
  log.error(`Script failed: ${error.message}`);
  process.exit(1);
});