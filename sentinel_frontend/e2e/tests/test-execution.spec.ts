import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { SpecificationsPage } from '../pages/specifications.page';
import { testUsers, sampleAPISpec } from '../fixtures/test-data';

test.describe('Test Execution Workflow', () => {
  let loginPage: LoginPage;
  let specsPage: SpecificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    specsPage = new SpecificationsPage(page);
    
    // Login as tester
    await loginPage.goto();
    await loginPage.login(testUsers.tester.email, testUsers.tester.password);
    await page.waitForURL(/.*dashboard/);
  });

  test('should execute complete test workflow from spec to results', async ({ page }) => {
    // Step 1: Upload specification
    await specsPage.goto();
    await specsPage.uploadSpecification(
      'Execution Test Spec',
      'Complete workflow test',
      sampleAPISpec.content
    );
    await expect(specsPage.successMessage).toBeVisible();

    // Step 2: Navigate to test runs
    await page.goto('/test-runs');
    await page.waitForLoadState('networkidle');
    
    // Step 3: Create new test run
    const newTestButton = page.locator('button').filter({ hasText: /new test|create test/i });
    await newTestButton.click();
    
    // Step 4: Configure test run
    const specDropdown = page.locator('select[name="spec_id"], [data-testid="spec-select"]');
    await specDropdown.selectOption({ label: 'Execution Test Spec' });
    
    // Select multiple agents for comprehensive testing
    const agents = ['functional-positive', 'functional-negative', 'security-auth'];
    for (const agent of agents) {
      const checkbox = page.locator(`input[value="${agent}"]`);
      if (await checkbox.isVisible()) {
        await checkbox.check();
      }
    }
    
    const nameInput = page.locator('input[name="name"], input[placeholder*="test run name"]');
    await nameInput.fill('Full Execution Test ' + Date.now());
    
    // Step 5: Start test generation
    const generateButton = page.locator('button').filter({ hasText: /generate|start/i });
    await generateButton.click();
    
    // Step 6: Wait for generation to complete
    await expect(page.locator('.loading, .spinner, text=Generating')).toBeVisible({ timeout: 10000 });
    await page.waitForURL(/test-runs\/[\w-]+/);
    
    // Wait for test cases to be generated
    await page.waitForSelector('.test-cases, [data-testid="test-cases"]', { timeout: 30000 });
    
    // Step 7: Execute tests
    const executeButton = page.locator('button').filter({ hasText: /execute|run all/i });
    await executeButton.click();
    
    // Step 8: Monitor execution progress
    const executionStatus = page.locator('.execution-status, [data-testid="execution-status"]');
    await expect(executionStatus).toBeVisible();
    
    // Wait for execution to complete
    await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 60000 });
    
    // Step 9: Verify results
    const results = page.locator('.test-results, [data-testid="test-results"]');
    await expect(results).toBeVisible();
    
    // Check for pass/fail indicators
    const passedTests = page.locator('.test-passed, .success, [data-testid="passed-tests"]');
    const failedTests = page.locator('.test-failed, .failure, [data-testid="failed-tests"]');
    
    // Should have some results
    const passedCount = await passedTests.count();
    const failedCount = await failedTests.count();
    expect(passedCount + failedCount).toBeGreaterThan(0);
  });

  test('should handle partial test execution', async ({ page }) => {
    // Navigate to existing test run
    await page.goto('/test-runs');
    
    const testRunRows = page.locator('tr, .test-run-item');
    if (await testRunRows.count() > 0) {
      await testRunRows.first().click();
      
      // Wait for test cases
      await page.waitForSelector('.test-cases, [data-testid="test-cases"]', { timeout: 10000 });
      
      // Select specific test cases for execution
      const testCaseCheckboxes = page.locator('.test-case-checkbox, input[type="checkbox"][name*="test"]');
      const checkboxCount = await testCaseCheckboxes.count();
      
      if (checkboxCount > 2) {
        // Select only first 2 test cases
        await testCaseCheckboxes.nth(0).check();
        await testCaseCheckboxes.nth(1).check();
        
        // Execute selected tests
        const executeSelectedButton = page.locator('button').filter({ hasText: /execute selected|run selected/i });
        if (await executeSelectedButton.isVisible()) {
          await executeSelectedButton.click();
          
          // Verify only selected tests are running
          const runningTests = page.locator('.running-test, [data-testid="running"]');
          await expect(runningTests).toHaveCount(2, { timeout: 10000 });
        }
      }
    }
  });

  test('should support test re-execution', async ({ page }) => {
    // Navigate to test run with completed tests
    await page.goto('/test-runs');
    
    const completedRuns = page.locator('.completed, [data-status="completed"]');
    if (await completedRuns.count() > 0) {
      await completedRuns.first().click();
      
      // Find re-run button
      const rerunButton = page.locator('button').filter({ hasText: /re-run|retry|execute again/i });
      if (await rerunButton.isVisible()) {
        await rerunButton.click();
        
        // Confirm re-execution
        const confirmButton = page.locator('button').filter({ hasText: /confirm|yes/i });
        if (await confirmButton.isVisible()) {
          await confirmButton.click();
        }
        
        // Should start new execution
        await expect(page.locator('.executing, .running')).toBeVisible({ timeout: 10000 });
      }
    }
  });

  test('should handle execution interruption gracefully', async ({ page }) => {
    // Start a test execution
    await page.goto('/test-runs');
    
    const testRunRows = page.locator('tr, .test-run-item');
    if (await testRunRows.count() > 0) {
      await testRunRows.first().click();
      
      // Start execution
      const executeButton = page.locator('button').filter({ hasText: /execute|run/i });
      if (await executeButton.isVisible()) {
        await executeButton.click();
        
        // Wait for execution to start
        await expect(page.locator('.executing, .running')).toBeVisible({ timeout: 10000 });
        
        // Stop execution
        const stopButton = page.locator('button').filter({ hasText: /stop|cancel|abort/i });
        if (await stopButton.isVisible()) {
          await stopButton.click();
          
          // Verify execution stopped
          await expect(page.locator('.stopped, .cancelled, [data-status="stopped"]')).toBeVisible({ timeout: 10000 });
          
          // Should show partial results
          const partialResults = page.locator('.partial-results, .incomplete-results');
          if (await partialResults.isVisible()) {
            await expect(partialResults).toContainText(/partial|incomplete|stopped/i);
          }
        }
      }
    }
  });

  test('should export test execution results', async ({ page }) => {
    // Navigate to completed test run
    await page.goto('/test-runs');
    
    const completedRuns = page.locator('.completed, [data-status="completed"]');
    if (await completedRuns.count() > 0) {
      await completedRuns.first().click();
      
      // Wait for results to load
      await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 10000 });
      
      // Find export button
      const exportButton = page.locator('button').filter({ hasText: /export|download/i });
      if (await exportButton.isVisible()) {
        // Set up download promise before clicking
        const downloadPromise = page.waitForEvent('download');
        
        await exportButton.click();
        
        // Select export format if dialog appears
        const formatSelector = page.locator('select[name="export_format"], [data-testid="export-format"]');
        if (await formatSelector.isVisible()) {
          await formatSelector.selectOption('json');
          
          const confirmExport = page.locator('button').filter({ hasText: /export|download/i }).last();
          await confirmExport.click();
        }
        
        // Wait for download
        const download = await downloadPromise;
        
        // Verify download
        expect(download).toBeTruthy();
        const fileName = download.suggestedFilename();
        expect(fileName).toMatch(/test.*results|export/i);
      }
    }
  });

  test('should display execution metrics and statistics', async ({ page }) => {
    // Navigate to completed test run
    await page.goto('/test-runs');
    
    const completedRuns = page.locator('.completed, [data-status="completed"]');
    if (await completedRuns.count() > 0) {
      await completedRuns.first().click();
      
      // Wait for results
      await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 10000 });
      
      // Check for metrics display
      const metricsSection = page.locator('.metrics, .statistics, [data-testid="execution-metrics"]');
      if (await metricsSection.isVisible()) {
        // Verify key metrics are displayed
        await expect(metricsSection).toContainText(/total tests/i);
        await expect(metricsSection).toContainText(/passed/i);
        await expect(metricsSection).toContainText(/failed/i);
        
        // Check for execution time
        const executionTime = page.locator('.execution-time, [data-testid="duration"]');
        if (await executionTime.isVisible()) {
          const timeText = await executionTime.textContent();
          expect(timeText).toMatch(/\d+.*(?:ms|s|sec|min)/i);
        }
        
        // Check for success rate
        const successRate = page.locator('.success-rate, [data-testid="pass-rate"]');
        if (await successRate.isVisible()) {
          const rateText = await successRate.textContent();
          expect(rateText).toMatch(/\d+\.?\d*\s*%/);
        }
      }
    }
  });

  test('should filter execution results by status', async ({ page }) => {
    // Navigate to completed test run
    await page.goto('/test-runs');
    
    const completedRuns = page.locator('.completed, [data-status="completed"]');
    if (await completedRuns.count() > 0) {
      await completedRuns.first().click();
      
      // Wait for results
      await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 10000 });
      
      // Find status filter
      const statusFilter = page.locator('select[name="status_filter"], [data-testid="status-filter"]');
      if (await statusFilter.isVisible()) {
        // Filter by passed tests
        await statusFilter.selectOption('passed');
        
        // Verify only passed tests are shown
        const visibleTests = page.locator('.test-result-item:visible, .test-case-result:visible');
        const count = await visibleTests.count();
        
        for (let i = 0; i < count; i++) {
          const testItem = visibleTests.nth(i);
          await expect(testItem).toHaveClass(/passed|success/);
        }
        
        // Filter by failed tests
        await statusFilter.selectOption('failed');
        
        // Verify only failed tests are shown
        const failedTests = page.locator('.test-result-item:visible, .test-case-result:visible');
        const failedCount = await failedTests.count();
        
        if (failedCount > 0) {
          for (let i = 0; i < failedCount; i++) {
            const testItem = failedTests.nth(i);
            await expect(testItem).toHaveClass(/failed|failure|error/);
          }
        }
      }
    }
  });

  test('should show detailed error information for failed tests', async ({ page }) => {
    // Navigate to test run with failures
    await page.goto('/test-runs');
    
    const testRuns = page.locator('tr, .test-run-item');
    if (await testRuns.count() > 0) {
      // Find a run with failures
      for (let i = 0; i < await testRuns.count(); i++) {
        const run = testRuns.nth(i);
        const failureIndicator = run.locator('.failures, .failed-count, [data-testid="failures"]');
        
        if (await failureIndicator.isVisible()) {
          await run.click();
          
          // Wait for results
          await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 10000 });
          
          // Find a failed test
          const failedTest = page.locator('.test-failed, .failure').first();
          if (await failedTest.isVisible()) {
            await failedTest.click();
            
            // Should show error details
            const errorDetails = page.locator('.error-details, .failure-details, [data-testid="error-info"]');
            await expect(errorDetails).toBeVisible({ timeout: 5000 });
            
            // Check for error message
            await expect(errorDetails).toContainText(/error|failed|exception/i);
            
            // Check for stack trace or request/response details
            const stackTrace = page.locator('.stack-trace, .error-trace, [data-testid="stack-trace"]');
            const requestDetails = page.locator('.request-details, [data-testid="request"]');
            
            const hasDetails = await stackTrace.isVisible() || await requestDetails.isVisible();
            expect(hasDetails).toBeTruthy();
          }
          break;
        }
      }
    }
  });
});