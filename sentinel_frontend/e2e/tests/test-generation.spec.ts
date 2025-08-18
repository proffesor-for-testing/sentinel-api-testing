import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { SpecificationsPage } from '../pages/specifications.page';
import { testUsers, sampleAPISpec, testAgents } from '../fixtures/test-data';

test.describe('Test Generation Workflow', () => {
  let loginPage: LoginPage;
  let specsPage: SpecificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    specsPage = new SpecificationsPage(page);
    
    // Login and upload a spec
    await loginPage.goto();
    await loginPage.login(testUsers.tester.email, testUsers.tester.password);
    await page.waitForURL(/.*dashboard/);
    
    // Upload specification for testing
    await specsPage.goto();
    await specsPage.uploadSpecification(
      'Test Generation Spec',
      'Spec for test generation',
      sampleAPISpec.content
    );
  });

  test('should create new test run with AI agents', async ({ page }) => {
    // Navigate to test runs
    await page.goto('/test-runs');
    await page.waitForLoadState('networkidle');
    
    // Click new test run button
    const newTestButton = page.locator('button').filter({ hasText: /new test|create test/i });
    await newTestButton.click();
    
    // Select specification
    const specDropdown = page.locator('select[name="spec_id"], [data-testid="spec-select"]');
    await specDropdown.selectOption({ label: 'Test Generation Spec' });
    
    // Select AI agents
    for (const agent of testAgents.slice(0, 3)) { // Select first 3 agents
      const agentCheckbox = page.locator(`input[type="checkbox"][value="${agent}"]`);
      if (await agentCheckbox.isVisible()) {
        await agentCheckbox.check();
      }
    }
    
    // Configure test run
    const nameInput = page.locator('input[name="name"], input[placeholder*="test run name"]');
    await nameInput.fill('E2E Test Run ' + Date.now());
    
    // Start test generation
    const generateButton = page.locator('button').filter({ hasText: /generate|start|run/i });
    await generateButton.click();
    
    // Wait for test generation to start
    await expect(page.locator('.loading, .spinner, text=Generating')).toBeVisible({ timeout: 10000 });
    
    // Should navigate to test run details
    await expect(page).toHaveURL(/test-runs\/[\w-]+/);
  });

  test('should monitor test generation progress', async ({ page }) => {
    // Create and start a test run
    await page.goto('/test-runs/new');
    
    const specDropdown = page.locator('select[name="spec_id"], [data-testid="spec-select"]');
    await specDropdown.selectOption({ label: 'Test Generation Spec' });
    
    // Select functional agents
    const functionalPositive = page.locator('input[value="functional-positive"]');
    const functionalNegative = page.locator('input[value="functional-negative"]');
    
    if (await functionalPositive.isVisible()) await functionalPositive.check();
    if (await functionalNegative.isVisible()) await functionalNegative.check();
    
    const generateButton = page.locator('button').filter({ hasText: /generate|start/i });
    await generateButton.click();
    
    // Monitor progress
    const progressBar = page.locator('.progress-bar, [role="progressbar"]');
    const statusText = page.locator('.status, [data-testid="status"]');
    
    // Should show progress updates
    await expect(progressBar.or(statusText)).toBeVisible({ timeout: 10000 });
    
    // Wait for some progress
    await page.waitForTimeout(3000);
    
    // Should show agent status
    const agentStatus = page.locator('.agent-status, [data-testid="agent-status"]');
    if (await agentStatus.isVisible()) {
      await expect(agentStatus).toContainText(/running|processing|generating/i);
    }
  });

  test('should display generated test cases', async ({ page }) => {
    // Navigate to an existing test run or create one
    await page.goto('/test-runs');
    
    // Click on a test run or create new one
    const testRunRows = page.locator('tr, .test-run-item');
    const count = await testRunRows.count();
    
    if (count > 0) {
      // Click on first test run
      await testRunRows.first().click();
    } else {
      // Create new test run
      await page.locator('button:has-text("New Test")').click();
      await page.locator('select[name="spec_id"]').selectOption({ index: 1 });
      await page.locator('input[value="functional-positive"]').check();
      await page.locator('button:has-text("Generate")').click();
      await page.waitForTimeout(5000); // Wait for generation
    }
    
    // Should show test cases section
    const testCasesSection = page.locator('.test-cases, [data-testid="test-cases"]');
    await expect(testCasesSection).toBeVisible({ timeout: 15000 });
    
    // Should display test case details
    const testCaseItems = page.locator('.test-case-item, .test-case-row');
    const testCaseCount = await testCaseItems.count();
    expect(testCaseCount).toBeGreaterThan(0);
    
    // Verify test case structure
    if (testCaseCount > 0) {
      const firstTestCase = testCaseItems.first();
      await expect(firstTestCase).toContainText(/GET|POST|PUT|DELETE/i); // HTTP method
      await expect(firstTestCase).toContainText(/\/\w+/); // Endpoint path
    }
  });

  test('should filter test cases by agent type', async ({ page }) => {
    // Navigate to test run with generated tests
    await page.goto('/test-runs');
    
    const testRunRows = page.locator('tr, .test-run-item');
    if (await testRunRows.count() > 0) {
      await testRunRows.first().click();
      
      // Wait for test cases to load
      await page.waitForSelector('.test-cases, [data-testid="test-cases"]', { timeout: 10000 });
      
      // Look for agent filter
      const agentFilter = page.locator('select[name="agent_type"], [data-testid="agent-filter"]');
      
      if (await agentFilter.isVisible()) {
        // Filter by functional-positive
        await agentFilter.selectOption('functional-positive');
        
        // Verify filtered results
        const testCases = page.locator('.test-case-item');
        const visibleCount = await testCases.count();
        
        // All visible test cases should be from selected agent
        for (let i = 0; i < visibleCount; i++) {
          const testCase = testCases.nth(i);
          const agentTag = testCase.locator('.agent-tag, [data-testid="agent-type"]');
          if (await agentTag.isVisible()) {
            await expect(agentTag).toContainText(/functional.*positive/i);
          }
        }
      }
    }
  });

  test('should execute generated test cases', async ({ page }) => {
    // Navigate to test run
    await page.goto('/test-runs');
    
    const testRunRows = page.locator('tr, .test-run-item');
    if (await testRunRows.count() > 0) {
      await testRunRows.first().click();
      
      // Wait for test cases
      await page.waitForSelector('.test-cases, [data-testid="test-cases"]', { timeout: 10000 });
      
      // Find execute button
      const executeButton = page.locator('button').filter({ hasText: /execute|run test/i });
      
      if (await executeButton.isVisible()) {
        await executeButton.click();
        
        // Should show execution progress
        await expect(page.locator('.executing, .running, [data-testid="execution-status"]')).toBeVisible({ timeout: 10000 });
        
        // Wait for some execution progress
        await page.waitForTimeout(3000);
        
        // Should show results
        const results = page.locator('.test-results, [data-testid="test-results"]');
        await expect(results).toBeVisible({ timeout: 30000 });
      }
    }
  });

  test('should handle test generation errors gracefully', async ({ page }) => {
    await page.goto('/test-runs/new');
    
    // Try to create test run without selecting specification
    const generateButton = page.locator('button').filter({ hasText: /generate|start/i });
    await generateButton.click();
    
    // Should show validation error
    const errorMessage = page.locator('.error-message, .alert-danger');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/specification|required/i);
    
    // Select spec but no agents
    const specDropdown = page.locator('select[name="spec_id"]');
    await specDropdown.selectOption({ index: 1 });
    
    await generateButton.click();
    
    // Should show error about agents
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/agent|select/i);
  });
});