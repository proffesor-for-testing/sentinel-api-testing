import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { SpecificationsPage } from '../pages/specifications.page';
import { testUsers, sampleAPISpec, testAgents } from '../fixtures/test-data';

test.describe('Multi-Agent Coordination', () => {
  let loginPage: LoginPage;
  let specsPage: SpecificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    specsPage = new SpecificationsPage(page);
    
    // Login as admin for full access
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await page.waitForURL(/.*dashboard/);
    
    // Ensure we have a spec to work with
    await specsPage.goto();
    await specsPage.uploadSpecification(
      'Multi-Agent Test Spec',
      'Testing multi-agent coordination',
      sampleAPISpec.content
    );
  });

  test('should coordinate multiple agents for comprehensive testing', async ({ page }) => {
    // Navigate to test runs
    await page.goto('/test-runs/new');
    
    // Select specification
    const specDropdown = page.locator('select[name="spec_id"], [data-testid="spec-select"]');
    await specDropdown.selectOption({ label: 'Multi-Agent Test Spec' });
    
    // Select all available agents
    const allAgents = [
      'functional-positive',
      'functional-negative',
      'functional-stateful',
      'security-auth',
      'security-injection',
      'performance-planner',
      'data-mocking'
    ];
    
    let selectedCount = 0;
    for (const agent of allAgents) {
      const checkbox = page.locator(`input[value="${agent}"]`);
      if (await checkbox.isVisible()) {
        await checkbox.check();
        selectedCount++;
      }
    }
    
    // Should have selected multiple agents
    expect(selectedCount).toBeGreaterThanOrEqual(3);
    
    // Configure coordination settings
    const coordinationMode = page.locator('select[name="coordination_mode"], [data-testid="coordination"]');
    if (await coordinationMode.isVisible()) {
      await coordinationMode.selectOption('parallel');
    }
    
    // Set test run name
    const nameInput = page.locator('input[name="name"], input[placeholder*="test run name"]');
    await nameInput.fill('Multi-Agent Coordination Test');
    
    // Start generation
    const generateButton = page.locator('button').filter({ hasText: /generate|start/i });
    await generateButton.click();
    
    // Monitor multi-agent progress
    await page.waitForURL(/test-runs\/[\w-]+/);
    
    // Should show all agent statuses
    const agentStatuses = page.locator('.agent-status-card, [data-testid="agent-status"]');
    await expect(agentStatuses).toHaveCount(selectedCount, { timeout: 10000 });
    
    // Verify agents are running
    for (let i = 0; i < selectedCount; i++) {
      const agentStatus = agentStatuses.nth(i);
      await expect(agentStatus).toContainText(/running|processing|generating|completed/i);
    }
    
    // Wait for some generation progress
    await page.waitForTimeout(5000);
    
    // Check for inter-agent dependencies
    const dependencies = page.locator('.agent-dependencies, [data-testid="dependencies"]');
    if (await dependencies.isVisible()) {
      // Data mocking agent should complete before others
      const dataMockingStatus = page.locator('[data-testid="agent-status"]:has-text("data-mocking")');
      if (await dataMockingStatus.isVisible()) {
        await expect(dataMockingStatus).toContainText(/completed|done/i, { timeout: 15000 });
      }
    }
  });

  test('should handle agent failures gracefully', async ({ page }) => {
    await page.goto('/test-runs/new');
    
    // Create test run with multiple agents
    const specDropdown = page.locator('select[name="spec_id"]');
    await specDropdown.selectOption({ index: 1 });
    
    // Select multiple agents
    const agents = ['functional-positive', 'security-auth', 'performance-planner'];
    for (const agent of agents) {
      const checkbox = page.locator(`input[value="${agent}"]`);
      if (await checkbox.isVisible()) {
        await checkbox.check();
      }
    }
    
    await page.locator('button:has-text("Generate")').click();
    await page.waitForURL(/test-runs\/[\w-]+/);
    
    // Monitor for agent failures
    const agentStatuses = page.locator('.agent-status-card, [data-testid="agent-status"]');
    
    // Wait for status updates
    await page.waitForTimeout(3000);
    
    // Check if any agent failed
    const failedAgent = page.locator('.agent-failed, [data-status="failed"]');
    if (await failedAgent.count() > 0) {
      // Should show error details
      await failedAgent.first().click();
      
      const errorDetails = page.locator('.agent-error, [data-testid="error-details"]');
      await expect(errorDetails).toBeVisible();
      await expect(errorDetails).toContainText(/error|failed|exception/i);
      
      // Other agents should continue
      const runningAgents = page.locator('[data-status="running"], [data-status="completed"]');
      expect(await runningAgents.count()).toBeGreaterThan(0);
    }
    
    // Should allow retry of failed agent
    const retryButton = page.locator('button').filter({ hasText: /retry.*agent/i });
    if (await retryButton.isVisible()) {
      await retryButton.click();
      
      // Should restart the failed agent
      await expect(page.locator('.agent-restarting, [data-status="restarting"]')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should display agent collaboration insights', async ({ page }) => {
    // Navigate to existing multi-agent test run
    await page.goto('/test-runs');
    
    // Find a run with multiple agents
    const multiAgentRun = page.locator('.test-run-item').filter({ hasText: /multi.*agent/i });
    if (await multiAgentRun.count() > 0) {
      await multiAgentRun.first().click();
    } else {
      // Create a new multi-agent run
      await page.goto('/test-runs/new');
      const specDropdown = page.locator('select[name="spec_id"]');
      await specDropdown.selectOption({ index: 1 });
      
      await page.locator('input[value="functional-positive"]').check();
      await page.locator('input[value="functional-negative"]').check();
      await page.locator('input[value="data-mocking"]').check();
      
      await page.locator('button:has-text("Generate")').click();
      await page.waitForURL(/test-runs\/[\w-]+/);
    }
    
    // Look for collaboration insights
    const insightsSection = page.locator('.collaboration-insights, [data-testid="agent-insights"]');
    if (await insightsSection.isVisible()) {
      // Should show agent interactions
      await expect(insightsSection).toContainText(/collaboration|interaction|shared/i);
      
      // Should show data flow between agents
      const dataFlow = page.locator('.data-flow, [data-testid="data-flow"]');
      if (await dataFlow.isVisible()) {
        // Data mocking -> Functional agents flow
        await expect(dataFlow).toContainText(/data.*mocking/i);
        await expect(dataFlow).toContainText(/functional/i);
      }
      
      // Should show coverage overlap
      const coverage = page.locator('.coverage-overlap, [data-testid="coverage"]');
      if (await coverage.isVisible()) {
        await expect(coverage).toContainText(/coverage|overlap|unique/i);
      }
    }
  });

  test('should optimize agent selection based on API spec', async ({ page }) => {
    await page.goto('/test-runs/new');
    
    // Select specification
    const specDropdown = page.locator('select[name="spec_id"]');
    await specDropdown.selectOption({ label: 'Multi-Agent Test Spec' });
    
    // Look for agent recommendations
    const recommendButton = page.locator('button').filter({ hasText: /recommend|suggest|optimize/i });
    if (await recommendButton.isVisible()) {
      await recommendButton.click();
      
      // Should show recommended agents
      const recommendations = page.locator('.agent-recommendations, [data-testid="recommendations"]');
      await expect(recommendations).toBeVisible();
      
      // Should explain why agents are recommended
      await expect(recommendations).toContainText(/recommended|suggested|optimal/i);
      
      // Apply recommendations
      const applyButton = page.locator('button').filter({ hasText: /apply|use.*recommend/i });
      if (await applyButton.isVisible()) {
        await applyButton.click();
        
        // Should auto-select recommended agents
        const selectedAgents = page.locator('input[type="checkbox"]:checked');
        const selectedCount = await selectedAgents.count();
        expect(selectedCount).toBeGreaterThan(0);
      }
    }
  });

  test('should manage agent priorities and sequencing', async ({ page }) => {
    await page.goto('/test-runs/new');
    
    const specDropdown = page.locator('select[name="spec_id"]');
    await specDropdown.selectOption({ index: 1 });
    
    // Select agents
    await page.locator('input[value="data-mocking"]').check();
    await page.locator('input[value="functional-positive"]').check();
    await page.locator('input[value="security-auth"]').check();
    
    // Look for advanced settings
    const advancedButton = page.locator('button').filter({ hasText: /advanced|settings/i });
    if (await advancedButton.isVisible()) {
      await advancedButton.click();
      
      // Should show agent priority settings
      const prioritySection = page.locator('.agent-priorities, [data-testid="priorities"]');
      if (await prioritySection.isVisible()) {
        // Set data-mocking as high priority (should run first)
        const dataMockingPriority = prioritySection.locator('select[name*="data-mocking"]');
        if (await dataMockingPriority.isVisible()) {
          await dataMockingPriority.selectOption('high');
        }
        
        // Set dependencies
        const dependencyCheckbox = page.locator('input[name*="dependency"]');
        if (await dependencyCheckbox.isVisible()) {
          await dependencyCheckbox.check();
        }
      }
    }
    
    // Start generation with configured priorities
    await page.locator('button:has-text("Generate")').click();
    await page.waitForURL(/test-runs\/[\w-]+/);
    
    // Verify execution order
    const timeline = page.locator('.execution-timeline, [data-testid="timeline"]');
    if (await timeline.isVisible()) {
      const timelineItems = timeline.locator('.timeline-item');
      const firstItem = timelineItems.first();
      
      // Data mocking should start first
      await expect(firstItem).toContainText(/data.*mocking/i);
    }
  });

  test('should aggregate results from multiple agents', async ({ page }) => {
    // Navigate to completed multi-agent test run
    await page.goto('/test-runs');
    
    const completedRuns = page.locator('.completed').filter({ hasText: /multi.*agent/i });
    if (await completedRuns.count() > 0) {
      await completedRuns.first().click();
      
      // Wait for results
      await page.waitForSelector('.test-results, [data-testid="test-results"]', { timeout: 10000 });
      
      // Should show aggregated results
      const aggregatedResults = page.locator('.aggregated-results, [data-testid="summary"]');
      if (await aggregatedResults.isVisible()) {
        // Should show total from all agents
        await expect(aggregatedResults).toContainText(/total.*tests/i);
        
        // Should show breakdown by agent
        const agentBreakdown = page.locator('.agent-breakdown, [data-testid="by-agent"]');
        if (await agentBreakdown.isVisible()) {
          // Should list each agent's contribution
          const agentResults = agentBreakdown.locator('.agent-result');
          const agentCount = await agentResults.count();
          expect(agentCount).toBeGreaterThanOrEqual(2);
          
          // Each should show test count
          for (let i = 0; i < Math.min(agentCount, 3); i++) {
            const agentResult = agentResults.nth(i);
            await expect(agentResult).toContainText(/\d+.*test/i);
          }
        }
        
        // Should show combined coverage
        const coverageSection = page.locator('.combined-coverage, [data-testid="coverage"]');
        if (await coverageSection.isVisible()) {
          await expect(coverageSection).toContainText(/coverage.*\d+\s*%/i);
        }
      }
    }
  });

  test('should visualize agent coordination flow', async ({ page }) => {
    await page.goto('/test-runs');
    
    // Find multi-agent run
    const multiAgentRun = page.locator('.test-run-item').filter({ hasText: /multi/i });
    if (await multiAgentRun.count() > 0) {
      await multiAgentRun.first().click();
      
      // Look for visualization
      const visualizationTab = page.locator('button, [role="tab"]').filter({ hasText: /visual|flow|diagram/i });
      if (await visualizationTab.isVisible()) {
        await visualizationTab.click();
        
        // Should show flow diagram
        const flowDiagram = page.locator('.flow-diagram, [data-testid="flow-visualization"]');
        await expect(flowDiagram).toBeVisible();
        
        // Should have nodes for each agent
        const agentNodes = flowDiagram.locator('.agent-node, .node');
        expect(await agentNodes.count()).toBeGreaterThan(1);
        
        // Should show connections between agents
        const connections = flowDiagram.locator('.connection, .edge, line');
        if (await connections.count() > 0) {
          // Hover over connection for details
          await connections.first().hover();
          
          const tooltip = page.locator('.tooltip, [role="tooltip"]');
          if (await tooltip.isVisible({ timeout: 2000 })) {
            await expect(tooltip).toContainText(/data|dependency|flow/i);
          }
        }
      }
    }
  });

  test('should handle concurrent agent execution limits', async ({ page }) => {
    await page.goto('/test-runs/new');
    
    const specDropdown = page.locator('select[name="spec_id"]');
    await specDropdown.selectOption({ index: 1 });
    
    // Try to select many agents
    const allCheckboxes = page.locator('input[type="checkbox"][name*="agent"]');
    const totalAgents = await allCheckboxes.count();
    
    // Select all agents
    for (let i = 0; i < totalAgents; i++) {
      await allCheckboxes.nth(i).check();
    }
    
    // Look for concurrency settings
    const concurrencyInput = page.locator('input[name="max_concurrent"], [data-testid="concurrency"]');
    if (await concurrencyInput.isVisible()) {
      // Set max concurrent agents
      await concurrencyInput.fill('3');
    }
    
    // Start generation
    await page.locator('button:has-text("Generate")').click();
    await page.waitForURL(/test-runs\/[\w-]+/);
    
    // Monitor concurrent execution
    const runningAgents = page.locator('[data-status="running"]');
    
    // Should not exceed concurrency limit
    for (let i = 0; i < 3; i++) {
      await page.waitForTimeout(2000);
      const currentRunning = await runningAgents.count();
      expect(currentRunning).toBeLessThanOrEqual(3);
    }
    
    // Should queue remaining agents
    const queuedAgents = page.locator('[data-status="queued"], [data-status="pending"]');
    if (totalAgents > 3) {
      expect(await queuedAgents.count()).toBeGreaterThan(0);
    }
  });
});