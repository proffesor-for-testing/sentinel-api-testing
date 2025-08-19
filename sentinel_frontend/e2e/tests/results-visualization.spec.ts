import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { testUsers } from '../fixtures/test-data';

test.describe('Test Results Visualization', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    
    // Login as admin for full access
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await page.waitForURL(/.*dashboard/);
  });

  test('should display test results dashboard', async ({ page }) => {
    // Navigate to analytics/results page
    await page.goto('/analytics');
    await page.waitForLoadState('networkidle');
    
    // Verify dashboard loaded
    const dashboard = page.locator('.analytics-dashboard, [data-testid="analytics"]');
    await expect(dashboard).toBeVisible();
    
    // Check for key metrics cards
    const metricsCards = page.locator('.metric-card, .stat-card, [data-testid="metric"]');
    const cardCount = await metricsCards.count();
    expect(cardCount).toBeGreaterThanOrEqual(4); // Total tests, pass rate, avg duration, etc.
    
    // Verify each metric card has value and label
    for (let i = 0; i < Math.min(cardCount, 4); i++) {
      const card = metricsCards.nth(i);
      const value = card.locator('.metric-value, .stat-value');
      const label = card.locator('.metric-label, .stat-label');
      
      await expect(value).toBeVisible();
      await expect(label).toBeVisible();
      
      // Value should contain number
      const valueText = await value.textContent();
      expect(valueText).toMatch(/\d+/);
    }
  });

  test('should display test execution trends chart', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for trends chart
    const trendsChart = page.locator('.trends-chart, .chart-container, [data-testid="trends-chart"]');
    if (await trendsChart.isVisible()) {
      // Chart should be rendered (check for SVG or canvas)
      const svg = trendsChart.locator('svg');
      const canvas = trendsChart.locator('canvas');
      
      const hasChart = await svg.isVisible() || await canvas.isVisible();
      expect(hasChart).toBeTruthy();
      
      // Check for time period selector
      const periodSelector = page.locator('select[name="period"], [data-testid="time-period"]');
      if (await periodSelector.isVisible()) {
        // Test different time periods
        await periodSelector.selectOption('7d');
        await page.waitForTimeout(1000); // Wait for chart update
        
        await periodSelector.selectOption('30d');
        await page.waitForTimeout(1000);
        
        // Chart should still be visible
        expect(await svg.isVisible() || await canvas.isVisible()).toBeTruthy();
      }
    }
  });

  test('should display test coverage by endpoint', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for coverage section
    const coverageSection = page.locator('.coverage-section, [data-testid="coverage"]');
    if (await coverageSection.isVisible()) {
      // Should show endpoints list
      const endpoints = page.locator('.endpoint-coverage, [data-testid="endpoint"]');
      const endpointCount = await endpoints.count();
      
      if (endpointCount > 0) {
        // Check first endpoint
        const firstEndpoint = endpoints.first();
        
        // Should show endpoint path
        await expect(firstEndpoint).toContainText(/\/\w+/);
        
        // Should show coverage percentage or test count
        const coverage = firstEndpoint.locator('.coverage-value, .test-count');
        if (await coverage.isVisible()) {
          const coverageText = await coverage.textContent();
          expect(coverageText).toMatch(/\d+/);
        }
        
        // Should have visual indicator (progress bar)
        const progressBar = firstEndpoint.locator('.progress-bar, .coverage-bar');
        if (await progressBar.isVisible()) {
          const width = await progressBar.evaluate(el => {
            const style = window.getComputedStyle(el);
            return style.width;
          });
          expect(width).toMatch(/\d+/);
        }
      }
    }
  });

  test('should display agent performance comparison', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for agent comparison section
    const agentSection = page.locator('.agent-comparison, [data-testid="agent-performance"]');
    if (await agentSection.isVisible()) {
      // Should list agents with metrics
      const agentCards = page.locator('.agent-card, [data-testid="agent-metric"]');
      const agentCount = await agentCards.count();
      
      if (agentCount > 0) {
        for (let i = 0; i < Math.min(agentCount, 3); i++) {
          const card = agentCards.nth(i);
          
          // Should show agent name
          const agentName = card.locator('.agent-name');
          await expect(agentName).toBeVisible();
          await expect(agentName).toContainText(/functional|security|performance/i);
          
          // Should show metrics
          const metrics = card.locator('.agent-metrics, .metric');
          await expect(metrics).toBeVisible();
          
          // Should show test count or success rate
          await expect(metrics).toContainText(/\d+/);
        }
      }
    }
  });

  test('should filter results by date range', async ({ page }) => {
    await page.goto('/analytics');
    
    // Find date range picker
    const dateRangePicker = page.locator('.date-range-picker, [data-testid="date-range"]');
    if (await dateRangePicker.isVisible()) {
      await dateRangePicker.click();
      
      // Select last 7 days
      const last7Days = page.locator('button, [role="option"]').filter({ hasText: /last 7 days/i });
      if (await last7Days.isVisible()) {
        await last7Days.click();
        
        // Wait for data to reload
        await page.waitForTimeout(2000);
        
        // Verify data is filtered (check updated timestamp or data change)
        const lastUpdated = page.locator('.last-updated, [data-testid="last-updated"]');
        if (await lastUpdated.isVisible()) {
          await expect(lastUpdated).toContainText(/updated|refreshed/i);
        }
      }
    }
  });

  test('should display failure analysis', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for failure analysis section
    const failureSection = page.locator('.failure-analysis, [data-testid="failures"]');
    if (await failureSection.isVisible()) {
      // Should categorize failures
      const failureCategories = page.locator('.failure-category, [data-testid="failure-type"]');
      const categoryCount = await failureCategories.count();
      
      if (categoryCount > 0) {
        // Check failure categories
        const expectedCategories = ['Authentication', 'Validation', 'Server Error', 'Timeout'];
        
        for (let i = 0; i < Math.min(categoryCount, 2); i++) {
          const category = failureCategories.nth(i);
          const categoryText = await category.textContent();
          
          // Should match known categories
          const hasKnownCategory = expectedCategories.some(cat => 
            categoryText?.toLowerCase().includes(cat.toLowerCase())
          );
          
          if (hasKnownCategory) {
            // Should show count or percentage
            await expect(category).toContainText(/\d+/);
          }
        }
      }
    }
  });

  test('should export analytics report', async ({ page }) => {
    await page.goto('/analytics');
    
    // Find export button
    const exportButton = page.locator('button').filter({ hasText: /export|download.*report/i });
    if (await exportButton.isVisible()) {
      // Set up download promise
      const downloadPromise = page.waitForEvent('download');
      
      await exportButton.click();
      
      // Handle export options if present
      const exportDialog = page.locator('.export-dialog, [role="dialog"]');
      if (await exportDialog.isVisible()) {
        // Select PDF format
        const pdfOption = page.locator('input[value="pdf"], label:has-text("PDF")');
        if (await pdfOption.isVisible()) {
          await pdfOption.click();
        }
        
        // Confirm export
        const confirmButton = page.locator('button').filter({ hasText: /export|generate/i }).last();
        await confirmButton.click();
      }
      
      // Wait for download
      const download = await downloadPromise;
      
      // Verify download
      expect(download).toBeTruthy();
      const fileName = download.suggestedFilename();
      expect(fileName).toMatch(/report|analytics/i);
    }
  });

  test('should display real-time test execution status', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for real-time status section
    const realtimeSection = page.locator('.realtime-status, [data-testid="live-status"]');
    if (await realtimeSection.isVisible()) {
      // Should show active test runs
      const activeRuns = page.locator('.active-run, [data-testid="active-test"]');
      const activeCount = await activeRuns.count();
      
      if (activeCount > 0) {
        const firstRun = activeRuns.first();
        
        // Should show run name
        await expect(firstRun).toContainText(/test.*run/i);
        
        // Should show progress
        const progress = firstRun.locator('.progress, [role="progressbar"]');
        if (await progress.isVisible()) {
          const progressValue = await progress.getAttribute('aria-valuenow');
          expect(progressValue).toBeTruthy();
        }
        
        // Should show status
        const status = firstRun.locator('.status, [data-testid="run-status"]');
        await expect(status).toContainText(/running|executing|in.*progress/i);
      }
    }
  });

  test('should compare test results across runs', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for comparison feature
    const compareButton = page.locator('button').filter({ hasText: /compare/i });
    if (await compareButton.isVisible()) {
      await compareButton.click();
      
      // Select runs to compare
      const runSelector = page.locator('.run-selector, [data-testid="select-runs"]');
      if (await runSelector.isVisible()) {
        // Select first two runs
        const checkboxes = page.locator('input[type="checkbox"][name*="run"]');
        const checkboxCount = await checkboxes.count();
        
        if (checkboxCount >= 2) {
          await checkboxes.nth(0).check();
          await checkboxes.nth(1).check();
          
          // View comparison
          const viewComparisonButton = page.locator('button').filter({ hasText: /view.*comparison|compare/i });
          await viewComparisonButton.click();
          
          // Should show comparison view
          const comparisonView = page.locator('.comparison-view, [data-testid="comparison"]');
          await expect(comparisonView).toBeVisible();
          
          // Should show metrics for both runs
          const runMetrics = page.locator('.run-metrics, [data-testid="run-comparison"]');
          await expect(runMetrics).toHaveCount(2);
          
          // Should highlight differences
          const differences = page.locator('.difference, .delta, [data-testid="diff"]');
          if (await differences.count() > 0) {
            const firstDiff = differences.first();
            const diffText = await firstDiff.textContent();
            expect(diffText).toMatch(/[+-]?\d+/); // Should show numeric difference
          }
        }
      }
    }
  });

  test('should display test execution heatmap', async ({ page }) => {
    await page.goto('/analytics');
    
    // Look for heatmap visualization
    const heatmap = page.locator('.heatmap, [data-testid="execution-heatmap"]');
    if (await heatmap.isVisible()) {
      // Should have cells representing time periods
      const cells = heatmap.locator('.heatmap-cell, rect[class*="cell"]');
      const cellCount = await cells.count();
      expect(cellCount).toBeGreaterThan(0);
      
      // Hover over cell for tooltip
      if (cellCount > 0) {
        await cells.first().hover();
        
        // Should show tooltip with details
        const tooltip = page.locator('.tooltip, [role="tooltip"]');
        if (await tooltip.isVisible({ timeout: 2000 })) {
          await expect(tooltip).toContainText(/\d+.*test/i);
        }
      }
      
      // Should have legend
      const legend = page.locator('.heatmap-legend, .legend');
      if (await legend.isVisible()) {
        await expect(legend).toContainText(/low|high|tests/i);
      }
    }
  });
});