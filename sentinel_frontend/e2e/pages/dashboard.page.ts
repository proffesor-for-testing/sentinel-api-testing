import { Page, Locator } from '@playwright/test';

export class DashboardPage {
  readonly page: Page;
  readonly welcomeMessage: Locator;
  readonly statsCards: Locator;
  readonly recentTestRuns: Locator;
  readonly quickActionsSection: Locator;
  readonly newTestButton: Locator;
  readonly uploadSpecButton: Locator;
  readonly viewReportsButton: Locator;
  readonly userMenu: Locator;
  readonly logoutButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.welcomeMessage = page.locator('h1, h2').filter({ hasText: /welcome|dashboard/i });
    this.statsCards = page.locator('.stats-card, .metric-card, [data-testid="stats-card"]');
    this.recentTestRuns = page.locator('[data-testid="recent-runs"], .recent-runs');
    this.quickActionsSection = page.locator('.quick-actions, [data-testid="quick-actions"]');
    this.newTestButton = page.locator('button, a').filter({ hasText: /new test|create test/i });
    this.uploadSpecButton = page.locator('button, a').filter({ hasText: /upload.*spec|add.*spec/i });
    this.viewReportsButton = page.locator('button, a').filter({ hasText: /view reports|reports/i });
    this.userMenu = page.locator('[data-testid="user-menu"], .user-menu, .user-dropdown');
    this.logoutButton = page.locator('button, a').filter({ hasText: /log\s*out|sign\s*out/i });
  }

  async goto() {
    await this.page.goto('/dashboard');
    await this.page.waitForLoadState('networkidle');
  }

  async waitForDashboardLoad() {
    await this.welcomeMessage.waitFor({ state: 'visible' });
    await this.page.waitForLoadState('networkidle');
  }

  async getStatistics(): Promise<{ [key: string]: string }> {
    const stats: { [key: string]: string } = {};
    const cards = await this.statsCards.all();
    
    for (const card of cards) {
      const label = await card.locator('.label, .title, h3, h4').textContent();
      const value = await card.locator('.value, .number, .count').textContent();
      if (label && value) {
        stats[label.trim()] = value.trim();
      }
    }
    
    return stats;
  }

  async getRecentTestRuns(): Promise<string[]> {
    const runs = await this.recentTestRuns.locator('.run-item, tr, li').all();
    const runNames: string[] = [];
    
    for (const run of runs) {
      const name = await run.textContent();
      if (name) {
        runNames.push(name.trim());
      }
    }
    
    return runNames;
  }

  async navigateToNewTest() {
    await this.newTestButton.click();
    await this.page.waitForURL('**/test-runs/new', { timeout: 5000 });
  }

  async navigateToSpecUpload() {
    await this.uploadSpecButton.click();
    await this.page.waitForURL('**/specifications/new', { timeout: 5000 });
  }

  async logout() {
    await this.userMenu.click();
    await this.logoutButton.click();
    await this.page.waitForURL('**/login', { timeout: 5000 });
  }
}