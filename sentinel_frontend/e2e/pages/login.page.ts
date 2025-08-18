import { Page, Locator } from '@playwright/test';

export class LoginPage {
  readonly page: Page;
  readonly emailInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly errorMessage: Locator;
  readonly forgotPasswordLink: Locator;

  constructor(page: Page) {
    this.page = page;
    this.emailInput = page.locator('input[name="email"]');
    this.passwordInput = page.locator('input[name="password"]');
    this.loginButton = page.locator('button[type="submit"]').filter({ hasText: /log\s*in/i });
    this.errorMessage = page.locator('.error-message, .alert-danger');
    this.forgotPasswordLink = page.locator('a', { hasText: /forgot password/i });
  }

  async goto() {
    await this.page.goto('/login');
    await this.page.waitForLoadState('networkidle');
  }

  async login(email: string, password: string) {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.loginButton.click();
    
    // Wait for either navigation or error message
    await Promise.race([
      this.page.waitForURL('**/dashboard', { timeout: 5000 }).catch(() => {}),
      this.errorMessage.waitFor({ state: 'visible', timeout: 5000 }).catch(() => {})
    ]);
  }

  async getErrorMessage(): Promise<string | null> {
    if (await this.errorMessage.isVisible()) {
      return await this.errorMessage.textContent();
    }
    return null;
  }

  async isLoggedIn(): Promise<boolean> {
    // Check if redirected to dashboard or has auth token
    return this.page.url().includes('/dashboard') || 
           await this.page.evaluate(() => !!localStorage.getItem('access_token'));
  }
}