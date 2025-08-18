import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { DashboardPage } from '../pages/dashboard.page';
import { testUsers } from '../fixtures/test-data';

test.describe('Authentication Flow', () => {
  let loginPage: LoginPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    dashboardPage = new DashboardPage(page);
  });

  test('should login successfully with valid credentials', async ({ page }) => {
    await loginPage.goto();
    
    // Verify login page is loaded
    await expect(page).toHaveTitle(/sentinel|login/i);
    
    // Login with admin credentials
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    
    // Verify successful login
    await expect(page).toHaveURL(/.*dashboard/);
    await dashboardPage.waitForDashboardLoad();
    
    // Verify welcome message is displayed
    await expect(dashboardPage.welcomeMessage).toBeVisible();
  });

  test('should show error message with invalid credentials', async ({ page }) => {
    await loginPage.goto();
    
    // Try to login with invalid credentials
    await loginPage.login('invalid@email.com', 'wrongpassword');
    
    // Verify error message is displayed
    const errorMessage = await loginPage.getErrorMessage();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage).toMatch(/invalid|incorrect|failed/i);
    
    // Verify still on login page
    await expect(page).toHaveURL(/.*login/);
  });

  test('should enforce role-based access control', async ({ page }) => {
    // Test admin access
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await dashboardPage.waitForDashboardLoad();
    
    // Admin should see all menu items
    await expect(page.locator('nav, .sidebar')).toContainText('Users');
    await expect(page.locator('nav, .sidebar')).toContainText('Specifications');
    await expect(page.locator('nav, .sidebar')).toContainText('Test Runs');
    
    // Logout
    await dashboardPage.logout();
    
    // Test viewer access
    await loginPage.login(testUsers.viewer.email, testUsers.viewer.password);
    await dashboardPage.waitForDashboardLoad();
    
    // Viewer should not see Users menu
    await expect(page.locator('nav, .sidebar')).not.toContainText('Users');
  });

  test('should logout successfully', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await dashboardPage.waitForDashboardLoad();
    
    // Logout
    await dashboardPage.logout();
    
    // Verify redirected to login page
    await expect(page).toHaveURL(/.*login/);
    
    // Try to access dashboard directly
    await page.goto('/dashboard');
    
    // Should redirect to login
    await expect(page).toHaveURL(/.*login/);
  });

  test('should persist login session', async ({ page, context }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await dashboardPage.waitForDashboardLoad();
    
    // Get cookies/storage
    const cookies = await context.cookies();
    const hasAuthCookie = cookies.some(c => c.name.includes('token') || c.name.includes('session'));
    
    // Check localStorage for token
    const hasToken = await page.evaluate(() => {
      return !!localStorage.getItem('access_token') || !!sessionStorage.getItem('access_token');
    });
    
    expect(hasAuthCookie || hasToken).toBeTruthy();
    
    // Navigate to another page and back
    await page.goto('/specifications');
    await page.goto('/dashboard');
    
    // Should still be logged in
    await expect(dashboardPage.welcomeMessage).toBeVisible();
  });

  test('should handle concurrent login sessions', async ({ browser }) => {
    // Create two browser contexts
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    
    const page1 = await context1.newPage();
    const page2 = await context2.newPage();
    
    const loginPage1 = new LoginPage(page1);
    const loginPage2 = new LoginPage(page2);
    
    // Login in both contexts
    await loginPage1.goto();
    await loginPage1.login(testUsers.admin.email, testUsers.admin.password);
    
    await loginPage2.goto();
    await loginPage2.login(testUsers.tester.email, testUsers.tester.password);
    
    // Both should be logged in
    await expect(page1).toHaveURL(/.*dashboard/);
    await expect(page2).toHaveURL(/.*dashboard/);
    
    // Clean up
    await context1.close();
    await context2.close();
  });
});