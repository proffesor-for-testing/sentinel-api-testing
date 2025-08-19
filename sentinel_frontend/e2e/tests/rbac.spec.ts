import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { DashboardPage } from '../pages/dashboard.page';
import { testUsers } from '../fixtures/test-data';

test.describe('Role-Based Access Control (RBAC)', () => {
  let loginPage: LoginPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    dashboardPage = new DashboardPage(page);
  });

  test('admin should have full access to all features', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await dashboardPage.waitForDashboardLoad();
    
    // Check navigation menu items
    const navMenu = page.locator('nav, .sidebar, [role="navigation"]');
    
    // Admin should see all menu items
    await expect(navMenu).toContainText('Dashboard');
    await expect(navMenu).toContainText('Specifications');
    await expect(navMenu).toContainText('Test Runs');
    await expect(navMenu).toContainText('Analytics');
    await expect(navMenu).toContainText('Users');
    await expect(navMenu).toContainText('Settings');
    
    // Test access to Users management
    await page.goto('/users');
    await expect(page).not.toHaveURL(/unauthorized|403|login/);
    await expect(page.locator('h1, .page-title')).toContainText(/users|management/i);
    
    // Should see user management actions
    const addUserButton = page.locator('button').filter({ hasText: /add.*user|new.*user/i });
    await expect(addUserButton).toBeVisible();
    
    // Should see user list with actions
    const userActions = page.locator('.user-actions, [data-testid="user-actions"]');
    if (await userActions.count() > 0) {
      const firstUserActions = userActions.first();
      await expect(firstUserActions).toContainText(/edit|delete/i);
    }
    
    // Test access to Settings
    await page.goto('/settings');
    await expect(page).not.toHaveURL(/unauthorized|403/);
    
    // Should see system settings
    const systemSettings = page.locator('.system-settings, [data-testid="system"]');
    await expect(systemSettings).toBeVisible();
  });

  test('manager should have limited administrative access', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.manager.email, testUsers.manager.password);
    await dashboardPage.waitForDashboardLoad();
    
    const navMenu = page.locator('nav, .sidebar, [role="navigation"]');
    
    // Manager should see most menu items
    await expect(navMenu).toContainText('Dashboard');
    await expect(navMenu).toContainText('Specifications');
    await expect(navMenu).toContainText('Test Runs');
    await expect(navMenu).toContainText('Analytics');
    
    // Should NOT see Users management
    await expect(navMenu).not.toContainText('Users');
    
    // Test specifications management
    await page.goto('/specifications');
    await expect(page).not.toHaveURL(/unauthorized|403/);
    
    // Should be able to create/edit specifications
    const uploadButton = page.locator('button').filter({ hasText: /upload|new.*spec/i });
    await expect(uploadButton).toBeVisible();
    
    // Test restricted access to Users
    await page.goto('/users');
    // Should be redirected or show unauthorized
    await expect(page).toHaveURL(/unauthorized|403|dashboard/);
  });

  test('tester should have operational access only', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.tester.email, testUsers.tester.password);
    await dashboardPage.waitForDashboardLoad();
    
    const navMenu = page.locator('nav, .sidebar, [role="navigation"]');
    
    // Tester should see operational menu items
    await expect(navMenu).toContainText('Dashboard');
    await expect(navMenu).toContainText('Specifications');
    await expect(navMenu).toContainText('Test Runs');
    
    // Should NOT see administrative items
    await expect(navMenu).not.toContainText('Users');
    await expect(navMenu).not.toContainText('Settings');
    
    // Test creating test runs
    await page.goto('/test-runs');
    const newTestButton = page.locator('button').filter({ hasText: /new test|create test/i });
    await expect(newTestButton).toBeVisible();
    
    // Test specifications - can view but limited edit
    await page.goto('/specifications');
    
    // Should see specifications
    const specsList = page.locator('.specifications-list, [data-testid="specs"]');
    await expect(specsList).toBeVisible();
    
    // Check if delete is restricted
    const deleteButtons = page.locator('button').filter({ hasText: /delete/i });
    const deleteCount = await deleteButtons.count();
    
    // Tester might have limited delete permissions
    if (deleteCount > 0) {
      // Try to delete
      await deleteButtons.first().click();
      
      // Might show permission error
      const errorMessage = page.locator('.error, .permission-denied');
      if (await errorMessage.isVisible({ timeout: 2000 })) {
        await expect(errorMessage).toContainText(/permission|authorized|cannot/i);
      }
    }
  });

  test('viewer should have read-only access', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login(testUsers.viewer.email, testUsers.viewer.password);
    await dashboardPage.waitForDashboardLoad();
    
    const navMenu = page.locator('nav, .sidebar, [role="navigation"]');
    
    // Viewer should see limited menu items
    await expect(navMenu).toContainText('Dashboard');
    await expect(navMenu).toContainText('Analytics');
    
    // Should NOT see action items
    await expect(navMenu).not.toContainText('Users');
    await expect(navMenu).not.toContainText('Settings');
    
    // Test read-only access to specifications
    await page.goto('/specifications');
    
    // Should NOT see upload/create buttons
    const uploadButton = page.locator('button').filter({ hasText: /upload|new|create/i });
    expect(await uploadButton.count()).toBe(0);
    
    // Should NOT see edit/delete buttons
    const editButtons = page.locator('button').filter({ hasText: /edit/i });
    const deleteButtons = page.locator('button').filter({ hasText: /delete/i });
    expect(await editButtons.count()).toBe(0);
    expect(await deleteButtons.count()).toBe(0);
    
    // Test read-only access to test runs
    await page.goto('/test-runs');
    
    // Should NOT see create button
    const newTestButton = page.locator('button').filter({ hasText: /new test|create/i });
    expect(await newTestButton.count()).toBe(0);
    
    // Can view test run details
    const testRunRows = page.locator('tr, .test-run-item');
    if (await testRunRows.count() > 0) {
      await testRunRows.first().click();
      
      // Should see details but no action buttons
      await expect(page.locator('.test-details, [data-testid="details"]')).toBeVisible();
      
      // Should NOT see execute button
      const executeButton = page.locator('button').filter({ hasText: /execute|run/i });
      expect(await executeButton.count()).toBe(0);
    }
  });

  test('should enforce field-level permissions', async ({ page }) => {
    // Test as manager
    await loginPage.goto();
    await loginPage.login(testUsers.manager.email, testUsers.manager.password);
    await page.goto('/settings');
    
    if (!page.url().includes('unauthorized')) {
      // Manager might have limited settings access
      const sensitiveFields = page.locator('input[name*="api_key"], input[name*="secret"]');
      
      if (await sensitiveFields.count() > 0) {
        // Sensitive fields might be read-only or hidden
        const firstField = sensitiveFields.first();
        const isDisabled = await firstField.isDisabled();
        const isReadonly = await firstField.getAttribute('readonly');
        
        expect(isDisabled || isReadonly).toBeTruthy();
      }
    }
  });

  test('should handle permission changes dynamically', async ({ page }) => {
    // Login as admin
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    
    // Navigate to users management
    await page.goto('/users');
    
    // Find a user to modify (not self)
    const userRows = page.locator('.user-row, tr').filter({ hasNotText: testUsers.admin.email });
    
    if (await userRows.count() > 0) {
      const firstUser = userRows.first();
      const editButton = firstUser.locator('button').filter({ hasText: /edit/i });
      
      if (await editButton.isVisible()) {
        await editButton.click();
        
        // Change user role
        const roleSelect = page.locator('select[name="role"], [data-testid="role-select"]');
        if (await roleSelect.isVisible()) {
          const currentRole = await roleSelect.inputValue();
          const newRole = currentRole === 'viewer' ? 'tester' : 'viewer';
          
          await roleSelect.selectOption(newRole);
          
          // Save changes
          const saveButton = page.locator('button').filter({ hasText: /save|update/i });
          await saveButton.click();
          
          // Verify success message
          const successMessage = page.locator('.success, .alert-success');
          await expect(successMessage).toBeVisible();
          await expect(successMessage).toContainText(/updated|saved|success/i);
        }
      }
    }
  });

  test('should audit permission-related actions', async ({ page }) => {
    // Login as admin
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    
    // Navigate to audit log if available
    await page.goto('/settings');
    
    const auditTab = page.locator('button, [role="tab"]').filter({ hasText: /audit|log|activity/i });
    if (await auditTab.isVisible()) {
      await auditTab.click();
      
      // Should show audit entries
      const auditEntries = page.locator('.audit-entry, [data-testid="audit-log"]');
      await expect(auditEntries.first()).toBeVisible();
      
      // Should show permission-related events
      const permissionEvents = auditEntries.filter({ hasText: /permission|role|access/i });
      if (await permissionEvents.count() > 0) {
        const firstEvent = permissionEvents.first();
        
        // Should show user, action, and timestamp
        await expect(firstEvent).toContainText(/admin|user/i);
        await expect(firstEvent).toContainText(/\d{4}-\d{2}-\d{2}|\d+.*ago/i);
      }
    }
  });

  test('should handle API key permissions correctly', async ({ page }) => {
    // Test with different roles
    const rolesToTest = [
      { user: testUsers.admin, canManageKeys: true },
      { user: testUsers.manager, canManageKeys: true },
      { user: testUsers.tester, canManageKeys: false },
      { user: testUsers.viewer, canManageKeys: false }
    ];
    
    for (const roleTest of rolesToTest) {
      // Login as user
      await loginPage.goto();
      await loginPage.login(roleTest.user.email, roleTest.user.password);
      
      // Navigate to API keys section
      await page.goto('/settings/api-keys');
      
      if (roleTest.canManageKeys) {
        // Should see API key management
        await expect(page).not.toHaveURL(/unauthorized|403/);
        
        const generateButton = page.locator('button').filter({ hasText: /generate.*key|new.*key/i });
        await expect(generateButton).toBeVisible();
        
        // Should see existing keys (masked)
        const apiKeys = page.locator('.api-key, [data-testid="api-key"]');
        if (await apiKeys.count() > 0) {
          const firstKey = await apiKeys.first().textContent();
          expect(firstKey).toMatch(/\*{4,}|hidden|masked/i);
        }
      } else {
        // Should be denied access
        await expect(page).toHaveURL(/unauthorized|403|dashboard/);
      }
      
      // Logout for next iteration
      await dashboardPage.logout();
    }
  });

  test('should enforce data visibility based on role', async ({ page }) => {
    // Login as viewer
    await loginPage.goto();
    await loginPage.login(testUsers.viewer.email, testUsers.viewer.password);
    
    // Navigate to analytics
    await page.goto('/analytics');
    
    // Viewer should see aggregated data only
    const detailedData = page.locator('.detailed-data, [data-testid="raw-data"]');
    const aggregatedData = page.locator('.aggregated-data, [data-testid="summary"]');
    
    // Should see summary
    await expect(aggregatedData).toBeVisible();
    
    // Should NOT see detailed/raw data
    expect(await detailedData.count()).toBe(0);
    
    // Try to access detailed view
    const detailButton = page.locator('button').filter({ hasText: /detail|raw|full/i });
    if (await detailButton.count() > 0) {
      await detailButton.first().click();
      
      // Should show permission error or be disabled
      const errorMessage = page.locator('.error, .permission-denied');
      if (await errorMessage.isVisible({ timeout: 2000 })) {
        await expect(errorMessage).toContainText(/permission|access|authorized/i);
      }
    }
    
    // Logout and login as admin
    await dashboardPage.logout();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await page.goto('/analytics');
    
    // Admin should see all data
    const adminDetailButton = page.locator('button').filter({ hasText: /detail|raw|full/i });
    if (await adminDetailButton.count() > 0) {
      await adminDetailButton.first().click();
      
      // Should see detailed data
      const detailedView = page.locator('.detailed-view, [data-testid="detailed"]');
      await expect(detailedView).toBeVisible();
    }
  });
});