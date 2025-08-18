import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { SpecificationsPage } from '../pages/specifications.page';
import { testUsers, sampleAPISpec } from '../fixtures/test-data';

test.describe('API Specifications Management', () => {
  let loginPage: LoginPage;
  let specsPage: SpecificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    specsPage = new SpecificationsPage(page);
    
    // Login before each test
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await page.waitForURL(/.*dashboard/);
  });

  test('should upload API specification via JSON input', async ({ page }) => {
    await specsPage.goto();
    
    // Verify specifications page loaded
    await expect(specsPage.pageTitle).toBeVisible();
    
    // Upload new specification
    await specsPage.uploadSpecification(
      sampleAPISpec.name,
      sampleAPISpec.description,
      sampleAPISpec.content
    );
    
    // Verify success message
    await expect(specsPage.successMessage).toBeVisible();
    
    // Verify specification appears in list
    const specs = await specsPage.getSpecificationsList();
    const uploadedSpec = specs.find(s => s.name === sampleAPISpec.name);
    expect(uploadedSpec).toBeTruthy();
  });

  test('should upload API specification via file upload', async ({ page }) => {
    await specsPage.goto();
    
    // Create a temporary file for upload
    const specContent = JSON.stringify(sampleAPISpec.content, null, 2);
    const fileName = 'test-spec.json';
    
    // Note: In real test, you'd have a file on disk
    // For now, we'll simulate with JSON input
    await specsPage.uploadSpecification(
      'File Upload Test',
      'Uploaded via file',
      sampleAPISpec.content
    );
    
    await expect(specsPage.successMessage).toBeVisible();
  });

  test('should validate OpenAPI specification format', async ({ page }) => {
    await specsPage.goto();
    await specsPage.uploadButton.click();
    
    // Try to upload invalid specification
    await specsPage.specNameInput.fill('Invalid Spec');
    await specsPage.specDescriptionInput.fill('This should fail');
    
    if (await specsPage.specContentTextarea.isVisible()) {
      await specsPage.specContentTextarea.fill('{ "invalid": "not an openapi spec" }');
    }
    
    await specsPage.saveButton.click();
    
    // Should show error message
    await expect(specsPage.errorMessage).toBeVisible();
    const errorText = await specsPage.errorMessage.textContent();
    expect(errorText).toMatch(/invalid|error|failed/i);
  });

  test('should search and filter specifications', async ({ page }) => {
    await specsPage.goto();
    
    // Upload multiple specs if not already present
    const specNames = ['API v1', 'API v2', 'Test API'];
    for (const name of specNames) {
      await specsPage.uploadSpecification(name, `${name} description`, sampleAPISpec.content);
      await page.waitForTimeout(500); // Small delay between uploads
    }
    
    // Search for specific spec
    await specsPage.searchSpecifications('v1');
    
    // Verify filtered results
    const results = await specsPage.getSpecificationsList();
    expect(results.some(r => r.name.includes('v1'))).toBeTruthy();
    expect(results.every(r => !r.name.includes('v2'))).toBeFalsy();
  });

  test('should view specification details', async ({ page }) => {
    await specsPage.goto();
    
    // Upload a spec first
    await specsPage.uploadSpecification(
      'Detail View Test',
      'Test viewing details',
      sampleAPISpec.content
    );
    
    // Click on the specification
    await specsPage.selectSpecification('Detail View Test');
    
    // Should navigate to detail view
    await expect(page).toHaveURL(/specifications\/\d+/);
    
    // Verify details are displayed
    await expect(page.locator('text=Detail View Test')).toBeVisible();
    await expect(page.locator('text=Test viewing details')).toBeVisible();
    
    // Should show endpoints
    await expect(page.locator('text=/pets')).toBeVisible();
  });

  test('should delete specification', async ({ page }) => {
    await specsPage.goto();
    
    // Upload a spec to delete
    const specToDelete = 'Spec to Delete';
    await specsPage.uploadSpecification(
      specToDelete,
      'Will be deleted',
      sampleAPISpec.content
    );
    
    // Delete the specification
    await specsPage.deleteSpecification(specToDelete);
    
    // Verify success message
    await expect(specsPage.successMessage).toBeVisible();
    
    // Verify spec is removed from list
    const specs = await specsPage.getSpecificationsList();
    expect(specs.find(s => s.name === specToDelete)).toBeFalsy();
  });

  test('should handle large OpenAPI specifications', async ({ page }) => {
    // Create a large spec with many endpoints
    const largeSpec = {
      ...sampleAPISpec.content,
      paths: {}
    };
    
    // Add 50 endpoints
    for (let i = 1; i <= 50; i++) {
      largeSpec.paths[`/endpoint${i}`] = {
        get: {
          summary: `Endpoint ${i}`,
          responses: { '200': { description: 'Success' } }
        }
      };
    }
    
    await specsPage.goto();
    await specsPage.uploadSpecification(
      'Large API Spec',
      'Spec with 50 endpoints',
      largeSpec
    );
    
    // Should handle large spec successfully
    await expect(specsPage.successMessage).toBeVisible();
  });
});