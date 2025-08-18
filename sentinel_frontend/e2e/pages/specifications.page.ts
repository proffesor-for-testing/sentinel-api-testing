import { Page, Locator } from '@playwright/test';

export class SpecificationsPage {
  readonly page: Page;
  readonly pageTitle: Locator;
  readonly uploadButton: Locator;
  readonly specNameInput: Locator;
  readonly specDescriptionInput: Locator;
  readonly specFileInput: Locator;
  readonly specContentTextarea: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;
  readonly specsList: Locator;
  readonly searchInput: Locator;
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;
    this.pageTitle = page.locator('h1').filter({ hasText: /specifications/i });
    this.uploadButton = page.locator('button').filter({ hasText: /upload|add.*spec/i });
    this.specNameInput = page.locator('input[name="name"], input[placeholder*="name"]');
    this.specDescriptionInput = page.locator('textarea[name="description"], input[name="description"]');
    this.specFileInput = page.locator('input[type="file"]');
    this.specContentTextarea = page.locator('textarea[name="spec_content"], textarea[name="content"]');
    this.saveButton = page.locator('button').filter({ hasText: /save|submit|upload/i });
    this.cancelButton = page.locator('button').filter({ hasText: /cancel/i });
    this.specsList = page.locator('.specs-list, table, [data-testid="specs-list"]');
    this.searchInput = page.locator('input[type="search"], input[placeholder*="search"]');
    this.successMessage = page.locator('.success-message, .alert-success');
    this.errorMessage = page.locator('.error-message, .alert-danger');
  }

  async goto() {
    await this.page.goto('/specifications');
    await this.page.waitForLoadState('networkidle');
  }

  async uploadSpecification(name: string, description: string, content: object) {
    await this.uploadButton.click();
    
    // Fill in specification details
    await this.specNameInput.fill(name);
    await this.specDescriptionInput.fill(description);
    
    // If there's a JSON content textarea, use it
    if (await this.specContentTextarea.isVisible()) {
      await this.specContentTextarea.fill(JSON.stringify(content, null, 2));
    }
    
    await this.saveButton.click();
    
    // Wait for success message or navigation
    await Promise.race([
      this.successMessage.waitFor({ state: 'visible', timeout: 5000 }),
      this.page.waitForURL('**/specifications', { timeout: 5000 })
    ]);
  }

  async uploadSpecificationFile(name: string, description: string, filePath: string) {
    await this.uploadButton.click();
    
    await this.specNameInput.fill(name);
    await this.specDescriptionInput.fill(description);
    
    // Upload file
    await this.specFileInput.setInputFiles(filePath);
    
    await this.saveButton.click();
    
    // Wait for success
    await this.successMessage.waitFor({ state: 'visible', timeout: 5000 });
  }

  async searchSpecifications(query: string) {
    await this.searchInput.fill(query);
    await this.page.keyboard.press('Enter');
    await this.page.waitForLoadState('networkidle');
  }

  async getSpecificationsList(): Promise<Array<{name: string, description: string}>> {
    const specs: Array<{name: string, description: string}> = [];
    const rows = await this.specsList.locator('tr, .spec-item').all();
    
    for (const row of rows) {
      const name = await row.locator('.spec-name, td:first-child').textContent();
      const description = await row.locator('.spec-description, td:nth-child(2)').textContent();
      
      if (name) {
        specs.push({
          name: name.trim(),
          description: description?.trim() || ''
        });
      }
    }
    
    return specs;
  }

  async selectSpecification(name: string) {
    const specRow = this.specsList.locator(`text="${name}"`).first();
    await specRow.click();
    await this.page.waitForLoadState('networkidle');
  }

  async deleteSpecification(name: string) {
    const specRow = this.specsList.locator(`tr:has-text("${name}"), .spec-item:has-text("${name}")`);
    const deleteButton = specRow.locator('button').filter({ hasText: /delete|remove/i });
    await deleteButton.click();
    
    // Confirm deletion if dialog appears
    const confirmButton = this.page.locator('button').filter({ hasText: /confirm|yes/i });
    if (await confirmButton.isVisible({ timeout: 1000 })) {
      await confirmButton.click();
    }
    
    await this.successMessage.waitFor({ state: 'visible', timeout: 5000 });
  }
}