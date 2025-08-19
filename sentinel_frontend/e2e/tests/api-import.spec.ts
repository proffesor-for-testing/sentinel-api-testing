import { test, expect } from '@playwright/test';
import { LoginPage } from '../pages/login.page';
import { SpecificationsPage } from '../pages/specifications.page';
import { testUsers, sampleAPISpec } from '../fixtures/test-data';

test.describe('API Import Workflows', () => {
  let loginPage: LoginPage;
  let specsPage: SpecificationsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    specsPage = new SpecificationsPage(page);
    
    // Login as admin for full access
    await loginPage.goto();
    await loginPage.login(testUsers.admin.email, testUsers.admin.password);
    await page.waitForURL(/.*dashboard/);
  });

  test('should import OpenAPI 3.0 specification', async ({ page }) => {
    await specsPage.goto();
    
    // Click import button
    const importButton = page.locator('button').filter({ hasText: /import|upload/i });
    await importButton.click();
    
    // Select OpenAPI format
    const formatSelect = page.locator('select[name="format"], [data-testid="format-select"]');
    if (await formatSelect.isVisible()) {
      await formatSelect.selectOption('openapi3');
    }
    
    // Enter spec details
    await specsPage.specNameInput.fill('OpenAPI 3.0 Test Spec');
    await specsPage.specDescriptionInput.fill('Imported OpenAPI 3.0 specification');
    
    // Paste OpenAPI 3.0 spec
    const openapi3Spec = {
      openapi: '3.0.0',
      info: {
        title: 'Sample API',
        version: '1.0.0',
        description: 'A sample API for testing'
      },
      servers: [
        { url: 'https://api.example.com/v1' }
      ],
      paths: {
        '/users': {
          get: {
            summary: 'List users',
            operationId: 'listUsers',
            responses: {
              '200': {
                description: 'Successful response',
                content: {
                  'application/json': {
                    schema: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/User' }
                    }
                  }
                }
              }
            }
          },
          post: {
            summary: 'Create user',
            operationId: 'createUser',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/User' }
                }
              }
            },
            responses: {
              '201': { description: 'User created' }
            }
          }
        }
      },
      components: {
        schemas: {
          User: {
            type: 'object',
            properties: {
              id: { type: 'integer' },
              name: { type: 'string' },
              email: { type: 'string', format: 'email' }
            }
          }
        }
      }
    };
    
    await specsPage.specContentTextarea.fill(JSON.stringify(openapi3Spec, null, 2));
    
    // Save specification
    await specsPage.saveButton.click();
    
    // Verify successful import
    await expect(specsPage.successMessage).toBeVisible();
    await expect(specsPage.successMessage).toContainText(/imported|saved|success/i);
    
    // Verify spec appears in list
    const specs = await specsPage.getSpecificationsList();
    const imported = specs.find(s => s.name === 'OpenAPI 3.0 Test Spec');
    expect(imported).toBeTruthy();
  });

  test('should import Swagger 2.0 specification', async ({ page }) => {
    await specsPage.goto();
    await specsPage.uploadButton.click();
    
    // Select Swagger 2.0 format
    const formatSelect = page.locator('select[name="format"], [data-testid="format-select"]');
    if (await formatSelect.isVisible()) {
      await formatSelect.selectOption('swagger2');
    }
    
    // Swagger 2.0 spec
    const swagger2Spec = {
      swagger: '2.0',
      info: {
        title: 'Swagger 2.0 API',
        version: '1.0.0',
        description: 'Legacy Swagger specification'
      },
      host: 'api.example.com',
      basePath: '/v1',
      schemes: ['https'],
      paths: {
        '/products': {
          get: {
            summary: 'List products',
            produces: ['application/json'],
            responses: {
              200: {
                description: 'Successful response',
                schema: {
                  type: 'array',
                  items: { $ref: '#/definitions/Product' }
                }
              }
            }
          }
        }
      },
      definitions: {
        Product: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            name: { type: 'string' },
            price: { type: 'number' }
          }
        }
      }
    };
    
    await specsPage.specNameInput.fill('Swagger 2.0 Import');
    await specsPage.specDescriptionInput.fill('Converted from Swagger 2.0');
    await specsPage.specContentTextarea.fill(JSON.stringify(swagger2Spec, null, 2));
    
    await specsPage.saveButton.click();
    
    // Should handle conversion
    await expect(specsPage.successMessage).toBeVisible();
    
    // May show conversion notice
    const conversionNotice = page.locator('.conversion-notice, [data-testid="conversion"]');
    if (await conversionNotice.isVisible()) {
      await expect(conversionNotice).toContainText(/converted|swagger.*2/i);
    }
  });

  test('should import specification from URL', async ({ page }) => {
    await specsPage.goto();
    
    // Look for import from URL option
    const importFromUrlButton = page.locator('button').filter({ hasText: /import.*url|fetch/i });
    if (await importFromUrlButton.isVisible()) {
      await importFromUrlButton.click();
      
      // Enter URL
      const urlInput = page.locator('input[name="spec_url"], [placeholder*="url"]');
      await urlInput.fill('https://petstore.swagger.io/v2/swagger.json');
      
      // Fetch specification
      const fetchButton = page.locator('button').filter({ hasText: /fetch|load|import/i });
      await fetchButton.click();
      
      // Wait for fetch
      await expect(page.locator('.loading, .fetching')).toBeVisible();
      
      // Should populate form with fetched data
      await expect(specsPage.specContentTextarea).not.toBeEmpty({ timeout: 10000 });
      
      // Set name if not auto-populated
      if (await specsPage.specNameInput.inputValue() === '') {
        await specsPage.specNameInput.fill('Petstore API (Imported)');
      }
      
      // Save imported spec
      await specsPage.saveButton.click();
      await expect(specsPage.successMessage).toBeVisible();
    }
  });

  test('should validate and fix common import errors', async ({ page }) => {
    await specsPage.goto();
    await specsPage.uploadButton.click();
    
    // Try to import spec with errors
    const invalidSpec = {
      openapi: '3.0.0',
      info: {
        title: 'Invalid Spec'
        // Missing required 'version' field
      },
      paths: {
        '/users': {
          get: {
            // Missing responses
          }
        }
      }
    };
    
    await specsPage.specNameInput.fill('Invalid Spec Test');
    await specsPage.specContentTextarea.fill(JSON.stringify(invalidSpec, null, 2));
    
    await specsPage.saveButton.click();
    
    // Should show validation errors
    const validationErrors = page.locator('.validation-errors, [data-testid="errors"]');
    await expect(validationErrors).toBeVisible();
    await expect(validationErrors).toContainText(/version|required|missing/i);
    
    // Look for auto-fix option
    const autoFixButton = page.locator('button').filter({ hasText: /fix|repair|auto/i });
    if (await autoFixButton.isVisible()) {
      await autoFixButton.click();
      
      // Should attempt to fix errors
      await expect(page.locator('.fixing, .processing')).toBeVisible();
      
      // Check if errors were fixed
      const fixedNotice = page.locator('.fixed-notice, [data-testid="fixed"]');
      if (await fixedNotice.isVisible()) {
        await expect(fixedNotice).toContainText(/fixed|repaired|corrected/i);
        
        // Try saving again
        await specsPage.saveButton.click();
        await expect(specsPage.successMessage).toBeVisible();
      }
    }
  });

  test('should import Postman collection', async ({ page }) => {
    await specsPage.goto();
    
    // Look for Postman import option
    const postmanImportButton = page.locator('button').filter({ hasText: /postman|collection/i });
    if (await postmanImportButton.isVisible()) {
      await postmanImportButton.click();
      
      // Postman collection format
      const postmanCollection = {
        info: {
          name: 'Sample Collection',
          schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
        },
        item: [
          {
            name: 'Get Users',
            request: {
              method: 'GET',
              url: {
                raw: 'https://api.example.com/users',
                protocol: 'https',
                host: ['api', 'example', 'com'],
                path: ['users']
              }
            }
          },
          {
            name: 'Create User',
            request: {
              method: 'POST',
              url: 'https://api.example.com/users',
              body: {
                mode: 'raw',
                raw: '{"name": "John", "email": "john@example.com"}'
              }
            }
          }
        ]
      };
      
      const collectionInput = page.locator('textarea[name="collection"], [data-testid="postman-json"]');
      await collectionInput.fill(JSON.stringify(postmanCollection, null, 2));
      
      // Convert to OpenAPI
      const convertButton = page.locator('button').filter({ hasText: /convert|import/i });
      await convertButton.click();
      
      // Should show conversion progress
      await expect(page.locator('.converting')).toBeVisible();
      
      // Should generate OpenAPI spec
      await expect(specsPage.specContentTextarea).not.toBeEmpty({ timeout: 10000 });
      
      // Set name for converted spec
      await specsPage.specNameInput.fill('Converted Postman Collection');
      
      // Save converted spec
      await specsPage.saveButton.click();
      await expect(specsPage.successMessage).toBeVisible();
    }
  });

  test('should handle GraphQL schema import', async ({ page }) => {
    await specsPage.goto();
    
    // Look for GraphQL import
    const graphqlButton = page.locator('button').filter({ hasText: /graphql/i });
    if (await graphqlButton.isVisible()) {
      await graphqlButton.click();
      
      // GraphQL schema
      const graphqlSchema = `
        type Query {
          users: [User!]!
          user(id: ID!): User
        }
        
        type Mutation {
          createUser(input: CreateUserInput!): User!
          updateUser(id: ID!, input: UpdateUserInput!): User!
        }
        
        type User {
          id: ID!
          name: String!
          email: String!
          posts: [Post!]!
        }
        
        type Post {
          id: ID!
          title: String!
          content: String!
          author: User!
        }
        
        input CreateUserInput {
          name: String!
          email: String!
        }
        
        input UpdateUserInput {
          name: String
          email: String
        }
      `;
      
      const schemaInput = page.locator('textarea[name="graphql_schema"], [data-testid="graphql"]');
      await schemaInput.fill(graphqlSchema);
      
      // Convert to REST-like OpenAPI
      const convertButton = page.locator('button').filter({ hasText: /convert|generate/i });
      await convertButton.click();
      
      // Should generate OpenAPI from GraphQL
      await expect(page.locator('.generating')).toBeVisible();
      
      // Check generated spec
      await expect(specsPage.specContentTextarea).not.toBeEmpty({ timeout: 10000 });
      
      // Should have GraphQL operations as REST endpoints
      const generatedSpec = await specsPage.specContentTextarea.inputValue();
      expect(generatedSpec).toContain('users');
      expect(generatedSpec).toContain('createUser');
    }
  });

  test('should support bulk import of multiple APIs', async ({ page }) => {
    await specsPage.goto();
    
    // Look for bulk import option
    const bulkImportButton = page.locator('button').filter({ hasText: /bulk|multiple/i });
    if (await bulkImportButton.isVisible()) {
      await bulkImportButton.click();
      
      // Should show bulk import interface
      const bulkImportDialog = page.locator('.bulk-import, [data-testid="bulk-import"]');
      await expect(bulkImportDialog).toBeVisible();
      
      // Add multiple API URLs or files
      const apiUrls = [
        'https://api1.example.com/openapi.json',
        'https://api2.example.com/swagger.json',
        'https://api3.example.com/spec.yaml'
      ];
      
      for (let i = 0; i < apiUrls.length; i++) {
        const urlInput = page.locator(`input[name="url_${i}"], input[placeholder*="URL"]`).nth(i);
        if (await urlInput.isVisible()) {
          await urlInput.fill(apiUrls[i]);
        }
        
        // Add another URL field if needed
        const addUrlButton = page.locator('button').filter({ hasText: /add.*url|another/i });
        if (i < apiUrls.length - 1 && await addUrlButton.isVisible()) {
          await addUrlButton.click();
        }
      }
      
      // Start bulk import
      const importAllButton = page.locator('button').filter({ hasText: /import.*all|process/i });
      await importAllButton.click();
      
      // Should show progress for each import
      const progressItems = page.locator('.import-progress-item, [data-testid="import-progress"]');
      await expect(progressItems).toHaveCount(apiUrls.length, { timeout: 10000 });
      
      // Check import results
      const successCount = await page.locator('.import-success, [data-status="success"]').count();
      const failureCount = await page.locator('.import-failed, [data-status="failed"]').count();
      
      expect(successCount + failureCount).toBe(apiUrls.length);
    }
  });

  test('should preserve API metadata during import', async ({ page }) => {
    await specsPage.goto();
    await specsPage.uploadButton.click();
    
    // Import spec with rich metadata
    const specWithMetadata = {
      openapi: '3.0.0',
      info: {
        title: 'Metadata Test API',
        version: '2.1.0',
        description: 'API with comprehensive metadata',
        termsOfService: 'https://example.com/terms',
        contact: {
          name: 'API Support',
          email: 'support@example.com',
          url: 'https://support.example.com'
        },
        license: {
          name: 'MIT',
          url: 'https://opensource.org/licenses/MIT'
        }
      },
      externalDocs: {
        description: 'Find more info here',
        url: 'https://docs.example.com'
      },
      servers: [
        {
          url: 'https://api.example.com',
          description: 'Production server'
        },
        {
          url: 'https://staging-api.example.com',
          description: 'Staging server'
        }
      ],
      tags: [
        {
          name: 'Users',
          description: 'User management operations'
        },
        {
          name: 'Products',
          description: 'Product catalog operations'
        }
      ],
      paths: {
        '/users': {
          get: {
            tags: ['Users'],
            summary: 'List all users',
            responses: {
              '200': { description: 'Success' }
            }
          }
        }
      }
    };
    
    await specsPage.specNameInput.fill('Metadata Preservation Test');
    await specsPage.specContentTextarea.fill(JSON.stringify(specWithMetadata, null, 2));
    await specsPage.saveButton.click();
    
    await expect(specsPage.successMessage).toBeVisible();
    
    // View imported spec details
    await specsPage.selectSpecification('Metadata Preservation Test');
    
    // Verify metadata is preserved
    const specDetails = page.locator('.spec-details, [data-testid="spec-info"]');
    await expect(specDetails).toContainText('2.1.0'); // Version
    await expect(specDetails).toContainText('MIT'); // License
    
    // Check if servers are preserved
    const serversSection = page.locator('.servers, [data-testid="servers"]');
    if (await serversSection.isVisible()) {
      await expect(serversSection).toContainText('Production');
      await expect(serversSection).toContainText('Staging');
    }
    
    // Check if tags are preserved
    const tagsSection = page.locator('.tags, [data-testid="tags"]');
    if (await tagsSection.isVisible()) {
      await expect(tagsSection).toContainText('Users');
      await expect(tagsSection).toContainText('Products');
    }
  });

  test('should support API versioning during import', async ({ page }) => {
    await specsPage.goto();
    
    // Import first version
    await specsPage.uploadSpecification(
      'API v1.0',
      'Initial version',
      { ...sampleAPISpec.content, info: { ...sampleAPISpec.content.info, version: '1.0.0' } }
    );
    
    // Import updated version
    await specsPage.uploadButton.click();
    
    // Check for version conflict detection
    await specsPage.specNameInput.fill('API v1.0'); // Same name
    await specsPage.specDescriptionInput.fill('Updated version');
    
    const v2Spec = {
      ...sampleAPISpec.content,
      info: { ...sampleAPISpec.content.info, version: '2.0.0' },
      paths: {
        ...sampleAPISpec.content.paths,
        '/users': {
          get: {
            summary: 'Get all users (v2)',
            responses: { '200': { description: 'Success' } }
          }
        }
      }
    };
    
    await specsPage.specContentTextarea.fill(JSON.stringify(v2Spec, null, 2));
    await specsPage.saveButton.click();
    
    // Should detect version difference
    const versionDialog = page.locator('.version-dialog, [data-testid="version-conflict"]');
    if (await versionDialog.isVisible()) {
      await expect(versionDialog).toContainText(/version|update|replace/i);
      
      // Options for handling versions
      const createNewVersion = page.locator('button').filter({ hasText: /new.*version|keep.*both/i });
      const replaceVersion = page.locator('button').filter({ hasText: /replace|update/i });
      
      // Create as new version
      if (await createNewVersion.isVisible()) {
        await createNewVersion.click();
        
        // Should create new versioned spec
        await expect(specsPage.successMessage).toBeVisible();
        
        // Both versions should exist
        const specs = await specsPage.getSpecificationsList();
        const v1 = specs.find(s => s.name.includes('v1'));
        const v2 = specs.find(s => s.name.includes('v2') || s.name.includes('2.0'));
        
        expect(v1).toBeTruthy();
        expect(v2).toBeTruthy();
      }
    }
  });
});