/**
 * Test data fixtures for E2E tests
 */

export const testUsers = {
  admin: {
    email: 'admin@sentinel.com',
    password: 'admin123',
    role: 'admin'
  },
  tester: {
    email: 'tester@sentinel.com',
    password: 'tester123',
    role: 'tester'
  },
  viewer: {
    email: 'viewer@sentinel.com',
    password: 'viewer123',
    role: 'viewer'
  }
};

export const sampleAPISpec = {
  name: 'Sample Pet Store API',
  description: 'E2E test API specification',
  content: {
    openapi: '3.0.0',
    info: {
      title: 'Pet Store API',
      version: '1.0.0'
    },
    servers: [
      { url: 'https://petstore.example.com/api' }
    ],
    paths: {
      '/pets': {
        get: {
          summary: 'List all pets',
          operationId: 'listPets',
          responses: {
            '200': {
              description: 'A list of pets',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        id: { type: 'integer' },
                        name: { type: 'string' },
                        species: { type: 'string' }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        post: {
          summary: 'Create a pet',
          operationId: 'createPet',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['name', 'species'],
                  properties: {
                    name: { type: 'string' },
                    species: { type: 'string', enum: ['dog', 'cat', 'bird'] }
                  }
                }
              }
            }
          },
          responses: {
            '201': { description: 'Pet created' }
          }
        }
      }
    }
  }
};

export const testAgents = [
  'functional-positive',
  'functional-negative',
  'security-auth',
  'security-injection',
  'performance-planner'
];