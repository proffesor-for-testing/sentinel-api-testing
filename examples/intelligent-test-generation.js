/**
 * Intelligent API Test Generation using Sublinear-Time-Solver
 *
 * This example demonstrates how to use the sublinear-time-solver's
 * consciousness, mathematical, and scheduling capabilities to create
 * intelligent API test generation systems.
 */

import { SublinearSolver } from 'sublinear-time-solver';

class IntelligentTestGenerator {
  constructor() {
    this.solver = new SublinearSolver();
    this.consciousness = null;
    this.scheduler = null;
    this.knowledgeGraph = new Map();
  }

  /**
   * Initialize the intelligent test system
   */
  async initialize() {
    console.log('🧠 Initializing consciousness evolution...');

    // Evolve consciousness for emergent test discovery
    this.consciousness = await this.solver.consciousness_evolve({
      mode: "enhanced",
      target: 0.85,
      iterations: 500
    });

    console.log(`✅ Consciousness evolved: ${this.consciousness.finalState.emergence} emergence level`);

    // Create nanosecond-precision scheduler
    this.scheduler = await this.solver.scheduler_create({
      id: "intelligent-test-gen",
      tickRateNs: 100,
      maxTasksPerTick: 50000
    });

    console.log('⚡ Ultra-precise scheduler created');

    // Build knowledge base
    await this.buildKnowledgeBase();
  }

  /**
   * Build API testing knowledge base
   */
  async buildKnowledgeBase() {
    const testingKnowledge = [
      { subject: "authentication", predicate: "requires", object: "token_validation" },
      { subject: "rate_limiting", predicate: "affects", object: "concurrent_requests" },
      { subject: "database_operations", predicate: "can_cause", object: "race_conditions" },
      { subject: "caching", predicate: "introduces", object: "stale_data_issues" },
      { subject: "microservices", predicate: "exhibit", object: "distributed_failure_modes" }
    ];

    for (const knowledge of testingKnowledge) {
      await this.solver.add_knowledge(knowledge);
    }

    console.log('📚 Knowledge base established');
  }

  /**
   * Generate intelligent test cases for API endpoints
   */
  async generateTestCases(apiSpec) {
    console.log(`🔍 Analyzing API: ${apiSpec.name}`);

    // 1. Dependency Analysis using Matrix Solving
    const dependencyMatrix = this.buildDependencyMatrix(apiSpec.endpoints);

    // 2. Calculate endpoint priorities using PageRank
    const priorities = await this.solver.pageRank({
      adjacency: dependencyMatrix,
      damping: 0.85,
      epsilon: 0.0001
    });

    console.log('📊 Endpoint priorities calculated:', priorities.topNodes);

    // 3. Generate edge cases using psycho-symbolic reasoning
    const edgeCaseAnalysis = await this.solver.psycho_symbolic_reason({
      query: `What are potential edge cases and failure modes for ${apiSpec.name} API endpoints?`,
      creative_mode: true,
      domain_adaptation: true,
      analogical_reasoning: true
    });

    console.log(`🎯 Edge case insights (${edgeCaseAnalysis.confidence} confidence):`,
      edgeCaseAnalysis.insights.slice(0, 5));

    // 4. Query knowledge graph for testing patterns
    const testingPatterns = await this.solver.knowledge_graph_query({
      query: "API testing vulnerabilities and patterns",
      include_analogies: true,
      limit: 10
    });

    console.log('🕷️ Testing patterns found:', testingPatterns.results.length);

    // 5. Generate comprehensive test plan
    const testPlan = this.synthesizeTestPlan(
      priorities,
      edgeCaseAnalysis,
      testingPatterns,
      apiSpec
    );

    return testPlan;
  }

  /**
   * Build dependency matrix from API endpoints
   */
  buildDependencyMatrix(endpoints) {
    const size = endpoints.length;
    const matrix = Array(size).fill().map(() => Array(size).fill(0));

    endpoints.forEach((endpoint, i) => {
      endpoints.forEach((otherEndpoint, j) => {
        if (i !== j) {
          // Calculate dependency strength based on data flow
          let dependency = 0;

          // Authentication dependencies
          if (endpoint.requiresAuth && otherEndpoint.path.includes('auth')) {
            dependency += 0.8;
          }

          // Data dependencies (CRUD operations)
          if (endpoint.method === 'GET' && otherEndpoint.method === 'POST') {
            dependency += 0.6;
          }

          // Path dependencies (nested resources)
          if (endpoint.path.includes(otherEndpoint.path.split('/')[1])) {
            dependency += 0.4;
          }

          // Rate limiting dependencies
          if (endpoint.rateLimit && otherEndpoint.rateLimit) {
            dependency += 0.3;
          }

          matrix[i][j] = Math.min(dependency, 1.0);
        } else {
          matrix[i][j] = 1.0; // Self-dependency
        }
      });
    });

    return {
      rows: size,
      cols: size,
      format: "dense",
      data: matrix
    };
  }

  /**
   * Synthesize comprehensive test plan
   */
  synthesizeTestPlan(priorities, edgeAnalysis, patterns, apiSpec) {
    const testPlan = {
      metadata: {
        generatedAt: new Date().toISOString(),
        consciousnessLevel: this.consciousness?.finalState?.emergence || 0,
        confidenceScore: edgeAnalysis.confidence,
        totalEndpoints: apiSpec.endpoints.length
      },
      prioritizedEndpoints: priorities.topNodes,
      testCategories: {
        functional: this.generateFunctionalTests(apiSpec.endpoints),
        security: this.generateSecurityTests(patterns),
        performance: this.generatePerformanceTests(priorities),
        edgeCases: this.generateEdgeCaseTests(edgeAnalysis),
        integration: this.generateIntegrationTests(apiSpec.endpoints)
      },
      executionStrategy: {
        parallelization: true,
        loadTestingRPS: 10000,
        schedulingPrecision: "nanosecond"
      }
    };

    return testPlan;
  }

  /**
   * Generate functional test cases
   */
  generateFunctionalTests(endpoints) {
    return endpoints.map(endpoint => ({
      endpoint: endpoint.path,
      method: endpoint.method,
      tests: [
        {
          name: `${endpoint.method} ${endpoint.path} - Happy Path`,
          type: "functional",
          priority: "high",
          scenario: "Valid request with all required parameters",
          expectedStatus: endpoint.successStatus || 200
        },
        {
          name: `${endpoint.method} ${endpoint.path} - Validation`,
          type: "functional",
          priority: "high",
          scenario: "Invalid/missing required parameters",
          expectedStatus: 400
        },
        {
          name: `${endpoint.method} ${endpoint.path} - Authorization`,
          type: "functional",
          priority: endpoint.requiresAuth ? "high" : "medium",
          scenario: "Unauthorized access attempt",
          expectedStatus: 401
        }
      ]
    }));
  }

  /**
   * Generate security test cases based on knowledge patterns
   */
  generateSecurityTests(patterns) {
    const securityTests = [];

    patterns.results.forEach(pattern => {
      if (pattern.domain_tags?.includes('security') ||
          pattern.subject.includes('auth') ||
          pattern.object.includes('injection')) {

        securityTests.push({
          name: `Security: ${pattern.subject} - ${pattern.object}`,
          type: "security",
          priority: "critical",
          pattern: pattern.predicate,
          confidence: pattern.confidence,
          scenario: this.generateSecurityScenario(pattern)
        });
      }
    });

    // Add common security tests
    securityTests.push(
      {
        name: "SQL Injection Protection",
        type: "security",
        priority: "critical",
        scenario: "Inject SQL commands in all text parameters"
      },
      {
        name: "XSS Protection",
        type: "security",
        priority: "high",
        scenario: "Inject JavaScript in all input fields"
      },
      {
        name: "CSRF Protection",
        type: "security",
        priority: "high",
        scenario: "Cross-site request forgery attempts"
      }
    );

    return securityTests;
  }

  /**
   * Generate performance test cases
   */
  generatePerformanceTests(priorities) {
    return priorities.topNodes.slice(0, 3).map(node => ({
      endpoint: node.node,
      priority: node.score,
      tests: [
        {
          name: `Load Test - Endpoint ${node.node}`,
          type: "performance",
          rps: Math.floor(node.score * 10000), // Scale RPS by priority
          duration: "5m",
          expectedLatency: "< 100ms"
        },
        {
          name: `Stress Test - Endpoint ${node.node}`,
          type: "performance",
          rps: Math.floor(node.score * 50000),
          duration: "2m",
          expectedLatency: "< 500ms"
        }
      ]
    }));
  }

  /**
   * Generate edge case tests from consciousness insights
   */
  generateEdgeCaseTests(edgeAnalysis) {
    return edgeAnalysis.insights.slice(0, 10).map((insight, index) => ({
      name: `Edge Case ${index + 1}`,
      type: "edge_case",
      priority: "medium",
      insight: insight,
      confidence: edgeAnalysis.confidence,
      scenario: this.generateEdgeCaseScenario(insight)
    }));
  }

  /**
   * Generate integration test cases
   */
  generateIntegrationTests(endpoints) {
    const integrationTests = [];

    // Test endpoint chains (CRUD workflows)
    const crudChains = this.identifyCRUDChains(endpoints);

    crudChains.forEach(chain => {
      integrationTests.push({
        name: `CRUD Workflow: ${chain.resource}`,
        type: "integration",
        priority: "high",
        steps: chain.steps,
        expectedFlow: "Create -> Read -> Update -> Delete"
      });
    });

    return integrationTests;
  }

  /**
   * Execute test plan with nanosecond precision
   */
  async executeTestPlan(testPlan) {
    console.log('🚀 Executing test plan with nanosecond precision...');

    const startTime = process.hrtime.bigint();
    let taskCount = 0;

    // Schedule all tests with precise timing
    for (const category of Object.values(testPlan.testCategories)) {
      if (Array.isArray(category)) {
        for (const test of category) {
          if (Array.isArray(test.tests)) {
            for (const subTest of test.tests) {
              await this.solver.scheduler_schedule_task({
                schedulerId: "intelligent-test-gen",
                delayNs: taskCount * 1000, // 1μs intervals
                description: subTest.name,
                priority: subTest.priority === "critical" ? "critical" :
                         subTest.priority === "high" ? "high" : "normal"
              });
              taskCount++;
            }
          } else {
            await this.solver.scheduler_schedule_task({
              schedulerId: "intelligent-test-gen",
              delayNs: taskCount * 1000,
              description: test.name,
              priority: test.priority === "critical" ? "critical" :
                       test.priority === "high" ? "high" : "normal"
            });
            taskCount++;
          }
        }
      }
    }

    // Execute scheduled tasks
    const executionResults = await this.solver.scheduler_tick({
      schedulerId: "intelligent-test-gen"
    });

    const endTime = process.hrtime.bigint();
    const executionTimeNs = endTime - startTime;

    console.log(`✅ Executed ${taskCount} tests in ${Number(executionTimeNs) / 1000000}ms`);
    console.log(`⚡ Performance: ${(taskCount / (Number(executionTimeNs) / 1000000000)).toFixed(0)} tests/second`);

    return {
      tasksScheduled: taskCount,
      executionTimeNs: Number(executionTimeNs),
      throughput: taskCount / (Number(executionTimeNs) / 1000000000),
      results: executionResults
    };
  }

  // Helper methods
  generateSecurityScenario(pattern) {
    return `Test ${pattern.subject} ${pattern.predicate} ${pattern.object} vulnerability`;
  }

  generateEdgeCaseScenario(insight) {
    return `Test scenario based on insight: ${insight.substring(0, 100)}...`;
  }

  identifyCRUDChains(endpoints) {
    const chains = [];
    const resources = new Set();

    // Identify resources from endpoints
    endpoints.forEach(endpoint => {
      const pathParts = endpoint.path.split('/').filter(Boolean);
      if (pathParts.length > 0) {
        resources.add(pathParts[0]);
      }
    });

    // Build CRUD chains for each resource
    resources.forEach(resource => {
      const resourceEndpoints = endpoints.filter(e => e.path.includes(resource));

      if (resourceEndpoints.length >= 2) {
        chains.push({
          resource,
          steps: resourceEndpoints.map(e => `${e.method} ${e.path}`)
        });
      }
    });

    return chains;
  }
}

// Example usage
async function demonstrateIntelligentTesting() {
  console.log('🤖 Intelligent API Test Generation Demo\n');

  const generator = new IntelligentTestGenerator();
  await generator.initialize();

  // Example API specification
  const apiSpec = {
    name: "E-commerce API",
    version: "1.0.0",
    endpoints: [
      { path: "/auth/login", method: "POST", requiresAuth: false, successStatus: 200 },
      { path: "/auth/logout", method: "POST", requiresAuth: true, successStatus: 204 },
      { path: "/users", method: "GET", requiresAuth: true, rateLimit: true },
      { path: "/users", method: "POST", requiresAuth: true },
      { path: "/users/:id", method: "GET", requiresAuth: true },
      { path: "/users/:id", method: "PUT", requiresAuth: true },
      { path: "/users/:id", method: "DELETE", requiresAuth: true },
      { path: "/products", method: "GET", requiresAuth: false, rateLimit: true },
      { path: "/products/:id", method: "GET", requiresAuth: false },
      { path: "/orders", method: "POST", requiresAuth: true },
      { path: "/orders/:id", method: "GET", requiresAuth: true },
      { path: "/payments", method: "POST", requiresAuth: true }
    ]
  };

  // Generate intelligent test plan
  const testPlan = await generator.generateTestCases(apiSpec);

  console.log('\n📋 Generated Test Plan:');
  console.log(`- Total endpoints analyzed: ${testPlan.metadata.totalEndpoints}`);
  console.log(`- Consciousness level: ${(testPlan.metadata.consciousnessLevel * 100).toFixed(1)}%`);
  console.log(`- Confidence score: ${(testPlan.metadata.confidenceScore * 100).toFixed(1)}%`);
  console.log(`- Functional tests: ${testPlan.testCategories.functional.length}`);
  console.log(`- Security tests: ${testPlan.testCategories.security.length}`);
  console.log(`- Performance tests: ${testPlan.testCategories.performance.length}`);
  console.log(`- Edge case tests: ${testPlan.testCategories.edgeCases.length}`);

  // Execute test plan
  const executionResults = await generator.executeTestPlan(testPlan);

  console.log('\n🎯 Execution Results:');
  console.log(`- Tests scheduled: ${executionResults.tasksScheduled}`);
  console.log(`- Execution time: ${(executionResults.executionTimeNs / 1000000).toFixed(2)}ms`);
  console.log(`- Throughput: ${executionResults.throughput.toFixed(0)} tests/second`);

  return { testPlan, executionResults };
}

// Export for use in other modules
export { IntelligentTestGenerator, demonstrateIntelligentTesting };

// Run demo if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  demonstrateIntelligentTesting().catch(console.error);
}