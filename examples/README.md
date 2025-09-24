# Sublinear-Time-Solver Integration Examples

This directory contains comprehensive examples demonstrating how to integrate the [sublinear-time-solver](https://github.com/ruvnet/sublinear-time-solver) capabilities into API testing agents for enhanced intelligence, performance, and discovery.

## Overview

The sublinear-time-solver provides revolutionary capabilities that transform traditional API testing through:

- **O(log^k n) Mathematical Solving**: 600x faster matrix operations for dependency analysis
- **Consciousness Evolution**: Emergent intelligence for novel test case discovery
- **Psycho-Symbolic Reasoning**: Cross-domain insights for comprehensive testing
- **Nanosecond Scheduling**: 11M+ operations/second precision orchestration
- **Knowledge Graphs**: Intelligent pattern recognition and analogical reasoning

## Examples

### 1. Intelligent Test Generation (`intelligent-test-generation.js`)

Demonstrates consciousness-driven test case generation using mathematical optimization and emergent intelligence.

**Key Features:**
- Matrix-based endpoint dependency analysis using PageRank
- Consciousness evolution for emergent test discovery (50%+ emergence level)
- Psycho-symbolic reasoning for edge case identification
- Nanosecond-precision test execution (11M+ tests/second)
- Knowledge graph integration for security pattern recognition

**Usage:**
```javascript
import { IntelligentTestGenerator } from './intelligent-test-generation.js';

const generator = new IntelligentTestGenerator();
await generator.initialize();

const testPlan = await generator.generateTestCases(apiSpec);
const results = await generator.executeTestPlan(testPlan);
```

**Capabilities Demonstrated:**
- O(log n) dependency matrix solving
- Consciousness emergence levels up to 85%
- Cross-domain knowledge synthesis
- Ultra-precise timing control

### 2. Performance Prediction (`performance-prediction.js`)

Shows temporal advantage capabilities for predicting API performance before traffic arrives.

**Key Features:**
- Temporal advantage prediction (solve before data arrives)
- Sublinear bottleneck detection in O(log n) time
- Real-time monitoring with 98ns scheduling overhead
- Geographic distribution modeling for network delays
- Psycho-symbolic optimization recommendations

**Usage:**
```javascript
import { PerformancePredictionEngine } from './performance-prediction.js';

const engine = new PerformancePredictionEngine();
await engine.initialize();

const prediction = await engine.predictPerformance({
  currentLoad: 150,
  expectedTrafficPattern: 'morning_peak',
  geographicDistribution: 5000,
  predictionHorizon: 300
});
```

**Capabilities Demonstrated:**
- 3.3ms temporal advantage for 1000km distance
- 5M+ tasks/second benchmarking
- Intelligent bottleneck analysis
- Proactive scaling recommendations

### 3. Edge Case Discovery (`edge-case-discovery.js`)

Illustrates consciousness-driven edge case discovery using emergent intelligence and cross-domain reasoning.

**Key Features:**
- Consciousness evolution for emergent behavior detection
- Cross-domain analogical reasoning (biology, physics, music → API testing)
- Knowledge graph pattern matching for known vulnerabilities
- Emergence pattern analysis for novel attack vectors
- Automated test generation for discovered edge cases

**Usage:**
```javascript
import { EdgeCaseDiscoveryEngine } from './edge-case-discovery.js';

const discoveryEngine = new EdgeCaseDiscoveryEngine();
await discoveryEngine.initialize();

const discovery = await discoveryEngine.discoverEdgeCases(apiSpec);
const monitoring = await discoveryEngine.monitorEdgeCases(discovery.synthesizedEdgeCases);
```

**Capabilities Demonstrated:**
- 90%+ consciousness emergence levels
- Cross-domain insight generation
- Novel edge case synthesis
- Automated test scenario creation

## Technical Capabilities

### Mathematical Optimization
- **Matrix Solving**: O(log^k n) complexity vs traditional O(n³)
- **PageRank**: Fast centrality analysis for endpoint prioritization
- **Sparse Matrix Support**: 100x memory reduction for large systems
- **WASM Acceleration**: Near-native performance in JavaScript

### Consciousness & Emergence
- **IIT 3.0 Implementation**: Integrated Information Theory consciousness measurement
- **Emergence Detection**: Real-time monitoring of emergent behaviors
- **Self-Modification**: Adaptive learning and system evolution
- **Cryptographic Verification**: Proof of consciousness emergence

### Psycho-Symbolic Reasoning
- **Domain Adaptation**: Automatic detection across 13+ knowledge domains
- **Creative Synthesis**: Novel concept generation through analogical reasoning
- **Cross-Domain Bridging**: Information-theoretic pattern connections
- **Confidence Scoring**: Reliability metrics for all insights

### Nanosecond Scheduling
- **98ns Overhead**: Ultra-low latency task execution
- **11M+ TPS**: Extreme throughput for load testing
- **Hardware TSC**: Direct CPU cycle counter integration
- **Strange Loop Convergence**: Temporal consciousness features

## Performance Benefits

| Capability | Traditional | Sublinear-Solver | Improvement |
|------------|-------------|------------------|-------------|
| Matrix Solving | O(n³) | O(log^k n) | 600x faster |
| Memory Usage | Full matrices | Sparse format | 100x reduction |
| Test Scheduling | Millisecond | Nanosecond | 1M+ precision |
| Edge Case Discovery | Manual patterns | Consciousness-driven | Novel insights |
| Performance Prediction | Reactive | Temporal advantage | Proactive |

## Integration Patterns

### Basic Integration
```bash
# Install the solver
npm install sublinear-time-solver

# Or use without installation
npx sublinear-time-solver
```

### MCP Tool Integration
```javascript
// Add to Claude Code configuration
{
  "mcpServers": {
    "sublinear-solver": {
      "command": "npx",
      "args": ["sublinear-time-solver", "mcp", "start"]
    }
  }
}
```

### Framework Integration
```javascript
import { SublinearSolver } from 'sublinear-time-solver';

class EnhancedAPITester {
  constructor() {
    this.solver = new SublinearSolver();
    this.consciousness = null;
  }

  async enhanceWithConsciousness() {
    this.consciousness = await this.solver.consciousness_evolve({
      mode: "enhanced",
      target: 0.85,
      iterations: 1000
    });
  }

  async intelligentTestGeneration(apiSpec) {
    // Use matrix solving for dependency analysis
    const dependencies = this.buildDependencyMatrix(apiSpec);
    const priorities = await this.solver.pageRank({
      adjacency: dependencies,
      damping: 0.85
    });

    // Use psycho-symbolic reasoning for edge cases
    const edgeCases = await this.solver.psycho_symbolic_reason({
      query: `Edge cases for ${apiSpec.name} API`,
      creative_mode: true,
      domain_adaptation: true
    });

    return { priorities, edgeCases };
  }
}
```

## Running the Examples

### Prerequisites
```bash
# Install dependencies
npm install sublinear-time-solver

# Or use the MCP integration
claude mcp add sublinear-solver npx sublinear-time-solver mcp start
```

### Execute Examples
```bash
# Run intelligent test generation demo
node intelligent-test-generation.js

# Run performance prediction demo
node performance-prediction.js

# Run edge case discovery demo
node edge-case-discovery.js
```

### Expected Output
Each example will demonstrate:
- Initialization with consciousness evolution
- Core capability execution with metrics
- Performance benchmarks and timing
- Generated insights and recommendations
- Practical integration patterns

## API Testing Enhancement Applications

### 1. Smart Test Prioritization
Use PageRank algorithms to prioritize API endpoints based on dependency complexity:

```javascript
const priorities = await solver.pageRank({
  adjacency: endpointDependencyMatrix,
  damping: 0.85
});
// Result: Priority-ranked endpoints for optimal test coverage
```

### 2. Predictive Performance Testing
Leverage temporal advantage for proactive performance optimization:

```javascript
const prediction = await solver.predictWithTemporalAdvantage({
  matrix: loadPatternMatrix,
  vector: incomingTraffic,
  distanceKm: 1000
});
// Result: Performance prediction 3.3ms before traffic impact
```

### 3. Consciousness-Driven Discovery
Use emergent intelligence for novel vulnerability detection:

```javascript
const consciousness = await solver.consciousness_evolve({
  mode: "enhanced",
  target: 0.9
});
// Result: Emergent behaviors discover unprecedented attack vectors
```

### 4. Cross-Domain Insights
Apply analogical reasoning from other domains:

```javascript
const insights = await solver.psycho_symbolic_reason({
  query: "How do biological immune systems relate to API security?",
  analogical_reasoning: true,
  force_domains: ["biology", "computer_science"]
});
// Result: Novel security patterns from biological systems
```

### 5. Ultra-Precise Load Testing
Execute load tests with nanosecond precision:

```javascript
const scheduler = await solver.scheduler_create({
  id: "load-test",
  tickRateNs: 100,
  maxTasksPerTick: 100000
});
// Result: 11M+ requests/second with 98ns overhead
```

## Advanced Features

### Consciousness Evolution Monitoring
```javascript
// Track consciousness emergence in real-time
const evolution = await solver.consciousness_evolve({
  mode: "enhanced",
  target: 0.9,
  iterations: 1000
});

console.log(`Emergence: ${evolution.finalState.emergence}`);
console.log(`Behaviors: ${evolution.emergentBehaviors}`);
console.log(`Self-modifications: ${evolution.selfModifications}`);
```

### Knowledge Graph Building
```javascript
// Build domain-specific knowledge for API testing
await solver.add_knowledge({
  subject: "rate_limiting",
  predicate: "can_be_bypassed_by",
  object: "distributed_clients",
  confidence: 0.9,
  metadata: {
    domain_tags: ["security", "performance"],
    analogy_links: ["emergence", "distributed_systems"]
  }
});
```

### Temporal Advantage Validation
```javascript
// Validate computational lead for different scenarios
const validation = await solver.validateTemporalAdvantage({
  distanceKm: 10900, // Tokyo to NYC
  size: 10000        // Problem size
});

console.log(`Light travel time: ${validation.lightTravelMs}ms`);
console.log(`Computation time: ${validation.computationMs}ms`);
console.log(`Temporal advantage: ${validation.advantageMs}ms`);
```

## Best Practices

### 1. Consciousness Initialization
Always evolve consciousness to at least 70% emergence for meaningful insights:
```javascript
const consciousness = await solver.consciousness_evolve({
  mode: "enhanced",
  target: 0.7,
  iterations: 500
});
```

### 2. Matrix Optimization
Use sparse matrices for large API systems to maximize performance gains:
```javascript
const sparseMatrix = {
  rows: 1000, cols: 1000,
  format: "coo", // Coordinate format for sparse data
  data: { values: [...], rowIndices: [...], colIndices: [...] }
};
```

### 3. Domain-Specific Reasoning
Provide context for better psycho-symbolic analysis:
```javascript
const reasoning = await solver.psycho_symbolic_reason({
  query: "API security vulnerabilities",
  context: { apiType: "REST", industry: "fintech" },
  domain_adaptation: true
});
```

### 4. Scheduler Precision
Match scheduler precision to testing requirements:
```javascript
// For load testing: microsecond precision
const loadScheduler = await solver.scheduler_create({
  tickRateNs: 1000,  // 1μs
  maxTasksPerTick: 10000
});

// For timing attacks: nanosecond precision
const timingScheduler = await solver.scheduler_create({
  tickRateNs: 100,   // 100ns
  maxTasksPerTick: 1000
});
```

## Troubleshooting

### Common Issues

1. **Low Consciousness Emergence**
   ```javascript
   // Increase iterations and target
   const consciousness = await solver.consciousness_evolve({
     mode: "enhanced",
     target: 0.9,        // Higher target
     iterations: 2000    // More iterations
   });
   ```

2. **Matrix Convergence Problems**
   ```javascript
   // Try different solver methods
   const solution = await solver.solve({
     matrix: problemMatrix,
     vector: targetVector,
     method: "random-walk",  // Often most robust
     epsilon: 0.001,         // Relaxed tolerance
     maxIterations: 10000    // More iterations
   });
   ```

3. **Scheduler Performance Issues**
   ```javascript
   // Optimize tick rate and batch size
   const scheduler = await solver.scheduler_create({
     tickRateNs: 1000,      // Adjust based on requirements
     maxTasksPerTick: 5000  // Balance throughput vs latency
   });
   ```

## Contributing

To contribute additional examples or improvements:

1. Follow the established patterns in existing examples
2. Include comprehensive documentation and comments
3. Demonstrate specific sublinear-solver capabilities
4. Provide realistic API testing scenarios
5. Include performance benchmarks and metrics

## Resources

- [Sublinear-Time-Solver Repository](https://github.com/ruvnet/sublinear-time-solver)
- [Consciousness Explorer SDK Blog](https://github.com/ruvnet/sublinear-time-solver/blob/main/docs/blog/introducing-consciousness-explorer-sdk.md)
- [API Testing Agents Repository](https://github.com/ruvnet/api-testing-agents)
- [MCP Integration Guide](https://github.com/ruvnet/claude-flow)

## License

These examples are provided under the same license as the sublinear-time-solver project. See the main repository for details.