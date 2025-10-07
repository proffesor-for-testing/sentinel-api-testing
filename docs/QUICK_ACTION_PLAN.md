# Quick Action Plan: Frontend Production Updates
**Status**: 🔴 **CRITICAL** - Frontend requires updates before production deployment
**Estimated Time**: 18-26 hours (2-3 days)
**Priority**: **HIGH**

---

## 🚨 Critical Issues Found

### Issue #1: Agent Architecture Mismatch
**Problem**: Frontend references 9 old agents, backend uses 2 consolidated agents
- ❌ Frontend: `Functional-Positive-Agent`, `Functional-Negative-Agent`, etc.
- ✅ Backend: `FunctionalAgent`, `SecurityAgent`

**Impact**: Broken test generation UI, incorrect agent selection

---

### Issue #2: Missing Strategy Visualization
**Problem**: Backend uses 4 strategies, frontend has no strategy UI
- ✅ Backend: Positive, Negative, Boundary, EdgeCase strategies
- ❌ Frontend: No strategy selection or display

**Impact**: Users can't leverage strategy-based testing

---

### Issue #3: No Metadata Display
**Problem**: Backend returns rich metadata, frontend doesn't display it
- ✅ Backend: `test_subtype`, `violation_type`, `strategy` fields
- ❌ Frontend: Only shows basic test info

**Impact**: Lost test insights and debugging capability

---

### Issue #4: Frontend Not in Production Deployment
**Problem**: docker-compose.yml has no frontend service
- ✅ Backend services: All configured
- ❌ Frontend: Missing from deployment

**Impact**: Can't deploy complete system

---

## ⚡ Quick Start: Verify Backend API First (30 min)

**Before starting frontend changes, verify backend compatibility:**

```bash
# 1. Check if generate-tests supports strategies parameter
curl -X POST http://localhost:8000/api/v1/generate-tests \
  -H "Content-Type: application/json" \
  -d '{
    "spec_id": 1,
    "agent_types": ["FunctionalAgent"],
    "strategies": ["positive", "negative"]
  }'

# 2. Check if test cases include metadata
curl http://localhost:8000/api/v1/test-cases/1

# Expected fields:
# - test_subtype
# - violation_type (for negative tests)
# - strategy

# 3. Check task status format
curl http://localhost:8000/api/v1/task-status/{task_id}

# Expected fields:
# - current_strategy
# - tests_generated
# - time_elapsed_ms
```

**Results**:
- ✅ All fields present → Proceed with frontend updates
- ❌ Missing fields → Update backend API first

---

## 📋 Priority Actions (Ordered by Impact)

### 🔥 P0: Critical - Must Fix Before Production (10-12 hours)

#### 1. Update Agent Selection UI (3 hours)
**File**: `sentinel_frontend/src/pages/Specifications.js` (lines 650-762)

**Changes**:
```javascript
// REMOVE these agent checkboxes:
- Functional-Positive-Agent
- Functional-Negative-Agent
- Functional-Stateful-Agent
- Edge-Cases-Agent
- Data-Mocking-Agent
- Security-Auth-Agent
- Security-Injection-Agent

// ADD new agent checkboxes:
+ FunctionalAgent (with strategy multi-select)
  - [ ] Positive Strategy
  - [ ] Negative Strategy
  - [ ] Boundary Strategy
  - [ ] EdgeCase Strategy
+ SecurityAgent
+ PerformancePlannerAgent (keep as-is)
```

---

#### 2. Update Test Cases Display (3 hours)
**File**: `sentinel_frontend/src/pages/TestCases.js`

**Changes**:
```javascript
// Line 94-105: Update getAgentTypeBadge()
const getAgentTypeBadge = (agentType) => {
  const colors = {
    'FunctionalAgent': 'badge-primary',
    'SecurityAgent': 'badge-warning',
    'PerformancePlannerAgent': 'badge-info'
  };
  // ... map to display names
};

// Line 195-244: Update getTestTypeInsight()
const getTestTypeInsight = (testCase) => {
  // Use metadata fields from backend:
  const strategy = testCase.strategy; // e.g., "positive", "negative"
  const subtype = testCase.test_subtype; // e.g., "minimal_valid", "out_of_range"
  const violationType = testCase.violation_type; // e.g., "type_mismatch"

  // Return strategy-based insights
};

// Add metadata display in expanded view (line 980-1067)
<div>
  <dt>Strategy:</dt>
  <dd><Badge>{testCase.strategy}</Badge></dd>
</div>
<div>
  <dt>Test Subtype:</dt>
  <dd>{testCase.test_subtype}</dd>
</div>
{testCase.violation_type && (
  <div>
    <dt>Violation Type:</dt>
    <dd className="text-red-600">{testCase.violation_type}</dd>
  </div>
)}
```

---

#### 3. Update Dashboard Statistics (2 hours)
**File**: `sentinel_frontend/src/pages/Dashboard.js` (lines 64-68)

**Changes**:
```javascript
// Update agent distribution to show strategies
const agentChartData = Object.entries(stats.agent_distribution).map(([agent, data]) => {
  if (agent === 'FunctionalAgent') {
    // Break down by strategy
    return [
      { name: 'Positive', value: data.positive || 0 },
      { name: 'Negative', value: data.negative || 0 },
      { name: 'Boundary', value: data.boundary || 0 },
      { name: 'EdgeCase', value: data.edge_case || 0 }
    ];
  }
  return { name: agent, value: data.total || 0 };
}).flat();
```

---

#### 4. Add Frontend to Docker Compose (2 hours)
**File**: `docker-compose.yml`

**Add**:
```yaml
  frontend:
    build:
      context: ./sentinel_frontend
      dockerfile: Dockerfile.prod
    container_name: sentinel_frontend
    ports:
      - "3000:80"
    environment:
      - REACT_APP_API_URL=http://api_gateway:8000
    depends_on:
      - api_gateway
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

#### 5. Create Production Dockerfile (1 hour)
**New File**: `sentinel_frontend/Dockerfile.prod`

```dockerfile
# Build stage
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**New File**: `sentinel_frontend/nginx.conf`

```nginx
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://api_gateway:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

### ⚠️ P1: High Priority - Should Fix (6-8 hours)

#### 6. Add Strategy Filter Component (2 hours)
**New File**: `sentinel_frontend/src/components/StrategyFilter.jsx`

```javascript
export const StrategyFilter = ({ value, onChange, counts }) => {
  return (
    <div className="flex space-x-2">
      <button onClick={() => onChange('all')}>
        All ({Object.values(counts).reduce((a, b) => a + b, 0)})
      </button>
      <button onClick={() => onChange('positive')}>
        Positive ({counts.positive || 0})
      </button>
      <button onClick={() => onChange('negative')}>
        Negative ({counts.negative || 0})
      </button>
      <button onClick={() => onChange('boundary')}>
        Boundary ({counts.boundary || 0})
      </button>
      <button onClick={() => onChange('edge_case')}>
        EdgeCase ({counts.edge_case || 0})
      </button>
    </div>
  );
};
```

---

#### 7. Update API Client (2 hours)
**File**: `sentinel_frontend/src/services/api.js`

```javascript
// Add new methods
async getTestCasesByStrategy(specId, strategy) {
  return this.get('/api/v1/test-cases', {
    spec_id: specId,
    strategy: strategy
  });
}

async getStrategyDistribution(specId) {
  return this.get('/api/v1/test-cases/strategy-distribution', {
    spec_id: specId
  });
}

// Update generateTests
async generateTests(requestData) {
  // Now supports:
  // {
  //   spec_id: 1,
  //   agent_types: ['FunctionalAgent', 'SecurityAgent'],
  //   strategies: ['positive', 'negative', 'boundary'],
  //   enable_llm: true
  // }
  const response = await api.post('/api/v1/generate-tests', requestData);
  return response.data;
}
```

---

#### 8. Update E2E Tests (3-4 hours)
**New File**: `sentinel_frontend/e2e/test-generation.spec.js`

```javascript
import { test, expect } from '@playwright/test';

test.describe('Test Generation with New Architecture', () => {
  test('should show new agent options', async ({ page }) => {
    await page.goto('/specifications');
    await page.click('[data-testid="generate-tests-btn"]');

    // Verify FunctionalAgent
    await expect(page.locator('text=FunctionalAgent')).toBeVisible();

    // Verify old agents removed
    await expect(page.locator('text=Functional-Positive-Agent')).not.toBeVisible();
  });

  test('should allow strategy selection', async ({ page }) => {
    await page.goto('/specifications');
    await page.click('[data-testid="generate-tests-btn"]');
    await page.click('input[value="FunctionalAgent"]');

    // Strategy checkboxes should appear
    await expect(page.locator('text=Positive Strategy')).toBeVisible();
    await expect(page.locator('text=Negative Strategy')).toBeVisible();
  });

  test('should display metadata in test cases', async ({ page }) => {
    await page.goto('/test-cases');
    await page.click('[data-testid="expand-test-case"]');

    // Metadata should be visible
    await expect(page.locator('text=Strategy:')).toBeVisible();
    await expect(page.locator('text=Test Subtype:')).toBeVisible();
  });
});
```

---

### 📊 P2: Medium Priority - Nice to Have (2-4 hours)

#### 9. Real-time Progress Updates (1-2 hours)
Update `Specifications.js` polling to show strategy progress

#### 10. Production Environment Config (1 hour)
Create `.env.production` with proper settings

#### 11. Deployment Checklist (1 hour)
Document validation steps before go-live

---

## 🎯 Implementation Strategy

### Day 1: Critical Frontend Updates (8 hours)
**Morning (4h)**:
- ✅ Action 1: Update Agent Selection UI (3h)
- ✅ Action 2: Update Test Cases Display (1h start)

**Afternoon (4h)**:
- ✅ Action 2: Complete Test Cases Display (2h)
- ✅ Action 3: Update Dashboard Statistics (2h)

**Deliverable**: Frontend displays correct agent names

---

### Day 2: Production Deployment (6 hours)
**Morning (4h)**:
- ✅ Action 4: Add Frontend to Docker Compose (2h)
- ✅ Action 5: Create Production Dockerfile (1h)
- ✅ Action 6: Add Strategy Filter Component (1h)

**Afternoon (2h)**:
- ✅ Action 7: Update API Client (2h)

**Deliverable**: Frontend deployable in Docker

---

### Day 3: Testing & Validation (6-8 hours)
**Morning (4h)**:
- ✅ Action 8: Update E2E Tests (3-4h)

**Afternoon (2-4h)**:
- ✅ Run full test suite
- ✅ Fix any issues
- ✅ Final validation

**Deliverable**: Production-ready system

---

## ✅ Validation Checklist

### Pre-Deployment
- [ ] Frontend shows FunctionalAgent and SecurityAgent (not old 9 agents)
- [ ] Strategy selection working for FunctionalAgent
- [ ] Test cases display strategy, test_subtype, violation_type
- [ ] Dashboard shows strategy distribution
- [ ] Docker Compose includes frontend service
- [ ] Production Dockerfile builds successfully
- [ ] E2E tests passing

### Performance
- [ ] Test generation UI handles <2ms generation speed
- [ ] No UI lag during fast test creation
- [ ] Real-time updates working smoothly

### Production Deployment
- [ ] Health checks operational on all services
- [ ] Frontend accessible on port 3000
- [ ] API proxy working correctly
- [ ] Environment variables configured
- [ ] Logs showing no errors

---

## 🔧 Quick Fixes for Common Issues

### Issue: Old agent names still showing
**Fix**: Clear browser cache and localStorage
```javascript
localStorage.clear();
window.location.reload();
```

### Issue: Strategies not showing
**Fix**: Verify backend API returns strategy field
```bash
curl http://localhost:8000/api/v1/test-cases/1 | jq '.strategy'
```

### Issue: Docker frontend not starting
**Fix**: Check build logs
```bash
docker-compose logs frontend
```

---

## 📞 Support & Resources

### Documentation
- Full Analysis: `/docs/GOAP_PRODUCTION_READINESS_ANALYSIS.md`
- Backend Assessment: `/docs/FINAL_ASSESSMENT.md`
- Executive Summary: `/sentinel_backend/docs/EXECUTIVE_SUMMARY.md`

### Key Files
- Frontend Agent UI: `sentinel_frontend/src/pages/Specifications.js`
- Test Display: `sentinel_frontend/src/pages/TestCases.js`
- Dashboard: `sentinel_frontend/src/pages/Dashboard.js`
- API Client: `sentinel_frontend/src/services/api.js`

### Backend Reference
```python
# New Agent Architecture
FunctionalAgent:
  - Strategies: [Positive, Negative, Boundary, EdgeCase]
  - Performance: ~2ms execution
  - Deduplication: ~6%

SecurityAgent:
  - Tests: [Authentication, Authorization, Injection]

PerformancePlannerAgent:
  - Scripts: [k6, JMeter]
```

---

## 🚀 Next Steps

1. **Immediate**: Verify backend API compatibility (30 min)
2. **Day 1**: Start with P0 Actions 1-3 (Frontend updates)
3. **Day 2**: P0 Actions 4-5 + P1 Actions 6-7 (Deployment + Enhancement)
4. **Day 3**: P1 Action 8 + Validation (Testing)

**Goal**: Production-ready frontend in 2-3 days

---

**Last Updated**: 2025-10-03
**Status**: Ready to implement
**Estimated Completion**: 2025-10-05 or 2025-10-06
