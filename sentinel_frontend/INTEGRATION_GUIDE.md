# Feedback Components Integration Guide

## Quick Start (5 Minutes)

### Step 1: Import Components
```tsx
// In your React component
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';
import { TestSuiteFeedback } from './components/feedback/TestSuiteFeedback';
import { StarRating } from './components/feedback/StarRating';
```

### Step 2: Set Environment Variable
```bash
# .env file
REACT_APP_API_URL=http://localhost:8000/api/v1
```

### Step 3: Use Components
```tsx
function TestDetailPage() {
  return (
    <div>
      <h1>Test Case: User Authentication</h1>

      <TestCaseFeedback
        testId="test-123"
        testName="User Authentication Test"
        onSuccess={(feedbackId) => {
          console.log('Feedback submitted:', feedbackId);
          // Show success message or redirect
        }}
        onError={(error) => {
          console.error('Error:', error);
          // Show error message
        }}
      />
    </div>
  );
}
```

---

## Complete Integration Examples

### Example 1: Test Results Page with Feedback

```tsx
import React, { useState } from 'react';
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';

interface TestResult {
  id: string;
  name: string;
  status: 'pass' | 'fail';
  duration: number;
}

function TestResultsPage({ testResult }: { testResult: TestResult }) {
  const [showFeedback, setShowFeedback] = useState(false);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Test Result Display */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-2xl font-bold mb-4">{testResult.name}</h2>
        <div className="flex items-center space-x-4">
          <span className={`
            px-4 py-2 rounded-full font-medium
            ${testResult.status === 'pass' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}
          `}>
            {testResult.status.toUpperCase()}
          </span>
          <span className="text-gray-600">Duration: {testResult.duration}ms</span>
        </div>
      </div>

      {/* Feedback Section */}
      {!feedbackSubmitted ? (
        <>
          {!showFeedback ? (
            <button
              onClick={() => setShowFeedback(true)}
              className="bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700"
            >
              Provide Feedback
            </button>
          ) : (
            <TestCaseFeedback
              testId={testResult.id}
              testName={testResult.name}
              onSuccess={(feedbackId) => {
                setFeedbackSubmitted(true);
                console.log('Feedback ID:', feedbackId);
              }}
              onError={(error) => {
                console.error('Feedback error:', error);
              }}
            />
          )}
        </>
      ) : (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <p className="text-green-800">Thank you for your feedback!</p>
        </div>
      )}
    </div>
  );
}

export default TestResultsPage;
```

### Example 2: Test Suite Dashboard with Feedback

```tsx
import React from 'react';
import { TestSuiteFeedback } from './components/feedback/TestSuiteFeedback';

interface TestSuite {
  id: string;
  name: string;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  duration: number;
}

function TestSuiteDashboard({ suite }: { suite: TestSuite }) {
  const passRate = (suite.passedTests / suite.totalTests) * 100;

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Suite Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard title="Total Tests" value={suite.totalTests} />
        <StatCard title="Passed" value={suite.passedTests} color="green" />
        <StatCard title="Failed" value={suite.failedTests} color="red" />
        <StatCard title="Pass Rate" value={`${passRate.toFixed(1)}%`} color="blue" />
      </div>

      {/* Feedback Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-xl font-semibold mb-4">Suite Feedback</h3>
        <TestSuiteFeedback
          suiteId={suite.id}
          suiteName={suite.name}
          onSuccess={(feedbackId) => {
            console.log('Suite feedback submitted:', feedbackId);
            // Optionally refresh statistics or navigate
          }}
          onError={(error) => {
            console.error('Feedback submission error:', error);
          }}
        />
      </div>
    </div>
  );
}

function StatCard({ title, value, color = 'gray' }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h4 className="text-sm text-gray-600 mb-2">{title}</h4>
      <p className={`text-3xl font-bold text-${color}-600`}>{value}</p>
    </div>
  );
}

export default TestSuiteDashboard;
```

### Example 3: Standalone Rating Component

```tsx
import React, { useState } from 'react';
import { StarRating } from './components/feedback/StarRating';

function QuickRatingForm() {
  const [rating, setRating] = useState(0);
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async () => {
    // Submit to API
    try {
      const response = await fetch('/api/v1/quick-rating', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rating })
      });
      setSubmitted(true);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <div className="max-w-md mx-auto bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4">
        How was your experience?
      </h3>

      <StarRating
        value={rating}
        onChange={setRating}
        label="Rate your experience"
        size="lg"
        required
      />

      {rating > 0 && !submitted && (
        <button
          onClick={handleSubmit}
          className="mt-4 w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700"
        >
          Submit Rating
        </button>
      )}

      {submitted && (
        <div className="mt-4 text-green-600 text-center">
          Thank you for rating!
        </div>
      )}
    </div>
  );
}

export default QuickRatingForm;
```

---

## Advanced Integration Patterns

### Pattern 1: Feedback Modal

```tsx
import React, { useState } from 'react';
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';

function FeedbackModal({ testId, testName, onClose }: any) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-2xl font-bold">Provide Feedback</h2>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-700"
            >
              ✕
            </button>
          </div>

          <TestCaseFeedback
            testId={testId}
            testName={testName}
            onSuccess={(feedbackId) => {
              console.log('Feedback submitted:', feedbackId);
              setTimeout(onClose, 2000); // Auto-close after 2s
            }}
            onError={(error) => {
              console.error('Error:', error);
            }}
          />
        </div>
      </div>
    </div>
  );
}

// Usage
function TestCard({ test }: any) {
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      <div className="test-card">
        <h3>{test.name}</h3>
        <button onClick={() => setShowModal(true)}>
          Give Feedback
        </button>
      </div>

      {showModal && (
        <FeedbackModal
          testId={test.id}
          testName={test.name}
          onClose={() => setShowModal(false)}
        />
      )}
    </>
  );
}
```

### Pattern 2: Inline Feedback in List

```tsx
import React, { useState } from 'react';
import { StarRating } from './components/feedback/StarRating';

function TestListWithInlineFeedback({ tests }: { tests: any[] }) {
  const [ratings, setRatings] = useState<Record<string, number>>({});

  const handleRatingChange = (testId: string, rating: number) => {
    setRatings(prev => ({ ...prev, [testId]: rating }));

    // Auto-submit after rating
    submitQuickRating(testId, rating);
  };

  const submitQuickRating = async (testId: string, rating: number) => {
    try {
      await fetch('/api/v1/quick-rating', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ testId, rating })
      });
    } catch (error) {
      console.error('Error submitting rating:', error);
    }
  };

  return (
    <div className="space-y-4">
      {tests.map(test => (
        <div key={test.id} className="bg-white rounded-lg shadow p-4">
          <div className="flex justify-between items-center">
            <div>
              <h4 className="font-semibold">{test.name}</h4>
              <p className="text-sm text-gray-600">{test.description}</p>
            </div>
            <div>
              <StarRating
                value={ratings[test.id] || 0}
                onChange={(rating) => handleRatingChange(test.id, rating)}
                size="sm"
                label=""
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
```

### Pattern 3: Feedback with Redux Integration

```tsx
import React from 'react';
import { useDispatch } from 'react-redux';
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';
import { addFeedback, setFeedbackError } from './store/feedbackSlice';

function ReduxIntegratedFeedback({ testId, testName }: any) {
  const dispatch = useDispatch();

  return (
    <TestCaseFeedback
      testId={testId}
      testName={testName}
      onSuccess={(feedbackId) => {
        dispatch(addFeedback({
          id: feedbackId,
          testId,
          timestamp: Date.now()
        }));
      }}
      onError={(error) => {
        dispatch(setFeedbackError(error.message));
      }}
    />
  );
}
```

---

## API Backend Integration

### Required Endpoints

#### 1. Submit Test Case Feedback
```python
# FastAPI endpoint example
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/api/v1/feedback")

class TestCaseFeedbackPayload(BaseModel):
    testId: str
    rating: int  # 1-5
    helpful: bool | None
    foundIssue: bool
    comment: str
    categories: List[str]
    timestamp: str

@router.post("/test-case")
async def submit_test_case_feedback(
    payload: TestCaseFeedbackPayload,
    user_id: str = Depends(get_current_user_id)
):
    # Save to database
    feedback_id = await save_feedback(payload, user_id)

    return {
        "success": True,
        "feedbackId": feedback_id,
        "message": "Feedback submitted successfully"
    }
```

#### 2. Submit Test Suite Feedback
```python
class TestSuiteFeedbackPayload(BaseModel):
    suiteId: str
    overallRating: int  # 1-5
    coverageRating: int  # 0-100
    qualityRating: int  # 0-100
    coverageGaps: str
    improvementSuggestions: str
    timestamp: str

@router.post("/test-suite")
async def submit_test_suite_feedback(
    payload: TestSuiteFeedbackPayload,
    user_id: str = Depends(get_current_user_id)
):
    feedback_id = await save_suite_feedback(payload, user_id)

    return {
        "success": True,
        "feedbackId": feedback_id,
        "message": "Test suite feedback submitted successfully"
    }
```

#### 3. Get Feedback Statistics
```python
@router.get("/statistics")
async def get_feedback_statistics():
    stats = await calculate_feedback_stats()

    return {
        "totalFeedback": stats.total,
        "averageRating": stats.avg_rating,
        "helpfulPercentage": stats.helpful_pct,
        "issuesReported": stats.issues_count,
        "categoryBreakdown": stats.category_breakdown,
        "lastUpdated": datetime.utcnow().isoformat()
    }
```

### Database Schema

```sql
-- PostgreSQL schema
CREATE TABLE feedback_test_case (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    helpful BOOLEAN,
    found_issue BOOLEAN DEFAULT FALSE,
    comment TEXT NOT NULL,
    categories TEXT[] NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE feedback_test_suite (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suite_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    overall_rating INTEGER CHECK (overall_rating >= 1 AND overall_rating <= 5),
    coverage_rating INTEGER CHECK (coverage_rating >= 0 AND coverage_rating <= 100),
    quality_rating INTEGER CHECK (quality_rating >= 0 AND quality_rating <= 100),
    coverage_gaps TEXT,
    improvement_suggestions TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for performance
CREATE INDEX idx_feedback_test_case_test_id ON feedback_test_case(test_id);
CREATE INDEX idx_feedback_test_case_user_id ON feedback_test_case(user_id);
CREATE INDEX idx_feedback_test_suite_suite_id ON feedback_test_suite(suite_id);
```

---

## Testing the Integration

### Unit Test Example
```tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';
import * as feedbackService from './services/feedbackService';

jest.mock('./services/feedbackService');

test('submits feedback successfully', async () => {
  const mockResponse = {
    success: true,
    feedbackId: 'feedback-123',
    message: 'Success'
  };

  (feedbackService.submitTestCaseFeedback as jest.Mock)
    .mockResolvedValue(mockResponse);

  const onSuccess = jest.fn();

  render(
    <TestCaseFeedback
      testId="test-123"
      onSuccess={onSuccess}
    />
  );

  // Fill out form and submit
  // ... test interactions ...

  await waitFor(() => {
    expect(onSuccess).toHaveBeenCalledWith('feedback-123');
  });
});
```

### E2E Test Example (Playwright)
```typescript
import { test, expect } from '@playwright/test';

test('submit test case feedback', async ({ page }) => {
  await page.goto('/test-results/test-123');

  // Click feedback button
  await page.click('text=Provide Feedback');

  // Fill out form
  await page.click('[aria-label="4 stars"]');
  await page.click('text=👍 Helpful');
  await page.check('text=I found an issue');
  await page.fill('textarea[placeholder*="thoughts"]', 'Great test!');
  await page.click('text=Accuracy');

  // Submit
  await page.click('text=Submit Feedback');

  // Verify success
  await expect(page.locator('text=Feedback submitted successfully'))
    .toBeVisible();
});
```

---

## Troubleshooting

### Common Issues

#### Issue 1: CORS Errors
```typescript
// In feedbackService.ts, add credentials
this.client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true, // Add this
  headers: {
    'Content-Type': 'application/json'
  }
});
```

#### Issue 2: Authentication Token Not Sent
```typescript
// Ensure token is stored correctly
localStorage.setItem('authToken', yourToken);

// Or use custom header
config.headers['X-Auth-Token'] = yourToken;
```

#### Issue 3: Form Not Resetting
```typescript
// Ensure all state is reset in component
const resetForm = () => {
  setRating(0);
  setHelpful(null);
  setFoundIssue(false);
  setComment('');
  setCategories([]);
};
```

---

## Performance Optimization

### Lazy Loading
```tsx
import React, { lazy, Suspense } from 'react';

const TestCaseFeedback = lazy(() =>
  import('./components/feedback/TestCaseFeedback')
);

function App() {
  return (
    <Suspense fallback={<div>Loading feedback form...</div>}>
      <TestCaseFeedback testId="test-123" />
    </Suspense>
  );
}
```

### Memoization
```tsx
import React, { memo } from 'react';
import { StarRating } from './components/feedback/StarRating';

const MemoizedStarRating = memo(StarRating);

// Use MemoizedStarRating in lists for better performance
```

---

## Support

For issues or questions:
1. Check component README: `/src/components/feedback/README.md`
2. Review test examples: `/src/tests/components/`
3. Check type definitions: `/src/types/feedback.ts`
4. Review this integration guide

---

**Ready to integrate!** 🚀
