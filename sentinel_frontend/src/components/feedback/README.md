# Feedback Components

Comprehensive feedback UI components for the Sentinel platform, implementing Phase 1, Week 2 (Days 8-10) requirements.

## Components

### StarRating
Interactive star rating component with full keyboard navigation and accessibility support.

**Features:**
- 1-5 star rating (configurable)
- Hover effects with visual feedback
- Keyboard navigation (Arrow keys, Enter, Space)
- WCAG 2.1 AA compliant
- Customizable size and color
- Disabled state support

**Usage:**
```tsx
import { StarRating } from './components/feedback/StarRating';

<StarRating
  value={rating}
  onChange={setRating}
  label="Rate this test case"
  required
  size="md"
/>
```

### TestCaseFeedback
Comprehensive feedback form for individual test cases.

**Features:**
- Star rating (1-5)
- Helpful/Not Helpful toggle
- Found Issue checkbox
- Comment textarea (2000 char limit with counter)
- Category tags (7 categories)
- Form validation
- Success/error toast notifications
- Loading states

**Usage:**
```tsx
import { TestCaseFeedback } from './components/feedback/TestCaseFeedback';

<TestCaseFeedback
  testId="test-123"
  testName="User Authentication Test"
  onSuccess={(feedbackId) => console.log('Submitted:', feedbackId)}
  onError={(error) => console.error('Error:', error)}
/>
```

### TestSuiteFeedback
Feedback form for entire test suites with rating sliders.

**Features:**
- Overall star rating
- Coverage rating slider (0-100%)
- Quality rating slider (0-100%)
- Coverage gaps textarea
- Improvement suggestions textarea
- Form validation
- Toast notifications

**Usage:**
```tsx
import { TestSuiteFeedback } from './components/feedback/TestSuiteFeedback';

<TestSuiteFeedback
  suiteId="suite-456"
  suiteName="API Integration Test Suite"
  onSuccess={(feedbackId) => console.log('Submitted:', feedbackId)}
/>
```

## API Service

### feedbackService
Axios-based service with retry logic and error handling.

**Methods:**
- `submitTestCaseFeedback(payload)` - Submit test case feedback
- `submitTestSuiteFeedback(payload)` - Submit test suite feedback
- `getFeedbackStats()` - Get feedback statistics
- `getTestCaseFeedback(testId)` - Get feedback for specific test
- `getTestSuiteFeedback(suiteId)` - Get feedback for specific suite
- `deleteFeedback(feedbackId)` - Delete feedback (admin only)

**Features:**
- Automatic retry (3 attempts with exponential backoff)
- JWT authentication via localStorage
- Comprehensive error handling
- 10 second timeout

## Types

TypeScript types are defined in `/types/feedback.ts`:
- `FeedbackCategory` - Feedback category enum
- `TestCaseFeedbackPayload` - Test case feedback data
- `TestSuiteFeedbackPayload` - Test suite feedback data
- `FeedbackResponse` - API response structure
- `FeedbackStatistics` - Statistics data structure

## Styling

Components use Tailwind CSS with custom CSS in `FeedbackForm.css`:
- Star hover animations
- Slider custom styling
- Toast slide-in animation
- Focus states for accessibility
- Responsive design (mobile-first)

## Testing

Comprehensive test suites with 90%+ coverage:
- **StarRating.test.tsx** - 45+ tests
- **TestCaseFeedback.test.tsx** - 40+ tests
- **TestSuiteFeedback.test.tsx** - 35+ tests

**Test Coverage:**
- Rendering in all states
- User interactions
- Form validation
- API integration (mocked)
- Keyboard navigation
- Accessibility (ARIA labels, focus management)
- Error handling
- Edge cases

## Accessibility

All components follow WCAG 2.1 AA standards:
- Proper ARIA labels and roles
- Keyboard navigation support
- Focus management
- Color contrast ratios
- Screen reader compatibility
- Live regions for notifications

## Dependencies

```json
{
  "react": "^18.x",
  "axios": "^1.x",
  "@testing-library/react": "^14.x",
  "@testing-library/user-event": "^14.x",
  "jest": "^29.x"
}
```

## Environment Variables

```bash
REACT_APP_API_URL=http://localhost:8000/api/v1
```

## Running Tests

```bash
# Run all feedback component tests
npm test -- src/tests/components/

# Run specific test file
npm test StarRating.test.tsx

# Run with coverage
npm test -- --coverage src/tests/components/
```

## Future Enhancements

- [ ] Rich text editor for comments
- [ ] File attachment support
- [ ] Real-time feedback analytics dashboard
- [ ] AI-powered feedback categorization
- [ ] Feedback sentiment analysis
- [ ] Export feedback reports
- [ ] Bulk feedback actions
