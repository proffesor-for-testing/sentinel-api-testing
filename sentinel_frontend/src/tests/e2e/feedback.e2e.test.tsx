/**
 * End-to-End Feedback Tests (React + Playwright)
 *
 * Tests user feedback functionality through the UI:
 * - User can submit feedback through UI
 * - Feedback appears in statistics
 * - Real-time updates work
 * - Error handling works correctly
 */

import { test, expect, Page } from '@playwright/test';

// Test configuration
test.describe.configure({ mode: 'parallel' });

test.describe('Feedback Submission Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to feedback page
    await page.goto('http://localhost:3000/feedback');
    await page.waitForLoadState('networkidle');
  });

  test('should display feedback form', async ({ page }) => {
    // Verify form elements are present
    await expect(page.locator('[data-testid="feedback-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="test-id-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="rating-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="submit-feedback-btn"]')).toBeVisible();
  });

  test('should submit feedback successfully', async ({ page }) => {
    // Fill out feedback form
    await page.fill('[data-testid="test-id-input"]', 'test_001');

    // Click 5-star rating
    await page.click('[data-testid="rating-star-5"]');

    // Check helpful checkbox
    await page.check('[data-testid="helpful-checkbox"]');

    // Check found issue checkbox
    await page.check('[data-testid="found-issue-checkbox"]');

    // Fill comment
    await page.fill('[data-testid="comment-input"]', 'Excellent test case! Found a critical bug.');

    // Mock API response
    await page.route('**/api/feedback', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          feedback_id: 'fb_e2e_001',
          status: 'accepted',
          verdict: 'positive',
          reward: 0.95,
          processed_at: new Date().toISOString()
        })
      });
    });

    // Submit form
    await page.click('[data-testid="submit-feedback-btn"]');

    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Feedback submitted successfully');

    // Verify feedback ID is displayed
    await expect(page.locator('[data-testid="feedback-id"]')).toContainText('fb_e2e_001');
  });

  test('should validate required fields', async ({ page }) => {
    // Try to submit without filling required fields
    await page.click('[data-testid="submit-feedback-btn"]');

    // Verify validation errors
    await expect(page.locator('[data-testid="test-id-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="test-id-error"]')).toContainText('Test ID is required');

    await expect(page.locator('[data-testid="rating-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="rating-error"]')).toContainText('Please select a rating');
  });

  test('should handle API errors gracefully', async ({ page }) => {
    // Fill out form
    await page.fill('[data-testid="test-id-input"]', 'test_002');
    await page.click('[data-testid="rating-star-4"]');

    // Mock API error
    await page.route('**/api/feedback', async route => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'internal_error',
          message: 'An internal error occurred'
        })
      });
    });

    // Submit form
    await page.click('[data-testid="submit-feedback-btn"]');

    // Verify error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Failed to submit feedback');

    // Verify form is not cleared (user can retry)
    await expect(page.locator('[data-testid="test-id-input"]')).toHaveValue('test_002');
  });

  test('should enforce character limit on comment', async ({ page }) => {
    const longComment = 'x'.repeat(1001); // Exceeds 1000 char limit

    await page.fill('[data-testid="comment-input"]', longComment);

    // Verify character counter
    await expect(page.locator('[data-testid="char-count"]')).toContainText('1001 / 1000');

    // Verify validation error
    await expect(page.locator('[data-testid="comment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="comment-error"]')).toContainText('Comment must be 1000 characters or less');

    // Submit button should be disabled
    await expect(page.locator('[data-testid="submit-feedback-btn"]')).toBeDisabled();
  });
});

test.describe('Feedback Statistics Display', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to statistics page
    await page.goto('http://localhost:3000/statistics');
    await page.waitForLoadState('networkidle');
  });

  test('should display feedback statistics', async ({ page }) => {
    // Mock statistics API
    await page.route('**/api/feedback/statistics', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_feedback: 150,
          avg_rating: 4.2,
          helpful_percentage: 75.0,
          issues_found: 45,
          feedback_by_rating: {
            5: 60,
            4: 40,
            3: 30,
            2: 15,
            1: 5
          }
        })
      });
    });

    await page.reload();

    // Verify statistics are displayed
    await expect(page.locator('[data-testid="total-feedback"]')).toContainText('150');
    await expect(page.locator('[data-testid="avg-rating"]')).toContainText('4.2');
    await expect(page.locator('[data-testid="helpful-percentage"]')).toContainText('75%');
    await expect(page.locator('[data-testid="issues-found"]')).toContainText('45');
  });

  test('should display feedback chart', async ({ page }) => {
    // Mock statistics API
    await page.route('**/api/feedback/statistics', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_feedback: 150,
          feedback_by_rating: {
            5: 60,
            4: 40,
            3: 30,
            2: 15,
            1: 5
          }
        })
      });
    });

    await page.reload();

    // Verify chart is rendered
    await expect(page.locator('[data-testid="feedback-chart"]')).toBeVisible();

    // Verify chart has correct number of bars
    const bars = page.locator('[data-testid="feedback-chart"] .recharts-bar-rectangle');
    await expect(bars).toHaveCount(5); // 5 rating levels
  });

  test('should filter feedback by date range', async ({ page }) => {
    // Select date range
    await page.click('[data-testid="date-range-picker"]');
    await page.click('[data-testid="last-7-days"]');

    // Mock filtered API
    await page.route('**/api/feedback/statistics?days=7', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_feedback: 45,
          avg_rating: 4.5,
          date_range: 'last_7_days'
        })
      });
    });

    // Wait for update
    await page.waitForResponse(response =>
      response.url().includes('/api/feedback/statistics?days=7') && response.status() === 200
    );

    // Verify filtered statistics
    await expect(page.locator('[data-testid="total-feedback"]')).toContainText('45');
  });
});

test.describe('Real-time Feedback Updates', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:3000/feedback/live');
    await page.waitForLoadState('networkidle');
  });

  test('should show real-time feedback updates', async ({ page }) => {
    // Initial state
    const initialCount = await page.locator('[data-testid="feedback-count"]').textContent();

    // Simulate WebSocket message for new feedback
    await page.evaluate(() => {
      const event = new CustomEvent('feedback-update', {
        detail: {
          feedback_id: 'fb_realtime_001',
          test_id: 'test_003',
          rating: 5,
          verdict: 'positive',
          timestamp: new Date().toISOString()
        }
      });
      window.dispatchEvent(event);
    });

    // Wait for update
    await page.waitForTimeout(500);

    // Verify new feedback appears in list
    await expect(page.locator('[data-testid="feedback-item-fb_realtime_001"]')).toBeVisible();

    // Verify count increased
    const newCount = await page.locator('[data-testid="feedback-count"]').textContent();
    expect(parseInt(newCount!)).toBeGreaterThan(parseInt(initialCount!));
  });

  test('should display real-time quality metrics', async ({ page }) => {
    // Mock initial metrics
    await page.route('**/api/feedback/metrics', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          current_quality_score: 0.85,
          tests_generated: 120,
          avg_rating: 4.3
        })
      });
    });

    await page.reload();

    // Verify initial metrics
    await expect(page.locator('[data-testid="quality-score"]')).toContainText('85%');

    // Simulate real-time metric update
    await page.evaluate(() => {
      const event = new CustomEvent('metrics-update', {
        detail: {
          current_quality_score: 0.87,
          tests_generated: 125,
          avg_rating: 4.4
        }
      });
      window.dispatchEvent(event);
    });

    // Wait for update
    await page.waitForTimeout(500);

    // Verify metrics updated
    await expect(page.locator('[data-testid="quality-score"]')).toContainText('87%');
    await expect(page.locator('[data-testid="tests-generated"]')).toContainText('125');
  });
});

test.describe('Feedback History', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('http://localhost:3000/feedback/history');
    await page.waitForLoadState('networkidle');
  });

  test('should display feedback history', async ({ page }) => {
    // Mock history API
    await page.route('**/api/feedback?page=1&page_size=10', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          feedback: [
            {
              feedback_id: 'fb_001',
              test_id: 'test_001',
              rating: 5,
              verdict: 'positive',
              submitted_at: '2025-10-28T10:00:00Z'
            },
            {
              feedback_id: 'fb_002',
              test_id: 'test_002',
              rating: 4,
              verdict: 'positive',
              submitted_at: '2025-10-28T09:55:00Z'
            }
          ],
          total: 100,
          page: 1,
          page_size: 10,
          has_more: true
        })
      });
    });

    await page.reload();

    // Verify feedback items are displayed
    await expect(page.locator('[data-testid="feedback-item-fb_001"]')).toBeVisible();
    await expect(page.locator('[data-testid="feedback-item-fb_002"]')).toBeVisible();

    // Verify pagination info
    await expect(page.locator('[data-testid="pagination-info"]')).toContainText('1-10 of 100');
  });

  test('should paginate feedback history', async ({ page }) => {
    // Mock page 1
    await page.route('**/api/feedback?page=1&page_size=10', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          feedback: Array(10).fill(null).map((_, i) => ({
            feedback_id: `fb_${i + 1}`,
            test_id: `test_${i + 1}`,
            rating: 4
          })),
          total: 25,
          page: 1,
          has_more: true
        })
      });
    });

    await page.reload();

    // Click next page
    await page.route('**/api/feedback?page=2&page_size=10', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          feedback: Array(10).fill(null).map((_, i) => ({
            feedback_id: `fb_${i + 11}`,
            test_id: `test_${i + 11}`,
            rating: 3
          })),
          total: 25,
          page: 2,
          has_more: true
        })
      });
    });

    await page.click('[data-testid="next-page-btn"]');

    // Verify page 2 content
    await expect(page.locator('[data-testid="feedback-item-fb_11"]')).toBeVisible();
  });

  test('should search feedback by test ID', async ({ page }) => {
    // Enter search term
    await page.fill('[data-testid="search-input"]', 'test_001');

    // Mock search API
    await page.route('**/api/feedback?search=test_001', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          feedback: [
            {
              feedback_id: 'fb_001',
              test_id: 'test_001',
              rating: 5
            }
          ],
          total: 1
        })
      });
    });

    // Click search button
    await page.click('[data-testid="search-btn"]');

    // Wait for results
    await page.waitForResponse(response =>
      response.url().includes('search=test_001') && response.status() === 200
    );

    // Verify filtered results
    await expect(page.locator('[data-testid="feedback-item-fb_001"]')).toBeVisible();
    await expect(page.locator('[data-testid="search-results-count"]')).toContainText('1 result');
  });
});

test.describe('Accessibility', () => {
  test('feedback form should be keyboard accessible', async ({ page }) => {
    await page.goto('http://localhost:3000/feedback');

    // Tab through form
    await page.keyboard.press('Tab'); // Focus test ID
    await page.keyboard.type('test_001');

    await page.keyboard.press('Tab'); // Focus rating
    await page.keyboard.press('Space'); // Select rating

    await page.keyboard.press('Tab'); // Focus helpful checkbox
    await page.keyboard.press('Space'); // Check it

    await page.keyboard.press('Tab'); // Focus comment
    await page.keyboard.type('Great test!');

    await page.keyboard.press('Tab'); // Focus submit button

    // Mock API
    await page.route('**/api/feedback', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ feedback_id: 'fb_001', status: 'accepted' })
      });
    });

    await page.keyboard.press('Enter'); // Submit

    // Verify submission succeeded
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('should have proper ARIA labels', async ({ page }) => {
    await page.goto('http://localhost:3000/feedback');

    // Verify ARIA labels
    await expect(page.locator('[aria-label="Test ID"]')).toBeVisible();
    await expect(page.locator('[aria-label="Rating"]')).toBeVisible();
    await expect(page.locator('[aria-label="Comment"]')).toBeVisible();
    await expect(page.locator('[aria-label="Submit feedback"]')).toBeVisible();
  });
});
