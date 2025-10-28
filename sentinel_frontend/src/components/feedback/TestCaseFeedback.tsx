import React, { useState, useCallback } from 'react';
import { StarRating } from './StarRating';
import { submitTestCaseFeedback } from '../../services/feedbackService';
import type { FeedbackCategory, TestCaseFeedbackPayload } from '../../types/feedback';

export interface TestCaseFeedbackProps {
  testId: string;
  testName?: string;
  onSuccess?: (feedbackId: string) => void;
  onError?: (error: Error) => void;
}

const CATEGORY_OPTIONS: Array<{ value: FeedbackCategory; label: string }> = [
  { value: 'accuracy', label: 'Accuracy' },
  { value: 'completeness', label: 'Completeness' },
  { value: 'performance', label: 'Performance' },
  { value: 'usability', label: 'Usability' },
  { value: 'bug', label: 'Bug Report' },
  { value: 'feature-request', label: 'Feature Request' },
  { value: 'other', label: 'Other' }
];

const MAX_COMMENT_LENGTH = 2000;

/**
 * TestCaseFeedback Component
 * Comprehensive feedback form for individual test cases
 */
export const TestCaseFeedback: React.FC<TestCaseFeedbackProps> = ({
  testId,
  testName,
  onSuccess,
  onError
}) => {
  const [rating, setRating] = useState<number>(0);
  const [helpful, setHelpful] = useState<boolean | null>(null);
  const [foundIssue, setFoundIssue] = useState<boolean>(false);
  const [comment, setComment] = useState<string>('');
  const [categories, setCategories] = useState<FeedbackCategory[]>([]);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [showToast, setShowToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const remainingChars = MAX_COMMENT_LENGTH - comment.length;

  const handleCategoryToggle = useCallback((category: FeedbackCategory) => {
    setCategories(prev =>
      prev.includes(category)
        ? prev.filter(c => c !== category)
        : [...prev, category]
    );
  }, []);

  const validateForm = useCallback((): boolean => {
    if (rating === 0) {
      setShowToast({ type: 'error', message: 'Please provide a rating' });
      return false;
    }
    if (comment.trim().length === 0) {
      setShowToast({ type: 'error', message: 'Please provide a comment' });
      return false;
    }
    if (categories.length === 0) {
      setShowToast({ type: 'error', message: 'Please select at least one category' });
      return false;
    }
    return true;
  }, [rating, comment, categories]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);
    setShowToast(null);

    const payload: TestCaseFeedbackPayload = {
      testId,
      rating,
      helpful,
      foundIssue,
      comment: comment.trim(),
      categories,
      timestamp: new Date().toISOString()
    };

    try {
      const response = await submitTestCaseFeedback(payload);
      setShowToast({ type: 'success', message: 'Feedback submitted successfully!' });

      // Reset form
      setRating(0);
      setHelpful(null);
      setFoundIssue(false);
      setComment('');
      setCategories([]);

      if (onSuccess) {
        onSuccess(response.feedbackId);
      }

      // Auto-hide success toast
      setTimeout(() => setShowToast(null), 3000);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to submit feedback';
      setShowToast({ type: 'error', message: errorMessage });

      if (onError) {
        onError(error instanceof Error ? error : new Error(errorMessage));
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="test-case-feedback bg-white rounded-lg shadow-md p-6 max-w-2xl mx-auto">
      {testName && (
        <h3 className="text-xl font-semibold text-gray-800 mb-4">
          Provide Feedback: {testName}
        </h3>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Star Rating */}
        <div>
          <StarRating
            value={rating}
            onChange={setRating}
            label="How would you rate this test case?"
            required
          />
        </div>

        {/* Helpful/Not Helpful Toggle */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Was this test case helpful?
          </label>
          <div className="flex space-x-4">
            <button
              type="button"
              onClick={() => setHelpful(true)}
              className={`
                px-6 py-2 rounded-md font-medium transition-all
                ${helpful === true
                  ? 'bg-green-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'}
              `}
              aria-pressed={helpful === true}
            >
              👍 Helpful
            </button>
            <button
              type="button"
              onClick={() => setHelpful(false)}
              className={`
                px-6 py-2 rounded-md font-medium transition-all
                ${helpful === false
                  ? 'bg-red-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'}
              `}
              aria-pressed={helpful === false}
            >
              👎 Not Helpful
            </button>
          </div>
        </div>

        {/* Found Issue Checkbox */}
        <div className="flex items-center">
          <input
            type="checkbox"
            id="foundIssue"
            checked={foundIssue}
            onChange={(e) => setFoundIssue(e.target.checked)}
            className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
          />
          <label htmlFor="foundIssue" className="ml-2 text-sm font-medium text-gray-700">
            I found an issue with this test case
          </label>
        </div>

        {/* Categories */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Feedback Categories <span className="text-red-500">*</span>
          </label>
          <div className="flex flex-wrap gap-2">
            {CATEGORY_OPTIONS.map(({ value, label }) => (
              <button
                key={value}
                type="button"
                onClick={() => handleCategoryToggle(value)}
                className={`
                  px-4 py-2 rounded-full text-sm font-medium transition-all
                  ${categories.includes(value)
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'}
                `}
                aria-pressed={categories.includes(value)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Comment Textarea */}
        <div>
          <label htmlFor="comment" className="block text-sm font-medium text-gray-700 mb-2">
            Additional Comments <span className="text-red-500">*</span>
          </label>
          <textarea
            id="comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            maxLength={MAX_COMMENT_LENGTH}
            rows={5}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
            placeholder="Share your thoughts about this test case..."
            required
          />
          <div className="mt-1 text-sm text-gray-500 text-right">
            {remainingChars} characters remaining
          </div>
        </div>

        {/* Submit Button */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting}
            className={`
              px-6 py-3 rounded-md font-medium transition-all
              ${isSubmitting
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 text-white'}
            `}
          >
            {isSubmitting ? (
              <span className="flex items-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Submitting...
              </span>
            ) : (
              'Submit Feedback'
            )}
          </button>
        </div>
      </form>

      {/* Toast Notification */}
      {showToast && (
        <div
          className={`
            fixed top-4 right-4 px-6 py-4 rounded-lg shadow-lg z-50 transition-all
            ${showToast.type === 'success' ? 'bg-green-500' : 'bg-red-500'}
            text-white
          `}
          role="alert"
          aria-live="polite"
        >
          {showToast.message}
        </div>
      )}
    </div>
  );
};

export default TestCaseFeedback;
