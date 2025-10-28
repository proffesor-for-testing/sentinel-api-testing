import React, { useState, useCallback } from 'react';
import { StarRating } from './StarRating';
import { submitTestSuiteFeedback } from '../../services/feedbackService';
import type { TestSuiteFeedbackPayload } from '../../types/feedback';

export interface TestSuiteFeedbackProps {
  suiteId: string;
  suiteName?: string;
  onSuccess?: (feedbackId: string) => void;
  onError?: (error: Error) => void;
}

/**
 * TestSuiteFeedback Component
 * Comprehensive feedback form for test suites with ratings and suggestions
 */
export const TestSuiteFeedback: React.FC<TestSuiteFeedbackProps> = ({
  suiteId,
  suiteName,
  onSuccess,
  onError
}) => {
  const [overallRating, setOverallRating] = useState<number>(0);
  const [coverageRating, setCoverageRating] = useState<number>(50);
  const [qualityRating, setQualityRating] = useState<number>(50);
  const [coverageGaps, setCoverageGaps] = useState<string>('');
  const [improvementSuggestions, setImprovementSuggestions] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [showToast, setShowToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const validateForm = useCallback((): boolean => {
    if (overallRating === 0) {
      setShowToast({ type: 'error', message: 'Please provide an overall rating' });
      return false;
    }
    return true;
  }, [overallRating]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsSubmitting(true);
    setShowToast(null);

    const payload: TestSuiteFeedbackPayload = {
      suiteId,
      overallRating,
      coverageRating,
      qualityRating,
      coverageGaps: coverageGaps.trim(),
      improvementSuggestions: improvementSuggestions.trim(),
      timestamp: new Date().toISOString()
    };

    try {
      const response = await submitTestSuiteFeedback(payload);
      setShowToast({ type: 'success', message: 'Test suite feedback submitted successfully!' });

      // Reset form
      setOverallRating(0);
      setCoverageRating(50);
      setQualityRating(50);
      setCoverageGaps('');
      setImprovementSuggestions('');

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
    <div className="test-suite-feedback bg-white rounded-lg shadow-md p-6 max-w-3xl mx-auto">
      {suiteName && (
        <h3 className="text-xl font-semibold text-gray-800 mb-4">
          Test Suite Feedback: {suiteName}
        </h3>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Overall Rating */}
        <div>
          <StarRating
            value={overallRating}
            onChange={setOverallRating}
            label="Overall Test Suite Rating"
            required
          />
        </div>

        {/* Coverage Rating Slider */}
        <div>
          <label htmlFor="coverageRating" className="block text-sm font-medium text-gray-700 mb-2">
            Coverage Rating: {coverageRating}%
          </label>
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-600">0%</span>
            <input
              type="range"
              id="coverageRating"
              min="0"
              max="100"
              value={coverageRating}
              onChange={(e) => setCoverageRating(Number(e.target.value))}
              className="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
              style={{
                background: `linear-gradient(to right, #3b82f6 0%, #3b82f6 ${coverageRating}%, #e5e7eb ${coverageRating}%, #e5e7eb 100%)`
              }}
            />
            <span className="text-sm text-gray-600">100%</span>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            Rate the completeness of test coverage
          </div>
        </div>

        {/* Quality Rating Slider */}
        <div>
          <label htmlFor="qualityRating" className="block text-sm font-medium text-gray-700 mb-2">
            Quality Rating: {qualityRating}%
          </label>
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-600">0%</span>
            <input
              type="range"
              id="qualityRating"
              min="0"
              max="100"
              value={qualityRating}
              onChange={(e) => setQualityRating(Number(e.target.value))}
              className="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
              style={{
                background: `linear-gradient(to right, #10b981 0%, #10b981 ${qualityRating}%, #e5e7eb ${qualityRating}%, #e5e7eb 100%)`
              }}
            />
            <span className="text-sm text-gray-600">100%</span>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            Rate the overall quality of test cases
          </div>
        </div>

        {/* Coverage Gaps Textarea */}
        <div>
          <label htmlFor="coverageGaps" className="block text-sm font-medium text-gray-700 mb-2">
            Coverage Gaps (Optional)
          </label>
          <textarea
            id="coverageGaps"
            value={coverageGaps}
            onChange={(e) => setCoverageGaps(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
            placeholder="Describe any gaps in test coverage you've identified..."
          />
        </div>

        {/* Improvement Suggestions Textarea */}
        <div>
          <label htmlFor="improvementSuggestions" className="block text-sm font-medium text-gray-700 mb-2">
            Improvement Suggestions (Optional)
          </label>
          <textarea
            id="improvementSuggestions"
            value={improvementSuggestions}
            onChange={(e) => setImprovementSuggestions(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
            placeholder="Share suggestions for improving this test suite..."
          />
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

export default TestSuiteFeedback;
