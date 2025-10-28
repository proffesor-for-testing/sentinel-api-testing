import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TestCaseFeedback } from '../../components/feedback/TestCaseFeedback';
import * as feedbackService from '../../services/feedbackService';

// Mock the feedback service
jest.mock('../../services/feedbackService');

describe('TestCaseFeedback Component', () => {
  const mockTestId = 'test-123';
  const mockTestName = 'User Authentication Test';
  const mockOnSuccess = jest.fn();
  const mockOnError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render feedback form', () => {
      render(<TestCaseFeedback testId={mockTestId} />);

      expect(screen.getByText('How would you rate this test case?')).toBeInTheDocument();
      expect(screen.getByText('Was this test case helpful?')).toBeInTheDocument();
      expect(screen.getByLabelText('I found an issue with this test case')).toBeInTheDocument();
      expect(screen.getByLabelText('Additional Comments *')).toBeInTheDocument();
    });

    it('should render test name when provided', () => {
      render(<TestCaseFeedback testId={mockTestId} testName={mockTestName} />);

      expect(screen.getByText(`Provide Feedback: ${mockTestName}`)).toBeInTheDocument();
    });

    it('should render all category options', () => {
      render(<TestCaseFeedback testId={mockTestId} />);

      expect(screen.getByText('Accuracy')).toBeInTheDocument();
      expect(screen.getByText('Completeness')).toBeInTheDocument();
      expect(screen.getByText('Performance')).toBeInTheDocument();
      expect(screen.getByText('Usability')).toBeInTheDocument();
      expect(screen.getByText('Bug Report')).toBeInTheDocument();
      expect(screen.getByText('Feature Request')).toBeInTheDocument();
      expect(screen.getByText('Other')).toBeInTheDocument();
    });

    it('should show character counter', () => {
      render(<TestCaseFeedback testId={mockTestId} />);

      expect(screen.getByText('2000 characters remaining')).toBeInTheDocument();
    });
  });

  describe('Form Interaction', () => {
    it('should update rating when star is clicked', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      expect(screen.getByText('3 / 5')).toBeInTheDocument();
    });

    it('should toggle helpful state', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const helpfulBtn = screen.getByText('👍 Helpful');
      await user.click(helpfulBtn);

      expect(helpfulBtn).toHaveAttribute('aria-pressed', 'true');
    });

    it('should toggle not helpful state', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const notHelpfulBtn = screen.getByText('👎 Not Helpful');
      await user.click(notHelpfulBtn);

      expect(notHelpfulBtn).toHaveAttribute('aria-pressed', 'true');
    });

    it('should toggle found issue checkbox', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const checkbox = screen.getByLabelText('I found an issue with this test case');
      await user.click(checkbox);

      expect(checkbox).toBeChecked();
    });

    it('should update comment textarea', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Great test!');

      expect(textarea).toHaveValue('Great test!');
      expect(screen.getByText('1989 characters remaining')).toBeInTheDocument();
    });

    it('should enforce maximum comment length', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      const longText = 'a'.repeat(2001);
      await user.type(textarea, longText);

      expect(textarea.value.length).toBeLessThanOrEqual(2000);
    });

    it('should toggle category selection', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      expect(accuracyBtn).toHaveAttribute('aria-pressed', 'true');

      await user.click(accuracyBtn);
      expect(accuracyBtn).toHaveAttribute('aria-pressed', 'false');
    });

    it('should allow multiple category selections', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const accuracyBtn = screen.getByText('Accuracy');
      const performanceBtn = screen.getByText('Performance');

      await user.click(accuracyBtn);
      await user.click(performanceBtn);

      expect(accuracyBtn).toHaveAttribute('aria-pressed', 'true');
      expect(performanceBtn).toHaveAttribute('aria-pressed', 'true');
    });
  });

  describe('Form Validation', () => {
    it('should show error when submitting without rating', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Please provide a rating')).toBeInTheDocument();
      });
    });

    it('should show error when submitting without comment', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      // Set rating
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      // Select category
      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Please provide a comment')).toBeInTheDocument();
      });
    });

    it('should show error when submitting without categories', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      // Set rating
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      // Add comment
      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Great test!');

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Please select at least one category')).toBeInTheDocument();
      });
    });
  });

  describe('Form Submission', () => {
    it('should submit valid feedback successfully', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-456',
        message: 'Feedback submitted successfully'
      };

      (feedbackService.submitTestCaseFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(
        <TestCaseFeedback
          testId={mockTestId}
          onSuccess={mockOnSuccess}
        />
      );

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[3]); // 4 stars

      const helpfulBtn = screen.getByText('👍 Helpful');
      await user.click(helpfulBtn);

      const checkbox = screen.getByLabelText('I found an issue with this test case');
      await user.click(checkbox);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Excellent test coverage!');

      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(feedbackService.submitTestCaseFeedback).toHaveBeenCalledWith(
          expect.objectContaining({
            testId: mockTestId,
            rating: 4,
            helpful: true,
            foundIssue: true,
            comment: 'Excellent test coverage!',
            categories: ['accuracy']
          })
        );
        expect(mockOnSuccess).toHaveBeenCalledWith('feedback-456');
        expect(screen.getByText('Feedback submitted successfully!')).toBeInTheDocument();
      });
    });

    it('should show loading state during submission', async () => {
      const user = userEvent.setup();
      (feedbackService.submitTestCaseFeedback as jest.Mock).mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 1000))
      );

      render(<TestCaseFeedback testId={mockTestId} />);

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Test comment');

      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      expect(screen.getByText('Submitting...')).toBeInTheDocument();
      expect(submitBtn).toBeDisabled();
    });

    it('should handle submission error', async () => {
      const user = userEvent.setup();
      const mockError = new Error('Network error');

      (feedbackService.submitTestCaseFeedback as jest.Mock).mockRejectedValue(mockError);

      render(
        <TestCaseFeedback
          testId={mockTestId}
          onError={mockOnError}
        />
      );

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Test comment');

      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Network error')).toBeInTheDocument();
        expect(mockOnError).toHaveBeenCalled();
      });
    });

    it('should reset form after successful submission', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-789',
        message: 'Success'
      };

      (feedbackService.submitTestCaseFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(<TestCaseFeedback testId={mockTestId} />);

      // Fill and submit form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const textarea = screen.getByPlaceholderText('Share your thoughts about this test case...');
      await user.type(textarea, 'Test comment');

      const accuracyBtn = screen.getByText('Accuracy');
      await user.click(accuracyBtn);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.queryByText('3 / 5')).not.toBeInTheDocument();
        expect(textarea).toHaveValue('');
        expect(accuracyBtn).toHaveAttribute('aria-pressed', 'false');
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<TestCaseFeedback testId={mockTestId} />);

      expect(screen.getByRole('form')).toBeInTheDocument();
      expect(screen.getByLabelText('Additional Comments *')).toBeInTheDocument();
    });

    it('should have live region for toast notifications', async () => {
      const user = userEvent.setup();
      render(<TestCaseFeedback testId={mockTestId} />);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        const alert = screen.getByRole('alert');
        expect(alert).toHaveAttribute('aria-live', 'polite');
      });
    });
  });
});
