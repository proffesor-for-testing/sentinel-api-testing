import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TestSuiteFeedback } from '../../components/feedback/TestSuiteFeedback';
import * as feedbackService from '../../services/feedbackService';

// Mock the feedback service
jest.mock('../../services/feedbackService');

describe('TestSuiteFeedback Component', () => {
  const mockSuiteId = 'suite-123';
  const mockSuiteName = 'API Integration Test Suite';
  const mockOnSuccess = jest.fn();
  const mockOnError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render feedback form', () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      expect(screen.getByText('Overall Test Suite Rating')).toBeInTheDocument();
      expect(screen.getByText(/Coverage Rating:/)).toBeInTheDocument();
      expect(screen.getByText(/Quality Rating:/)).toBeInTheDocument();
      expect(screen.getByLabelText('Coverage Gaps (Optional)')).toBeInTheDocument();
      expect(screen.getByLabelText('Improvement Suggestions (Optional)')).toBeInTheDocument();
    });

    it('should render suite name when provided', () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} suiteName={mockSuiteName} />);

      expect(screen.getByText(`Test Suite Feedback: ${mockSuiteName}`)).toBeInTheDocument();
    });

    it('should render sliders with default values', () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      expect(screen.getByText('Coverage Rating: 50%')).toBeInTheDocument();
      expect(screen.getByText('Quality Rating: 50%')).toBeInTheDocument();
    });
  });

  describe('Slider Interaction', () => {
    it('should update coverage rating slider', async () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const slider = screen.getByLabelText(/Coverage Rating:/);
      fireEvent.change(slider, { target: { value: '75' } });

      await waitFor(() => {
        expect(screen.getByText('Coverage Rating: 75%')).toBeInTheDocument();
      });
    });

    it('should update quality rating slider', async () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const slider = screen.getByLabelText(/Quality Rating:/);
      fireEvent.change(slider, { target: { value: '90' } });

      await waitFor(() => {
        expect(screen.getByText('Quality Rating: 90%')).toBeInTheDocument();
      });
    });

    it('should accept slider values from 0 to 100', async () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const slider = screen.getByLabelText(/Coverage Rating:/);

      fireEvent.change(slider, { target: { value: '0' } });
      expect(screen.getByText('Coverage Rating: 0%')).toBeInTheDocument();

      fireEvent.change(slider, { target: { value: '100' } });
      expect(screen.getByText('Coverage Rating: 100%')).toBeInTheDocument();
    });
  });

  describe('Star Rating', () => {
    it('should update overall rating', async () => {
      const user = userEvent.setup();
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[3]); // 4 stars

      expect(screen.getByText('4 / 5')).toBeInTheDocument();
    });
  });

  describe('Textarea Input', () => {
    it('should update coverage gaps textarea', async () => {
      const user = userEvent.setup();
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const textarea = screen.getByPlaceholderText('Describe any gaps in test coverage you\'ve identified...');
      await user.type(textarea, 'Missing edge case tests');

      expect(textarea).toHaveValue('Missing edge case tests');
    });

    it('should update improvement suggestions textarea', async () => {
      const user = userEvent.setup();
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const textarea = screen.getByPlaceholderText('Share suggestions for improving this test suite...');
      await user.type(textarea, 'Add performance tests');

      expect(textarea).toHaveValue('Add performance tests');
    });
  });

  describe('Form Validation', () => {
    it('should show error when submitting without rating', async () => {
      const user = userEvent.setup();
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Please provide an overall rating')).toBeInTheDocument();
      });
    });

    it('should allow submission with only required fields', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-456',
        message: 'Success'
      };

      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      // Set rating only
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(feedbackService.submitTestSuiteFeedback).toHaveBeenCalled();
      });
    });
  });

  describe('Form Submission', () => {
    it('should submit complete feedback successfully', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-789',
        message: 'Feedback submitted successfully'
      };

      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(
        <TestSuiteFeedback
          suiteId={mockSuiteId}
          onSuccess={mockOnSuccess}
        />
      );

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[4]); // 5 stars

      const coverageSlider = screen.getByLabelText(/Coverage Rating:/);
      fireEvent.change(coverageSlider, { target: { value: '85' } });

      const qualitySlider = screen.getByLabelText(/Quality Rating:/);
      fireEvent.change(qualitySlider, { target: { value: '90' } });

      const gapsTextarea = screen.getByPlaceholderText('Describe any gaps in test coverage you\'ve identified...');
      await user.type(gapsTextarea, 'Need more negative tests');

      const suggestionsTextarea = screen.getByPlaceholderText('Share suggestions for improving this test suite...');
      await user.type(suggestionsTextarea, 'Add integration tests');

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(feedbackService.submitTestSuiteFeedback).toHaveBeenCalledWith(
          expect.objectContaining({
            suiteId: mockSuiteId,
            overallRating: 5,
            coverageRating: 85,
            qualityRating: 90,
            coverageGaps: 'Need more negative tests',
            improvementSuggestions: 'Add integration tests'
          })
        );
        expect(mockOnSuccess).toHaveBeenCalledWith('feedback-789');
        expect(screen.getByText('Test suite feedback submitted successfully!')).toBeInTheDocument();
      });
    });

    it('should show loading state during submission', async () => {
      const user = userEvent.setup();
      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 1000))
      );

      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      expect(screen.getByText('Submitting...')).toBeInTheDocument();
      expect(submitBtn).toBeDisabled();
    });

    it('should handle submission error', async () => {
      const user = userEvent.setup();
      const mockError = new Error('Server error');

      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockRejectedValue(mockError);

      render(
        <TestSuiteFeedback
          suiteId={mockSuiteId}
          onError={mockOnError}
        />
      );

      // Fill form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Server error')).toBeInTheDocument();
        expect(mockOnError).toHaveBeenCalled();
      });
    });

    it('should reset form after successful submission', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-999',
        message: 'Success'
      };

      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      // Fill and submit form
      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[3]);

      const coverageSlider = screen.getByLabelText(/Coverage Rating:/);
      fireEvent.change(coverageSlider, { target: { value: '75' } });

      const gapsTextarea = screen.getByPlaceholderText('Describe any gaps in test coverage you\'ve identified...');
      await user.type(gapsTextarea, 'Some gaps');

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(screen.queryByText('4 / 5')).not.toBeInTheDocument();
        expect(screen.getByText('Coverage Rating: 50%')).toBeInTheDocument();
        expect(gapsTextarea).toHaveValue('');
      });
    });

    it('should trim whitespace from textarea values', async () => {
      const user = userEvent.setup();
      const mockResponse = {
        success: true,
        feedbackId: 'feedback-111',
        message: 'Success'
      };

      (feedbackService.submitTestSuiteFeedback as jest.Mock).mockResolvedValue(mockResponse);

      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const stars = screen.getAllByRole('button', { name: /star/i });
      await user.click(stars[2]);

      const gapsTextarea = screen.getByPlaceholderText('Describe any gaps in test coverage you\'ve identified...');
      await user.type(gapsTextarea, '  Gaps with spaces  ');

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        expect(feedbackService.submitTestSuiteFeedback).toHaveBeenCalledWith(
          expect.objectContaining({
            coverageGaps: 'Gaps with spaces'
          })
        );
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper form structure', () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      expect(screen.getByRole('form')).toBeInTheDocument();
    });

    it('should have accessible labels for all inputs', () => {
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      expect(screen.getByLabelText(/Coverage Rating:/)).toBeInTheDocument();
      expect(screen.getByLabelText(/Quality Rating:/)).toBeInTheDocument();
      expect(screen.getByLabelText('Coverage Gaps (Optional)')).toBeInTheDocument();
      expect(screen.getByLabelText('Improvement Suggestions (Optional)')).toBeInTheDocument();
    });

    it('should have live region for notifications', async () => {
      const user = userEvent.setup();
      render(<TestSuiteFeedback suiteId={mockSuiteId} />);

      const submitBtn = screen.getByText('Submit Feedback');
      await user.click(submitBtn);

      await waitFor(() => {
        const alert = screen.getByRole('alert');
        expect(alert).toHaveAttribute('aria-live', 'polite');
      });
    });
  });
});
