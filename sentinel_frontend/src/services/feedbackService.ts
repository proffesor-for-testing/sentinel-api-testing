import axios, { AxiosError, AxiosInstance } from 'axios';
import type {
  TestCaseFeedbackPayload,
  TestSuiteFeedbackPayload,
  FeedbackResponse,
  FeedbackStatistics,
  ApiError
} from '../types/feedback';

/**
 * Feedback Service
 * API integration for submitting and retrieving feedback
 *
 * Backend Configuration:
 * - Development: http://localhost:8002 (orchestration service)
 * - Docker: http://orchestration_service:8002
 *
 * Required Backend Setup:
 * - CORS must be enabled on orchestration service for frontend origin
 * - Add CORSMiddleware with:
 *   - allow_origins: ["http://localhost:3000", "http://frontend:3000"]
 *   - allow_credentials: True
 *   - allow_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
 *   - allow_headers: ["Content-Type", "Authorization", "X-Correlation-ID"]
 *
 * Endpoints:
 * - POST /api/v1/feedback/test-case - Submit test case feedback
 * - POST /api/v1/feedback/test-suite - Submit test suite feedback
 * - GET /api/v1/feedback/statistics - Get feedback statistics
 * - GET /api/v1/feedback/test-case/{test_id} - Get test case feedback
 * - GET /api/v1/feedback/patterns/{pattern_id} - Get pattern feedback
 */

// Use API Gateway (port 8000) instead of direct orchestration service access
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';
const FEEDBACK_ENDPOINT = process.env.REACT_APP_FEEDBACK_ENDPOINT || '/api/v1/feedback';

class FeedbackService {
  private client: AxiosInstance;
  private maxRetries: number = 3;
  private retryDelay: number = 1000; // ms

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000, // Increased timeout for backend processing
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      withCredentials: false // Set to true if using cookies for auth
    });

    // Request interceptor for adding auth token and correlation ID
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add correlation ID for request tracing
        config.headers['X-Correlation-ID'] = this.generateCorrelationId();

        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        // Handle network errors
        if (!error.response) {
          const networkError: ApiError = {
            message: 'Unable to connect to backend service. Please check if the orchestration service is running.',
            code: 'NETWORK_ERROR',
            details: {
              url: error.config?.url,
              baseURL: error.config?.baseURL,
              suggestion: 'Verify orchestration service is running on port 8002'
            }
          };
          return Promise.reject(networkError);
        }

        // Handle CORS errors
        if (error.message?.includes('CORS')) {
          const corsError: ApiError = {
            message: 'CORS error: Backend needs CORS configuration for frontend origin',
            code: 'CORS_ERROR',
            details: {
              suggestion: 'Add CORSMiddleware to orchestration service with allow_origins=["http://localhost:3000"]'
            }
          };
          return Promise.reject(corsError);
        }

        // Type the error response data
        const responseData = error.response?.data as any;
        const apiError: ApiError = {
          message: responseData?.message || error.message || 'An unexpected error occurred',
          code: responseData?.code || error.code,
          details: responseData?.details
        };
        return Promise.reject(apiError);
      }
    );
  }

  /**
   * Generate correlation ID for request tracing
   */
  private generateCorrelationId(): string {
    return `frontend-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Submit feedback for a test case
   * Includes retry logic for transient failures
   */
  async submitTestCaseFeedback(
    payload: TestCaseFeedbackPayload,
    retryCount: number = 0
  ): Promise<FeedbackResponse> {
    try {
      const response = await this.client.post<FeedbackResponse>(
        `${FEEDBACK_ENDPOINT}/test-case`,
        payload
      );
      return response.data;
    } catch (error) {
      if (retryCount < this.maxRetries && this.isRetryableError(error)) {
        await this.delay(this.retryDelay * Math.pow(2, retryCount));
        return this.submitTestCaseFeedback(payload, retryCount + 1);
      }
      throw this.handleError(error, 'Failed to submit test case feedback');
    }
  }

  /**
   * Submit feedback for a test suite
   * Includes retry logic for transient failures
   */
  async submitTestSuiteFeedback(
    payload: TestSuiteFeedbackPayload,
    retryCount: number = 0
  ): Promise<FeedbackResponse> {
    try {
      const response = await this.client.post<FeedbackResponse>(
        `${FEEDBACK_ENDPOINT}/test-suite`,
        payload
      );
      return response.data;
    } catch (error) {
      if (retryCount < this.maxRetries && this.isRetryableError(error)) {
        await this.delay(this.retryDelay * Math.pow(2, retryCount));
        return this.submitTestSuiteFeedback(payload, retryCount + 1);
      }
      throw this.handleError(error, 'Failed to submit test suite feedback');
    }
  }

  /**
   * Get feedback statistics
   */
  async getFeedbackStats(): Promise<FeedbackStatistics> {
    try {
      const response = await this.client.get<FeedbackStatistics>(
        `${FEEDBACK_ENDPOINT}/statistics`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error, 'Failed to retrieve feedback statistics');
    }
  }

  /**
   * Get feedback for a specific test case
   */
  async getTestCaseFeedback(testId: string): Promise<TestCaseFeedbackPayload[]> {
    try {
      const response = await this.client.get<TestCaseFeedbackPayload[]>(
        `${FEEDBACK_ENDPOINT}/test-case/${testId}`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error, 'Failed to retrieve test case feedback');
    }
  }

  /**
   * Get feedback for a specific test suite
   */
  async getTestSuiteFeedback(suiteId: string): Promise<TestSuiteFeedbackPayload[]> {
    try {
      const response = await this.client.get<TestSuiteFeedbackPayload[]>(
        `${FEEDBACK_ENDPOINT}/test-suite/${suiteId}`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error, 'Failed to retrieve test suite feedback');
    }
  }

  /**
   * Delete feedback (admin only)
   */
  async deleteFeedback(feedbackId: string): Promise<{ success: boolean }> {
    try {
      const response = await this.client.delete<{ success: boolean }>(
        `${FEEDBACK_ENDPOINT}/${feedbackId}`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error, 'Failed to delete feedback');
    }
  }

  /**
   * Check if error is retryable (network errors, 5xx errors)
   */
  private isRetryableError(error: unknown): boolean {
    if (!axios.isAxiosError(error)) {
      return false;
    }

    // Network errors
    if (!error.response) {
      return true;
    }

    // Server errors (5xx)
    const status = error.response.status;
    return status >= 500 && status < 600;
  }

  /**
   * Delay helper for retry logic
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Enhanced error handling with context
   */
  private handleError(error: unknown, context: string): Error {
    if (axios.isAxiosError(error)) {
      const apiError = error as AxiosError<ApiError>;
      const message = apiError.response?.data?.message || error.message;
      return new Error(`${context}: ${message}`);
    }

    if (error instanceof Error) {
      return new Error(`${context}: ${error.message}`);
    }

    return new Error(`${context}: Unknown error occurred`);
  }
}

// Export singleton instance
const feedbackService = new FeedbackService();

export const {
  submitTestCaseFeedback,
  submitTestSuiteFeedback,
  getFeedbackStats,
  getTestCaseFeedback,
  getTestSuiteFeedback,
  deleteFeedback
} = {
  submitTestCaseFeedback: feedbackService.submitTestCaseFeedback.bind(feedbackService),
  submitTestSuiteFeedback: feedbackService.submitTestSuiteFeedback.bind(feedbackService),
  getFeedbackStats: feedbackService.getFeedbackStats.bind(feedbackService),
  getTestCaseFeedback: feedbackService.getTestCaseFeedback.bind(feedbackService),
  getTestSuiteFeedback: feedbackService.getTestSuiteFeedback.bind(feedbackService),
  deleteFeedback: feedbackService.deleteFeedback.bind(feedbackService)
};

export default feedbackService;
