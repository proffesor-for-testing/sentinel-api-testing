/**
 * Feedback Types for Sentinel Platform
 */

export type FeedbackCategory =
  | 'accuracy'
  | 'completeness'
  | 'performance'
  | 'usability'
  | 'bug'
  | 'feature-request'
  | 'other';

export interface TestCaseFeedbackPayload {
  testId: string;
  rating: number; // 1-5
  helpful: boolean | null;
  foundIssue: boolean;
  comment: string;
  categories: FeedbackCategory[];
  timestamp: string;
}

export interface TestSuiteFeedbackPayload {
  suiteId: string;
  overallRating: number; // 1-5
  coverageRating: number; // 0-100
  qualityRating: number; // 0-100
  coverageGaps: string;
  improvementSuggestions: string;
  timestamp: string;
}

export interface FeedbackResponse {
  success: boolean;
  feedbackId: string;
  message: string;
}

export interface FeedbackStatistics {
  totalFeedback: number;
  averageRating: number;
  helpfulPercentage: number;
  issuesReported: number;
  categoryBreakdown: Record<FeedbackCategory, number>;
  lastUpdated: string;
}

export interface ApiError {
  message: string;
  code?: string;
  details?: unknown;
}
