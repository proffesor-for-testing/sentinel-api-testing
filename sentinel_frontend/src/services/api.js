import axios from 'axios';
import { getApiUrl, getApiTimeout } from '../config/settings';

const api = axios.create({
  baseURL: getApiUrl(),
  timeout: getApiTimeout(),
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    if (error.response?.status === 503) {
      console.error('Service unavailable - check if backend services are running');
    }
    return Promise.reject(error);
  }
);

// API service methods
export const apiService = {
  // Generic methods for react-query
  async get(url, params = {}) {
    const response = await api.get(url, { params });
    return response.data;
  },

  async post(url, data) {
    const response = await api.post(url, data);
    return response.data;
  },

  async put(url, data) {
    const response = await api.put(url, data);
    return response.data;
  },

  async delete(url) {
    const response = await api.delete(url);
    return response.data;
  },

  // Health check
  async getHealth() {
    const response = await api.get('/health');
    return response.data;
  },

  // Specifications
  async getSpecifications() {
    const response = await api.get('/api/v1/specifications');
    return response.data;
  },

  async getSpecification(id) {
    const response = await api.get(`/api/v1/specifications/${id}`);
    return response.data;
  },

  async uploadSpecification(specData) {
    const response = await api.post('/api/v1/specifications', specData);
    return response.data;
  },

  // Test Cases
  async getTestCases(params = {}) {
    const queryParams = new URLSearchParams();
    if (params.spec_id) queryParams.append('spec_id', params.spec_id);
    if (params.agent_type) queryParams.append('agent_type', params.agent_type);
    
    const url = `/api/v1/test-cases${queryParams.toString() ? `?${queryParams.toString()}` : ''}`;
    const response = await api.get(url);
    return response.data;
  },

  async getTestCase(caseId) {
    const response = await api.get(`/api/v1/test-cases/${caseId}`);
    return response.data;
  },

  async updateTestCase(caseId, testCaseData) {
    const response = await api.put(`/api/v1/test-cases/${caseId}`, testCaseData);
    return response.data;
  },

  async deleteTestCase(caseId) {
    const response = await api.delete(`/api/v1/test-cases/${caseId}`);
    return response.data;
  },

  async bulkUpdateTestCases(updates) {
    const response = await api.post('/api/v1/test-cases/bulk-update', updates);
    return response.data;
  },

  // Test Generation
  async generateTests(requestData) {
    const response = await api.post('/api/v1/generate-tests', requestData);
    return response.data;
  },

  // Test Suites
  async getTestSuites() {
    const response = await api.get('/api/v1/test-suites');
    return response.data;
  },

  async createTestSuite(suiteData) {
    const response = await api.post('/api/v1/test-suites', suiteData);
    return response.data;
  },

  // Test Runs
  async getTestRuns() {
    const response = await api.get('/api/v1/test-runs');
    return response.data;
  },

  async getTestRun(runId) {
    const response = await api.get(`/api/v1/test-runs/${runId}`);
    return response.data;
  },

  async runTests(runData) {
    const response = await api.post('/api/v1/test-runs', runData);
    return response.data;
  },

  async getTestRunResults(runId) {
    const response = await api.get(`/api/v1/test-runs/${runId}/results`);
    return response.data;
  },

  // Complete Flow
  async runCompleteFlow(flowData) {
    const response = await api.post('/api/v1/test-complete-flow', flowData);
    return response.data;
  },

};

export default api;
