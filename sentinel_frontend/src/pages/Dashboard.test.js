import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from 'react-query';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from './Dashboard';
import { apiService } from '../services/api';

jest.mock('../services/api', () => ({
  apiService: {
    get: jest.fn(),
  },
}));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

const wrapper = ({ children }) => (
  <QueryClientProvider client={queryClient}>
    <MemoryRouter>{children}</MemoryRouter>
  </QueryClientProvider>
);

describe('Dashboard', () => {
  beforeEach(() => {
    apiService.get.mockClear();
    queryClient.clear();
  });

  it('renders loading state initially', () => {
    apiService.get.mockReturnValue(new Promise(() => {}));
    render(<Dashboard />, { wrapper });
    expect(screen.getByText(/Loading dashboard.../i)).toBeInTheDocument();
  });

  it('renders dashboard with data after successful fetch', async () => {
    const mockData = {
      dashboard_stats: {
        total_test_cases: 30,
        total_test_runs: 20,
        total_test_suites: 5,
        success_rate: 0.85,
        recent_runs: [],
        agent_distribution: { 'Functional-Positive-Agent': 30 },
      },
      recent_specifications: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], // 10 specs
    };
    apiService.get.mockResolvedValue(mockData);

    render(<Dashboard />, { wrapper });

    expect(await screen.findByText('API Specifications')).toBeInTheDocument();

    expect(screen.getByText('10')).toBeInTheDocument(); // spec count
    expect(screen.getByText('20')).toBeInTheDocument(); // test runs
    expect(screen.getByText('30')).toBeInTheDocument(); // test cases
    expect(screen.getByText('85%')).toBeInTheDocument(); // success rate
  });

  it('renders error state on fetch failure', async () => {
    const mockError = { message: 'Failed to fetch' };
    apiService.get.mockRejectedValue(mockError);
    render(<Dashboard />, { wrapper });

    expect(await screen.findByText(/Error/i)).toBeInTheDocument();
    expect(screen.getByText(/Failed to fetch/i)).toBeInTheDocument();
  });
});