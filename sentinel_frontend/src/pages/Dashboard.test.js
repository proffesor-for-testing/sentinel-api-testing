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
        totalSpecs: 10,
        totalTestRuns: 20,
        totalTestCases: 30,
        successRate: 85,
        recentRuns: [],
        agentDistribution: { 'Functional-Positive-Agent': 30 },
      },
      recent_specifications: [],
    };
    apiService.get.mockResolvedValue(mockData);

    render(<Dashboard />, { wrapper });

    expect(await screen.findByText('API Specifications')).toBeInTheDocument();

    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('20')).toBeInTheDocument();
    expect(screen.getByText('30')).toBeInTheDocument();
    expect(screen.getByText('85%')).toBeInTheDocument();
  });

  it('renders error state on fetch failure', async () => {
    apiService.get.mockRejectedValue(new Error('Failed to fetch'));
    render(<Dashboard />, { wrapper });

    expect(await screen.findByText(/Error/i)).toBeInTheDocument();
    expect(screen.getByText(/Failed to fetch/i)).toBeInTheDocument();
  });
});