import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Activity, 
  FileText, 
  TestTube, 
  PlayCircle, 
  TrendingUp,
  AlertCircle,
  CheckCircle,
  Clock,
  BarChart3
} from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiService } from '../services/api';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalSpecs: 0,
    totalTestRuns: 0,
    totalTestCases: 0,
    successRate: 0,
    recentRuns: [],
    agentDistribution: {}
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const data = await apiService.getDashboardStats();
      setStats(data);
      setError(null);
    } catch (err) {
      console.error('Error loading dashboard data:', err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-success-600';
      case 'failed': return 'text-danger-600';
      case 'running': return 'text-primary-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'failed': return <AlertCircle className="h-4 w-4" />;
      case 'running': return <Clock className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  // Prepare chart data
  const agentChartData = Object.entries(stats.agentDistribution).map(([agent, count]) => ({
    name: agent.replace('Functional-', '').replace('-Agent', ''),
    value: count,
    fullName: agent
  }));

  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];

  const recentRunsChartData = stats.recentRuns.slice(0, 7).reverse().map((run, index) => ({
    name: `Run ${run.id}`,
    passed: run.passed || 0,
    failed: run.failed || 0,
    errors: run.errors || 0
  }));

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading dashboard...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-danger-50 border border-danger-200 rounded-md p-4">
        <div className="flex">
          <AlertCircle className="h-5 w-5 text-danger-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-danger-800">Error</h3>
            <p className="text-sm text-danger-700 mt-1">{error}</p>
            <button 
              onClick={loadDashboardData}
              className="btn btn-sm btn-danger mt-2"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600 mt-1">
          Overview of your API testing activities and system performance
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <FileText className="h-8 w-8 text-primary-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">API Specifications</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalSpecs}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <TestTube className="h-8 w-8 text-success-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Test Cases</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalTestCases}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <PlayCircle className="h-8 w-8 text-warning-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Test Runs</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalTestRuns}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <TrendingUp className="h-8 w-8 text-success-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Success Rate</p>
              <p className="text-2xl font-bold text-gray-900">{stats.successRate}%</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent Distribution Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900">Test Cases by Agent Type</h3>
            <p className="text-sm text-gray-500">Distribution of generated test cases</p>
          </div>
          
          {agentChartData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={agentChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {agentChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value, name, props) => [value, props.payload.fullName]} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              <div className="text-center">
                <BarChart3 className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                <p>No test cases generated yet</p>
              </div>
            </div>
          )}
        </div>

        {/* Recent Test Runs Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-medium text-gray-900">Recent Test Results</h3>
            <p className="text-sm text-gray-500">Last 7 test runs performance</p>
          </div>
          
          {recentRunsChartData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={recentRunsChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="passed" stackId="a" fill="#10b981" name="Passed" />
                  <Bar dataKey="failed" stackId="a" fill="#ef4444" name="Failed" />
                  <Bar dataKey="errors" stackId="a" fill="#f59e0b" name="Errors" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              <div className="text-center">
                <Activity className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                <p>No test runs completed yet</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent Test Runs Table */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-medium text-gray-900">Recent Test Runs</h3>
              <p className="text-sm text-gray-500">Latest test execution results</p>
            </div>
            <Link to="/test-runs" className="btn btn-primary btn-sm">
              View All
            </Link>
          </div>
        </div>

        {stats.recentRuns.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Status</th>
                  <th>Tests</th>
                  <th>Passed</th>
                  <th>Failed</th>
                  <th>Errors</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {stats.recentRuns.slice(0, 5).map((run) => (
                  <tr key={run.id}>
                    <td className="font-medium">#{run.id}</td>
                    <td>
                      <div className={`flex items-center ${getStatusColor(run.status)}`}>
                        {getStatusIcon(run.status)}
                        <span className="ml-1 capitalize">{run.status}</span>
                      </div>
                    </td>
                    <td>{(run.passed || 0) + (run.failed || 0) + (run.errors || 0)}</td>
                    <td>
                      <span className="badge badge-success">{run.passed || 0}</span>
                    </td>
                    <td>
                      <span className="badge badge-danger">{run.failed || 0}</span>
                    </td>
                    <td>
                      <span className="badge badge-warning">{run.errors || 0}</span>
                    </td>
                    <td className="text-gray-500">
                      {run.created_at ? new Date(run.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td>
                      <Link 
                        to={`/test-runs/${run.id}`}
                        className="text-primary-600 hover:text-primary-900 text-sm font-medium"
                      >
                        View Details
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <PlayCircle className="h-12 w-12 mx-auto text-gray-300 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No test runs yet</h3>
            <p className="text-gray-500 mb-4">Start by uploading an API specification and generating tests.</p>
            <Link to="/specifications" className="btn btn-primary">
              Upload Specification
            </Link>
          </div>
        )}
      </div>

    </div>
  );
};

export default Dashboard;
