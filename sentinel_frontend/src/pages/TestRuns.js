import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  PlayCircle, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Clock,
  Plus,
  RefreshCw,
  Filter,
  Search,
  Calendar
} from 'lucide-react';
import { apiService } from '../services/api';

const TestRuns = () => {
  const [testRuns, setTestRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadTestRuns();
  }, []);

  const loadTestRuns = async () => {
    try {
      setLoading(true);
      const data = await apiService.getTestRuns();
      setTestRuns(data);
      setError(null);
    } catch (err) {
      console.error('Error loading test runs:', err);
      setError('Failed to load test runs');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-success-500" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-danger-500" />;
      case 'running':
        return <Clock className="h-5 w-5 text-primary-500 animate-pulse" />;
      default:
        return <AlertTriangle className="h-5 w-5 text-warning-500" />;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'completed':
        return <span className="badge badge-success">Completed</span>;
      case 'failed':
        return <span className="badge badge-danger">Failed</span>;
      case 'running':
        return <span className="badge badge-primary">Running</span>;
      default:
        return <span className="badge badge-warning">Unknown</span>;
    }
  };

  const getSuccessRate = (run) => {
    const total = (run.passed || 0) + (run.failed || 0) + (run.errors || 0);
    if (total === 0) return 0;
    return Math.round(((run.passed || 0) / total) * 100);
  };

  const filteredRuns = testRuns.filter(run => {
    const matchesFilter = filter === 'all' || run.status === filter;
    const matchesSearch = searchTerm === '' || 
      run.id.toString().includes(searchTerm) ||
      (run.target_environment && run.target_environment.toLowerCase().includes(searchTerm.toLowerCase()));
    
    return matchesFilter && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading test runs...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-danger-50 border border-danger-200 rounded-md p-4">
        <div className="flex">
          <AlertTriangle className="h-5 w-5 text-danger-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-danger-800">Error</h3>
            <p className="text-sm text-danger-700 mt-1">{error}</p>
            <button 
              onClick={loadTestRuns}
              className="btn btn-sm btn-danger mt-2"
            >
              <RefreshCw className="h-4 w-4 mr-1" />
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Test Runs</h1>
          <p className="text-gray-600 mt-1">
            View and manage your API test execution history
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button onClick={loadTestRuns} className="btn btn-secondary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
          <Link to="/specifications" className="btn btn-primary">
            <Plus className="h-4 w-4 mr-2" />
            New Test Run
          </Link>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="card">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Filter className="h-4 w-4 text-gray-500" />
              <select 
                value={filter} 
                onChange={(e) => setFilter(e.target.value)}
                className="border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Status</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="failed">Failed</option>
              </select>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search by ID or environment..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm w-64"
            />
          </div>
        </div>
      </div>

      {/* Test Runs List */}
      {filteredRuns.length > 0 ? (
        <div className="space-y-4">
          {filteredRuns.map((run) => (
            <div key={run.id} className="card hover:shadow-md transition-shadow duration-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  {getStatusIcon(run.status)}
                  
                  <div>
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-medium text-gray-900">
                        Test Run #{run.id}
                      </h3>
                      {getStatusBadge(run.status)}
                    </div>
                    
                    <div className="mt-1 text-sm text-gray-500 space-y-1">
                      <div className="flex items-center space-x-4">
                        <span>
                          <strong>Environment:</strong> {run.target_environment || 'N/A'}
                        </span>
                        <span>
                          <Calendar className="h-4 w-4 inline mr-1" />
                          {run.created_at ? new Date(run.created_at).toLocaleString() : 'N/A'}
                        </span>
                      </div>
                      
                      {run.duration && (
                        <div>
                          <strong>Duration:</strong> {run.duration}s
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-6">
                  {/* Test Results Summary */}
                  <div className="text-right">
                    <div className="flex items-center space-x-4 text-sm">
                      <div className="flex items-center">
                        <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                        <span className="font-medium">{run.passed || 0}</span>
                      </div>
                      <div className="flex items-center">
                        <XCircle className="h-4 w-4 text-danger-500 mr-1" />
                        <span className="font-medium">{run.failed || 0}</span>
                      </div>
                      <div className="flex items-center">
                        <AlertTriangle className="h-4 w-4 text-warning-500 mr-1" />
                        <span className="font-medium">{run.errors || 0}</span>
                      </div>
                    </div>
                    
                    <div className="mt-1 text-xs text-gray-500">
                      Success Rate: {getSuccessRate(run)}%
                    </div>
                  </div>
                  
                  {/* Actions */}
                  <div className="flex items-center space-x-2">
                    <Link 
                      to={`/test-runs/${run.id}`}
                      className="btn btn-primary btn-sm"
                    >
                      View Details
                    </Link>
                  </div>
                </div>
              </div>
              
              {/* Progress Bar for Success Rate */}
              <div className="mt-4">
                <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
                  <span>Test Results</span>
                  <span>{(run.passed || 0) + (run.failed || 0) + (run.errors || 0)} total tests</span>
                </div>
                
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="flex h-2 rounded-full overflow-hidden">
                    {/* Passed tests */}
                    {run.passed > 0 && (
                      <div 
                        className="bg-success-500"
                        style={{ 
                          width: `${((run.passed || 0) / ((run.passed || 0) + (run.failed || 0) + (run.errors || 0))) * 100}%` 
                        }}
                      />
                    )}
                    {/* Failed tests */}
                    {run.failed > 0 && (
                      <div 
                        className="bg-danger-500"
                        style={{ 
                          width: `${((run.failed || 0) / ((run.passed || 0) + (run.failed || 0) + (run.errors || 0))) * 100}%` 
                        }}
                      />
                    )}
                    {/* Error tests */}
                    {run.errors > 0 && (
                      <div 
                        className="bg-warning-500"
                        style={{ 
                          width: `${((run.errors || 0) / ((run.passed || 0) + (run.failed || 0) + (run.errors || 0))) * 100}%` 
                        }}
                      />
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card text-center py-12">
          <PlayCircle className="h-16 w-16 mx-auto text-gray-300 mb-4" />
          <h3 className="text-xl font-medium text-gray-900 mb-2">
            {searchTerm || filter !== 'all' ? 'No matching test runs found' : 'No test runs yet'}
          </h3>
          <p className="text-gray-500 mb-6">
            {searchTerm || filter !== 'all' 
              ? 'Try adjusting your search or filter criteria.'
              : 'Start by uploading an API specification and running tests.'
            }
          </p>
          
          {(!searchTerm && filter === 'all') && (
            <Link to="/specifications" className="btn btn-primary">
              <Plus className="h-4 w-4 mr-2" />
              Create Your First Test Run
            </Link>
          )}
          
          {(searchTerm || filter !== 'all') && (
            <div className="space-x-2">
              <button 
                onClick={() => {
                  setSearchTerm('');
                  setFilter('all');
                }}
                className="btn btn-secondary"
              >
                Clear Filters
              </button>
              <Link to="/specifications" className="btn btn-primary">
                <Plus className="h-4 w-4 mr-2" />
                New Test Run
              </Link>
            </div>
          )}
        </div>
      )}

      {/* Summary Stats */}
      {filteredRuns.length > 0 && (
        <div className="card bg-gray-50">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-gray-900">{filteredRuns.length}</div>
              <div className="text-sm text-gray-500">Total Runs</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-success-600">
                {filteredRuns.filter(run => run.status === 'completed').length}
              </div>
              <div className="text-sm text-gray-500">Completed</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-primary-600">
                {filteredRuns.filter(run => run.status === 'running').length}
              </div>
              <div className="text-sm text-gray-500">Running</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-gray-600">
                {filteredRuns.reduce((sum, run) => sum + (run.passed || 0) + (run.failed || 0) + (run.errors || 0), 0)}
              </div>
              <div className="text-sm text-gray-500">Total Tests</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TestRuns;
