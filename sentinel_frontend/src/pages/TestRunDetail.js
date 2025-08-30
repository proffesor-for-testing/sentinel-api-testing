import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  ArrowLeft, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Clock,
  Eye,
  Code,
  Filter,
  Download,
  RefreshCw
} from 'lucide-react';
import { apiService } from '../services/api';

const TestRunDetail = () => {
  const { runId } = useParams();
  const [testRun, setTestRun] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all'); // all, passed, failed, error
  const [expandedTest, setExpandedTest] = useState(null);

  useEffect(() => {
    loadTestRunDetails();
  }, [runId]);

  const loadTestRunDetails = async () => {
    try {
      setLoading(true);
      const data = await apiService.getTestRun(runId);
      // Calculate counts from results
      const passed = data.results?.filter(r => r.status === 'pass').length || 0;
      const failed = data.results?.filter(r => r.status === 'fail').length || 0;
      const errors = data.results?.filter(r => r.status === 'error').length || 0;
      
      // Calculate duration if timestamps exist
      let duration = null;
      if (data.run?.started_at && data.run?.completed_at) {
        const start = new Date(data.run.started_at);
        const end = new Date(data.run.completed_at);
        duration = ((end - start) / 1000).toFixed(2); // Convert to seconds
      }
      
      // Restructure data for easier access in the component
      setTestRun({
        ...data.run,
        passed,
        failed,
        errors,
        duration,
        results: data.results
      });
      setError(null);
    } catch (err) {
      console.error('Error loading test run details:', err);
      setError('Failed to load test run details');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'pass':
      case 'passed':
        return <CheckCircle className="h-5 w-5 text-success-500" />;
      case 'fail':
      case 'failed':
        return <XCircle className="h-5 w-5 text-danger-500" />;
      case 'error':
        return <AlertTriangle className="h-5 w-5 text-warning-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'pass':
      case 'passed':
        return <span className="badge badge-success">Passed</span>;
      case 'fail':
      case 'failed':
        return <span className="badge badge-danger">Failed</span>;
      case 'error':
        return <span className="badge badge-warning">Error</span>;
      default:
        return <span className="badge">Unknown</span>;
    }
  };

  const getAgentTypeBadge = (agentType) => {
    const colors = {
      'Functional-Positive-Agent': 'badge-primary',
      'Functional-Negative-Agent': 'badge-warning',
      'Functional-Stateful-Agent': 'badge-success'
    };
    
    const displayName = agentType?.replace('Functional-', '').replace('-Agent', '') || 'Unknown';
    const colorClass = colors[agentType] || 'badge';
    
    return <span className={`badge ${colorClass}`}>{displayName}</span>;
  };

  const filteredResults = testRun?.results?.filter(result => {
    if (filter === 'all') return true;
    return result.status === filter;
  }) || [];

  const getTestTypeInsight = (result) => {
    // Check multiple fields for test type information
    const description = (result.description || result.test_case?.description || '')?.toLowerCase();
    const testName = (result.test_case?.name || '')?.toLowerCase();
    const agentType = result.agent_type || result.test_case?.agent_type || '';
    
    // Check agent type first for more accurate categorization
    if (agentType) {
      if (agentType.includes('Negative')) {
        return {
          type: 'Negative Testing',
          icon: '❌',
          color: 'text-red-600',
          description: 'Tests invalid inputs and error conditions'
        };
      } else if (agentType.includes('Positive')) {
        return {
          type: 'Positive Testing',
          icon: '✅',
          color: 'text-green-600',
          description: 'Tests valid inputs and happy paths'
        };
      } else if (agentType.includes('Stateful')) {
        return {
          type: 'Stateful Testing',
          icon: '🔄',
          color: 'text-purple-600',
          description: 'Tests multi-step workflows and state management'
        };
      }
    }
    
    // Fallback to description/name analysis
    const combinedText = `${description} ${testName}`;
    
    if (combinedText.includes('boundary') || combinedText.includes('bva') || combinedText.includes('edge')) {
      return {
        type: 'Boundary Value Analysis',
        icon: '📊',
        color: 'text-blue-600',
        description: 'Tests edge cases and boundary conditions'
      };
    } else if (combinedText.includes('invalid') || combinedText.includes('negative') || combinedText.includes('error')) {
      return {
        type: 'Negative Testing',
        icon: '❌',
        color: 'text-red-600',
        description: 'Tests invalid inputs and error conditions'
      };
    } else if (combinedText.includes('stateful') || combinedText.includes('workflow') || combinedText.includes('sequence')) {
      return {
        type: 'Stateful Testing',
        icon: '🔄',
        color: 'text-purple-600',
        description: 'Tests multi-step workflows and state management'
      };
    } else if (combinedText.includes('positive') || combinedText.includes('valid') || combinedText.includes('success')) {
      return {
        type: 'Positive Testing',
        icon: '✅',
        color: 'text-green-600',
        description: 'Tests valid inputs and happy paths'
      };
    } else if (combinedText.includes('security') || combinedText.includes('auth') || combinedText.includes('injection')) {
      return {
        type: 'Security Testing',
        icon: '🔐',
        color: 'text-yellow-600',
        description: 'Tests security vulnerabilities and authentication'
      };
    } else if (combinedText.includes('performance') || combinedText.includes('load') || combinedText.includes('stress')) {
      return {
        type: 'Performance Testing',
        icon: '⚡',
        color: 'text-orange-600',
        description: 'Tests performance and load handling'
      };
    }
    
    // Better default based on HTTP method
    const method = result.test_case?.test_definition?.method || '';
    if (method) {
      return {
        type: `${method} API Test`,
        icon: '🧪',
        color: 'text-indigo-600',
        description: `Standard ${method} API test case`
      };
    }
    
    return {
      type: 'API Test',
      icon: '🧪',
      color: 'text-gray-600',
      description: 'Standard API test case'
    };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading test run details...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Link to="/test-runs" className="inline-flex items-center text-primary-600 hover:text-primary-900">
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Test Runs
        </Link>
        
        <div className="bg-danger-50 border border-danger-200 rounded-md p-4">
          <div className="flex">
            <AlertTriangle className="h-5 w-5 text-danger-400" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-danger-800">Error</h3>
              <p className="text-sm text-danger-700 mt-1">{error}</p>
              <button 
                onClick={loadTestRunDetails}
                className="btn btn-sm btn-danger mt-2"
              >
                <RefreshCw className="h-4 w-4 mr-1" />
                Retry
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!testRun) {
    return (
      <div className="text-center py-8">
        <AlertTriangle className="h-12 w-12 mx-auto text-gray-300 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Test run not found</h3>
        <Link to="/test-runs" className="btn btn-primary">
          Back to Test Runs
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link to="/test-runs" className="inline-flex items-center text-primary-600 hover:text-primary-900">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to Test Runs
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Test Run #{runId}</h1>
            <p className="text-gray-600 mt-1">
              Detailed results and failure analysis
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <button className="btn btn-secondary btn-sm">
            <Download className="h-4 w-4 mr-1" />
            Export Report
          </button>
          <button onClick={loadTestRunDetails} className="btn btn-secondary btn-sm">
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-success-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Passed</p>
              <p className="text-2xl font-bold text-gray-900">{testRun.passed || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <XCircle className="h-8 w-8 text-danger-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Failed</p>
              <p className="text-2xl font-bold text-gray-900">{testRun.failed || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <AlertTriangle className="h-8 w-8 text-warning-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Errors</p>
              <p className="text-2xl font-bold text-gray-900">{testRun.errors || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <Clock className="h-8 w-8 text-primary-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Duration</p>
              <p className="text-2xl font-bold text-gray-900">
                {testRun.duration ? `${testRun.duration}s` : 'N/A'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Test Run Info */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900">Run Information</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <dl className="space-y-3">
              <div>
                <dt className="text-sm font-medium text-gray-500">Status</dt>
                <dd className="mt-1">
                  <div className="flex items-center">
                    {getStatusIcon(testRun.status)}
                    <span className="ml-2 capitalize">{testRun.status}</span>
                  </div>
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Target Environment</dt>
                <dd className="mt-1 text-sm text-gray-900">{testRun.target_environment || 'N/A'}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Total Tests</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {(testRun.passed || 0) + (testRun.failed || 0) + (testRun.errors || 0)}
                </dd>
              </div>
            </dl>
          </div>
          
          <div>
            <dl className="space-y-3">
              <div>
                <dt className="text-sm font-medium text-gray-500">Created</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {testRun.started_at ? new Date(testRun.started_at).toLocaleString() : 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Completed</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {testRun.completed_at ? new Date(testRun.completed_at).toLocaleString() : 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Success Rate</dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {testRun.passed && (testRun.passed + testRun.failed + testRun.errors) > 0
                    ? `${Math.round((testRun.passed / (testRun.passed + testRun.failed + testRun.errors)) * 100)}%`
                    : '0%'
                  }
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium text-gray-900">Test Results</h3>
          
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-500" />
            <select 
              value={filter} 
              onChange={(e) => setFilter(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-1 text-sm"
            >
              <option value="all">All Results ({testRun.results?.length || 0})</option>
              <option value="passed">Passed ({testRun.passed || 0})</option>
              <option value="failed">Failed ({testRun.failed || 0})</option>
              <option value="error">Errors ({testRun.errors || 0})</option>
            </select>
          </div>
        </div>
      </div>

      {/* Test Results */}
      <div className="space-y-4">
        {filteredResults.length > 0 ? (
          filteredResults.map((result, index) => {
            const testInsight = getTestTypeInsight(result);
            const isExpanded = expandedTest === index;
            
            return (
              <div key={index} className="card">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      {getStatusIcon(result.status)}
                      <h4 className="text-lg font-medium text-gray-900">
                        {result.description || `Test ${index + 1}`}
                      </h4>
                      {getStatusBadge(result.status)}
                      {result.agent_type && getAgentTypeBadge(result.agent_type)}
                    </div>
                    
                    {/* Test Type Insight */}
                    <div className="flex items-center space-x-2 mb-3">
                      <span className="text-lg">{testInsight.icon}</span>
                      <span className={`text-sm font-medium ${testInsight.color}`}>
                        {testInsight.type}
                      </span>
                      <span className="text-sm text-gray-500">
                        {testInsight.description}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="font-medium text-gray-500">Method:</span>
                        <span className="ml-2 font-mono bg-gray-100 px-2 py-1 rounded">
                          {result.test_case?.test_definition?.method || 'N/A'}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-500">Endpoint:</span>
                        <span className="ml-2 font-mono text-gray-900">
                          {result.test_case?.test_definition?.path || result.test_case?.test_definition?.endpoint || 'N/A'}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-500">Response:</span>
                        <span className={`ml-2 font-mono px-2 py-1 rounded ${
                          result.response_code >= 200 && result.response_code < 300 
                            ? 'bg-success-100 text-success-800'
                            : result.response_code >= 400 
                            ? 'bg-danger-100 text-danger-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}>
                          {result.response_code || 'N/A'}
                        </span>
                      </div>
                    </div>
                    
                    {/* Failure Analysis for Failed Tests */}
                    {result.status === 'failed' && result.error_message && (
                      <div className="mt-4 p-3 bg-danger-50 border border-danger-200 rounded-md">
                        <h5 className="text-sm font-medium text-danger-800 mb-2">Failure Analysis</h5>
                        <p className="text-sm text-danger-700">{result.error_message}</p>
                        
                        {/* Enhanced failure insights for negative tests */}
                        {result.agent_type === 'Functional-Negative-Agent' && (
                          <div className="mt-2 text-xs text-danger-600">
                            <strong>Negative Test Insight:</strong> This test was designed to validate error handling. 
                            The failure might indicate that the API is not properly rejecting invalid inputs or 
                            returning appropriate error responses.
                          </div>
                        )}
                      </div>
                    )}
                    
                    {/* Success insights for negative tests */}
                    {result.status === 'passed' && result.agent_type === 'Functional-Negative-Agent' && (
                      <div className="mt-4 p-3 bg-success-50 border border-success-200 rounded-md">
                        <h5 className="text-sm font-medium text-success-800 mb-2">Negative Test Success</h5>
                        <p className="text-sm text-success-700">
                          ✅ API correctly rejected invalid input and returned expected error response (HTTP {result.response_code})
                        </p>
                      </div>
                    )}
                  </div>
                  
                  <button
                    onClick={() => setExpandedTest(isExpanded ? null : index)}
                    className="btn btn-secondary btn-sm ml-4"
                  >
                    <Eye className="h-4 w-4 mr-1" />
                    {isExpanded ? 'Hide' : 'Details'}
                  </button>
                </div>
                
                {/* Expanded Details */}
                {isExpanded && (
                  <div className="mt-6 pt-6 border-t border-gray-200">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Request Details */}
                      <div>
                        <h5 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                          <Code className="h-4 w-4 mr-1" />
                          Request Details
                        </h5>
                        
                        {result.test_case?.test_definition?.body && (
                          <div className="mb-4">
                            <h6 className="text-xs font-medium text-gray-700 mb-2">Request Body:</h6>
                            <div className="code-block">
                              <pre>{JSON.stringify(result.test_case.test_definition.body, null, 2)}</pre>
                            </div>
                          </div>
                        )}
                        
                        {result.test_case?.test_definition?.headers && (
                          <div className="mb-4">
                            <h6 className="text-xs font-medium text-gray-700 mb-2">Request Headers:</h6>
                            <div className="code-block">
                              <pre>{JSON.stringify(result.test_case.test_definition.headers, null, 2)}</pre>
                            </div>
                          </div>
                        )}
                        
                        {result.test_case?.test_definition?.query_params && Object.keys(result.test_case.test_definition.query_params).length > 0 && (
                          <div>
                            <h6 className="text-xs font-medium text-gray-700 mb-2">Query Parameters:</h6>
                            <div className="code-block">
                              <pre>{JSON.stringify(result.test_case.test_definition.query_params, null, 2)}</pre>
                            </div>
                          </div>
                        )}
                        
                        {!result.test_case?.test_definition?.body && 
                         !result.test_case?.test_definition?.headers && 
                         (!result.test_case?.test_definition?.query_params || Object.keys(result.test_case.test_definition.query_params).length === 0) && (
                          <p className="text-sm text-gray-500 italic">No request details available</p>
                        )}
                      </div>
                      
                      {/* Response Details */}
                      <div>
                        <h5 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                          <Code className="h-4 w-4 mr-1" />
                          Response Details
                        </h5>
                        
                        {result.response_body && (
                          <div className="mb-4">
                            <h6 className="text-xs font-medium text-gray-700 mb-2">Response Body:</h6>
                            <div className="code-block">
                              <pre>{typeof result.response_body === 'string' 
                                ? result.response_body 
                                : JSON.stringify(result.response_body, null, 2)
                              }</pre>
                            </div>
                          </div>
                        )}
                        
                        {result.response_headers && (
                          <div>
                            <h6 className="text-xs font-medium text-gray-700 mb-2">Response Headers:</h6>
                            <div className="code-block">
                              <pre>{JSON.stringify(result.response_headers, null, 2)}</pre>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="card text-center py-8">
            <AlertTriangle className="h-12 w-12 mx-auto text-gray-300 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No results found</h3>
            <p className="text-gray-500">
              {filter === 'all' 
                ? 'This test run has no results yet.'
                : `No ${filter} test results found.`
              }
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default TestRunDetail;
