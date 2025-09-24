import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
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
  Calendar,
  X,
  Trash2
} from 'lucide-react';
import { apiService } from '../services/api';

const TestRuns = () => {
  const location = useLocation();
  const [testRuns, setTestRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [testSuites, setTestSuites] = useState([]);
  const [createForm, setCreateForm] = useState({
    suite_id: '',
    target_environment: 'http://host.docker.internal:8080'
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [deleteModal, setDeleteModal] = useState({ show: false, runId: null, runName: '' });
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [selectedRuns, setSelectedRuns] = useState([]);
  const [bulkDeleteModal, setBulkDeleteModal] = useState(false);
  const [bulkDeleteLoading, setBulkDeleteLoading] = useState(false);
  const [notification, setNotification] = useState({ show: false, type: '', message: '' });

  useEffect(() => {
    loadTestRuns();
    loadTestSuites();
    
    // Check if navigated from Test Suites page with selected suite
    if (location.state?.selectedSuiteId) {
      setCreateForm(prev => ({ ...prev, suite_id: location.state.selectedSuiteId.toString() }));
      setShowCreateModal(true);
    }
  }, [location.state]);

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

  const loadTestSuites = async () => {
    try {
      const data = await apiService.getTestSuites();
      // Handle both direct array and wrapped response
      const suitesArray = Array.isArray(data) ? data : (data?.data || []);
      setTestSuites(suitesArray);
    } catch (err) {
      console.error('Error loading test suites:', err);
      setTestSuites([]);
    }
  };

  const handleCreateTestRun = async () => {
    if (!createForm.suite_id || !createForm.target_environment) {
      showNotification('warning', 'Please select a test suite and enter target environment URL');
      return;
    }

    // Validate URL format
    if (!createForm.target_environment.match(/^https?:\/\//)) {
      showNotification('error', 'Target environment URL must start with http:// or https://');
      return;
    }

    try {
      setCreateLoading(true);
      await apiService.runTests({
        suite_id: parseInt(createForm.suite_id),
        target_environment: createForm.target_environment
      });
      
      // Reset form and close modal
      setCreateForm({ suite_id: '', target_environment: 'http://host.docker.internal:8080' });
      setShowCreateModal(false);
      
      // Reload test runs
      loadTestRuns();
      
      // Show success message
      showNotification('success', 'Test run created successfully');
    } catch (err) {
      console.error('Error creating test run:', err);
      showNotification('error', 'Failed to create test run. Please try again.');
    } finally {
      setCreateLoading(false);
    }
  };

  const showNotification = (type, message) => {
    setNotification({ show: true, type, message });
    // Auto-hide notification after 5 seconds
    setTimeout(() => {
      setNotification({ show: false, type: '', message: '' });
    }, 5000);
  };

  const handleDeleteTestRun = async () => {
    if (!deleteModal.runId) return;

    try {
      setDeleteLoading(true);
      await apiService.deleteTestRun(deleteModal.runId);
      
      // Close modal and reload test runs
      setDeleteModal({ show: false, runId: null, runName: '' });
      loadTestRuns();
      
      // Show success message
      showNotification('success', 'Test run deleted successfully');
    } catch (err) {
      console.error('Error deleting test run:', err);
      showNotification('error', 'Failed to delete test run. Please try again.');
    } finally {
      setDeleteLoading(false);
    }
  };

  const openDeleteModal = (run) => {
    setDeleteModal({ 
      show: true, 
      runId: run.id, 
      runName: `Test Run #${run.id}` 
    });
  };

  const handleSelectRun = (runId) => {
    setSelectedRuns(prev => {
      if (prev.includes(runId)) {
        return prev.filter(id => id !== runId);
      }
      return [...prev, runId];
    });
  };

  const handleSelectAll = () => {
    if (selectedRuns.length === filteredRuns.length) {
      setSelectedRuns([]);
    } else {
      setSelectedRuns(filteredRuns.map(run => run.id));
    }
  };

  const handleBulkDelete = async () => {
    if (selectedRuns.length === 0) return;

    try {
      setBulkDeleteLoading(true);
      const count = selectedRuns.length;
      await apiService.bulkDeleteTestRuns(selectedRuns);
      
      // Close modal, clear selection and reload test runs
      setBulkDeleteModal(false);
      setSelectedRuns([]);
      loadTestRuns();
      
      // Show success message
      showNotification('success', `Successfully deleted ${count} test run${count > 1 ? 's' : ''}`);
    } catch (err) {
      console.error('Error deleting test runs:', err);
      showNotification('error', 'Failed to delete test runs. Please try again.');
    } finally {
      setBulkDeleteLoading(false);
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
          {selectedRuns.length > 0 && (
            <button 
              onClick={() => setBulkDeleteModal(true)}
              className="btn btn-danger"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete Selected ({selectedRuns.length})
            </button>
          )}
          <button onClick={loadTestRuns} className="btn btn-secondary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
          <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
            <Plus className="h-4 w-4 mr-2" />
            New Test Run
          </button>
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
          {/* Select All Checkbox */}
          {testRuns.length > 0 && (
            <div className="card bg-gray-50 px-4 py-2">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedRuns.length === filteredRuns.length && filteredRuns.length > 0}
                  onChange={handleSelectAll}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <span className="text-sm font-medium text-gray-700">
                  Select All ({filteredRuns.length} runs)
                </span>
              </label>
            </div>
          )}
          
          {filteredRuns.map((run) => (
            <div key={run.id} className="card hover:shadow-md transition-shadow duration-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  {/* Checkbox for selection */}
                  <input
                    type="checkbox"
                    checked={selectedRuns.includes(run.id)}
                    onChange={() => handleSelectRun(run.id)}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  
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
                    <button
                      onClick={() => openDeleteModal(run)}
                      className="btn btn-danger btn-sm"
                      title="Delete test run"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
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
            <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
              <Plus className="h-4 w-4 mr-2" />
              Create Your First Test Run
            </button>
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
              <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
                <Plus className="h-4 w-4 mr-2" />
                New Test Run
              </button>
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

      {/* Create Test Run Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:p-0">
            {/* Background overlay */}
            <div 
              className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
              onClick={() => setShowCreateModal(false)}
            />

            {/* Modal panel */}
            <div className="relative inline-block px-4 pt-5 pb-4 overflow-hidden text-left align-bottom transition-all transform bg-white rounded-lg shadow-xl sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div className="absolute top-0 right-0 pt-4 pr-4">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="text-gray-400 hover:text-gray-500"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>

              <div className="sm:flex sm:items-start">
                <div className="flex items-center justify-center flex-shrink-0 w-12 h-12 mx-auto bg-primary-100 rounded-full sm:mx-0 sm:h-10 sm:w-10">
                  <PlayCircle className="w-6 h-6 text-primary-600" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left flex-1">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    Create New Test Run
                  </h3>
                  <div className="mt-4">
                    {/* Test Suite Selection */}
                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Test Suite
                      </label>
                      {testSuites.length > 0 ? (
                        <select
                          value={createForm.suite_id}
                          onChange={(e) => setCreateForm({...createForm, suite_id: e.target.value})}
                          className="w-full border border-gray-300 rounded-md px-3 py-2"
                        >
                          <option value="">Select a test suite...</option>
                          {testSuites.map(suite => (
                            <option key={suite.id} value={suite.id}>
                              {suite.name} ({suite.test_case_count || 0} tests)
                            </option>
                          ))}
                        </select>
                      ) : (
                        <div className="text-sm text-gray-500 p-3 bg-gray-50 rounded-md">
                          No test suites available. Please create a test suite first.
                        </div>
                      )}
                    </div>

                    {/* Target Environment */}
                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Target Environment URL
                      </label>
                      <input
                        type="url"
                        placeholder="https://api.example.com"
                        value={createForm.target_environment}
                        onChange={(e) => setCreateForm({...createForm, target_environment: e.target.value})}
                        className="w-full border border-gray-300 rounded-md px-3 py-2"
                      />
                      <p className="mt-1 text-xs text-gray-500">
                        The base URL where your API is hosted
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  onClick={handleCreateTestRun}
                  disabled={createLoading || testSuites.length === 0}
                  className="inline-flex justify-center w-full px-4 py-2 text-base font-medium text-white bg-primary-600 border border-transparent rounded-md shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createLoading ? 'Starting...' : 'Start Test Run'}
                </button>
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="inline-flex justify-center w-full px-4 py-2 mt-3 text-base font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModal.show && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:p-0">
            {/* Background overlay */}
            <div 
              className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
              onClick={() => setDeleteModal({ show: false, runId: null, runName: '' })}
            />

            {/* Modal panel */}
            <div className="relative inline-block px-4 pt-5 pb-4 overflow-hidden text-left align-bottom transition-all transform bg-white rounded-lg shadow-xl sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div className="absolute top-0 right-0 pt-4 pr-4">
                <button
                  onClick={() => setDeleteModal({ show: false, runId: null, runName: '' })}
                  className="text-gray-400 hover:text-gray-500"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>

              <div className="sm:flex sm:items-start">
                <div className="flex items-center justify-center flex-shrink-0 w-12 h-12 mx-auto bg-danger-100 rounded-full sm:mx-0 sm:h-10 sm:w-10">
                  <Trash2 className="w-6 h-6 text-danger-600" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left flex-1">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    Delete Test Run
                  </h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      Are you sure you want to delete <strong>{deleteModal.runName}</strong>? 
                      This action will permanently remove the test run and all its associated 
                      test results. This action cannot be undone.
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  onClick={handleDeleteTestRun}
                  disabled={deleteLoading}
                  className="inline-flex justify-center w-full px-4 py-2 text-base font-medium text-white bg-danger-600 border border-transparent rounded-md shadow-sm hover:bg-danger-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {deleteLoading ? 'Deleting...' : 'Delete Test Run'}
                </button>
                <button
                  onClick={() => setDeleteModal({ show: false, runId: null, runName: '' })}
                  className="inline-flex justify-center w-full px-4 py-2 mt-3 text-base font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Delete Confirmation Modal */}
      {bulkDeleteModal && (
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg max-w-md w-full p-6">
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-xl font-bold text-gray-900">Confirm Bulk Delete</h2>
              <button
                onClick={() => setBulkDeleteModal(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="sm:flex sm:items-start">
              <div className="flex items-center justify-center flex-shrink-0 w-12 h-12 mx-auto bg-danger-100 rounded-full sm:mx-0 sm:h-10 sm:w-10">
                <Trash2 className="w-6 h-6 text-danger-600" />
              </div>
              <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left flex-1">
                <h3 className="text-lg font-medium leading-6 text-gray-900">
                  Delete {selectedRuns.length} Test Runs
                </h3>
                <div className="mt-2">
                  <p className="text-sm text-gray-500">
                    Are you sure you want to delete <strong>{selectedRuns.length} test runs</strong>? 
                    This action will permanently remove all selected test runs and their associated 
                    test results. This action cannot be undone.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
              <button
                onClick={handleBulkDelete}
                disabled={bulkDeleteLoading}
                className="inline-flex justify-center w-full px-4 py-2 text-base font-medium text-white bg-danger-600 border border-transparent rounded-md shadow-sm hover:bg-danger-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {bulkDeleteLoading ? 'Deleting...' : `Delete ${selectedRuns.length} Runs`}
              </button>
              <button
                onClick={() => setBulkDeleteModal(false)}
                className="inline-flex justify-center w-full px-4 py-2 mt-3 text-base font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:w-auto sm:text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Notification Modal */}
      {notification.show && (
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg max-w-sm w-full p-6 transform transition-all">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                {notification.type === 'success' && (
                  <div className="flex-shrink-0 w-10 h-10 bg-success-100 rounded-full flex items-center justify-center">
                    <CheckCircle className="h-6 w-6 text-success-600" />
                  </div>
                )}
                {notification.type === 'error' && (
                  <div className="flex-shrink-0 w-10 h-10 bg-danger-100 rounded-full flex items-center justify-center">
                    <XCircle className="h-6 w-6 text-danger-600" />
                  </div>
                )}
                {notification.type === 'warning' && (
                  <div className="flex-shrink-0 w-10 h-10 bg-warning-100 rounded-full flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-warning-600" />
                  </div>
                )}
                <div>
                  <h3 className="text-lg font-medium text-gray-900">
                    {notification.type === 'success' && 'Success'}
                    {notification.type === 'error' && 'Error'}
                    {notification.type === 'warning' && 'Warning'}
                  </h3>
                </div>
              </div>
              <button
                onClick={() => setNotification({ show: false, type: '', message: '' })}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="text-sm text-gray-600 mb-4">
              {notification.message}
            </div>
            
            <div className="flex justify-end">
              <button
                onClick={() => setNotification({ show: false, type: '', message: '' })}
                className={`px-4 py-2 rounded-md text-white font-medium text-sm ${
                  notification.type === 'success' ? 'bg-success-600 hover:bg-success-700' :
                  notification.type === 'error' ? 'bg-danger-600 hover:bg-danger-700' :
                  'bg-warning-600 hover:bg-warning-700'
                } focus:outline-none focus:ring-2 focus:ring-offset-2 ${
                  notification.type === 'success' ? 'focus:ring-success-500' :
                  notification.type === 'error' ? 'focus:ring-danger-500' :
                  'focus:ring-warning-500'
                }`}
              >
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TestRuns;
