import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Package, 
  Plus,
  Edit3,
  Trash2,
  PlayCircle,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  MoreVertical,
  X,
  Save,
  List,
  FileText
} from 'lucide-react';
import { apiService } from '../services/api';
import NotificationModal from '../components/NotificationModal';
import ConfirmationModal from '../components/ConfirmationModal';
import useNotification from '../hooks/useNotification';

const TestSuites = () => {
  const [testSuites, setTestSuites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedSuite, setExpandedSuite] = useState(null);
  const [editingSuite, setEditingSuite] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({
    name: '',
    description: ''
  });
  const [actionLoading, setActionLoading] = useState(false);
  const [showAddTestCasesModal, setShowAddTestCasesModal] = useState(false);
  const [selectedSuiteForAddingCases, setSelectedSuiteForAddingCases] = useState(null);
  const [availableTestCases, setAvailableTestCases] = useState([]);
  const [selectedTestCaseIds, setSelectedTestCaseIds] = useState([]);
  const [testCaseSearchTerm, setTestCaseSearchTerm] = useState('');
  const [specifications, setSpecifications] = useState([]);
  
  // Notification system
  const { 
    notification, 
    confirmation, 
    showSuccess, 
    showError, 
    showWarning, 
    hideNotification, 
    confirm 
  } = useNotification();

  useEffect(() => {
    loadTestSuites();
    loadSpecifications();
  }, []);

  const loadTestSuites = async () => {
    try {
      setLoading(true);
      const data = await apiService.getTestSuites();
      // Handle both direct array and wrapped response
      const suitesArray = Array.isArray(data) ? data : (data?.data || []);
      setTestSuites(suitesArray);
      setError(null);
    } catch (err) {
      console.error('Error loading test suites:', err);
      setError('Failed to load test suites');
    } finally {
      setLoading(false);
    }
  };

  const loadSpecifications = async () => {
    try {
      const data = await apiService.getSpecifications();
      // Handle both direct array and wrapped response
      const specsArray = Array.isArray(data) ? data : (data?.data || []);
      setSpecifications(specsArray);
    } catch (err) {
      console.error('Error loading specifications:', err);
      setSpecifications([]);
    }
  };

  const getSpecificationName = (specId) => {
    if (!Array.isArray(specifications) || specifications.length === 0) {
      return `Spec ${specId}`;
    }
    const spec = specifications.find(s => s.id === specId);
    return spec ? (spec.title || spec.source_filename || `Spec ${specId}`) : `Spec ${specId}`;
  };

  const loadAvailableTestCases = async (suiteId) => {
    try {
      const allTestCases = await apiService.getTestCases();
      const suite = testSuites.find(s => s.id === suiteId);
      
      // Filter out test cases that are already in the suite
      const existingCaseIds = suite?.test_cases?.map(tc => tc.id) || [];
      const available = allTestCases.filter(tc => !existingCaseIds.includes(tc.id));
      
      setAvailableTestCases(available);
    } catch (err) {
      console.error('Error loading test cases:', err);
      setAvailableTestCases([]);
    }
  };

  const handleOpenAddTestCasesModal = async (suiteId) => {
    setSelectedSuiteForAddingCases(suiteId);
    setSelectedTestCaseIds([]);
    setTestCaseSearchTerm('');
    await loadAvailableTestCases(suiteId);
    setShowAddTestCasesModal(true);
  };

  const handleAddTestCasesToSuite = async () => {
    if (selectedTestCaseIds.length === 0) {
      showWarning('Please select at least one test case to add');
      return;
    }

    try {
      setActionLoading(true);
      
      // Add each selected test case to the suite
      for (const caseId of selectedTestCaseIds) {
        await apiService.addTestCaseToSuite(selectedSuiteForAddingCases, {
          case_id: caseId,
          execution_order: 0 // Let backend handle the ordering
        });
      }
      
      // Close modal and reload suites
      setShowAddTestCasesModal(false);
      setSelectedTestCaseIds([]);
      await loadTestSuites();
      
      // If the suite was expanded, reload its details
      if (expandedSuite === selectedSuiteForAddingCases) {
        const suiteDetails = await apiService.getTestSuite(selectedSuiteForAddingCases);
        const suiteIndex = testSuites.findIndex(s => s.id === selectedSuiteForAddingCases);
        if (suiteIndex !== -1) {
          const updatedSuites = [...testSuites];
          updatedSuites[suiteIndex] = { ...updatedSuites[suiteIndex], ...suiteDetails };
          setTestSuites(updatedSuites);
        }
      }
    } catch (err) {
      console.error('Error adding test cases to suite:', err);
      showError('Failed to add test cases. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const toggleTestCaseSelection = (caseId) => {
    setSelectedTestCaseIds(prev => {
      if (prev.includes(caseId)) {
        return prev.filter(id => id !== caseId);
      } else {
        return [...prev, caseId];
      }
    });
  };

  const handleCreateSuite = async () => {
    if (!createForm.name.trim()) {
      showWarning('Please enter a suite name');
      return;
    }

    try {
      setActionLoading(true);
      await apiService.createTestSuite({
        name: createForm.name,
        description: createForm.description
      });
      
      // Reset form and close modal
      setCreateForm({ name: '', description: '' });
      setShowCreateModal(false);
      
      // Reload test suites
      loadTestSuites();
    } catch (err) {
      console.error('Error creating test suite:', err);
      showError('Failed to create test suite. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleEditSuite = (suite) => {
    setEditingSuite(suite.id);
    setEditForm({
      name: suite.name,
      description: suite.description || ''
    });
  };

  const handleSaveEdit = async (suiteId) => {
    if (!editForm.name.trim()) {
      showWarning('Suite name cannot be empty');
      return;
    }

    try {
      setActionLoading(true);
      await apiService.updateTestSuite(suiteId, {
        name: editForm.name,
        description: editForm.description
      });
      
      setEditingSuite(null);
      setEditForm({});
      loadTestSuites();
    } catch (err) {
      console.error('Error updating test suite:', err);
      showError('Failed to update test suite. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteSuite = async (suiteId, suiteName) => {
    const confirmMessage = `Are you sure you want to delete the test suite "${suiteName}"?\n\nThis will also delete:\n• All test runs associated with this suite\n• All test results for those runs\n• All suite-test case associations\n\nThis action cannot be undone.`;
    
    const confirmed = await confirm({
      title: 'Delete Test Suite',
      message: confirmMessage,
      confirmText: 'Delete',
      confirmStyle: 'danger'
    });
    
    if (!confirmed) return;

    try {
      setActionLoading(true);
      const result = await apiService.deleteTestSuite(suiteId);
      
      // Show success message
      if (result && result.message) {
        // Use a temporary success notification instead of alert
        console.log('Success:', result.message);
      }
      
      // If the deleted suite was expanded, clear the expansion
      if (expandedSuite === suiteId) {
        setExpandedSuite(null);
      }
      
      // Reload the test suites list
      await loadTestSuites();
      
    } catch (err) {
      console.error('Error deleting test suite:', err);
      
      // Provide more specific error messages
      let errorMessage = 'Failed to delete test suite. Please try again.';
      
      if (err.response) {
        switch (err.response.status) {
          case 404:
            errorMessage = 'Test suite not found. It may have already been deleted.';
            break;
          case 403:
            errorMessage = 'You do not have permission to delete this test suite.';
            break;
          case 500:
            errorMessage = 'Server error occurred while deleting the test suite. Please try again later.';
            break;
          default:
            if (err.response.data && err.response.data.detail) {
              errorMessage = `Error: ${err.response.data.detail}`;
            }
        }
      } else if (err.message) {
        errorMessage = `Network error: ${err.message}`;
      }
      
      showError(errorMessage);
      
      // Refresh the list in case the suite was actually deleted despite the error
      await loadTestSuites();
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemoveTestCase = async (suiteId, caseId) => {
    const confirmed = await confirm({
      title: 'Remove Test Case',
      message: 'Are you sure you want to remove this test case from the suite?',
      confirmText: 'Remove',
      confirmStyle: 'warning'
    });
    
    if (!confirmed) return;

    try {
      setActionLoading(true);
      await apiService.removeTestCaseFromSuite(suiteId, caseId);
      
      // Update the local state immediately
      setTestSuites(prevSuites => {
        return prevSuites.map(suite => {
          if (suite.id === suiteId) {
            const updatedSuite = { ...suite };
            if (updatedSuite.test_cases) {
              updatedSuite.test_cases = updatedSuite.test_cases.filter(tc => tc.id !== caseId);
            }
            // Update the count
            updatedSuite.test_case_count = (updatedSuite.test_case_count || 0) - 1;
            return updatedSuite;
          }
          return suite;
        });
      });
      
      // Also reload to get fresh data
      loadTestSuites();
    } catch (err) {
      console.error('Error removing test case:', err);
      showError('Failed to remove test case. Please try again.');
    } finally {
      setActionLoading(false);
    }
  };

  const toggleExpandSuite = async (suiteId) => {
    if (expandedSuite === suiteId) {
      setExpandedSuite(null);
    } else {
      // Load suite details with test cases
      try {
        const suiteDetails = await apiService.getTestSuite(suiteId);
        const suiteIndex = testSuites.findIndex(s => s.id === suiteId);
        if (suiteIndex !== -1) {
          const updatedSuites = [...testSuites];
          updatedSuites[suiteIndex] = { ...updatedSuites[suiteIndex], ...suiteDetails };
          setTestSuites(updatedSuites);
        }
        setExpandedSuite(suiteId);
      } catch (err) {
        console.error('Error loading suite details:', err);
      }
    }
  };

  const filteredSuites = testSuites.filter(suite => {
    const matchesSearch = searchTerm === '' || 
      suite.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (suite.description && suite.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    return matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading test suites...</span>
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
              onClick={loadTestSuites}
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
          <h1 className="text-2xl font-bold text-gray-900">Test Suites</h1>
          <p className="text-gray-600 mt-1">
            Manage collections of test cases for organized test execution
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button onClick={loadTestSuites} className="btn btn-secondary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
          <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
            <Plus className="h-4 w-4 mr-2" />
            New Test Suite
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="card">
        <div className="flex items-center space-x-2">
          <Search className="h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search test suites..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="flex-1 outline-none text-gray-700"
          />
        </div>
      </div>

      {/* Test Suites List */}
      {filteredSuites.length > 0 ? (
        <div className="space-y-4">
          {filteredSuites.map((suite) => {
            const isExpanded = expandedSuite === suite.id;
            const isEditing = editingSuite === suite.id;
            
            return (
              <div key={suite.id} className="card">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3 flex-1">
                    <Package className="h-6 w-6 text-primary-500 mt-1" />
                    
                    <div className="flex-1">
                      {/* Suite Header */}
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex-1">
                          {isEditing ? (
                            <div className="space-y-2">
                              <input
                                type="text"
                                value={editForm.name}
                                onChange={(e) => setEditForm({...editForm, name: e.target.value})}
                                className="text-lg font-medium text-gray-900 border border-gray-300 rounded px-2 py-1 w-full"
                                placeholder="Suite name..."
                              />
                              <textarea
                                value={editForm.description}
                                onChange={(e) => setEditForm({...editForm, description: e.target.value})}
                                className="text-sm text-gray-600 border border-gray-300 rounded px-2 py-1 w-full"
                                placeholder="Suite description..."
                                rows={2}
                              />
                            </div>
                          ) : (
                            <>
                              <h3 className="text-lg font-medium text-gray-900">{suite.name}</h3>
                              {suite.description && (
                                <p className="text-sm text-gray-600 mt-1">{suite.description}</p>
                              )}
                            </>
                          )}
                        </div>
                        
                        {/* Action Buttons */}
                        <div className="flex items-center space-x-2 ml-4">
                          {isEditing ? (
                            <>
                              <button
                                onClick={() => handleSaveEdit(suite.id)}
                                disabled={actionLoading}
                                className="btn btn-primary btn-sm"
                              >
                                <Save className="h-4 w-4 mr-1" />
                                Save
                              </button>
                              <button
                                onClick={() => {
                                  setEditingSuite(null);
                                  setEditForm({});
                                }}
                                className="btn btn-secondary btn-sm"
                              >
                                <X className="h-4 w-4 mr-1" />
                                Cancel
                              </button>
                            </>
                          ) : (
                            <>
                              <Link
                                to="/test-runs"
                                state={{ selectedSuiteId: suite.id }}
                                className="btn btn-primary btn-sm"
                              >
                                <PlayCircle className="h-4 w-4 mr-1" />
                                Run Suite
                              </Link>
                              <button
                                onClick={() => toggleExpandSuite(suite.id)}
                                className="btn btn-secondary btn-sm"
                              >
                                <List className="h-4 w-4 mr-1" />
                                {isExpanded ? 'Hide' : 'View'} Tests
                              </button>
                              <button
                                onClick={() => handleEditSuite(suite)}
                                className="btn btn-secondary btn-sm"
                              >
                                <Edit3 className="h-4 w-4" />
                              </button>
                              <button
                                onClick={() => handleDeleteSuite(suite.id, suite.name)}
                                disabled={actionLoading}
                                className="btn btn-danger btn-sm"
                                title="Delete test suite and all related data"
                              >
                                {actionLoading ? (
                                  <RefreshCw className="h-4 w-4 animate-spin" />
                                ) : (
                                  <Trash2 className="h-4 w-4" />
                                )}
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                      
                      {/* Suite Stats */}
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span>
                          <strong>{suite.test_case_count || 0}</strong> test cases
                        </span>
                        <span>•</span>
                        <span>
                          Created: {new Date(suite.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      
                      {/* Expanded Test Cases */}
                      {isExpanded && suite.test_cases && (
                        <div className="mt-4 border-t pt-4">
                          <h4 className="text-sm font-medium text-gray-700 mb-3">Test Cases in this Suite:</h4>
                          {suite.test_cases.length > 0 ? (
                            <div className="space-y-2">
                              {suite.test_cases.map((testCase, index) => (
                                <div key={testCase.id} className="flex items-center justify-between bg-gray-50 rounded-md p-3">
                                  <div className="flex items-center space-x-3">
                                    <span className="text-sm text-gray-500">#{index + 1}</span>
                                    <div className="flex-1">
                                      <p className="text-sm font-medium text-gray-900">
                                        {testCase.description || `Test Case ${testCase.id}`}
                                      </p>
                                      <div className="flex items-center space-x-2 mt-1">
                                        {testCase.spec_id && (
                                          <span className="text-xs text-gray-600">
                                            <FileText className="h-3 w-3 inline mr-1" />
                                            {getSpecificationName(testCase.spec_id)}
                                          </span>
                                        )}
                                        {testCase.spec_id && (testCase.agent_type || testCase.tags?.length > 0) && (
                                          <span className="text-xs text-gray-400">•</span>
                                        )}
                                        {testCase.agent_type && (
                                          <span className="text-xs badge badge-secondary">
                                            {testCase.agent_type.replace('Functional-', '').replace('-Agent', '')}
                                          </span>
                                        )}
                                        {testCase.tags && testCase.tags.map(tag => (
                                          <span key={tag} className="text-xs badge">{tag}</span>
                                        ))}
                                      </div>
                                      {testCase.test_definition && (
                                        <p className="text-xs text-gray-500 mt-1">
                                          {testCase.test_definition.method} {testCase.test_definition.endpoint}
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                  <button
                                    onClick={() => handleRemoveTestCase(suite.id, testCase.id)}
                                    className="text-danger-600 hover:text-danger-800"
                                    title="Remove from suite"
                                  >
                                    <X className="h-4 w-4" />
                                  </button>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500 italic">No test cases in this suite yet.</p>
                          )}
                          
                          <button
                            onClick={() => handleOpenAddTestCasesModal(suite.id)}
                            className="btn btn-secondary btn-sm mt-3"
                          >
                            <Plus className="h-4 w-4 mr-1" />
                            Add Test Cases
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="card text-center py-12">
          <Package className="h-16 w-16 mx-auto text-gray-300 mb-4" />
          <h3 className="text-xl font-medium text-gray-900 mb-2">
            {searchTerm ? 'No matching test suites found' : 'No test suites yet'}
          </h3>
          <p className="text-gray-500 mb-6">
            {searchTerm 
              ? 'Try adjusting your search criteria.'
              : 'Create a test suite to organize your test cases for execution.'
            }
          </p>
          
          {!searchTerm && (
            <button onClick={() => setShowCreateModal(true)} className="btn btn-primary">
              <Plus className="h-4 w-4 mr-2" />
              Create Your First Test Suite
            </button>
          )}
        </div>
      )}

      {/* Create Test Suite Modal */}
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
                  <Package className="w-6 h-6 text-primary-600" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left flex-1">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    Create Test Suite
                  </h3>
                  <div className="mt-4">
                    {/* Suite Name */}
                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Suite Name
                      </label>
                      <input
                        type="text"
                        placeholder="e.g., Smoke Tests, Regression Suite"
                        value={createForm.name}
                        onChange={(e) => setCreateForm({...createForm, name: e.target.value})}
                        className="w-full border border-gray-300 rounded-md px-3 py-2"
                      />
                    </div>

                    {/* Suite Description */}
                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Description (Optional)
                      </label>
                      <textarea
                        placeholder="Describe the purpose of this test suite..."
                        value={createForm.description}
                        onChange={(e) => setCreateForm({...createForm, description: e.target.value})}
                        className="w-full border border-gray-300 rounded-md px-3 py-2"
                        rows={3}
                      />
                    </div>

                    <div className="bg-gray-50 rounded-md p-3">
                      <p className="text-sm text-gray-600">
                        After creating the suite, you can add test cases from the Test Cases page.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  onClick={handleCreateSuite}
                  disabled={actionLoading || !createForm.name.trim()}
                  className="inline-flex justify-center w-full px-4 py-2 text-base font-medium text-white bg-primary-600 border border-transparent rounded-md shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {actionLoading ? 'Creating...' : 'Create Suite'}
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

      {/* Add Test Cases Modal */}
      {showAddTestCasesModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:p-0">
            {/* Background overlay */}
            <div 
              className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
              onClick={() => setShowAddTestCasesModal(false)}
            />

            {/* Modal panel */}
            <div className="relative inline-block px-4 pt-5 pb-4 overflow-hidden text-left align-bottom transition-all transform bg-white rounded-lg shadow-xl sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full sm:p-6">
              <div className="absolute top-0 right-0 pt-4 pr-4">
                <button
                  onClick={() => setShowAddTestCasesModal(false)}
                  className="text-gray-400 hover:text-gray-500"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>

              <div className="sm:flex sm:items-start">
                <div className="flex items-center justify-center flex-shrink-0 w-12 h-12 mx-auto bg-primary-100 rounded-full sm:mx-0 sm:h-10 sm:w-10">
                  <Plus className="w-6 h-6 text-primary-600" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left flex-1">
                  <h3 className="text-lg font-medium leading-6 text-gray-900">
                    Add Test Cases to Suite
                  </h3>
                  
                  <div className="mt-4">
                    {/* Search Bar */}
                    <div className="mb-4">
                      <div className="flex items-center space-x-2 border border-gray-300 rounded-md px-3 py-2">
                        <Search className="h-5 w-5 text-gray-400" />
                        <input
                          type="text"
                          placeholder="Search test cases..."
                          value={testCaseSearchTerm}
                          onChange={(e) => setTestCaseSearchTerm(e.target.value)}
                          className="flex-1 outline-none text-gray-700"
                        />
                      </div>
                    </div>

                    {/* Test Cases List */}
                    <div className="max-h-96 overflow-y-auto border border-gray-200 rounded-md">
                      {availableTestCases.length > 0 ? (
                        <div className="divide-y divide-gray-200">
                          {availableTestCases
                            .filter(tc => {
                              if (!testCaseSearchTerm) return true;
                              const searchLower = testCaseSearchTerm.toLowerCase();
                              return (
                                tc.description?.toLowerCase().includes(searchLower) ||
                                tc.agent_type?.toLowerCase().includes(searchLower) ||
                                tc.tags?.some(tag => tag.toLowerCase().includes(searchLower))
                              );
                            })
                            .map((testCase) => (
                              <div 
                                key={testCase.id}
                                className={`p-3 hover:bg-gray-50 cursor-pointer transition-colors ${
                                  selectedTestCaseIds.includes(testCase.id) ? 'bg-primary-50' : ''
                                }`}
                                onClick={() => toggleTestCaseSelection(testCase.id)}
                              >
                                <div className="flex items-start space-x-3">
                                  <input
                                    type="checkbox"
                                    checked={selectedTestCaseIds.includes(testCase.id)}
                                    onChange={() => {}}
                                    className="mt-1 h-4 w-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                                  />
                                  <div className="flex-1">
                                    <p className="text-sm font-medium text-gray-900">
                                      {testCase.description || `Test Case ${testCase.id}`}
                                    </p>
                                    <div className="flex items-center space-x-2 mt-1">
                                      {testCase.spec_id && (
                                        <span className="text-xs text-gray-600">
                                          <FileText className="h-3 w-3 inline mr-1" />
                                          {getSpecificationName(testCase.spec_id)}
                                        </span>
                                      )}
                                      {testCase.spec_id && (testCase.agent_type || testCase.tags?.length > 0) && (
                                        <span className="text-xs text-gray-400">•</span>
                                      )}
                                      {testCase.agent_type && (
                                        <span className="text-xs badge badge-secondary">
                                          {testCase.agent_type.replace('Functional-', '').replace('-Agent', '')}
                                        </span>
                                      )}
                                      {testCase.tags && testCase.tags.map(tag => (
                                        <span key={tag} className="text-xs badge">{tag}</span>
                                      ))}
                                    </div>
                                    {testCase.test_definition && (
                                      <p className="text-xs text-gray-500 mt-1">
                                        {testCase.test_definition.method} {testCase.test_definition.endpoint}
                                      </p>
                                    )}
                                  </div>
                                </div>
                              </div>
                            ))}
                        </div>
                      ) : (
                        <div className="p-6 text-center text-gray-500">
                          <p>No available test cases to add.</p>
                          <p className="text-sm mt-2">All test cases may already be in this suite.</p>
                        </div>
                      )}
                    </div>

                    {/* Selected count */}
                    {availableTestCases.length > 0 && (
                      <div className="mt-3 text-sm text-gray-600">
                        {selectedTestCaseIds.length} test case(s) selected
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  onClick={handleAddTestCasesToSuite}
                  disabled={actionLoading || selectedTestCaseIds.length === 0}
                  className="inline-flex justify-center w-full px-4 py-2 text-base font-medium text-white bg-primary-600 border border-transparent rounded-md shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {actionLoading ? 'Adding...' : `Add ${selectedTestCaseIds.length} Test Case(s)`}
                </button>
                <button
                  onClick={() => setShowAddTestCasesModal(false)}
                  className="inline-flex justify-center w-full px-4 py-2 mt-3 text-base font-medium text-gray-700 bg-white border border-gray-300 rounded-md shadow-sm hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Notification Modal */}
      <NotificationModal
        show={notification.show}
        type={notification.type}
        message={notification.message}
        onClose={hideNotification}
      />
      
      {/* Confirmation Modal */}
      <ConfirmationModal
        show={confirmation.show}
        title={confirmation.title}
        message={confirmation.message}
        confirmText={confirmation.confirmText}
        cancelText={confirmation.cancelText}
        confirmStyle={confirmation.confirmStyle}
        onConfirm={confirmation.onConfirm}
        onCancel={confirmation.onCancel}
      />
    </div>
  );
};

export default TestSuites;