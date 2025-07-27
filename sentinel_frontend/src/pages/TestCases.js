import React, { useState, useEffect } from 'react';
import { 
  TestTube, 
  Filter, 
  Search, 
  RefreshCw,
  Eye,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Code,
  Tag,
  Edit3,
  Trash2,
  Plus,
  Save,
  X,
  MoreHorizontal,
  Copy,
  Archive,
  Star,
  Users,
  MessageSquare
} from 'lucide-react';
import { apiService } from '../services/api';

const TestCases = () => {
  const [testCases, setTestCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    agent_type: 'all',
    spec_id: 'all',
    search: ''
  });
  const [specifications, setSpecifications] = useState([]);
  const [expandedCase, setExpandedCase] = useState(null);
  
  // Collaborative features state
  const [selectedCases, setSelectedCases] = useState(new Set());
  const [editingCase, setEditingCase] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [bulkActionType, setBulkActionType] = useState('');
  const [newTags, setNewTags] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [casesData, specsData] = await Promise.all([
        apiService.getTestCases(),
        apiService.getSpecifications()
      ]);
      setTestCases(casesData);
      setSpecifications(specsData);
      setError(null);
    } catch (err) {
      console.error('Error loading test cases:', err);
      setError('Failed to load test cases');
    } finally {
      setLoading(false);
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

  const getTestTypeIcon = (description) => {
    const desc = description?.toLowerCase() || '';
    
    if (desc.includes('boundary') || desc.includes('bva')) {
      return '📊';
    } else if (desc.includes('invalid') || desc.includes('negative')) {
      return '❌';
    } else if (desc.includes('stateful') || desc.includes('workflow')) {
      return '🔄';
    } else if (desc.includes('positive') || desc.includes('valid')) {
      return '✅';
    }
    
    return '🧪';
  };

  const getTestTypeInsight = (testCase) => {
    const description = testCase.description?.toLowerCase() || '';
    
    if (description.includes('boundary') || description.includes('bva')) {
      return {
        type: 'Boundary Value Analysis',
        color: 'text-blue-600',
        description: 'Tests edge cases and boundary conditions'
      };
    } else if (description.includes('invalid') || description.includes('negative')) {
      return {
        type: 'Negative Testing',
        color: 'text-red-600',
        description: 'Tests invalid inputs and error conditions'
      };
    } else if (description.includes('stateful') || description.includes('workflow')) {
      return {
        type: 'Stateful Testing',
        color: 'text-green-600',
        description: 'Tests multi-step workflows and state management'
      };
    } else if (description.includes('positive') || description.includes('valid')) {
      return {
        type: 'Positive Testing',
        color: 'text-green-600',
        description: 'Tests valid inputs and happy paths'
      };
    }
    
    return {
      type: 'Standard Test',
      color: 'text-gray-600',
      description: 'Standard API test case'
    };
  };

  const filteredTestCases = testCases.filter(testCase => {
    const matchesAgentType = filters.agent_type === 'all' || testCase.agent_type === filters.agent_type;
    const matchesSpec = filters.spec_id === 'all' || testCase.spec_id?.toString() === filters.spec_id;
    const matchesSearch = filters.search === '' || 
      testCase.description?.toLowerCase().includes(filters.search.toLowerCase()) ||
      testCase.test_definition?.endpoint?.toLowerCase().includes(filters.search.toLowerCase()) ||
      testCase.test_definition?.method?.toLowerCase().includes(filters.search.toLowerCase());
    
    return matchesAgentType && matchesSpec && matchesSearch;
  });

  // Collaborative management functions
  const handleSelectCase = (caseId) => {
    const newSelected = new Set(selectedCases);
    if (newSelected.has(caseId)) {
      newSelected.delete(caseId);
    } else {
      newSelected.add(caseId);
    }
    setSelectedCases(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedCases.size === filteredTestCases.length) {
      setSelectedCases(new Set());
    } else {
      setSelectedCases(new Set(filteredTestCases.map(tc => tc.id)));
    }
  };

  const startEditing = (testCase) => {
    setEditingCase(testCase.id);
    setEditForm({
      description: testCase.description || '',
      tags: testCase.tags ? testCase.tags.join(', ') : '',
      spec_id: testCase.spec_id,
      agent_type: testCase.agent_type,
      test_definition: testCase.test_definition
    });
  };

  const cancelEditing = () => {
    setEditingCase(null);
    setEditForm({});
  };

  const saveEdit = async () => {
    if (!editingCase) return;
    
    try {
      setActionLoading(true);
      const updateData = {
        ...editForm,
        tags: editForm.tags ? editForm.tags.split(',').map(tag => tag.trim()).filter(tag => tag) : []
      };
      
      await apiService.updateTestCase(editingCase, updateData);
      await loadData();
      setEditingCase(null);
      setEditForm({});
    } catch (err) {
      console.error('Error updating test case:', err);
      setError('Failed to update test case');
    } finally {
      setActionLoading(false);
    }
  };

  const deleteTestCase = async (caseId) => {
    if (!window.confirm('Are you sure you want to delete this test case?')) return;
    
    try {
      setActionLoading(true);
      await apiService.deleteTestCase(caseId);
      await loadData();
    } catch (err) {
      console.error('Error deleting test case:', err);
      setError('Failed to delete test case');
    } finally {
      setActionLoading(false);
    }
  };

  const handleBulkAction = async () => {
    if (selectedCases.size === 0) return;
    
    try {
      setActionLoading(true);
      const caseIds = Array.from(selectedCases);
      
      let updateData = {
        case_ids: caseIds,
        action: bulkActionType
      };

      if (bulkActionType === 'add_tags' || bulkActionType === 'set_tags') {
        const tags = newTags.split(',').map(tag => tag.trim()).filter(tag => tag);
        updateData.data = { tags };
      } else if (bulkActionType === 'remove_tags') {
        const tags = newTags.split(',').map(tag => tag.trim()).filter(tag => tag);
        updateData.data = { tags };
      }

      await apiService.bulkUpdateTestCases(updateData);
      await loadData();
      setSelectedCases(new Set());
      setShowBulkActions(false);
      setBulkActionType('');
      setNewTags('');
    } catch (err) {
      console.error('Error in bulk action:', err);
      setError('Failed to perform bulk action');
    } finally {
      setActionLoading(false);
    }
  };

  // Group test cases by agent type for statistics
  const agentStats = testCases.reduce((acc, testCase) => {
    const agentType = testCase.agent_type || 'Unknown';
    acc[agentType] = (acc[agentType] || 0) + 1;
    return acc;
  }, {});

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading test cases...</span>
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
              onClick={loadData}
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
          <h1 className="text-2xl font-bold text-gray-900">Test Cases</h1>
          <p className="text-gray-600 mt-1">
            Browse and analyze generated test cases from all agent types
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button onClick={loadData} className="btn btn-secondary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center">
            <TestTube className="h-8 w-8 text-primary-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Test Cases</p>
              <p className="text-2xl font-bold text-gray-900">{testCases.length}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-success-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Positive Tests</p>
              <p className="text-2xl font-bold text-gray-900">
                {agentStats['Functional-Positive-Agent'] || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <XCircle className="h-8 w-8 text-warning-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Negative Tests</p>
              <p className="text-2xl font-bold text-gray-900">
                {agentStats['Functional-Negative-Agent'] || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <Code className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Stateful Tests</p>
              <p className="text-2xl font-bold text-gray-900">
                {agentStats['Functional-Stateful-Agent'] || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters and Selection */}
      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-500" />
            <select 
              value={filters.agent_type} 
              onChange={(e) => setFilters(prev => ({ ...prev, agent_type: e.target.value }))}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm flex-1"
            >
              <option value="all">All Agent Types</option>
              <option value="Functional-Positive-Agent">Positive Agent</option>
              <option value="Functional-Negative-Agent">Negative Agent</option>
              <option value="Functional-Stateful-Agent">Stateful Agent</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <Tag className="h-4 w-4 text-gray-500" />
            <select 
              value={filters.spec_id} 
              onChange={(e) => setFilters(prev => ({ ...prev, spec_id: e.target.value }))}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm flex-1"
            >
              <option value="all">All Specifications</option>
              {specifications.map(spec => (
                <option key={spec.id} value={spec.id.toString()}>
                  {spec.source_filename || `Spec ${spec.id}`}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search test cases..."
              value={filters.search}
              onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm flex-1"
            />
          </div>
        </div>

        {/* Selection and Bulk Actions */}
        {filteredTestCases.length > 0 && (
          <div className="flex items-center justify-between pt-4 border-t border-gray-200">
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={selectedCases.size === filteredTestCases.length && filteredTestCases.length > 0}
                  onChange={handleSelectAll}
                  className="rounded border-gray-300"
                />
                <span className="text-sm text-gray-700">
                  Select All ({selectedCases.size} selected)
                </span>
              </label>
            </div>

            {selectedCases.size > 0 && (
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setShowBulkActions(!showBulkActions)}
                  className="btn btn-secondary btn-sm"
                >
                  <Users className="h-4 w-4 mr-1" />
                  Bulk Actions ({selectedCases.size})
                </button>
              </div>
            )}
          </div>
        )}

        {/* Bulk Actions Panel */}
        {showBulkActions && selectedCases.size > 0 && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-md">
            <h4 className="text-sm font-medium text-gray-900 mb-3">
              Bulk Actions for {selectedCases.size} test cases
            </h4>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Action Type
                </label>
                <select
                  value={bulkActionType}
                  onChange={(e) => setBulkActionType(e.target.value)}
                  className="border border-gray-300 rounded-md px-3 py-2 text-sm w-full"
                >
                  <option value="">Select action...</option>
                  <option value="add_tags">Add Tags</option>
                  <option value="remove_tags">Remove Tags</option>
                  <option value="set_tags">Set Tags</option>
                </select>
              </div>

              {(bulkActionType === 'add_tags' || bulkActionType === 'remove_tags' || bulkActionType === 'set_tags') && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={newTags}
                    onChange={(e) => setNewTags(e.target.value)}
                    placeholder="tag1, tag2, tag3"
                    className="border border-gray-300 rounded-md px-3 py-2 text-sm w-full"
                  />
                </div>
              )}

              <div className="flex items-end space-x-2">
                <button
                  onClick={handleBulkAction}
                  disabled={!bulkActionType || actionLoading}
                  className="btn btn-primary btn-sm"
                >
                  {actionLoading ? (
                    <>
                      <div className="spinner-sm mr-1"></div>
                      Processing...
                    </>
                  ) : (
                    <>
                      <Save className="h-4 w-4 mr-1" />
                      Apply
                    </>
                  )}
                </button>
                <button
                  onClick={() => {
                    setShowBulkActions(false);
                    setBulkActionType('');
                    setNewTags('');
                  }}
                  className="btn btn-secondary btn-sm"
                >
                  <X className="h-4 w-4 mr-1" />
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Test Cases List */}
      {filteredTestCases.length > 0 ? (
        <div className="space-y-4">
          {filteredTestCases.map((testCase, index) => {
            const testInsight = getTestTypeInsight(testCase);
            const isExpanded = expandedCase === index;
            const testDef = testCase.test_definition || {};
            
            return (
              <div key={testCase.id || index} className="card hover:shadow-md transition-shadow duration-200">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3 flex-1">
                    {/* Selection Checkbox */}
                    <div className="pt-1">
                      <input
                        type="checkbox"
                        checked={selectedCases.has(testCase.id)}
                        onChange={() => handleSelectCase(testCase.id)}
                        className="rounded border-gray-300"
                      />
                    </div>
                    
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className="text-lg">{getTestTypeIcon(testCase.description)}</span>
                        {editingCase === testCase.id ? (
                          <input
                            type="text"
                            value={editForm.description}
                            onChange={(e) => setEditForm(prev => ({ ...prev, description: e.target.value }))}
                            className="text-lg font-medium text-gray-900 border border-gray-300 rounded px-2 py-1 flex-1"
                            placeholder="Test case description..."
                          />
                        ) : (
                          <h3 className="text-lg font-medium text-gray-900">
                            {testCase.description || `Test Case ${testCase.id || index + 1}`}
                          </h3>
                        )}
                        {testCase.agent_type && getAgentTypeBadge(testCase.agent_type)}
                      </div>
                    
                      {/* Test Type Insight */}
                      <div className="flex items-center space-x-2 mb-3">
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
                            {testDef.method || 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="font-medium text-gray-500">Endpoint:</span>
                          <span className="ml-2 font-mono text-gray-900">
                            {testDef.endpoint || 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="font-medium text-gray-500">Expected Status:</span>
                          <span className={`ml-2 font-mono px-2 py-1 rounded ${
                            testDef.expected_status >= 200 && testDef.expected_status < 300 
                              ? 'bg-success-100 text-success-800'
                              : testDef.expected_status >= 400 
                              ? 'bg-danger-100 text-danger-800'
                              : 'bg-gray-100 text-gray-800'
                          }`}>
                            {testDef.expected_status || 'N/A'}
                          </span>
                        </div>
                      </div>
                      
                      {/* Tags - Editable */}
                      {editingCase === testCase.id ? (
                        <div className="mt-3">
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Tags (comma-separated)
                          </label>
                          <input
                            type="text"
                            value={editForm.tags}
                            onChange={(e) => setEditForm(prev => ({ ...prev, tags: e.target.value }))}
                            placeholder="tag1, tag2, tag3"
                            className="border border-gray-300 rounded-md px-3 py-2 text-sm w-full"
                          />
                        </div>
                      ) : (
                        testCase.tags && testCase.tags.length > 0 && (
                          <div className="mt-3 flex flex-wrap gap-1">
                            {testCase.tags.map((tag, tagIndex) => (
                              <span key={tagIndex} className="badge">{tag}</span>
                            ))}
                          </div>
                        )
                      )}
                      
                      {/* Enhanced insights for negative tests */}
                      {testCase.agent_type === 'Functional-Negative-Agent' && (
                        <div className="mt-3 p-3 bg-warning-50 border border-warning-200 rounded-md">
                          <h5 className="text-sm font-medium text-warning-800 mb-1">Negative Test Strategy</h5>
                          <p className="text-sm text-warning-700">
                            This test validates error handling by sending invalid data and expecting appropriate error responses.
                          </p>
                        </div>
                      )}
                      
                      {/* Enhanced insights for stateful tests */}
                      {testCase.agent_type === 'Functional-Stateful-Agent' && (
                        <div className="mt-3 p-3 bg-success-50 border border-success-200 rounded-md">
                          <h5 className="text-sm font-medium text-success-800 mb-1">Stateful Workflow Test</h5>
                          <p className="text-sm text-success-700">
                            This test validates multi-step workflows and state management across API operations.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* Action Buttons */}
                  <div className="flex items-center space-x-2 ml-4">
                    {editingCase === testCase.id ? (
                      <>
                        <button
                          onClick={saveEdit}
                          disabled={actionLoading}
                          className="btn btn-primary btn-sm"
                        >
                          {actionLoading ? (
                            <>
                              <div className="spinner-sm mr-1"></div>
                              Saving...
                            </>
                          ) : (
                            <>
                              <Save className="h-4 w-4 mr-1" />
                              Save
                            </>
                          )}
                        </button>
                        <button
                          onClick={cancelEditing}
                          className="btn btn-secondary btn-sm"
                        >
                          <X className="h-4 w-4 mr-1" />
                          Cancel
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          onClick={() => startEditing(testCase)}
                          className="btn btn-secondary btn-sm"
                        >
                          <Edit3 className="h-4 w-4 mr-1" />
                          Edit
                        </button>
                        <button
                          onClick={() => deleteTestCase(testCase.id)}
                          disabled={actionLoading}
                          className="btn btn-danger btn-sm"
                        >
                          <Trash2 className="h-4 w-4 mr-1" />
                          Delete
                        </button>
                      </>
                    )}
                    
                    <button
                      onClick={() => setExpandedCase(isExpanded ? null : index)}
                      className="btn btn-secondary btn-sm"
                    >
                      <Eye className="h-4 w-4 mr-1" />
                      {isExpanded ? 'Hide' : 'Details'}
                    </button>
                  </div>
                </div>
                
                {/* Expanded Details */}
                {isExpanded && (
                  <div className="mt-6 pt-6 border-t border-gray-200">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Test Definition */}
                      <div>
                        <h5 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                          <Code className="h-4 w-4 mr-1" />
                          Test Definition
                        </h5>
                        
                        <div className="space-y-3">
                          {testDef.headers && Object.keys(testDef.headers).length > 0 && (
                            <div>
                              <h6 className="text-xs font-medium text-gray-700 mb-2">Headers:</h6>
                              <div className="code-block">
                                <pre>{JSON.stringify(testDef.headers, null, 2)}</pre>
                              </div>
                            </div>
                          )}
                          
                          {testDef.query_params && Object.keys(testDef.query_params).length > 0 && (
                            <div>
                              <h6 className="text-xs font-medium text-gray-700 mb-2">Query Parameters:</h6>
                              <div className="code-block">
                                <pre>{JSON.stringify(testDef.query_params, null, 2)}</pre>
                              </div>
                            </div>
                          )}
                          
                          {testDef.path_params && Object.keys(testDef.path_params).length > 0 && (
                            <div>
                              <h6 className="text-xs font-medium text-gray-700 mb-2">Path Parameters:</h6>
                              <div className="code-block">
                                <pre>{JSON.stringify(testDef.path_params, null, 2)}</pre>
                              </div>
                            </div>
                          )}
                          
                          {testDef.body && (
                            <div>
                              <h6 className="text-xs font-medium text-gray-700 mb-2">Request Body:</h6>
                              <div className="code-block">
                                <pre>{JSON.stringify(testDef.body, null, 2)}</pre>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      {/* Test Metadata */}
                      <div>
                        <h5 className="text-sm font-medium text-gray-900 mb-3">Test Metadata</h5>
                        
                        <dl className="space-y-3 text-sm">
                          <div>
                            <dt className="font-medium text-gray-500">Test ID:</dt>
                            <dd className="text-gray-900">{testCase.id || 'N/A'}</dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-500">Specification ID:</dt>
                            <dd className="text-gray-900">{testCase.spec_id || 'N/A'}</dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-500">Agent Type:</dt>
                            <dd className="text-gray-900">{testCase.agent_type || 'N/A'}</dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-500">Created:</dt>
                            <dd className="text-gray-900">
                              {testCase.created_at ? new Date(testCase.created_at).toLocaleString() : 'N/A'}
                            </dd>
                          </div>
                          
                          {testCase.metadata && (
                            <div>
                              <dt className="font-medium text-gray-500">Additional Metadata:</dt>
                              <dd className="text-gray-900">
                                <div className="code-block mt-1">
                                  <pre>{JSON.stringify(testCase.metadata, null, 2)}</pre>
                                </div>
                              </dd>
                            </div>
                          )}
                        </dl>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="card text-center py-12">
          <TestTube className="h-16 w-16 mx-auto text-gray-300 mb-4" />
          <h3 className="text-xl font-medium text-gray-900 mb-2">
            {filters.agent_type !== 'all' || filters.spec_id !== 'all' || filters.search 
              ? 'No matching test cases found' 
              : 'No test cases generated yet'
            }
          </h3>
          <p className="text-gray-500 mb-6">
            {filters.agent_type !== 'all' || filters.spec_id !== 'all' || filters.search
              ? 'Try adjusting your filters to see more test cases.'
              : 'Upload an API specification and generate test cases to get started.'
            }
          </p>
          
          {(filters.agent_type !== 'all' || filters.spec_id !== 'all' || filters.search) && (
            <button 
              onClick={() => setFilters({ agent_type: 'all', spec_id: 'all', search: '' })}
              className="btn btn-secondary"
            >
              Clear Filters
            </button>
          )}
        </div>
      )}

      {/* Summary Stats */}
      {filteredTestCases.length > 0 && (
        <div className="card bg-gray-50">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Test Case Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(agentStats).map(([agentType, count]) => (
              <div key={agentType} className="text-center">
                <div className="text-2xl font-bold text-gray-900">{count}</div>
                <div className="text-sm text-gray-500">
                  {agentType.replace('Functional-', '').replace('-Agent', '')} Tests
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default TestCases;
