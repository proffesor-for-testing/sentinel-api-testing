import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Upload, 
  Plus, 
  RefreshCw, 
  Eye, 
  Play,
  AlertTriangle,
  CheckCircle,
  Calendar,
  Code,
  Trash2
} from 'lucide-react';
import { apiService } from '../services/api';

const Specifications = () => {
  const [specifications, setSpecifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadData, setUploadData] = useState({
    raw_spec: '',
    source_filename: '',
    source_url: ''
  });
  const [uploading, setUploading] = useState(false);
  
  // Test generation modal state
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [selectedSpecForGeneration, setSelectedSpecForGeneration] = useState(null);
  const [selectedAgents, setSelectedAgents] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [generationResult, setGenerationResult] = useState(null);
  
  // View specification modal state
  const [showViewModal, setShowViewModal] = useState(false);
  const [selectedSpecForViewing, setSelectedSpecForViewing] = useState(null);
  const [viewLoading, setViewLoading] = useState(false);

  useEffect(() => {
    loadSpecifications();
  }, []);

  const loadSpecifications = async () => {
    try {
      setLoading(true);
      const data = await apiService.getSpecifications();
      // Handle different response formats
      const specificationsArray = Array.isArray(data) ? data : (data?.data || []);
      setSpecifications(specificationsArray);
      setError(null);
    } catch (err) {
      console.error('Error loading specifications:', err);
      setError('Failed to load specifications');
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    
    if (!uploadData.raw_spec.trim()) {
      alert('Please provide the API specification content');
      return;
    }

    try {
      setUploading(true);
      await apiService.uploadSpecification(uploadData);
      setShowUploadModal(false);
      setUploadData({ raw_spec: '', source_filename: '', source_url: '' });
      await loadSpecifications();
    } catch (err) {
      console.error('Error uploading specification:', err);
      alert('Failed to upload specification. Please check the format and try again.');
    } finally {
      setUploading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setUploadData(prev => ({
          ...prev,
          raw_spec: event.target.result,
          source_filename: file.name
        }));
      };
      reader.readAsText(file);
    }
  };

  const runQuickTest = async (specId) => {
    try {
      // Quick test generates tests with default agents
      const requestData = {
        spec_id: specId,
        agent_types: ['Functional-Positive-Agent', 'Functional-Negative-Agent']
      };
      
      const result = await apiService.generateTests(requestData);
      alert(`Quick test completed! Generated ${result.total_test_cases || 0} test cases with Positive and Negative agents.`);
      
      // Reload specifications to show updated test count if available
      await loadSpecifications();
    } catch (err) {
      console.error('Error running quick test:', err);
      alert('Failed to run quick test. Please check if all services are running and try again.');
    }
  };

  const openGenerateModal = (spec) => {
    setSelectedSpecForGeneration(spec);
    setSelectedAgents([]);
    setGenerationResult(null);
    setShowGenerateModal(true);
  };

  const toggleAgentSelection = (agentType) => {
    setSelectedAgents(prev => {
      if (prev.includes(agentType)) {
        return prev.filter(a => a !== agentType);
      } else {
        return [...prev, agentType];
      }
    });
  };

  const handleGenerateTests = async () => {
    if (!selectedSpecForGeneration || selectedAgents.length === 0) {
      alert('Please select at least one agent type');
      return;
    }

    try {
      setGenerating(true);
      const requestData = {
        spec_id: selectedSpecForGeneration.id,
        agent_types: selectedAgents
      };
      
      const result = await apiService.generateTests(requestData);
      setGenerationResult(result);
      
      // Show success message
      alert(`Successfully generated ${result.total_test_cases || 0} test cases!`);
      
      // Close modal after short delay
      setTimeout(() => {
        setShowGenerateModal(false);
        setSelectedSpecForGeneration(null);
        setSelectedAgents([]);
        setGenerationResult(null);
      }, 2000);
      
    } catch (err) {
      console.error('Error generating tests:', err);
      alert('Failed to generate tests. Please check if all services are running and try again.');
    } finally {
      setGenerating(false);
    }
  };

  const openViewModal = async (spec) => {
    setShowViewModal(true);
    setViewLoading(true);
    try {
      // Fetch full specification details
      const fullSpec = await apiService.getSpecification(spec.id);
      setSelectedSpecForViewing(fullSpec);
    } catch (err) {
      console.error('Error fetching specification details:', err);
      alert('Failed to load specification details');
      setShowViewModal(false);
    } finally {
      setViewLoading(false);
    }
  };

  const handleDeleteSpecification = async (specId, specName) => {
    if (!window.confirm(`Are you sure you want to delete the specification "${specName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await apiService.deleteSpecification(specId);
      // Reload specifications after successful deletion
      loadSpecifications();
      // Show success message
      alert(`Specification "${specName}" has been deleted successfully.`);
    } catch (err) {
      console.error('Error deleting specification:', err);
      alert('Failed to delete specification. Please try again.');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading specifications...</span>
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
              onClick={loadSpecifications}
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
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-600">
            Manage your OpenAPI specifications and generate comprehensive test suites
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button onClick={loadSpecifications} className="btn btn-secondary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
          <button 
            onClick={() => setShowUploadModal(true)}
            className="btn btn-primary"
          >
            <Plus className="h-4 w-4 mr-2" />
            Upload Specification
          </button>
        </div>
      </div>

      {/* Specifications List */}
      {specifications.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {specifications.map((spec) => (
            <div key={spec.id} className="card hover:shadow-md transition-shadow duration-200">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <FileText className="h-8 w-8 text-primary-600" />
                  <div>
                    <h3 className="text-lg font-medium text-gray-900">
                      {spec.source_filename || `Specification ${spec.id}`}
                    </h3>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="badge badge-primary">OpenAPI {spec.version || '3.0'}</span>
                      {spec.is_valid ? (
                        <span className="badge badge-success">Valid</span>
                      ) : (
                        <span className="badge badge-danger">Invalid</span>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button 
                    onClick={() => runQuickTest(spec.id)}
                    className="btn btn-primary btn-sm"
                    title="Run quick test with positive and negative agents"
                  >
                    <Play className="h-4 w-4 mr-1" />
                    Quick Test
                  </button>
                </div>
              </div>
              
              {/* Specification Details */}
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-gray-500">Title:</span>
                    <p className="text-gray-900 mt-1">{spec.title || 'N/A'}</p>
                  </div>
                  <div>
                    <span className="font-medium text-gray-500">Version:</span>
                    <p className="text-gray-900 mt-1">{spec.api_version || 'N/A'}</p>
                  </div>
                </div>
                
                {spec.description && (
                  <div>
                    <span className="font-medium text-gray-500 text-sm">Description:</span>
                    <p className="text-gray-900 text-sm mt-1 line-clamp-2">{spec.description}</p>
                  </div>
                )}
                
                <div className="flex items-center justify-between text-sm text-gray-500">
                  <div className="flex items-center">
                    <Calendar className="h-4 w-4 mr-1" />
                    {spec.created_at ? new Date(spec.created_at).toLocaleDateString() : 'N/A'}
                  </div>
                  <div>
                    ID: {spec.id}
                  </div>
                </div>
              </div>
              
              {/* Specification Stats */}
              {spec.endpoints_count !== undefined && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <div className="text-lg font-bold text-gray-900">{spec.endpoints_count || 0}</div>
                      <div className="text-xs text-gray-500">Endpoints</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-gray-900">{spec.operations_count || 0}</div>
                      <div className="text-xs text-gray-500">Operations</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-gray-900">{spec.schemas_count || 0}</div>
                      <div className="text-xs text-gray-500">Schemas</div>
                    </div>
                  </div>
                </div>
              )}
              
              {/* Actions */}
              <div className="mt-4 pt-4 border-t border-gray-200 flex items-center justify-between">
                <div className="text-xs text-gray-500">
                  {spec.source_url && (
                    <span>Source: {spec.source_url}</span>
                  )}
                </div>
                
                <div className="flex items-center space-x-2">
                  <button 
                    onClick={() => openViewModal(spec)}
                    className="btn btn-secondary btn-sm"
                  >
                    <Eye className="h-4 w-4 mr-1" />
                    View
                  </button>
                  <button 
                    onClick={() => openGenerateModal(spec)}
                    className="btn btn-primary btn-sm"
                  >
                    <Code className="h-4 w-4 mr-1" />
                    Generate Tests
                  </button>
                  <button 
                    onClick={() => handleDeleteSpecification(spec.id, spec.title || spec.source_filename || `Spec ${spec.id}`)}
                    className="btn btn-danger btn-sm"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card text-center py-12">
          <FileText className="h-16 w-16 mx-auto text-gray-300 mb-4" />
          <h3 className="text-xl font-medium text-gray-900 mb-2">No specifications uploaded yet</h3>
          <p className="text-gray-500 mb-6">
            Upload your first OpenAPI specification to start generating comprehensive test suites.
          </p>
          <button 
            onClick={() => setShowUploadModal(true)}
            className="btn btn-primary"
          >
            <Upload className="h-4 w-4 mr-2" />
            Upload Your First Specification
          </button>
        </div>
      )}

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity" aria-hidden="true">
              <div className="absolute inset-0 bg-gray-500 opacity-75"></div>
            </div>

            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <form onSubmit={handleUpload}>
                <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <div className="sm:flex sm:items-start">
                    <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-primary-100 sm:mx-0 sm:h-10 sm:w-10">
                      <Upload className="h-6 w-6 text-primary-600" />
                    </div>
                    <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                      <h3 className="text-lg leading-6 font-medium text-gray-900">
                        Upload API Specification
                      </h3>
                      <div className="mt-4 space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Upload File
                          </label>
                          <input
                            type="file"
                            accept=".json,.yaml,.yml"
                            onChange={handleFileUpload}
                            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-primary-50 file:text-primary-700 hover:file:bg-primary-100"
                          />
                        </div>
                        
                        <div className="text-center text-gray-500">or</div>
                        
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Paste Specification Content
                          </label>
                          <textarea
                            value={uploadData.raw_spec}
                            onChange={(e) => setUploadData(prev => ({ ...prev, raw_spec: e.target.value }))}
                            placeholder="Paste your OpenAPI specification here (JSON or YAML format)"
                            rows={8}
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Filename (optional)
                          </label>
                          <input
                            type="text"
                            value={uploadData.source_filename}
                            onChange={(e) => setUploadData(prev => ({ ...prev, source_filename: e.target.value }))}
                            placeholder="e.g., my-api-spec.yaml"
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Source URL (optional)
                          </label>
                          <input
                            type="url"
                            value={uploadData.source_url}
                            onChange={(e) => setUploadData(prev => ({ ...prev, source_url: e.target.value }))}
                            placeholder="https://api.example.com/openapi.json"
                            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button
                    type="submit"
                    disabled={uploading}
                    className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
                  >
                    {uploading ? (
                      <>
                        <div className="spinner mr-2"></div>
                        Uploading...
                      </>
                    ) : (
                      <>
                        <Upload className="h-4 w-4 mr-2" />
                        Upload
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowUploadModal(false)}
                    className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Generate Tests Modal */}
      {showGenerateModal && selectedSpecForGeneration && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity" aria-hidden="true">
              <div className="absolute inset-0 bg-gray-500 opacity-75"></div>
            </div>

            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
              <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="sm:flex sm:items-start">
                  <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-primary-100 sm:mx-0 sm:h-10 sm:w-10">
                    <Code className="h-6 w-6 text-primary-600" />
                  </div>
                  <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                    <h3 className="text-lg leading-6 font-medium text-gray-900">
                      Generate Test Cases
                    </h3>
                    <p className="text-sm text-gray-500 mt-2">
                      For: {selectedSpecForGeneration.source_filename || `Specification ${selectedSpecForGeneration.id}`}
                    </p>
                    
                    <div className="mt-6">
                      <h4 className="text-sm font-medium text-gray-900 mb-4">
                        Select AI Agents for Test Generation
                      </h4>
                      
                      <div className="space-y-3">
                        {/* Functional Testing Agents */}
                        <div className="border border-gray-200 rounded-lg p-4">
                          <h5 className="text-sm font-medium text-gray-900 mb-3">Functional Testing</h5>
                          
                          <div className="space-y-3">
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Functional-Positive-Agent')}
                                onChange={() => toggleAgentSelection('Functional-Positive-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Positive Test Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Generates valid test cases with correct data formats and happy path scenarios
                                </div>
                              </div>
                            </label>
                            
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Functional-Negative-Agent')}
                                onChange={() => toggleAgentSelection('Functional-Negative-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Negative Test Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Creates boundary value analysis and invalid input test cases
                                </div>
                              </div>
                            </label>
                            
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Functional-Stateful-Agent')}
                                onChange={() => toggleAgentSelection('Functional-Stateful-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Stateful Test Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Generates multi-step workflow tests and state management scenarios
                                </div>
                              </div>
                            </label>
                          </div>
                        </div>
                        
                        {/* Security Testing Agents */}
                        <div className="border border-gray-200 rounded-lg p-4">
                          <h5 className="text-sm font-medium text-gray-900 mb-3">Security Testing</h5>
                          
                          <div className="space-y-3">
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Security-Auth-Agent')}
                                onChange={() => toggleAgentSelection('Security-Auth-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Authentication & Authorization Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Tests for BOLA, function-level authorization, and auth bypass vulnerabilities
                                </div>
                              </div>
                            </label>
                            
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Security-Injection-Agent')}
                                onChange={() => toggleAgentSelection('Security-Injection-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Injection Vulnerability Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Tests for SQL, NoSQL, Command, and Prompt injection vulnerabilities
                                </div>
                              </div>
                            </label>
                          </div>
                        </div>
                        
                        {/* Other Agents */}
                        <div className="border border-gray-200 rounded-lg p-4">
                          <h5 className="text-sm font-medium text-gray-900 mb-3">Performance & Data</h5>
                          
                          <div className="space-y-3">
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Performance-Planner-Agent')}
                                onChange={() => toggleAgentSelection('Performance-Planner-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Performance Planning Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Generates k6/JMeter scripts for load and performance testing
                                </div>
                              </div>
                            </label>
                            
                            <label className="flex items-start cursor-pointer hover:bg-gray-50 p-2 rounded">
                              <input
                                type="checkbox"
                                checked={selectedAgents.includes('Data-Mocking-Agent')}
                                onChange={() => toggleAgentSelection('Data-Mocking-Agent')}
                                className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                              />
                              <div className="ml-3">
                                <div className="text-sm font-medium text-gray-900">
                                  Data Mocking Agent
                                </div>
                                <div className="text-sm text-gray-500">
                                  Creates realistic test data based on schema definitions
                                </div>
                              </div>
                            </label>
                          </div>
                        </div>
                      </div>
                      
                      {/* Selected agents summary */}
                      {selectedAgents.length > 0 && (
                        <div className="mt-4 p-3 bg-primary-50 border border-primary-200 rounded-md">
                          <p className="text-sm text-primary-800">
                            <strong>{selectedAgents.length} agents selected</strong> - 
                            Test generation will use LLM-powered agents to create comprehensive test cases
                          </p>
                        </div>
                      )}
                      
                      {/* Generation result */}
                      {generationResult && (
                        <div className="mt-4 p-3 bg-success-50 border border-success-200 rounded-md">
                          <p className="text-sm text-success-800">
                            <CheckCircle className="inline h-4 w-4 mr-1" />
                            Successfully generated {generationResult.total_test_cases || 0} test cases!
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  onClick={handleGenerateTests}
                  disabled={generating || selectedAgents.length === 0}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {generating ? (
                    <>
                      <div className="spinner mr-2"></div>
                      Generating...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Generate Tests
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowGenerateModal(false);
                    setSelectedSpecForGeneration(null);
                    setSelectedAgents([]);
                    setGenerationResult(null);
                  }}
                  disabled={generating}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* View Specification Modal */}
      {showViewModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity" aria-hidden="true">
              <div className="absolute inset-0 bg-gray-500 opacity-75"></div>
            </div>

            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
              <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="sm:flex sm:items-start">
                  <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-primary-100 sm:mx-0 sm:h-10 sm:w-10">
                    <Eye className="h-6 w-6 text-primary-600" />
                  </div>
                  <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                    <h3 className="text-lg leading-6 font-medium text-gray-900">
                      View Specification
                    </h3>
                    {viewLoading ? (
                      <div className="mt-4 flex items-center justify-center">
                        <div className="spinner"></div>
                        <span className="ml-2 text-gray-600">Loading specification...</span>
                      </div>
                    ) : selectedSpecForViewing ? (
                      <div className="mt-4 space-y-4">
                        {/* Basic Info */}
                        <div className="border-b pb-4">
                          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
                            <div>
                              <dt className="text-sm font-medium text-gray-500">Title</dt>
                              <dd className="text-sm text-gray-900">
                                {selectedSpecForViewing.parsed_spec?.info?.title || 'N/A'}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-sm font-medium text-gray-500">Version</dt>
                              <dd className="text-sm text-gray-900">
                                {selectedSpecForViewing.version || 'N/A'}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-sm font-medium text-gray-500">OpenAPI Version</dt>
                              <dd className="text-sm text-gray-900">
                                {selectedSpecForViewing.parsed_spec?.openapi || 'N/A'}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-sm font-medium text-gray-500">Source File</dt>
                              <dd className="text-sm text-gray-900">
                                {selectedSpecForViewing.source_filename || 'N/A'}
                              </dd>
                            </div>
                          </dl>
                          {selectedSpecForViewing.parsed_spec?.info?.description && (
                            <div className="mt-3">
                              <dt className="text-sm font-medium text-gray-500">Description</dt>
                              <dd className="text-sm text-gray-900 mt-1">
                                {selectedSpecForViewing.parsed_spec.info.description}
                              </dd>
                            </div>
                          )}
                        </div>

                        {/* Servers */}
                        {selectedSpecForViewing.parsed_spec?.servers && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 mb-2">Servers</h4>
                            <div className="bg-gray-50 rounded-md p-3">
                              {selectedSpecForViewing.parsed_spec.servers.map((server, idx) => (
                                <div key={idx} className="text-sm">
                                  <span className="font-mono text-gray-700">{server.url}</span>
                                  {server.description && (
                                    <span className="text-gray-500 ml-2">- {server.description}</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Endpoints */}
                        {selectedSpecForViewing.parsed_spec?.paths && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-900 mb-2">
                              Endpoints ({Object.keys(selectedSpecForViewing.parsed_spec.paths).length})
                            </h4>
                            <div className="bg-gray-50 rounded-md p-3 max-h-64 overflow-y-auto">
                              {Object.entries(selectedSpecForViewing.parsed_spec.paths).map(([path, methods]) => (
                                <div key={path} className="mb-3">
                                  <div className="font-mono text-sm text-gray-900 mb-1">{path}</div>
                                  <div className="ml-4 space-y-1">
                                    {Object.entries(methods).map(([method, details]) => (
                                      <div key={method} className="flex items-center space-x-2">
                                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase ${
                                          method === 'get' ? 'bg-blue-100 text-blue-800' :
                                          method === 'post' ? 'bg-green-100 text-green-800' :
                                          method === 'put' ? 'bg-yellow-100 text-yellow-800' :
                                          method === 'delete' ? 'bg-red-100 text-red-800' :
                                          'bg-gray-100 text-gray-800'
                                        }`}>
                                          {method}
                                        </span>
                                        <span className="text-sm text-gray-600">
                                          {details.summary || details.operationId || 'No description'}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Raw Specification */}
                        <div>
                          <h4 className="text-sm font-medium text-gray-900 mb-2">Raw Specification</h4>
                          <div className="bg-gray-900 text-gray-100 rounded-md p-4 max-h-96 overflow-y-auto">
                            <pre className="text-xs font-mono whitespace-pre-wrap">
                              {selectedSpecForViewing.raw_spec || JSON.stringify(selectedSpecForViewing.parsed_spec, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4 text-center text-gray-500">
                        No specification data available
                      </div>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={() => {
                    setShowViewModal(false);
                    setSelectedSpecForViewing(null);
                  }}
                  className="w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI-Powered Testing Info */}
      <div className="card bg-gradient-to-r from-primary-50 to-primary-100 border-primary-200">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            <CheckCircle className="h-8 w-8 text-primary-600" />
          </div>
          <div className="ml-4">
            <h3 className="text-lg font-medium text-primary-900">AI-Powered Test Generation</h3>
            <p className="text-primary-700 mt-1">
              Leverage Claude Sonnet 4 and specialized AI agents to automatically generate comprehensive test suites 
              from your OpenAPI specifications. Each agent uses advanced LLM capabilities to create intelligent, 
              context-aware test cases.
            </p>
            <div className="mt-4">
              <h4 className="text-sm font-medium text-primary-900 mb-2">Available Testing Capabilities:</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <span className="badge badge-primary">✅ Happy Path Testing</span>
                <span className="badge badge-primary">❌ Error Scenarios</span>
                <span className="badge badge-primary">🔄 Workflow Testing</span>
                <span className="badge badge-primary">🔒 Security Testing</span>
                <span className="badge badge-primary">💉 Injection Tests</span>
                <span className="badge badge-primary">📊 Boundary Analysis</span>
                <span className="badge badge-primary">⚡ Performance Scripts</span>
                <span className="badge badge-primary">🎭 Mock Data Generation</span>
              </div>
            </div>
            <p className="text-sm text-primary-600 mt-4">
              <strong>Tip:</strong> Start with Positive and Negative agents for comprehensive functional coverage, 
              then add Security agents for vulnerability testing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Specifications;
