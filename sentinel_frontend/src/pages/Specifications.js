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
  Code
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

  useEffect(() => {
    loadSpecifications();
  }, []);

  const loadSpecifications = async () => {
    try {
      setLoading(true);
      const data = await apiService.getSpecifications();
      setSpecifications(data);
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
      const flowData = {
        raw_spec: specifications.find(s => s.id === specId)?.raw_spec || '',
        target_environment: 'https://jsonplaceholder.typicode.com',
        source_filename: `spec_${specId}_quick_test.yaml`,
        agent_types: ['Functional-Positive-Agent', 'Functional-Negative-Agent']
      };
      
      const result = await apiService.runCompleteFlow(flowData);
      alert(`Quick test completed! Run ID: ${result.run_id}\nPassed: ${result.summary.passed}, Failed: ${result.summary.failed}`);
    } catch (err) {
      console.error('Error running quick test:', err);
      alert('Failed to run quick test. Please try again.');
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">API Specifications</h1>
          <p className="text-gray-600 mt-1">
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
                  <button className="btn btn-secondary btn-sm">
                    <Eye className="h-4 w-4 mr-1" />
                    View
                  </button>
                  <button className="btn btn-secondary btn-sm">
                    <Code className="h-4 w-4 mr-1" />
                    Generate Tests
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

      {/* Phase 3 Testing Info */}
      <div className="card bg-gradient-to-r from-primary-50 to-primary-100 border-primary-200">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            <CheckCircle className="h-8 w-8 text-primary-600" />
          </div>
          <div className="ml-4">
            <h3 className="text-lg font-medium text-primary-900">Phase 3 Enhanced Testing</h3>
            <p className="text-primary-700 mt-1">
              Your specifications will be tested with advanced agents including boundary value analysis, 
              creative negative testing, and stateful workflow validation.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="badge badge-primary">Positive Testing</span>
              <span className="badge badge-primary">Negative Testing + BVA</span>
              <span className="badge badge-primary">Stateful Workflows</span>
              <span className="badge badge-primary">Enhanced Reporting</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Specifications;
