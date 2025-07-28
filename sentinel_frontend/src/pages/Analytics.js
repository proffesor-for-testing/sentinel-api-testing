import React, { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  AlertTriangle, 
  Brain, 
  BarChart3,
  Calendar,
  Target,
  Zap,
  Activity,
  RefreshCw
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area,
  ScatterChart,
  Scatter,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import { apiService } from '../services/api';

const Analytics = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('trends');
  const [timeRange, setTimeRange] = useState(30);
  
  const [trendsData, setTrendsData] = useState({
    failureRates: [],
    latencyData: []
  });
  
  const [anomalies, setAnomalies] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [insights, setInsights] = useState(null);

  useEffect(() => {
    loadAnalyticsData();
  }, [timeRange]);

  const loadAnalyticsData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load all analytics data in parallel
      const [
        failureRatesResponse,
        latencyResponse,
        anomaliesResponse,
        predictionsResponse,
        insightsResponse
      ] = await Promise.all([
        fetch(`/api/v1/analytics/trends/failure-rate?days=${timeRange}`),
        fetch(`/api/v1/analytics/trends/latency?days=${timeRange}`),
        fetch(`/api/v1/analytics/anomalies?days=${timeRange}`),
        fetch('/api/v1/analytics/predictions?days_ahead=7'),
        fetch(`/api/v1/analytics/insights?days=${timeRange}`)
      ]);

      const [failureRates, latencyData, anomaliesData, predictionsData, insightsData] = await Promise.all([
        failureRatesResponse.json(),
        latencyResponse.json(),
        anomaliesResponse.json(),
        predictionsResponse.json(),
        insightsResponse.json()
      ]);

      setTrendsData({ failureRates, latencyData });
      setAnomalies(anomaliesData.anomalies || []);
      setPredictions(predictionsData.predictions || []);
      setInsights(insightsData);

    } catch (err) {
      console.error('Error loading analytics data:', err);
      setError('Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric' 
    });
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'text-danger-600 bg-danger-50 border-danger-200';
      case 'medium': return 'text-warning-600 bg-warning-50 border-warning-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getTrendColor = (trend) => {
    switch (trend) {
      case 'improving': return 'text-success-600';
      case 'degrading': return 'text-danger-600';
      default: return 'text-gray-600';
    }
  };

  const getQualityGradeColor = (grade) => {
    switch (grade) {
      case 'A': return 'text-success-600 bg-success-50';
      case 'B': return 'text-primary-600 bg-primary-50';
      case 'C': return 'text-warning-600 bg-warning-50';
      case 'D': return 'text-orange-600 bg-orange-50';
      case 'F': return 'text-danger-600 bg-danger-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
        <span className="ml-2 text-gray-600">Loading advanced analytics...</span>
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
              onClick={loadAnalyticsData}
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
          <h1 className="text-2xl font-bold text-gray-900">Advanced Analytics</h1>
          <p className="text-gray-600 mt-1">
            Deep insights into API testing performance and quality trends
          </p>
        </div>
        
        <div className="flex items-center space-x-4">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(parseInt(e.target.value))}
            className="form-select"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          
          <button
            onClick={loadAnalyticsData}
            className="btn btn-primary"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Quality Overview */}
      {insights && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-500">Quality Score</p>
                <p className="text-2xl font-bold text-gray-900">
                  {insights.overall_quality.score.toFixed(1)}
                </p>
              </div>
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${getQualityGradeColor(insights.overall_quality.grade)}`}>
                Grade {insights.overall_quality.grade}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Target className="h-8 w-8 text-primary-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Failure Rate</p>
                <p className="text-2xl font-bold text-gray-900">
                  {(insights.overall_quality.failure_rate * 100).toFixed(1)}%
                </p>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Activity className="h-8 w-8 text-success-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total Tests</p>
                <p className="text-2xl font-bold text-gray-900">
                  {insights.overall_quality.total_tests.toLocaleString()}
                </p>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-8 w-8 text-warning-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Anomalies</p>
                <p className="text-2xl font-bold text-gray-900">{anomalies.length}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'trends', label: 'Historical Trends', icon: TrendingUp },
            { id: 'anomalies', label: 'Anomaly Detection', icon: AlertTriangle },
            { id: 'predictions', label: 'Predictive Insights', icon: Brain },
            { id: 'insights', label: 'Quality Insights', icon: BarChart3 }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-4 w-4 mr-2" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="space-y-6">
        {activeTab === 'trends' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Failure Rate Trends */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-medium text-gray-900">Failure Rate Trends</h3>
                <p className="text-sm text-gray-500">Historical failure rates over time</p>
              </div>
              
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendsData.failureRates}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="date" 
                      tickFormatter={formatDate}
                    />
                    <YAxis 
                      tickFormatter={(value) => `${(value * 100).toFixed(1)}%`}
                    />
                    <Tooltip 
                      labelFormatter={formatDate}
                      formatter={(value) => [`${(value * 100).toFixed(2)}%`, 'Failure Rate']}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="failure_rate" 
                      stroke="#ef4444" 
                      fill="#fef2f2" 
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Latency Trends */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-medium text-gray-900">Latency Trends</h3>
                <p className="text-sm text-gray-500">Response time percentiles over time</p>
              </div>
              
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trendsData.latencyData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="date" 
                      tickFormatter={formatDate}
                    />
                    <YAxis 
                      tickFormatter={(value) => `${value}ms`}
                    />
                    <Tooltip 
                      labelFormatter={formatDate}
                      formatter={(value) => [`${value.toFixed(1)}ms`]}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="avg_latency_ms" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      name="Average"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="p95_latency_ms" 
                      stroke="#f59e0b" 
                      strokeWidth={2}
                      name="95th Percentile"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="p99_latency_ms" 
                      stroke="#ef4444" 
                      strokeWidth={2}
                      name="99th Percentile"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'anomalies' && (
          <div className="space-y-6">
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-medium text-gray-900">Detected Anomalies</h3>
                <p className="text-sm text-gray-500">
                  Statistical anomalies in test performance and failure patterns
                </p>
              </div>

              {anomalies.length > 0 ? (
                <div className="space-y-4">
                  {anomalies.map((anomaly, index) => (
                    <div 
                      key={index}
                      className={`p-4 rounded-lg border ${getSeverityColor(anomaly.severity)}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <AlertTriangle className="h-5 w-5 mr-2" />
                          <div>
                            <h4 className="font-medium">
                              {anomaly.type === 'failure_rate' ? 'Failure Rate Anomaly' : 'Latency Anomaly'}
                            </h4>
                            <p className="text-sm opacity-75">
                              {formatDate(anomaly.date)} - {anomaly.severity} severity
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="font-medium">
                            {anomaly.type === 'failure_rate' 
                              ? `${(anomaly.value * 100).toFixed(2)}%`
                              : `${anomaly.value.toFixed(1)}ms`
                            }
                          </p>
                          <p className="text-xs opacity-75">
                            Expected: {anomaly.type === 'failure_rate' 
                              ? `${(anomaly.expected_range[0] * 100).toFixed(1)}-${(anomaly.expected_range[1] * 100).toFixed(1)}%`
                              : `${anomaly.expected_range[0].toFixed(1)}-${anomaly.expected_range[1].toFixed(1)}ms`
                            }
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Zap className="h-12 w-12 mx-auto text-gray-300 mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No Anomalies Detected</h3>
                  <p className="text-gray-500">Your test performance is within normal parameters.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'predictions' && (
          <div className="space-y-6">
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-medium text-gray-900">Quality Predictions</h3>
                <p className="text-sm text-gray-500">
                  Predictive insights based on historical trends
                </p>
              </div>

              {predictions.length > 0 ? (
                <div className="space-y-4">
                  {predictions.map((prediction, index) => (
                    <div key={index} className="p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium">{formatDate(prediction.date)}</h4>
                          <p className="text-sm text-gray-600">
                            Predicted failure rate: {(prediction.predicted_failure_rate * 100).toFixed(2)}%
                          </p>
                        </div>
                        <div className="text-right">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTrendColor(prediction.trend)}`}>
                            {prediction.trend}
                          </span>
                          <p className="text-xs text-gray-500 mt-1">
                            {prediction.confidence} confidence
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Brain className="h-12 w-12 mx-auto text-gray-300 mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">Insufficient Data</h3>
                  <p className="text-gray-500">Need more historical data to generate predictions.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'insights' && insights && (
          <div className="space-y-6">
            {/* Agent Performance */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-medium text-gray-900">Agent Performance Analysis</h3>
                <p className="text-sm text-gray-500">Performance breakdown by agent type</p>
              </div>

              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Agent Type</th>
                      <th>Total Tests</th>
                      <th>Success Rate</th>
                      <th>Failure Rate</th>
                      <th>Performance</th>
                    </tr>
                  </thead>
                  <tbody>
                    {insights.agent_performance.map((agent, index) => (
                      <tr key={index}>
                        <td className="font-medium">{agent.agent_type}</td>
                        <td>{agent.total_tests.toLocaleString()}</td>
                        <td>
                          <span className="badge badge-success">
                            {(agent.success_rate * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${agent.failure_rate > 0.2 ? 'badge-danger' : agent.failure_rate > 0.1 ? 'badge-warning' : 'badge-success'}`}>
                            {(agent.failure_rate * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td>
                          <div className="flex items-center">
                            <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                              <div 
                                className={`h-2 rounded-full ${agent.failure_rate > 0.2 ? 'bg-danger-600' : agent.failure_rate > 0.1 ? 'bg-warning-600' : 'bg-success-600'}`}
                                style={{ width: `${(1 - agent.failure_rate) * 100}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-gray-600">
                              {agent.failure_rate < 0.05 ? 'Excellent' : agent.failure_rate < 0.1 ? 'Good' : agent.failure_rate < 0.2 ? 'Fair' : 'Poor'}
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Quality Insights */}
            {insights.insights.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <h3 className="text-lg font-medium text-gray-900">Quality Insights</h3>
                  <p className="text-sm text-gray-500">Automated insights and observations</p>
                </div>

                <div className="space-y-3">
                  {insights.insights.map((insight, index) => (
                    <div 
                      key={index}
                      className={`p-3 rounded-lg border ${getSeverityColor(insight.severity)}`}
                    >
                      <p className="font-medium">{insight.message}</p>
                      <p className="text-sm opacity-75 mt-1">
                        Agent: {insight.agent_type} | Type: {insight.type}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {insights.recommendations.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <h3 className="text-lg font-medium text-gray-900">Recommendations</h3>
                  <p className="text-sm text-gray-500">Actionable recommendations to improve quality</p>
                </div>

                <div className="space-y-2">
                  {insights.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start p-3 bg-primary-50 rounded-lg">
                      <Target className="h-5 w-5 text-primary-600 mr-2 mt-0.5 flex-shrink-0" />
                      <p className="text-primary-800">{recommendation}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Analytics;
