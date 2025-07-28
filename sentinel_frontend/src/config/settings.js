/**
 * Frontend Configuration Settings
 * 
 * This file contains configuration settings for the Sentinel frontend application.
 * These settings should be kept in sync with the backend configuration.
 */

// Environment detection
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';

// API Configuration
export const API_CONFIG = {
  // Base URL for API Gateway
  baseURL: process.env.REACT_APP_API_URL || (isDevelopment ? 'http://localhost:8000' : 'http://localhost:8080'),
  
  // Request timeout in milliseconds
  timeout: parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000,
  
  // API version
  version: 'v1',
  
  // Retry configuration
  retryAttempts: 3,
  retryDelay: 1000,
};

// Network Configuration
export const NETWORK_CONFIG = {
  // Service ports (for development reference)
  ports: {
    apiGateway: 8000,
    authService: 8005,
    specService: 8001,
    orchestrationService: 8002,
    executionService: 8003,
    dataService: 8004,
    database: 5432,
  },
  
  // Health check configuration
  healthCheck: {
    enabled: true,
    interval: 30000, // 30 seconds
    timeout: 5000,   // 5 seconds
  },
};

// Application Configuration
export const APP_CONFIG = {
  // Application metadata
  name: 'Sentinel API Testing Platform',
  version: '1.0.0',
  
  // Debug mode
  debug: isDevelopment,
  
  // Pagination settings
  pagination: {
    defaultPageSize: 20,
    maxPageSize: 100,
    pageSizeOptions: [10, 20, 50, 100],
  },
  
  // Feature flags
  features: {
    analytics: true,
    performanceTesting: true,
    securityTesting: true,
    dataMocking: true,
    rbac: true,
  },
  
  // UI Configuration
  ui: {
    theme: 'light',
    autoRefresh: true,
    autoRefreshInterval: 30000, // 30 seconds
    showNotifications: true,
    compactMode: false,
  },
  
  // Test Configuration
  test: {
    maxTestCasesPerSpec: 1000,
    defaultTestTypes: ['functional'],
    availableTestTypes: ['functional', 'security', 'performance'],
    defaultStrategy: 'realistic',
    availableStrategies: ['realistic', 'edge_cases', 'invalid', 'boundary'],
  },
};

// Security Configuration (frontend-specific)
export const SECURITY_CONFIG = {
  // CORS settings (for reference)
  cors: {
    allowedOrigins: ['http://localhost:3000', 'http://localhost:8080'],
    allowCredentials: true,
  },
  
  // Authentication settings
  auth: {
    tokenStorageKey: 'sentinel_auth_token',
    userStorageKey: 'sentinel_user_data',
    autoLogoutOnExpiry: true,
    sessionWarningMinutes: 5, // Warn 5 minutes before expiry
  },
  
  // Content Security Policy
  csp: {
    enforceHttps: isProduction,
    allowInlineStyles: isDevelopment,
    allowInlineScripts: false,
  },
};

// Analytics Configuration
export const ANALYTICS_CONFIG = {
  // Chart configuration
  charts: {
    defaultTimeRange: '7d',
    availableTimeRanges: ['1d', '7d', '30d', '90d'],
    refreshInterval: 60000, // 1 minute
    animationDuration: 300,
  },
  
  // Metrics configuration
  metrics: {
    precision: 2,
    showTrends: true,
    showAnomalies: true,
    confidenceThreshold: 0.8,
  },
  
  // Export configuration
  export: {
    formats: ['json', 'csv', 'pdf'],
    maxRecords: 10000,
    includeCharts: true,
  },
};

// Development Configuration
export const DEV_CONFIG = {
  // Logging configuration
  logging: {
    level: isDevelopment ? 'debug' : 'info',
    enableConsoleLogging: isDevelopment,
    enableNetworkLogging: isDevelopment,
    enablePerformanceLogging: isDevelopment,
  },
  
  // Mock data configuration
  mockData: {
    enabled: false, // Set to true to use mock data instead of API
    delay: 500,     // Simulate network delay
    errorRate: 0.1, // 10% error rate for testing
  },
  
  // Development tools
  devTools: {
    showReduxDevTools: isDevelopment,
    showPerformanceMetrics: isDevelopment,
    enableHotReload: isDevelopment,
  },
};

// Environment-specific overrides
const ENVIRONMENT_OVERRIDES = {
  development: {
    API_CONFIG: {
      baseURL: 'http://localhost:8000',
    },
    APP_CONFIG: {
      debug: true,
      ui: {
        autoRefresh: true,
        autoRefreshInterval: 10000, // Faster refresh in development
      },
    },
  },
  
  production: {
    API_CONFIG: {
      timeout: 60000, // Longer timeout in production
    },
    APP_CONFIG: {
      debug: false,
      ui: {
        autoRefresh: false, // Disable auto-refresh in production
      },
    },
    SECURITY_CONFIG: {
      csp: {
        enforceHttps: true,
        allowInlineStyles: false,
      },
    },
  },
  
  test: {
    API_CONFIG: {
      baseURL: 'http://localhost:8000',
      timeout: 5000,
    },
    DEV_CONFIG: {
      mockData: {
        enabled: true,
        delay: 100,
      },
    },
  },
};

// Apply environment-specific overrides
function applyEnvironmentOverrides(config, overrides) {
  if (!overrides) return config;
  
  const result = { ...config };
  for (const [key, value] of Object.entries(overrides)) {
    if (typeof value === 'object' && !Array.isArray(value)) {
      result[key] = { ...result[key], ...value };
    } else {
      result[key] = value;
    }
  }
  return result;
}

// Get current environment
const currentEnvironment = process.env.NODE_ENV || 'development';
const environmentOverrides = ENVIRONMENT_OVERRIDES[currentEnvironment];

// Export final configuration with environment overrides applied
export const config = {
  API_CONFIG: applyEnvironmentOverrides(API_CONFIG, environmentOverrides?.API_CONFIG),
  NETWORK_CONFIG: applyEnvironmentOverrides(NETWORK_CONFIG, environmentOverrides?.NETWORK_CONFIG),
  APP_CONFIG: applyEnvironmentOverrides(APP_CONFIG, environmentOverrides?.APP_CONFIG),
  SECURITY_CONFIG: applyEnvironmentOverrides(SECURITY_CONFIG, environmentOverrides?.SECURITY_CONFIG),
  ANALYTICS_CONFIG: applyEnvironmentOverrides(ANALYTICS_CONFIG, environmentOverrides?.ANALYTICS_CONFIG),
  DEV_CONFIG: applyEnvironmentOverrides(DEV_CONFIG, environmentOverrides?.DEV_CONFIG),
};

// Utility functions
export const getApiUrl = (endpoint = '') => {
  const baseUrl = config.API_CONFIG.baseURL.replace(/\/$/, '');
  const cleanEndpoint = endpoint.replace(/^\//, '');
  return cleanEndpoint ? `${baseUrl}/${cleanEndpoint}` : baseUrl;
};

export const getApiTimeout = () => config.API_CONFIG.timeout;

export const isFeatureEnabled = (feature) => config.APP_CONFIG.features[feature] || false;

export const getPageSize = (customSize = null) => {
  if (customSize && customSize <= config.APP_CONFIG.pagination.maxPageSize) {
    return customSize;
  }
  return config.APP_CONFIG.pagination.defaultPageSize;
};

// Environment helpers
export const isDev = () => currentEnvironment === 'development';
export const isProd = () => currentEnvironment === 'production';
export const isTest = () => currentEnvironment === 'test';

// Configuration validation
export const validateConfig = () => {
  const errors = [];
  
  // Validate API configuration
  if (!config.API_CONFIG.baseURL) {
    errors.push('API_CONFIG.baseURL is required');
  }
  
  if (config.API_CONFIG.timeout < 1000) {
    errors.push('API_CONFIG.timeout should be at least 1000ms');
  }
  
  // Validate pagination settings
  if (config.APP_CONFIG.pagination.defaultPageSize > config.APP_CONFIG.pagination.maxPageSize) {
    errors.push('Default page size cannot be larger than max page size');
  }
  
  // Log validation results
  if (errors.length > 0) {
    console.error('Configuration validation errors:', errors);
    return false;
  }
  
  if (isDev()) {
    console.log('Configuration validation passed');
  }
  
  return true;
};

// Initialize configuration validation
validateConfig();

export default config;
