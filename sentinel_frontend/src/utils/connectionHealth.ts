/**
 * Connection Health Utility
 * Monitors backend API connectivity and provides health status
 */

import axios, { AxiosError } from 'axios';

export interface ConnectionStatus {
  isConnected: boolean;
  service: string;
  url: string;
  latency?: number;
  error?: string;
  errorCode?: string;
  timestamp: number;
}

export interface ServiceHealth {
  orchestration: ConnectionStatus;
  apiGateway: ConnectionStatus;
  overall: 'healthy' | 'degraded' | 'offline';
}

/**
 * Check connection to orchestration service
 */
export async function checkOrchestrationService(): Promise<ConnectionStatus> {
  const baseUrl = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8002';
  const startTime = Date.now();

  try {
    const response = await axios.get(`${baseUrl}/`, {
      timeout: 5000,
      validateStatus: (status) => status < 500 // Accept any non-5xx status
    });

    return {
      isConnected: true,
      service: 'orchestration',
      url: baseUrl,
      latency: Date.now() - startTime,
      timestamp: Date.now()
    };
  } catch (error) {
    const axiosError = error as AxiosError;

    // Network error (service not running)
    if (!axiosError.response) {
      return {
        isConnected: false,
        service: 'orchestration',
        url: baseUrl,
        error: 'Service not reachable. Check if orchestration service is running on port 8002',
        errorCode: 'NETWORK_ERROR',
        timestamp: Date.now()
      };
    }

    // CORS error
    if (axiosError.message?.includes('CORS')) {
      return {
        isConnected: false,
        service: 'orchestration',
        url: baseUrl,
        error: 'CORS error. Backend needs CORS configuration',
        errorCode: 'CORS_ERROR',
        timestamp: Date.now()
      };
    }

    // Other errors
    return {
      isConnected: false,
      service: 'orchestration',
      url: baseUrl,
      error: axiosError.message || 'Unknown error',
      errorCode: axiosError.code,
      timestamp: Date.now()
    };
  }
}

/**
 * Check connection to API gateway
 */
export async function checkApiGateway(): Promise<ConnectionStatus> {
  const baseUrl = process.env.REACT_APP_API_GATEWAY_URL || 'http://localhost:8000';
  const startTime = Date.now();

  try {
    const response = await axios.get(`${baseUrl}/`, {
      timeout: 5000,
      validateStatus: (status) => status < 500
    });

    return {
      isConnected: true,
      service: 'apiGateway',
      url: baseUrl,
      latency: Date.now() - startTime,
      timestamp: Date.now()
    };
  } catch (error) {
    const axiosError = error as AxiosError;

    return {
      isConnected: false,
      service: 'apiGateway',
      url: baseUrl,
      error: axiosError.message || 'Unknown error',
      errorCode: axiosError.code,
      timestamp: Date.now()
    };
  }
}

/**
 * Check overall service health
 */
export async function checkServiceHealth(): Promise<ServiceHealth> {
  const [orchestration, apiGateway] = await Promise.all([
    checkOrchestrationService(),
    checkApiGateway()
  ]);

  let overall: 'healthy' | 'degraded' | 'offline' = 'healthy';

  if (!orchestration.isConnected && !apiGateway.isConnected) {
    overall = 'offline';
  } else if (!orchestration.isConnected || !apiGateway.isConnected) {
    overall = 'degraded';
  }

  return {
    orchestration,
    apiGateway,
    overall
  };
}

/**
 * Format latency for display
 */
export function formatLatency(latency?: number): string {
  if (!latency) return 'N/A';

  if (latency < 100) return `${latency}ms (excellent)`;
  if (latency < 500) return `${latency}ms (good)`;
  if (latency < 1000) return `${latency}ms (acceptable)`;
  return `${latency}ms (slow)`;
}

/**
 * Get troubleshooting suggestions based on error
 */
export function getTroubleshootingSuggestions(status: ConnectionStatus): string[] {
  const suggestions: string[] = [];

  if (status.errorCode === 'NETWORK_ERROR') {
    suggestions.push('Check if the service is running');
    suggestions.push(`Verify service is accessible at ${status.url}`);
    suggestions.push('Check firewall and network settings');

    if (status.service === 'orchestration') {
      suggestions.push('Start orchestration service: cd sentinel_backend && python -m uvicorn orchestration_service.main:app --port 8002');
    }
  }

  if (status.errorCode === 'CORS_ERROR') {
    suggestions.push('Add CORSMiddleware to backend service');
    suggestions.push('Add frontend origin to allow_origins list');
    suggestions.push('See: sentinel_backend/orchestration_service/CORS_SETUP.md');
  }

  if (status.errorCode === 'ECONNREFUSED') {
    suggestions.push('Service is not running or port is incorrect');
    suggestions.push('Check if another service is using the port');
    suggestions.push('Review service logs for startup errors');
  }

  if (status.errorCode === 'ETIMEDOUT') {
    suggestions.push('Service is running but not responding');
    suggestions.push('Check service health and logs');
    suggestions.push('Restart the service if needed');
  }

  return suggestions;
}

/**
 * Periodically check connection health
 */
export class ConnectionHealthMonitor {
  private intervalId?: NodeJS.Timeout;
  private listeners: Set<(health: ServiceHealth) => void> = new Set();

  start(intervalMs: number = 30000) {
    this.stop(); // Clear any existing interval

    // Check immediately
    this.check();

    // Then check periodically
    this.intervalId = setInterval(() => {
      this.check();
    }, intervalMs);
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }
  }

  addListener(callback: (health: ServiceHealth) => void) {
    this.listeners.add(callback);
  }

  removeListener(callback: (health: ServiceHealth) => void) {
    this.listeners.delete(callback);
  }

  private async check() {
    const health = await checkServiceHealth();
    this.listeners.forEach(listener => listener(health));
  }
}

// Export singleton monitor
export const connectionHealthMonitor = new ConnectionHealthMonitor();
