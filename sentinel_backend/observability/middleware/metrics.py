"""
Custom Prometheus Metrics Middleware for Sentinel Platform

Provides business-specific metrics beyond standard HTTP metrics.
"""
from prometheus_client import Counter, Histogram, Gauge, Info
from typing import Callable
import time
import structlog

logger = structlog.get_logger(__name__)

# ============================================================================
# Test Generation Metrics
# ============================================================================

test_generation_total = Counter(
    'sentinel_test_generation_total',
    'Total number of tests generated',
    ['test_type', 'agent_type', 'status']
)

test_generation_duration = Histogram(
    'sentinel_test_generation_duration_seconds',
    'Time taken to generate tests',
    ['test_type', 'agent_type'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0]
)

test_generation_queue_size = Gauge(
    'sentinel_test_generation_queue_size',
    'Number of pending test generation requests'
)

# ============================================================================
# Test Execution Metrics
# ============================================================================

test_execution_total = Counter(
    'sentinel_test_execution_total',
    'Total number of tests executed',
    ['test_type', 'status']
)

test_execution_duration = Histogram(
    'sentinel_test_execution_duration_seconds',
    'Time taken to execute tests',
    ['test_type'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

# ============================================================================
# Agent Metrics
# ============================================================================

agent_executions_total = Counter(
    'sentinel_agent_executions_total',
    'Total number of agent executions',
    ['agent_type', 'service', 'status']
)

agent_duration = Histogram(
    'sentinel_agent_duration_seconds',
    'Time taken for agent execution',
    ['agent_type', 'service'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

agent_active = Gauge(
    'sentinel_agent_active_executions',
    'Number of currently active agent executions',
    ['agent_type']
)

agent_queue_size = Gauge(
    'sentinel_agent_queue_size',
    'Number of pending agent execution requests',
    ['agent_type']
)

# ============================================================================
# Rust Core Agent Metrics
# ============================================================================

rust_agent_executions_total = Counter(
    'sentinel_rust_agent_executions_total',
    'Total number of Rust agent executions',
    ['agent_type', 'status']
)

rust_agent_duration = Histogram(
    'sentinel_rust_agent_duration_seconds',
    'Time taken for Rust agent execution',
    ['agent_type'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

rust_agent_errors_total = Counter(
    'sentinel_rust_agent_errors_total',
    'Total number of Rust agent errors',
    ['agent_type', 'error_type']
)

# ============================================================================
# LLM Provider Metrics
# ============================================================================

llm_requests_total = Counter(
    'sentinel_llm_requests_total',
    'Total number of LLM API requests',
    ['provider', 'model', 'status']
)

llm_request_duration = Histogram(
    'sentinel_llm_request_duration_seconds',
    'Time taken for LLM API requests',
    ['provider', 'model'],
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0]
)

llm_tokens_total = Counter(
    'sentinel_llm_tokens_total',
    'Total number of tokens used',
    ['provider', 'model', 'token_type']
)

llm_cost_total = Counter(
    'sentinel_llm_cost_total',
    'Total cost of LLM API requests in USD',
    ['provider', 'model']
)

llm_rate_limit_remaining = Gauge(
    'sentinel_llm_rate_limit_remaining',
    'Remaining LLM API rate limit',
    ['provider']
)

# ============================================================================
# Database Metrics
# ============================================================================

db_query_duration = Histogram(
    'db_query_duration_seconds',
    'Database query duration',
    ['operation', 'table'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
)

db_connections_active = Gauge(
    'db_connections_active',
    'Number of active database connections'
)

db_connections_max = Gauge(
    'db_connections_max',
    'Maximum number of database connections'
)

db_query_errors_total = Counter(
    'db_query_errors_total',
    'Total number of database query errors',
    ['operation', 'error_type']
)

# ============================================================================
# Message Broker Metrics
# ============================================================================

message_queue_size = Gauge(
    'sentinel_message_queue_size',
    'Number of messages in queue',
    ['queue_name']
)

message_processing_duration = Histogram(
    'sentinel_message_processing_duration_seconds',
    'Time taken to process messages',
    ['queue_name'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

message_processing_errors_total = Counter(
    'sentinel_message_processing_errors_total',
    'Total number of message processing errors',
    ['queue_name', 'error_type']
)

# ============================================================================
# API Specification Metrics
# ============================================================================

spec_analysis_duration = Histogram(
    'sentinel_spec_analysis_duration_seconds',
    'Time taken to analyze API specifications',
    ['spec_format'],
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
)

spec_endpoints_detected = Gauge(
    'sentinel_spec_endpoints_detected',
    'Number of endpoints detected in API spec',
    ['spec_id']
)

# ============================================================================
# Orchestration Metrics
# ============================================================================

workflow_executions_total = Counter(
    'sentinel_workflow_executions_total',
    'Total number of workflow executions',
    ['workflow_type', 'status']
)

workflow_duration = Histogram(
    'sentinel_workflow_duration_seconds',
    'Time taken for workflow execution',
    ['workflow_type'],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
)

# ============================================================================
# System Information
# ============================================================================

sentinel_info = Info(
    'sentinel_build_info',
    'Sentinel platform build information'
)

# ============================================================================
# Helper Functions
# ============================================================================

def track_test_generation(test_type: str, agent_type: str) -> Callable:
    """Context manager to track test generation metrics."""
    class TestGenerationTracker:
        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.time() - self.start_time
            status = 'success' if exc_type is None else 'failed'

            test_generation_total.labels(
                test_type=test_type,
                agent_type=agent_type,
                status=status
            ).inc()

            test_generation_duration.labels(
                test_type=test_type,
                agent_type=agent_type
            ).observe(duration)

            logger.info(
                "test_generation_completed",
                test_type=test_type,
                agent_type=agent_type,
                duration=duration,
                status=status
            )

    return TestGenerationTracker()


def track_agent_execution(agent_type: str, service: str) -> Callable:
    """Context manager to track agent execution metrics."""
    class AgentExecutionTracker:
        def __enter__(self):
            self.start_time = time.time()
            agent_active.labels(agent_type=agent_type).inc()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.time() - self.start_time
            status = 'success' if exc_type is None else 'failed'

            agent_executions_total.labels(
                agent_type=agent_type,
                service=service,
                status=status
            ).inc()

            agent_duration.labels(
                agent_type=agent_type,
                service=service
            ).observe(duration)

            agent_active.labels(agent_type=agent_type).dec()

            logger.info(
                "agent_execution_completed",
                agent_type=agent_type,
                service=service,
                duration=duration,
                status=status
            )

    return AgentExecutionTracker()


def track_llm_request(provider: str, model: str) -> Callable:
    """Context manager to track LLM request metrics."""
    class LLMRequestTracker:
        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.time() - self.start_time
            status = 'success' if exc_type is None else 'failed'

            llm_requests_total.labels(
                provider=provider,
                model=model,
                status=status
            ).inc()

            llm_request_duration.labels(
                provider=provider,
                model=model
            ).observe(duration)

            logger.info(
                "llm_request_completed",
                provider=provider,
                model=model,
                duration=duration,
                status=status
            )

    return LLMRequestTracker()


def track_db_query(operation: str, table: str) -> Callable:
    """Context manager to track database query metrics."""
    class DBQueryTracker:
        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.time() - self.start_time

            db_query_duration.labels(
                operation=operation,
                table=table
            ).observe(duration)

            if exc_type is not None:
                db_query_errors_total.labels(
                    operation=operation,
                    error_type=exc_type.__name__
                ).inc()

    return DBQueryTracker()


# Initialize build info
def set_build_info(version: str, git_commit: str = "unknown", build_date: str = "unknown"):
    """Set Sentinel build information."""
    sentinel_info.info({
        'version': version,
        'git_commit': git_commit,
        'build_date': build_date
    })
