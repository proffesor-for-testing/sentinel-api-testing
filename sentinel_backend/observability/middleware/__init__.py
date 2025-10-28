"""
Observability middleware for Sentinel Platform.
"""
from .metrics import (
    # Test metrics
    track_test_generation,
    test_generation_total,
    test_generation_duration,
    test_execution_total,
    test_execution_duration,

    # Agent metrics
    track_agent_execution,
    agent_executions_total,
    agent_duration,
    agent_active,

    # LLM metrics
    track_llm_request,
    llm_requests_total,
    llm_request_duration,
    llm_tokens_total,
    llm_cost_total,

    # Database metrics
    track_db_query,
    db_query_duration,
    db_connections_active,
    db_connections_max,

    # Rust core metrics
    rust_agent_executions_total,
    rust_agent_duration,

    # Build info
    set_build_info,
)

__all__ = [
    'track_test_generation',
    'test_generation_total',
    'test_generation_duration',
    'test_execution_total',
    'test_execution_duration',
    'track_agent_execution',
    'agent_executions_total',
    'agent_duration',
    'agent_active',
    'track_llm_request',
    'llm_requests_total',
    'llm_request_duration',
    'llm_tokens_total',
    'llm_cost_total',
    'track_db_query',
    'db_query_duration',
    'db_connections_active',
    'db_connections_max',
    'rust_agent_executions_total',
    'rust_agent_duration',
    'set_build_info',
]
