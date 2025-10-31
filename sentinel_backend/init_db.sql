-- Sentinel Database Initialization Script
-- This script creates all required tables with all columns
-- Run this when setting up a new database to avoid missing table/column errors

-- Create projects table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create API specifications table
CREATE TABLE IF NOT EXISTS api_specifications (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id),
    title TEXT,
    description TEXT,
    raw_spec TEXT NOT NULL,
    parsed_spec JSONB NOT NULL,
    internal_graph JSONB,
    source_url TEXT,
    source_filename TEXT,
    llm_readiness_score DOUBLE PRECISION,
    version VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

-- Create test cases table with ALL columns
CREATE TABLE IF NOT EXISTS test_cases (
    id SERIAL PRIMARY KEY,
    spec_id INTEGER REFERENCES api_specifications(id),
    agent_type VARCHAR(255),
    test_definition JSONB NOT NULL,
    description TEXT,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test suites table
CREATE TABLE IF NOT EXISTS test_suites (
    id SERIAL PRIMARY KEY,
    spec_id INTEGER REFERENCES api_specifications(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    test_type VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test suite entries (junction table)
CREATE TABLE IF NOT EXISTS test_suite_entries (
    suite_id INTEGER REFERENCES test_suites(id) ON DELETE CASCADE,
    case_id INTEGER REFERENCES test_cases(id) ON DELETE CASCADE,
    execution_order INTEGER DEFAULT 0,
    PRIMARY KEY (suite_id, case_id)
);

-- Create test runs table
CREATE TABLE IF NOT EXISTS test_runs (
    id SERIAL PRIMARY KEY,
    suite_id INTEGER REFERENCES test_suites(id),
    status VARCHAR(50) DEFAULT 'pending',
    target_environment VARCHAR(255),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    summary JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test results table with ALL columns
CREATE TABLE IF NOT EXISTS test_results (
    id SERIAL PRIMARY KEY,
    run_id INTEGER REFERENCES test_runs(id),
    test_case_id INTEGER REFERENCES test_cases(id),
    case_id INTEGER REFERENCES test_cases(id), -- Alias for compatibility
    status VARCHAR(50),
    response_code INTEGER,
    response_headers JSONB,
    response_body TEXT,
    response_time_ms INTEGER,
    latency_ms INTEGER,
    error_message TEXT,
    details JSONB,
    assertion_failures JSONB,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_test_cases_spec_id ON test_cases(spec_id);
CREATE INDEX IF NOT EXISTS idx_test_results_run_id ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_test_results_case_id ON test_results(case_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_suite_id ON test_runs(suite_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_status ON test_runs(status);
CREATE INDEX IF NOT EXISTS idx_test_runs_started_at ON test_runs(started_at);

-- Insert default admin user (password: admin123)
INSERT INTO users (email, full_name, hashed_password, role)
VALUES ('admin@sentinel.com', 'System Administrator', '$2b$12$bQHSYj6.KSOapL1lEVJ1mOaXDT7HJUV9XoP1XJOjGpCGgP3vdD0wi', 'admin')
ON CONFLICT (email) DO NOTHING;

-- Grant appropriate permissions (adjust as needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinel;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sentinel;

-- ============================================
-- ReasoningBank Tables
-- ============================================

-- Task Trajectories (execution history for learning)
CREATE TABLE IF NOT EXISTS task_trajectories (
    id SERIAL PRIMARY KEY,
    trajectory_id VARCHAR(100) NOT NULL UNIQUE,
    task_type VARCHAR(50) NOT NULL,
    task_description TEXT NOT NULL,
    context_data JSONB,
    agent_type VARCHAR(50),
    actions JSONB NOT NULL,
    intermediate_outputs JSONB,
    final_output JSONB NOT NULL,
    execution_time_ms INTEGER,
    token_count INTEGER,
    outcome VARCHAR(20) DEFAULT 'UNKNOWN' NOT NULL,
    outcome_confidence DOUBLE PRECISION DEFAULT 0.0 NOT NULL,
    judgment_reasoning TEXT,
    extracted_pattern_ids JSONB,
    distillation_performed INTEGER DEFAULT 0 NOT NULL,
    test_success_rate DOUBLE PRECISION,
    coverage_score DOUBLE PRECISION,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    judged_at TIMESTAMP WITH TIME ZONE,
    distilled_at TIMESTAMP WITH TIME ZONE,
    tenant_id VARCHAR(100),
    CONSTRAINT outcome_values_check CHECK (outcome IN ('SUCCESS', 'PARTIAL_SUCCESS', 'FAILURE', 'ERROR', 'UNKNOWN'))
);

CREATE INDEX IF NOT EXISTS idx_trajectory_id ON task_trajectories(trajectory_id);
CREATE INDEX IF NOT EXISTS idx_trajectory_task_type ON task_trajectories(task_type);
CREATE INDEX IF NOT EXISTS idx_trajectory_outcome ON task_trajectories(outcome);
CREATE INDEX IF NOT EXISTS idx_trajectory_created ON task_trajectories(created_at);
CREATE INDEX IF NOT EXISTS idx_trajectory_distilled ON task_trajectories(distillation_performed);
CREATE INDEX IF NOT EXISTS idx_trajectory_tenant ON task_trajectories(tenant_id);

-- Worker Checkpoints (for graceful shutdown and resumability)
CREATE TABLE IF NOT EXISTS worker_checkpoints (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL,
    worker_name VARCHAR(100) NOT NULL,
    checkpoint_data JSONB NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_checkpoint_task_worker ON worker_checkpoints(task_id, worker_name);
CREATE INDEX IF NOT EXISTS idx_checkpoint_created ON worker_checkpoints(created_at);
CREATE INDEX IF NOT EXISTS idx_checkpoint_incomplete ON worker_checkpoints(completed_at) WHERE completed_at IS NULL;

-- Pattern Embeddings (distilled reusable patterns)
CREATE TABLE IF NOT EXISTS pattern_embeddings (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(100) NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    content TEXT NOT NULL,
    embedding vector(1536),
    confidence DOUBLE PRECISION DEFAULT 0.0,
    usage_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    domain_tags JSONB,
    source_trajectory_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    tenant_id VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_id ON pattern_embeddings(pattern_id);
CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_domain ON pattern_embeddings USING GIN (domain_tags);
CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_vector ON pattern_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_tenant ON pattern_embeddings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_confidence ON pattern_embeddings(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_pattern_embeddings_usage ON pattern_embeddings(usage_count DESC);

-- Add comment
COMMENT ON DATABASE sentinel_db IS 'Sentinel API Testing Platform Database';