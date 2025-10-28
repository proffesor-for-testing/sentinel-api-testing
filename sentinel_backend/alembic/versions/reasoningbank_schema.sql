-- ReasoningBank Schema Migration
-- Phase 2, Milestone 2.2: Self-Improving Memory System
-- Date: 2025-10-27

-- Ensure pgvector extension is available
CREATE EXTENSION IF NOT EXISTS vector;

-- Table 1: pattern_embeddings
-- Vector representations of learned patterns for semantic retrieval
CREATE TABLE IF NOT EXISTS pattern_embeddings (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(1536) NOT NULL,
    confidence FLOAT DEFAULT 0.75 NOT NULL,
    usage_count INTEGER DEFAULT 0 NOT NULL,
    success_count INTEGER DEFAULT 0 NOT NULL,
    failure_count INTEGER DEFAULT 0 NOT NULL,
    domain_tags JSONB,
    source_trajectory_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    tenant_id VARCHAR(100)
);

-- Indexes for pattern_embeddings
CREATE INDEX IF NOT EXISTS idx_pattern_id ON pattern_embeddings(pattern_id);
CREATE INDEX IF NOT EXISTS idx_pattern_confidence ON pattern_embeddings(confidence);
CREATE INDEX IF NOT EXISTS idx_pattern_usage ON pattern_embeddings(usage_count);
CREATE INDEX IF NOT EXISTS idx_pattern_created ON pattern_embeddings(created_at);
CREATE INDEX IF NOT EXISTS idx_pattern_tenant ON pattern_embeddings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pattern_domain ON pattern_embeddings USING gin(domain_tags);

-- Vector similarity index (IVFFlat for fast approximate nearest neighbor search)
CREATE INDEX IF NOT EXISTS idx_pattern_embedding ON pattern_embeddings
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- Table 2: pattern_links
-- Relationships between patterns for memory quality control
CREATE TABLE IF NOT EXISTS pattern_links (
    id SERIAL PRIMARY KEY,
    source_pattern_id VARCHAR(100) NOT NULL,
    target_pattern_id VARCHAR(100) NOT NULL,
    link_type VARCHAR(50) NOT NULL,
    similarity_score FLOAT NOT NULL,
    is_resolved BOOLEAN DEFAULT FALSE NOT NULL,
    resolution_action VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    resolved_at TIMESTAMP,
    tenant_id VARCHAR(100)
);

-- Indexes for pattern_links
CREATE INDEX IF NOT EXISTS idx_link_source ON pattern_links(source_pattern_id);
CREATE INDEX IF NOT EXISTS idx_link_target ON pattern_links(target_pattern_id);
CREATE INDEX IF NOT EXISTS idx_link_source_target ON pattern_links(source_pattern_id, target_pattern_id);
CREATE INDEX IF NOT EXISTS idx_link_type ON pattern_links(link_type);
CREATE INDEX IF NOT EXISTS idx_link_type_resolved ON pattern_links(link_type, is_resolved);
CREATE INDEX IF NOT EXISTS idx_link_tenant ON pattern_links(tenant_id);

-- Table 3: task_trajectories
-- Complete execution paths for learning from experience
CREATE TABLE IF NOT EXISTS task_trajectories (
    id SERIAL PRIMARY KEY,
    trajectory_id VARCHAR(100) UNIQUE NOT NULL,
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
    outcome_confidence FLOAT DEFAULT 0.0 NOT NULL,
    judgment_reasoning TEXT,
    extracted_pattern_ids JSONB,
    distillation_performed BOOLEAN DEFAULT FALSE NOT NULL,
    test_success_rate FLOAT,
    coverage_score FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    judged_at TIMESTAMP,
    distilled_at TIMESTAMP,
    tenant_id VARCHAR(100)
);

-- Indexes for task_trajectories
CREATE INDEX IF NOT EXISTS idx_trajectory_id ON task_trajectories(trajectory_id);
CREATE INDEX IF NOT EXISTS idx_trajectory_task_type ON task_trajectories(task_type);
CREATE INDEX IF NOT EXISTS idx_trajectory_agent_type ON task_trajectories(agent_type);
CREATE INDEX IF NOT EXISTS idx_trajectory_outcome ON task_trajectories(outcome);
CREATE INDEX IF NOT EXISTS idx_trajectory_created ON task_trajectories(created_at);
CREATE INDEX IF NOT EXISTS idx_trajectory_distilled ON task_trajectories(distillation_performed);
CREATE INDEX IF NOT EXISTS idx_trajectory_tenant ON task_trajectories(tenant_id);

-- Table 4: matts_runs
-- Memory-aware Test-Time Scaling bookkeeping
CREATE TABLE IF NOT EXISTS matts_runs (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(100) UNIQUE NOT NULL,
    mode VARCHAR(20) NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    task_description TEXT NOT NULL,
    base_trajectory_id VARCHAR(100),
    parallel_k INTEGER DEFAULT 6,
    trajectory_ids JSONB,
    diversity_seeds JSONB,
    sequential_r INTEGER DEFAULT 3,
    iteration_trajectory_ids JSONB,
    success_count INTEGER DEFAULT 0 NOT NULL,
    failure_count INTEGER DEFAULT 0 NOT NULL,
    extracted_pattern_ids JSONB,
    aggregation_method VARCHAR(50),
    total_execution_time_ms INTEGER,
    total_token_count INTEGER,
    improvement_over_baseline FLOAT,
    is_completed BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    tenant_id VARCHAR(100)
);

-- Indexes for matts_runs
CREATE INDEX IF NOT EXISTS idx_matts_run_id ON matts_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_matts_mode ON matts_runs(mode);
CREATE INDEX IF NOT EXISTS idx_matts_task_type ON matts_runs(task_type);
CREATE INDEX IF NOT EXISTS idx_matts_completed ON matts_runs(is_completed);
CREATE INDEX IF NOT EXISTS idx_matts_created ON matts_runs(created_at);
CREATE INDEX IF NOT EXISTS idx_matts_tenant ON matts_runs(tenant_id);

-- Foreign key constraints (optional, depending on requirements)
-- ALTER TABLE pattern_links ADD CONSTRAINT fk_link_source
--     FOREIGN KEY (source_pattern_id) REFERENCES pattern_embeddings(pattern_id);
-- ALTER TABLE pattern_links ADD CONSTRAINT fk_link_target
--     FOREIGN KEY (target_pattern_id) REFERENCES pattern_embeddings(pattern_id);

-- Comments for documentation
COMMENT ON TABLE pattern_embeddings IS 'Vector representations of learned patterns for semantic retrieval with confidence tracking and reinforcement learning';
COMMENT ON TABLE pattern_links IS 'Relationships between patterns for deduplication, contradiction detection, and memory quality control';
COMMENT ON TABLE task_trajectories IS 'Complete execution paths capturing input → actions → output → judgment → learnings for closed-loop self-improvement';
COMMENT ON TABLE matts_runs IS 'Memory-aware Test-Time Scaling bookkeeping for parallel exploration (k=6) and sequential refinement (r=3) modes';

COMMENT ON COLUMN pattern_embeddings.embedding IS '1536-dimensional vector from text-embedding-3-large for semantic similarity search';
COMMENT ON COLUMN pattern_embeddings.confidence IS 'Confidence score (0.0-1.0) updated via reinforcement learning: confidence ← clamp(confidence + η·success_delta, 0, 1)';
COMMENT ON COLUMN pattern_links.link_type IS 'Relationship type: DUPLICATE (similarity >= 0.87), CONTRADICTION (NLI >= 0.60), REFINEMENT, RELATED, SUPERSEDES';
COMMENT ON COLUMN task_trajectories.outcome IS 'LLM-judged verdict: SUCCESS, FAILURE, PARTIAL, or UNKNOWN';
COMMENT ON COLUMN matts_runs.mode IS 'Scaling mode: PARALLEL (k independent rollouts) or SEQUENTIAL (r iterative refinements)';

-- Grant permissions (adjust as needed for your environment)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON pattern_embeddings TO sentinel_backend;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON pattern_links TO sentinel_backend;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON task_trajectories TO sentinel_backend;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON matts_runs TO sentinel_backend;

-- Verification queries
-- SELECT table_name, pg_size_pretty(pg_total_relation_size(table_name::regclass)) AS size
-- FROM information_schema.tables
-- WHERE table_schema = 'public'
-- AND table_name IN ('pattern_embeddings', 'pattern_links', 'task_trajectories', 'matts_runs');

-- SELECT indexname, tablename, indexdef
-- FROM pg_indexes
-- WHERE tablename IN ('pattern_embeddings', 'pattern_links', 'task_trajectories', 'matts_runs')
-- ORDER BY tablename, indexname;
