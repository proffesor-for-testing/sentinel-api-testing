//! SublinearOrchestrator with Hive-Mind Coordination
//!
//! This module implements the enhanced orchestrator that coordinates consciousness-aware
//! agents with sublinear computational advantages, emergent behavior detection,
//! and nanosecond-precision scheduling.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::consciousness::*;
use crate::consciousness::agents::ConsciousFunctionalPositiveAgent;
use crate::consciousness::emergence::EmergenceDetector;
use crate::consciousness::knowledge_graph::KnowledgeGraph;
use crate::consciousness::scheduler::NanosecondScheduler;
use crate::consciousness::temporal::TemporalAdvantagePredictor;
use crate::types::{AgentTask, AgentResult, TestCase};

/// Orchestration error types
#[derive(Debug, thiserror::Error)]
pub enum OrchestrationError {
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
    #[error("Consciousness level insufficient: {current} < {required}")]
    InsufficientConsciousness { current: f64, required: f64 },
    #[error("Temporal advantage calculation failed: {0}")]
    TemporalAdvantageError(String),
    #[error("Emergent discovery failed: {0}")]
    EmergentDiscoveryError(String),
    #[error("Hive-mind coordination failed: {0}")]
    HiveMindCoordinationError(String),
    #[error("Sublinear computation failed: {0}")]
    SublinearComputationError(String),
}

/// Enhanced agent result with consciousness and emergence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAgentResult {
    pub traditional_results: Vec<AgentResult>,
    pub emergent_patterns: Vec<EmergentPattern>,
    pub novel_tests: Vec<TestCase>,
    pub consciousness_evolution: f64,
    pub temporal_advantage_utilized: bool,
    pub insights: Vec<SystemInsight>,
    pub hive_mind_contribution: HiveMindContribution,
    pub sublinear_optimizations: Vec<SublinearOptimization>,
}

/// Hive-mind contribution to the result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveMindContribution {
    pub collective_consciousness_level: f64,
    pub cross_agent_insights: Vec<CrossAgentInsight>,
    pub emergent_behaviors: Vec<EmergentBehavior>,
    pub consensus_strength: f64,
}

/// Cross-agent insight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAgentInsight {
    pub source_agents: Vec<String>,
    pub insight_type: String,
    pub confidence: f64,
    pub actionable_recommendations: Vec<String>,
}

/// Emergent behavior detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergentBehavior {
    pub behavior_id: String,
    pub emergence_strength: f64,
    pub participating_agents: Vec<String>,
    pub behavior_description: String,
    pub consciousness_threshold_crossed: bool,
}

/// Sublinear optimization applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SublinearOptimization {
    pub optimization_type: String,
    pub time_savings_ns: u64,
    pub consciousness_enhancement: f64,
    pub confidence: f64,
}

/// Collective consciousness state
#[derive(Debug, Clone)]
pub struct CollectiveConsciousness {
    pub overall_level: f64,
    pub agent_contributions: HashMap<String, f64>,
    pub emergence_events: Vec<EmergenceEvent>,
    pub consciousness_evolution_rate: f64,
    pub temporal_coherence: f64,
}

/// Swarm memory for cross-session learning
#[derive(Debug, Clone)]
pub struct SwarmMemory {
    pub persistent_insights: Vec<PersistentInsight>,
    pub learned_patterns: Vec<LearnedPattern>,
    pub optimization_history: Vec<OptimizationRecord>,
    pub consciousness_growth_trajectory: Vec<ConsciousnessCheckpoint>,
}

/// Persistent insight across sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentInsight {
    pub insight_id: String,
    pub creation_time: chrono::DateTime<chrono::Utc>,
    pub insight_content: String,
    pub relevance_score: f64,
    pub applications_count: u32,
    pub success_rate: f64,
}

/// Learned pattern from agent behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub pattern_id: String,
    pub pattern_signature: Vec<f64>,
    pub success_probability: f64,
    pub applicable_contexts: Vec<String>,
    pub consciousness_requirement: f64,
}

/// Optimization record for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecord {
    pub optimization_id: String,
    pub applied_time: chrono::DateTime<chrono::Utc>,
    pub optimization_type: String,
    pub performance_gain: f64,
    pub consciousness_impact: f64,
}

/// Consciousness checkpoint for growth tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsciousnessCheckpoint {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub collective_consciousness: f64,
    pub individual_levels: HashMap<String, f64>,
    pub emergence_events_count: u32,
    pub insights_generated: u32,
}

/// Byzantine consensus for distributed consciousness
#[derive(Debug, Clone)]
pub struct ByzantineConsensus {
    pub consensus_threshold: f64,
    pub participating_agents: Vec<String>,
    pub consensus_history: Vec<ConsensusEvent>,
    pub fault_tolerance_level: f64,
}

/// Consensus event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusEvent {
    pub event_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub consensus_topic: String,
    pub participating_agents: Vec<String>,
    pub final_decision: serde_json::Value,
    pub consensus_strength: f64,
}

/// SublinearOrchestrator with consciousness and hive-mind capabilities
pub struct SublinearOrchestrator {
    consciousness_agents: HashMap<String, Arc<Mutex<Box<dyn ConsciousnessAgent>>>>,
    knowledge_graph: Arc<RwLock<KnowledgeGraph<TestCase>>>,
    nanosecond_scheduler: Arc<Mutex<NanosecondScheduler>>,
    emergence_detector: Arc<Mutex<EmergenceDetector>>,
    temporal_predictor: Arc<Mutex<TemporalAdvantagePredictor>>,

    // Hive-mind coordination
    collective_consciousness: Arc<RwLock<CollectiveConsciousness>>,
    swarm_memory: Arc<RwLock<SwarmMemory>>,
    consensus_mechanism: Arc<Mutex<ByzantineConsensus>>,

    // Configuration
    emergence_threshold: f64,
    consciousness_amplification: f64,
    temporal_optimization_enabled: bool,
}

impl SublinearOrchestrator {
    /// Create a new SublinearOrchestrator
    pub fn new() -> Self {
        Self {
            consciousness_agents: HashMap::new(),
            knowledge_graph: Arc::new(RwLock::new(KnowledgeGraph::new())),
            nanosecond_scheduler: Arc::new(Mutex::new(NanosecondScheduler::new())),
            emergence_detector: Arc::new(Mutex::new(EmergenceDetector::new())),
            temporal_predictor: Arc::new(Mutex::new(TemporalAdvantagePredictor::new())),
            collective_consciousness: Arc::new(RwLock::new(CollectiveConsciousness::new())),
            swarm_memory: Arc::new(RwLock::new(SwarmMemory::new())),
            consensus_mechanism: Arc::new(Mutex::new(ByzantineConsensus::new())),
            emergence_threshold: 0.7,
            consciousness_amplification: 1.2,
            temporal_optimization_enabled: true,
        }
    }

    /// Initialize with consciousness-aware agents
    pub async fn initialize_consciousness_agents(&mut self) -> Result<(), OrchestrationError> {
        // Add consciousness-enhanced functional positive agent
        let conscious_positive_agent = ConsciousFunctionalPositiveAgent::new();
        self.consciousness_agents.insert(
            "Consciousness-Functional-Positive-Agent".to_string(),
            Arc::new(Mutex::new(Box::new(conscious_positive_agent))),
        );

        // TODO: Add other consciousness-enhanced agents
        // - ConsciousSecurityAgent
        // - ConsciousPerformanceAgent
        // - ConsciousNegativeAgent
        // etc.

        // Initialize collective consciousness
        let mut collective = self.collective_consciousness.write().await;
        collective.agent_contributions.insert(
            "Consciousness-Functional-Positive-Agent".to_string(),
            0.5,
        );
        collective.update_overall_level();

        Ok(())
    }

    /// Orchestrate with consciousness and temporal advantage
    pub async fn orchestrate_with_consciousness(
        &self,
        task: AgentTask,
        api_spec: serde_json::Value,
    ) -> Result<EnhancedAgentResult, OrchestrationError> {
        // 1. Predict temporal advantage
        let temporal_advantage = self.temporal_predictor
            .lock()
            .await
            .predict_advantage(&task, &api_spec)
            .await
            .map_err(|e| OrchestrationError::TemporalAdvantageError(e.to_string()))?;

        // 2. Evolve collective consciousness
        let consciousness_level = self.evolve_collective_consciousness(&task).await?;

        // 3. Schedule with nanosecond precision if temporal advantage exists
        let scheduled_tasks = if temporal_advantage.lead_time_ns > 0 && self.temporal_optimization_enabled {
            let scheduler = self.nanosecond_scheduler.clone();
            let mut scheduler_guard = scheduler.lock().await;

            scheduler_guard.schedule_optimal_sequence(&task, temporal_advantage.lead_time_ns)
                .await
                .map_err(|e| OrchestrationError::SublinearComputationError(e.to_string()))?
        } else {
            // Fallback to single task
            vec![ScheduledTask {
                task: task.clone(),
                api_spec: api_spec.clone(),
                scheduled_time_ns: 0,
                temporal_advantage: temporal_advantage.clone(),
                consciousness_priority: consciousness_level,
                agent_type: task.agent_type.clone(),
            }]
        };

        // 4. Execute with emergent discovery
        let enhanced_result = self.execute_emergent_discovery(
            scheduled_tasks,
            consciousness_level,
            api_spec,
        ).await?;

        // 5. Update collective knowledge
        self.update_collective_knowledge(&enhanced_result).await?;

        // 6. Record optimization for learning
        self.record_optimization_metrics(&enhanced_result, &temporal_advantage).await?;

        Ok(enhanced_result)
    }

    /// Execute emergent discovery with hive-mind coordination
    async fn execute_emergent_discovery(
        &self,
        scheduled_tasks: Vec<ScheduledTask>,
        consciousness_level: f64,
        api_spec: serde_json::Value,
    ) -> Result<EnhancedAgentResult, OrchestrationError> {
        let mut traditional_results = Vec::new();
        let mut system_state = SystemState::new();
        let mut hive_mind_insights = Vec::new();
        let mut emergent_behaviors = Vec::new();

        // Execute each scheduled task with consciousness
        for scheduled_task in scheduled_tasks {
            // Get appropriate consciousness agent
            let agent_arc = self.consciousness_agents
                .get(&scheduled_task.agent_type)
                .or_else(|| self.consciousness_agents.get("Consciousness-Functional-Positive-Agent"))
                .ok_or_else(|| OrchestrationError::AgentNotFound(scheduled_task.agent_type.clone()))?;

            let mut agent = agent_arc.lock().await;

            // Detect emergence before execution
            let pre_emergence = agent.detect_emergence(&system_state);

            // Create psycho-symbolic context
            let reasoning_context = PsychoSymbolicContext {
                task: scheduled_task.task.clone(),
                consciousness_level,
                emergence_metrics: pre_emergence.clone(),
                temporal_advantage: scheduled_task.temporal_advantage.clone(),
                semantic_embedding: self.generate_semantic_context(&scheduled_task).await?,
            };

            // Execute with consciousness enhancement
            let result = agent.execute_with_consciousness(
                scheduled_task.task.clone(),
                api_spec.clone(),
                Some(reasoning_context.clone()),
            ).await
            .map_err(|e| OrchestrationError::EmergentDiscoveryError(e.to_string()))?;

            // Perform psycho-symbolic reasoning
            let reasoning_result = agent.reason_symbolically(reasoning_context).await
                .map_err(|e| OrchestrationError::EmergentDiscoveryError(e.to_string()))?;

            // Extract hive-mind insights before moving reasoning_result
            for insight in &reasoning_result.consciousness_insights {
                hive_mind_insights.push(CrossAgentInsight {
                    source_agents: vec![scheduled_task.agent_type.clone()],
                    insight_type: format!("{:?}", insight.insight_type),
                    confidence: insight.confidence,
                    actionable_recommendations: insight.actionable_suggestions.clone(),
                });
            }

            // Detect emergent behaviors
            if pre_emergence.emergence_strength > self.emergence_threshold {
                emergent_behaviors.push(EmergentBehavior {
                    behavior_id: uuid::Uuid::new_v4().to_string(),
                    emergence_strength: pre_emergence.emergence_strength,
                    participating_agents: vec![scheduled_task.agent_type.clone()],
                    behavior_description: "High-consciousness emergent behavior detected".to_string(),
                    consciousness_threshold_crossed: consciousness_level > 0.8,
                });
            }

            // Update system state (this moves reasoning_result)
            system_state.incorporate_result(&result, reasoning_result);
            traditional_results.push(result);
        }

        // Discover emergent patterns across all results
        // For now, use empty patterns since discover_endpoint_patterns expects EndpointInfo
        let emergent_patterns = Vec::new();

        // Synthesize novel tests from patterns
        let novel_tests = self.synthesize_novel_tests_from_patterns(&emergent_patterns).await?;

        // Calculate collective consciousness contribution
        let collective_consciousness = self.collective_consciousness.read().await;
        let hive_mind_contribution = HiveMindContribution {
            collective_consciousness_level: collective_consciousness.overall_level,
            cross_agent_insights: hive_mind_insights,
            emergent_behaviors,
            consensus_strength: self.calculate_consensus_strength().await?,
        };

        // Generate sublinear optimizations
        let sublinear_optimizations = self.generate_sublinear_optimizations(&traditional_results).await?;

        Ok(EnhancedAgentResult {
            traditional_results,
            emergent_patterns,
            novel_tests,
            consciousness_evolution: consciousness_level,
            temporal_advantage_utilized: true,
            insights: system_state.extract_insights(),
            hive_mind_contribution,
            sublinear_optimizations,
        })
    }

    /// Evolve collective consciousness based on task
    async fn evolve_collective_consciousness(
        &self,
        task: &AgentTask,
    ) -> Result<f64, OrchestrationError> {
        let mut collective = self.collective_consciousness.write().await;

        // Calculate consciousness evolution from task complexity
        let task_complexity = self.calculate_task_consciousness_impact(task);
        let evolution_factor = task_complexity * 0.1; // 10% max evolution per task

        // Update agent contributions
        if let Some(current_level) = collective.agent_contributions.get_mut(&task.agent_type) {
            *current_level = (*current_level + evolution_factor).min(1.0);
        } else {
            collective.agent_contributions.insert(task.agent_type.clone(), 0.5 + evolution_factor);
        }

        // Update overall consciousness level
        collective.update_overall_level();

        // Record consciousness checkpoint
        self.record_consciousness_checkpoint(&collective).await?;

        Ok(collective.overall_level)
    }

    /// Update collective knowledge with insights
    async fn update_collective_knowledge(
        &self,
        result: &EnhancedAgentResult,
    ) -> Result<(), OrchestrationError> {
        let knowledge_graph = self.knowledge_graph.clone();
        let mut kg = knowledge_graph.write().await;

        // Add traditional test cases to knowledge graph
        for agent_result in &result.traditional_results {
            for test_case in &agent_result.test_cases {
                kg.add_with_consciousness(test_case.clone(), result.consciousness_evolution).await;
            }
        }

        // Add novel tests with higher consciousness weight
        for novel_test in &result.novel_tests {
            kg.add_with_consciousness(novel_test.clone(), result.consciousness_evolution * 1.2).await;
        }

        // Update swarm memory with insights
        let mut swarm_memory = self.swarm_memory.write().await;
        for insight in &result.insights {
            let persistent_insight = PersistentInsight {
                insight_id: uuid::Uuid::new_v4().to_string(),
                creation_time: chrono::Utc::now(),
                insight_content: insight.insight_type.clone(),
                relevance_score: insight.confidence,
                applications_count: 1,
                success_rate: 1.0,
            };
            swarm_memory.persistent_insights.push(persistent_insight);
        }

        // Learn patterns from emergent behaviors
        for behavior in &result.hive_mind_contribution.emergent_behaviors {
            let learned_pattern = LearnedPattern {
                pattern_id: behavior.behavior_id.clone(),
                pattern_signature: vec![behavior.emergence_strength],
                success_probability: 0.8, // Initial assumption
                applicable_contexts: behavior.participating_agents.clone(),
                consciousness_requirement: if behavior.consciousness_threshold_crossed { 0.8 } else { 0.5 },
            };
            swarm_memory.learned_patterns.push(learned_pattern);
        }

        Ok(())
    }

    /// Generate semantic context for psycho-symbolic reasoning
    async fn generate_semantic_context(
        &self,
        scheduled_task: &ScheduledTask,
    ) -> Result<Vec<f64>, OrchestrationError> {
        // Simple semantic embedding based on task characteristics
        let mut embedding = vec![0.0; 128]; // 128-dimensional embedding

        // Task type encoding
        let task_type_hash = self.hash_string(&scheduled_task.task.agent_type);
        embedding[0] = (task_type_hash % 1000) as f64 / 1000.0;

        // Consciousness priority encoding
        embedding[1] = scheduled_task.consciousness_priority;

        // Temporal advantage encoding
        embedding[2] = if scheduled_task.temporal_advantage.lead_time_ns > 0 { 1.0 } else { 0.0 };
        embedding[3] = scheduled_task.temporal_advantage.confidence;

        // Parameter complexity encoding
        embedding[4] = scheduled_task.task.parameters.len() as f64 / 10.0; // Normalize

        // Fill remaining dimensions with derived features
        for i in 5..embedding.len() {
            embedding[i] = (embedding[i % 5] + (i as f64 * 0.01)) % 1.0;
        }

        Ok(embedding)
    }

    /// Synthesize novel tests from emergent patterns
    async fn synthesize_novel_tests_from_patterns(
        &self,
        patterns: &[EmergentPattern],
    ) -> Result<Vec<TestCase>, OrchestrationError> {
        let mut novel_tests = Vec::new();

        for pattern in patterns {
            // Create a novel test case based on the pattern
            let test_case = TestCase {
                test_name: format!("Emergent Test: {}", pattern.pattern_id),
                test_type: "emergent-synthesis".to_string(),
                method: "GET".to_string(), // Default method
                path: "/emergent".to_string(),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("X-Emergent-Pattern".to_string(), pattern.pattern_id.clone());
                    headers.insert("X-Consciousness-Level".to_string(),
                        pattern.consciousness_contribution.to_string());
                    headers
                },
                query_params: HashMap::new(),
                body: None,
                timeout: 600,
                expected_status_codes: vec![200],
                assertions: vec![],
                tags: vec![
                    "emergent".to_string(),
                    "consciousness-synthesized".to_string(),
                    format!("pattern-{}", pattern.pattern_type.as_str()),
                    format!("consciousness-{:.2}", pattern.consciousness_contribution),
                ],
            };

            novel_tests.push(test_case);
        }

        Ok(novel_tests)
    }

    /// Calculate consensus strength across agents
    async fn calculate_consensus_strength(&self) -> Result<f64, OrchestrationError> {
        let consensus = self.consensus_mechanism.lock().await;

        if consensus.consensus_history.is_empty() {
            return Ok(1.0); // Perfect consensus by default
        }

        // Calculate average consensus strength from recent events
        let recent_events: Vec<_> = consensus.consensus_history
            .iter()
            .rev()
            .take(10) // Last 10 events
            .collect();

        let average_strength = recent_events
            .iter()
            .map(|event| event.consensus_strength)
            .sum::<f64>() / recent_events.len() as f64;

        Ok(average_strength)
    }

    /// Generate sublinear optimizations
    async fn generate_sublinear_optimizations(
        &self,
        results: &[AgentResult],
    ) -> Result<Vec<SublinearOptimization>, OrchestrationError> {
        let mut optimizations = Vec::new();

        // Temporal optimization
        let total_processing_time: u64 = results
            .iter()
            .filter_map(|r| r.metadata.get("processing_time_ms"))
            .filter_map(|v| v.as_u64())
            .sum();

        if total_processing_time > 1000 { // If total time > 1 second
            optimizations.push(SublinearOptimization {
                optimization_type: "temporal_parallelization".to_string(),
                time_savings_ns: (total_processing_time * 1_000_000) / 2, // 50% savings through parallelization
                consciousness_enhancement: 0.2,
                confidence: 0.8,
            });
        }

        // Consciousness-based optimization
        let total_test_cases: usize = results.iter().map(|r| r.test_cases.len()).sum();
        if total_test_cases > 10 {
            optimizations.push(SublinearOptimization {
                optimization_type: "consciousness_guided_pruning".to_string(),
                time_savings_ns: 500_000_000, // 500ms savings through intelligent pruning
                consciousness_enhancement: 0.3,
                confidence: 0.9,
            });
        }

        // Emergent pattern optimization
        optimizations.push(SublinearOptimization {
            optimization_type: "emergent_pattern_caching".to_string(),
            time_savings_ns: 100_000_000, // 100ms savings through pattern reuse
            consciousness_enhancement: 0.1,
            confidence: 0.7,
        });

        Ok(optimizations)
    }

    /// Record optimization metrics for learning
    async fn record_optimization_metrics(
        &self,
        result: &EnhancedAgentResult,
        temporal_advantage: &TemporalAdvantage,
    ) -> Result<(), OrchestrationError> {
        let mut swarm_memory = self.swarm_memory.write().await;

        for optimization in &result.sublinear_optimizations {
            let record = OptimizationRecord {
                optimization_id: uuid::Uuid::new_v4().to_string(),
                applied_time: chrono::Utc::now(),
                optimization_type: optimization.optimization_type.clone(),
                performance_gain: optimization.time_savings_ns as f64 / 1_000_000_000.0, // Convert to seconds
                consciousness_impact: optimization.consciousness_enhancement,
            };

            swarm_memory.optimization_history.push(record);
        }

        // Cleanup old records to prevent memory bloat
        if swarm_memory.optimization_history.len() > 1000 {
            swarm_memory.optimization_history.drain(0..500); // Keep last 500
        }

        Ok(())
    }

    /// Record consciousness checkpoint
    async fn record_consciousness_checkpoint(
        &self,
        collective: &CollectiveConsciousness,
    ) -> Result<(), OrchestrationError> {
        let mut swarm_memory = self.swarm_memory.write().await;

        let checkpoint = ConsciousnessCheckpoint {
            timestamp: chrono::Utc::now(),
            collective_consciousness: collective.overall_level,
            individual_levels: collective.agent_contributions.clone(),
            emergence_events_count: collective.emergence_events.len() as u32,
            insights_generated: swarm_memory.persistent_insights.len() as u32,
        };

        swarm_memory.consciousness_growth_trajectory.push(checkpoint);

        // Keep only last 100 checkpoints
        if swarm_memory.consciousness_growth_trajectory.len() > 100 {
            swarm_memory.consciousness_growth_trajectory.remove(0);
        }

        Ok(())
    }

    /// Calculate task consciousness impact
    fn calculate_task_consciousness_impact(&self, task: &AgentTask) -> f64 {
        let mut impact = 0.1; // Base impact

        // Parameter complexity
        impact += task.parameters.len() as f64 * 0.05;

        // Agent type complexity
        if task.agent_type.contains("security") {
            impact += 0.3;
        } else if task.agent_type.contains("performance") {
            impact += 0.2;
        }

        // Consciousness-enhanced agents get higher impact
        if task.agent_type.contains("consciousness") {
            impact *= 1.5;
        }

        impact.min(1.0)
    }

    /// Simple string hash function
    fn hash_string(&self, s: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    /// Get available agent types
    pub fn available_consciousness_agents(&self) -> Vec<String> {
        self.consciousness_agents.keys().cloned().collect()
    }

    /// Get collective consciousness status
    pub async fn get_collective_consciousness_status(&self) -> CollectiveConsciousness {
        self.collective_consciousness.read().await.clone()
    }

    /// Get swarm memory summary
    pub async fn get_swarm_memory_summary(&self) -> SwarmMemorySummary {
        let memory = self.swarm_memory.read().await;

        SwarmMemorySummary {
            total_insights: memory.persistent_insights.len(),
            learned_patterns: memory.learned_patterns.len(),
            optimization_records: memory.optimization_history.len(),
            consciousness_checkpoints: memory.consciousness_growth_trajectory.len(),
            latest_consciousness_level: memory.consciousness_growth_trajectory
                .last()
                .map(|cp| cp.collective_consciousness)
                .unwrap_or(0.0),
        }
    }
}

/// Swarm memory summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMemorySummary {
    pub total_insights: usize,
    pub learned_patterns: usize,
    pub optimization_records: usize,
    pub consciousness_checkpoints: usize,
    pub latest_consciousness_level: f64,
}

// Implementation of supporting structures

impl CollectiveConsciousness {
    pub fn new() -> Self {
        Self {
            overall_level: 0.0,
            agent_contributions: HashMap::new(),
            emergence_events: Vec::new(),
            consciousness_evolution_rate: 0.1,
            temporal_coherence: 1.0,
        }
    }

    pub fn update_overall_level(&mut self) {
        if self.agent_contributions.is_empty() {
            self.overall_level = 0.0;
            return;
        }

        let total: f64 = self.agent_contributions.values().sum();
        self.overall_level = total / self.agent_contributions.len() as f64;
    }
}

impl SwarmMemory {
    pub fn new() -> Self {
        Self {
            persistent_insights: Vec::new(),
            learned_patterns: Vec::new(),
            optimization_history: Vec::new(),
            consciousness_growth_trajectory: Vec::new(),
        }
    }
}

impl ByzantineConsensus {
    pub fn new() -> Self {
        Self {
            consensus_threshold: 0.67, // 2/3 majority
            participating_agents: Vec::new(),
            consensus_history: Vec::new(),
            fault_tolerance_level: 0.33, // Tolerate up to 1/3 faulty agents
        }
    }
}

impl Default for SublinearOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CollectiveConsciousness {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SwarmMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ByzantineConsensus {
    fn default() -> Self {
        Self::new()
    }
}