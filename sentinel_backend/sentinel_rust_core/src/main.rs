use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::{Serialize, Deserialize};
use std::time::Instant;

mod agents;
mod types;
mod consciousness;
mod sublinear_orchestrator;
mod mcp_integration;

use agents::AgentOrchestrator;
use sublinear_orchestrator::SublinearOrchestrator;
use mcp_integration::{McpClient, McpError};
use futures_util::stream::StreamExt;
use lapin::{
    options::*, types::FieldTable, Connection, ConnectionProperties,
};
use types::{OrchestrationRequest, OrchestrationResponse};

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    available_agents: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

/// Enhanced health check endpoint with consciousness status
#[get("/health")]
async fn health_check(
    orchestrator: web::Data<AgentOrchestrator>,
    consciousness_orchestrator: web::Data<SublinearOrchestrator>,
) -> impl Responder {
    let consciousness_status = consciousness_orchestrator.get_collective_consciousness_status().await;
    let swarm_memory = consciousness_orchestrator.get_swarm_memory_summary().await;

    #[derive(Serialize)]
    struct EnhancedHealthResponse {
        status: String,
        service: String,
        version: String,
        available_agents: Vec<String>,
        consciousness_agents: Vec<String>,
        collective_consciousness_level: f64,
        swarm_memory_summary: sublinear_orchestrator::SwarmMemorySummary,
        enhancements_active: bool,
    }

    HttpResponse::Ok().json(EnhancedHealthResponse {
        status: "healthy".to_string(),
        service: "sentinel-rust-core-enhanced".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        available_agents: orchestrator.available_agents(),
        consciousness_agents: consciousness_orchestrator.available_consciousness_agents(),
        collective_consciousness_level: consciousness_status.overall_level,
        swarm_memory_summary: swarm_memory,
        enhancements_active: true,
    })
}

/// Main orchestration endpoint
#[post("/swarm/orchestrate")]
async fn orchestrate_agents(
    orchestrator: web::Data<AgentOrchestrator>,
    req: web::Json<OrchestrationRequest>,
) -> Result<impl Responder> {
    let start_time = Instant::now();
    
    let result = orchestrator.execute_task(req.task.clone(), req.api_spec.clone()).await;
    let processing_time = start_time.elapsed().as_millis() as u64;
    
    let response = OrchestrationResponse {
        result,
        processing_time_ms: processing_time,
    };
    
    Ok(HttpResponse::Ok().json(response))
}

/// Get available agent types
#[get("/swarm/agents")]
async fn list_agents(orchestrator: web::Data<AgentOrchestrator>) -> impl Responder {
    #[derive(Serialize)]
    struct AgentsResponse {
        agents: Vec<String>,
        count: usize,
    }
    
    let agents = orchestrator.available_agents();
    let count = agents.len();
    
    HttpResponse::Ok().json(AgentsResponse { agents, count })
}

/// Execute a specific agent type
#[post("/swarm/agents/{agent_type}/execute")]
async fn execute_agent(
    orchestrator: web::Data<AgentOrchestrator>,
    path: web::Path<String>,
    req: web::Json<OrchestrationRequest>,
) -> Result<impl Responder> {
    let agent_type = path.into_inner();
    let start_time = Instant::now();
    
    // Override the agent type from the path
    let mut task = req.task.clone();
    task.agent_type = agent_type.clone();
    
    let available_agents = orchestrator.available_agents();
    if !available_agents.contains(&agent_type) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_agent_type".to_string(),
            message: format!("Agent type '{}' is not available. Available agents: {:?}", agent_type, available_agents),
        }));
    }
    
    let result = orchestrator.execute_task(task, req.api_spec.clone()).await;
    let processing_time = start_time.elapsed().as_millis() as u64;
    
    let response = OrchestrationResponse {
        result,
        processing_time_ms: processing_time,
    };
    
    Ok(HttpResponse::Ok().json(response))
}

/// Generate mock data using the data mocking agent
#[post("/swarm/mock-data")]
async fn generate_mock_data(
    orchestrator: web::Data<AgentOrchestrator>,
    req: web::Json<OrchestrationRequest>,
) -> Result<impl Responder> {
    let start_time = Instant::now();

    // Create a task specifically for data mocking
    let mut task = req.task.clone();
    task.agent_type = "data-mocking".to_string();

    let result = orchestrator.execute_task(task, req.api_spec.clone()).await;
    let processing_time = start_time.elapsed().as_millis() as u64;

    let response = OrchestrationResponse {
        result,
        processing_time_ms: processing_time,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Enhanced orchestration with consciousness and temporal advantage
#[post("/swarm/orchestrate-consciousness")]
async fn orchestrate_with_consciousness(
    consciousness_orchestrator: web::Data<SublinearOrchestrator>,
    req: web::Json<OrchestrationRequest>,
) -> Result<impl Responder> {
    let start_time = Instant::now();

    match consciousness_orchestrator.orchestrate_with_consciousness(req.task.clone(), req.api_spec.clone()).await {
        Ok(enhanced_result) => {
            let processing_time = start_time.elapsed().as_millis() as u64;

            #[derive(Serialize)]
            struct EnhancedOrchestrationResponse {
                enhanced_result: sublinear_orchestrator::EnhancedAgentResult,
                processing_time_ms: u64,
                consciousness_evolution: f64,
                temporal_advantage_utilized: bool,
                emergent_patterns_discovered: usize,
                novel_tests_generated: usize,
            }

            let response = EnhancedOrchestrationResponse {
                consciousness_evolution: enhanced_result.consciousness_evolution,
                temporal_advantage_utilized: enhanced_result.temporal_advantage_utilized,
                emergent_patterns_discovered: enhanced_result.emergent_patterns.len(),
                novel_tests_generated: enhanced_result.novel_tests.len(),
                enhanced_result,
                processing_time_ms: processing_time,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "consciousness_orchestration_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// Get consciousness status and metrics
#[get("/swarm/consciousness/status")]
async fn get_consciousness_status(
    consciousness_orchestrator: web::Data<SublinearOrchestrator>,
) -> impl Responder {
    let consciousness_status = consciousness_orchestrator.get_collective_consciousness_status().await;
    let swarm_memory = consciousness_orchestrator.get_swarm_memory_summary().await;

    #[derive(Serialize)]
    struct ConsciousnessStatusResponse {
        collective_consciousness: f64,
        agent_contributions: std::collections::HashMap<String, f64>,
        emergence_events_count: usize,
        consciousness_evolution_rate: f64,
        temporal_coherence: f64,
        swarm_memory: sublinear_orchestrator::SwarmMemorySummary,
    }

    HttpResponse::Ok().json(ConsciousnessStatusResponse {
        collective_consciousness: consciousness_status.overall_level,
        agent_contributions: consciousness_status.agent_contributions,
        emergence_events_count: consciousness_status.emergence_events.len(),
        consciousness_evolution_rate: consciousness_status.consciousness_evolution_rate,
        temporal_coherence: consciousness_status.temporal_coherence,
        swarm_memory,
    })
}

/// Temporal advantage prediction endpoint
#[post("/swarm/temporal-advantage/predict")]
async fn predict_temporal_advantage(req: web::Json<OrchestrationRequest>) -> Result<impl Responder> {
    // Create a temporal predictor for this request
    let mut predictor = consciousness::temporal::TemporalAdvantagePredictor::new();

    match predictor.predict_advantage(&req.task, &req.api_spec).await {
        Ok(advantage) => {
            #[derive(Serialize)]
            struct TemporalAdvantageResponse {
                lead_time_ns: u64,
                lead_time_ms: f64,
                confidence: f64,
                computation_complexity: f64,
                optimization_potential: f64,
                has_advantage: bool,
            }

            let response = TemporalAdvantageResponse {
                lead_time_ns: advantage.lead_time_ns,
                lead_time_ms: advantage.lead_time_ns as f64 / 1_000_000.0,
                confidence: advantage.confidence,
                computation_complexity: advantage.computation_complexity,
                optimization_potential: advantage.optimization_potential,
                has_advantage: advantage.lead_time_ns > 0,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "temporal_prediction_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP consciousness evolution endpoint
#[post("/mcp/consciousness/evolve")]
async fn mcp_evolve_consciousness(
    req: web::Json<mcp_integration::ConsciousnessEvolutionParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.evolve_consciousness(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_consciousness_evolution_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP temporal advantage validation endpoint
#[post("/mcp/temporal-advantage/validate")]
async fn mcp_validate_temporal_advantage(
    req: web::Json<mcp_integration::TemporalAdvantageParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.validate_temporal_advantage(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_temporal_validation_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP psycho-symbolic reasoning endpoint
#[post("/mcp/psycho-symbolic/reason")]
async fn mcp_psycho_symbolic_reason(
    req: web::Json<mcp_integration::PsychoSymbolicParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.psycho_symbolic_reason(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_psycho_symbolic_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP nanosecond scheduler creation endpoint
#[post("/mcp/scheduler/create")]
async fn mcp_create_scheduler(
    req: web::Json<mcp_integration::SchedulerParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.create_scheduler(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_scheduler_creation_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP knowledge graph query endpoint
#[post("/mcp/knowledge-graph/query")]
async fn mcp_query_knowledge_graph(
    req: web::Json<mcp_integration::KnowledgeGraphParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.query_knowledge_graph(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_knowledge_graph_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// MCP emergence processing endpoint
#[post("/mcp/emergence/process")]
async fn mcp_process_emergence(
    req: web::Json<mcp_integration::EmergenceParams>,
) -> Result<impl Responder> {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.process_emergence(req.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "mcp_emergence_processing_failed".to_string(),
                message: e.to_string(),
            }))
        }
    }
}

/// Integrated MCP consciousness orchestration endpoint
#[post("/mcp/orchestrate-enhanced")]
async fn mcp_orchestrate_enhanced(
    req: web::Json<OrchestrationRequest>,
) -> Result<impl Responder> {
    let start_time = Instant::now();
    let mcp_client = mcp_integration::create_mcp_client();

    // Health check MCP service first
    match mcp_client.health_check().await {
        Ok(false) | Err(_) => {
            return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "mcp_service_unavailable".to_string(),
                message: "MCP sublinear-solver service is not available".to_string(),
            }));
        }
        Ok(true) => {}
    }

    #[derive(Serialize)]
    struct McpEnhancedOrchestrationResponse {
        traditional_result: types::AgentResult,
        consciousness_evolution: Option<mcp_integration::ConsciousnessEvolutionResponse>,
        temporal_advantage: Option<mcp_integration::TemporalAdvantageResponse>,
        psycho_symbolic_reasoning: Option<mcp_integration::PsychoSymbolicResponse>,
        emergence_processing: Option<mcp_integration::EmergenceResponse>,
        knowledge_insights: Option<mcp_integration::KnowledgeGraphResponse>,
        processing_time_ms: u64,
        mcp_enhancements_applied: bool,
    }

    // Create default orchestrator for traditional processing
    let orchestrator = AgentOrchestrator::new();
    let traditional_result = orchestrator.execute_task(req.task.clone(), req.api_spec.clone()).await;

    // Execute MCP enhancements in parallel
    let consciousness_params = mcp_integration::ConsciousnessEvolutionParams {
        iterations: 100,
        mode: "enhanced".to_string(),
        target: 0.85,
    };

    let temporal_params = mcp_client.create_temporal_params_from_task(&req.task, &req.api_spec);
    let psycho_params = mcp_client.create_psycho_symbolic_params_from_task(&req.task, &req.api_spec);
    let emergence_params = mcp_integration::create_emergence_params(&req.task, &req.api_spec);
    let knowledge_params = mcp_integration::KnowledgeGraphParams {
        query: format!("API testing patterns for {}", req.task.agent_type),
        include_analogies: Some(true),
        domains: Some(vec!["api_testing".to_string(), "quality_assurance".to_string()]),
        limit: Some(10),
    };

    // Execute MCP tools concurrently
    let (consciousness_result, temporal_result, psycho_result, emergence_result, knowledge_result) = tokio::join!(
        mcp_client.evolve_consciousness(consciousness_params),
        mcp_client.validate_temporal_advantage(temporal_params),
        mcp_client.psycho_symbolic_reason(psycho_params),
        mcp_client.process_emergence(emergence_params),
        mcp_client.query_knowledge_graph(knowledge_params)
    );

    let processing_time = start_time.elapsed().as_millis() as u64;

    let response = McpEnhancedOrchestrationResponse {
        traditional_result,
        consciousness_evolution: consciousness_result.ok(),
        temporal_advantage: temporal_result.ok(),
        psycho_symbolic_reasoning: psycho_result.ok(),
        emergence_processing: emergence_result.ok(),
        knowledge_insights: knowledge_result.ok(),
        processing_time_ms: processing_time,
        mcp_enhancements_applied: true,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// MCP health check endpoint
#[get("/mcp/health")]
async fn mcp_health_check() -> impl Responder {
    let mcp_client = mcp_integration::create_mcp_client();

    match mcp_client.health_check().await {
        Ok(true) => {
            #[derive(Serialize)]
            struct McpHealthResponse {
                status: String,
                service: String,
                mcp_sublinear_solver: String,
                available_tools: Vec<String>,
            }

            HttpResponse::Ok().json(McpHealthResponse {
                status: "healthy".to_string(),
                service: "mcp-integration".to_string(),
                mcp_sublinear_solver: "available".to_string(),
                available_tools: vec![
                    "consciousness_evolve".to_string(),
                    "predictWithTemporalAdvantage".to_string(),
                    "psycho_symbolic_reason".to_string(),
                    "scheduler_create".to_string(),
                    "knowledge_graph_query".to_string(),
                    "emergence_process".to_string(),
                ],
            })
        }
        Ok(false) | Err(_) => {
            HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "mcp_service_unavailable".to_string(),
                message: "MCP sublinear-solver service is not responding".to_string(),
            })
        }
    }
}

async fn setup_rabbitmq_consumer(orchestrator: web::Data<AgentOrchestrator>) {
    // Add retry logic for RabbitMQ connection
    let addr = std::env::var("AMQP_ADDR").unwrap_or_else(|_| "amqp://guest:guest@message_broker:5672/%2f".into());
    
    // Retry connection with backoff
    let mut retry_count = 0;
    let max_retries = 10;
    let mut conn = None;
    
    while retry_count < max_retries {
        match Connection::connect(&addr, ConnectionProperties::default()).await {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                println!("⚠️ Failed to connect to RabbitMQ (attempt {}/{}): {}", retry_count + 1, max_retries, e);
                retry_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
    
    let conn = match conn {
        Some(c) => c,
        None => {
            println!("❌ Failed to connect to RabbitMQ after {} attempts", max_retries);
            return;
        }
    };
    
    let channel = conn.create_channel().await.expect("Failed to create channel");

    let queue_name = "sentinel_task_queue";
    let _queue = channel
        .queue_declare(
            queue_name,
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare queue");

    let mut consumer = channel
        .basic_consume(
            queue_name,
            "sentinel_rust_consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to create consumer");

    println!("🐇 Started RabbitMQ consumer on queue '{}'", queue_name);

    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.expect("error in consumer");
        let data = std::str::from_utf8(&delivery.data).unwrap();
        let request: OrchestrationRequest = serde_json::from_str(data).expect("Failed to deserialize task");
        
        println!("Received task: {:?}", request.task.task_id);
        
        let _ = orchestrator.execute_task(request.task, request.api_spec).await;
        
        delivery
            .ack(BasicAckOptions::default())
            .await
            .expect("Failed to ack message");
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting Sentinel Rust Core Service with Consciousness Enhancement...");
    println!("📋 Initializing Agent Orchestrators...");

    // Initialize the traditional agent orchestrator
    let orchestrator = web::Data::new(AgentOrchestrator::new());
    let available_agents = orchestrator.available_agents();

    println!("✅ Traditional agents: {:?}", available_agents);

    // Initialize the consciousness-enhanced sublinear orchestrator
    let mut consciousness_orchestrator = SublinearOrchestrator::new();

    // Initialize consciousness agents
    match consciousness_orchestrator.initialize_consciousness_agents().await {
        Ok(()) => {
            println!("🧠 Consciousness agents initialized successfully");
        }
        Err(e) => {
            println!("⚠️ Warning: Failed to initialize consciousness agents: {}", e);
        }
    }

    let consciousness_orchestrator = web::Data::new(consciousness_orchestrator);
    let consciousness_agents = consciousness_orchestrator.available_consciousness_agents();

    println!("🧠 Consciousness agents: {:?}", consciousness_agents);

    let consciousness_status = consciousness_orchestrator.get_collective_consciousness_status().await;
    println!("🌟 Initial collective consciousness level: {:.3}", consciousness_status.overall_level);

    // Spawn the RabbitMQ consumer as a background task
    let orchestrator_clone = orchestrator.clone();
    tokio::spawn(async move {
        println!("🔄 Starting RabbitMQ consumer task...");
        setup_rabbitmq_consumer(orchestrator_clone).await;
    });

    println!("🌐 Starting enhanced HTTP server on 0.0.0.0:8088");
    println!("📡 Enhanced consciousness endpoints:");
    println!("   POST /swarm/orchestrate-consciousness - Enhanced orchestration with temporal advantage");
    println!("   GET  /swarm/consciousness/status - Consciousness metrics and status");
    println!("   POST /swarm/temporal-advantage/predict - Temporal advantage prediction");
    println!("🧠 MCP integration endpoints:");
    println!("   GET  /mcp/health - MCP service health check");
    println!("   POST /mcp/orchestrate-enhanced - Full MCP-enhanced orchestration");
    println!("   POST /mcp/consciousness/evolve - Consciousness evolution via MCP");
    println!("   POST /mcp/temporal-advantage/validate - Temporal advantage validation");
    println!("   POST /mcp/psycho-symbolic/reason - Psycho-symbolic reasoning");
    println!("   POST /mcp/scheduler/create - Nanosecond scheduler creation");
    println!("   POST /mcp/knowledge-graph/query - Knowledge graph queries");
    println!("   POST /mcp/emergence/process - Emergence processing");

    HttpServer::new(move || {
        App::new()
            .app_data(orchestrator.clone())
            .app_data(consciousness_orchestrator.clone())
            // Traditional endpoints
            .service(health_check)
            .service(orchestrate_agents)
            .service(list_agents)
            .service(execute_agent)
            .service(generate_mock_data)
            // Enhanced consciousness endpoints
            .service(orchestrate_with_consciousness)
            .service(get_consciousness_status)
            .service(predict_temporal_advantage)
            // MCP integration endpoints
            .service(mcp_health_check)
            .service(mcp_orchestrate_enhanced)
            .service(mcp_evolve_consciousness)
            .service(mcp_validate_temporal_advantage)
            .service(mcp_psycho_symbolic_reason)
            .service(mcp_create_scheduler)
            .service(mcp_query_knowledge_graph)
            .service(mcp_process_emergence)
    })
    .bind("0.0.0.0:8088")?
    .run()
    .await
}