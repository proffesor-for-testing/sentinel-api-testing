use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::Serialize;
use std::time::Instant;

mod agents;
mod types;

use agents::AgentOrchestrator;
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

/// Health check endpoint
#[get("/health")]
async fn health_check(orchestrator: web::Data<AgentOrchestrator>) -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        service: "sentinel-rust-core".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        available_agents: orchestrator.available_agents(),
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting Sentinel Rust Core Service...");
    println!("📋 Initializing Agent Orchestrator...");
    
    // Initialize the agent orchestrator
    let orchestrator = web::Data::new(AgentOrchestrator::new());
    let available_agents = orchestrator.available_agents();
    
    println!("✅ Available agents: {:?}", available_agents);
    println!("🌐 Starting HTTP server on 127.0.0.1:8088");

    HttpServer::new(move || {
        App::new()
            .app_data(orchestrator.clone())
            .service(health_check)
            .service(orchestrate_agents)
            .service(list_agents)
            .service(execute_agent)
            .service(generate_mock_data)
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}