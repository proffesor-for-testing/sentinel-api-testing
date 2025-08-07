use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::Serialize;
use std::time::Instant;

mod agents;
mod types;

use agents::AgentOrchestrator;
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
    println!("🚀 Starting Sentinel Rust Core Service...");
    println!("📋 Initializing Agent Orchestrator...");
    
    // Initialize the agent orchestrator
    let orchestrator = web::Data::new(AgentOrchestrator::new());
    let available_agents = orchestrator.available_agents();
    
    println!("✅ Available agents: {:?}", available_agents);

    // Spawn the RabbitMQ consumer as a background task
    let orchestrator_clone = orchestrator.clone();
    tokio::spawn(async move {
        println!("🔄 Starting RabbitMQ consumer task...");
        setup_rabbitmq_consumer(orchestrator_clone).await;
    });

    println!("🌐 Starting HTTP server on 0.0.0.0:8088");

    HttpServer::new(move || {
        App::new()
            .app_data(orchestrator.clone())
            .service(health_check)
            .service(orchestrate_agents)
            .service(list_agents)
            .service(execute_agent)
            .service(generate_mock_data)
    })
    .bind("0.0.0.0:8088")?
    .run()
    .await
}