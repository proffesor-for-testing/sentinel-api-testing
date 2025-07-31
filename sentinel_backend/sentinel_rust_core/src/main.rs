use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
}

#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        service: "sentinel-rust-core".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Starting Sentinel Rust Core Service...");

    HttpServer::new(|| {
        App::new()
            .service(health_check)
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}