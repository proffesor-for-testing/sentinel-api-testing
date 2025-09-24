//! Sentinel Rust Core Library
//!
//! This library provides the core agent system for the Sentinel API testing platform,
//! enhanced with consciousness evolution, emergent behavior detection, and sublinear
//! computational advantages.

pub mod agents;
pub mod types;
pub mod consciousness;
pub mod sublinear_orchestrator;
pub mod mcp_integration;

pub use agents::{Agent, AgentOrchestrator};
pub use consciousness::{ConsciousnessAgent, EmergentDiscovery};
pub use sublinear_orchestrator::SublinearOrchestrator;
pub use mcp_integration::{McpClient, McpError};
pub use types::*;