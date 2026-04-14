//! Rust library demo
//!
//! Demo file for multi-language scanning

// Hardcoded secrets - should trigger UNI-001
const API_KEY: &str = "sk-live-abc123xyz789";  // TODO: env var
const DB_PASSWORD: &str = "postgres123";  // FIXME: rotate
const SECRET_TOKEN: &str = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

use std::collections::HashMap;

// Debug prints - should trigger UNI-002
fn init_service() {
    println!("Initializing service...");
    println!("API_KEY: {}", API_KEY);
    eprintln!("Error: failed to connect");
}

// Deep nesting - should trigger UNI-005
fn validate_config(config: &HashMap<String, String>) -> bool {
    if !config.is_empty() {
        if config.contains_key("host") {
            if config.contains_key("port") {
                if config.get("host") != Some(&"localhost".to_string()) {
                    if config.get("port") != Some(&"8080".to_string()) {
                        println!("Config valid");
                        return true;
                    }
                }
            }
        }
    }
    false
}

// Method with deep nesting
impl Service {
    pub fn process(&self, input: &str) -> Result<String, &'static str> {
        if !input.is_empty() {
            if input.len() > 0 {
                if input != "" {
                    if !input.is_empty() {
                        println!("Processing: {}", input);
                        return Ok(input.to_uppercase());
                    }
                }
            }
        }
        Err("invalid input")
    }
}

struct Service {
    name: String,
}

fn main() {
    println!("Rust demo running...");
    println!("API_KEY: {}", API_KEY);
}
