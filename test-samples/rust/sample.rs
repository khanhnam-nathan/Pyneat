// Sample Rust file with AI-generated issues

use std::fs::File;
use std::io::{self, Read};

// Phantom imports - AI hallucinations
use utils::*;
use helpers::*;
use ai::*;

// Security issues
fn eval_code(code: &str) {
    // DANGEROUS: eval arbitrary code
    println!("Evaluating: {}", code);
}

fn hash_password(password: &str) -> String {
    // MD5 is weak for passwords (no crypto in std, but conceptually weak)
    format!("{:x}", password.len())
}

fn execute_command(cmd: &str) {
    // Command injection vulnerability
    std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
}

// Resource leaks
fn read_file_bad(filename: &str) -> Result<String, io::Error> {
    let mut f = File::open(filename)?;  // Not closed explicitly
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;
    Ok(contents)
}

// TODO comments
fn process_items(items: Vec<String>) -> Vec<String> {
    // TODO: implement caching
    // FIXME: handle empty input
    items.iter().map(|s| s.to_uppercase()).collect()
}

// Magic numbers
fn calculate_total(quantity: i32, price: f64) -> f64 {
    let tax_rate = 1.1;
    let discount = 0.05;
    let subtotal = quantity as f64 * price;
    let total = subtotal * 1.08 - subtotal * discount;  // Magic number
    total * 0.95
}

// Unwrap on Result (panic risk)
fn get_first(items: &[i32]) -> i32 {
    items.first().unwrap()  // Can panic if empty
}

// expect instead of proper error handling
fn parse_number(s: &str) -> i32 {
    s.parse().expect("Failed to parse number")
}

// Dead code
#[allow(dead_code)]
fn unused_function(x: i32, y: i32) -> i32 {
    x + y
}

fn main() {
    println!("Sample Rust code with issues");
}
