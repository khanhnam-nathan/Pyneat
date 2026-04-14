use md5::{Md5, Digest};
use sha1::Sha1;
use std::fs;
use std::path::Path;
use std::process::Command;

// ==================== RUST-SEC-001: unsafe Code (HIGH) ====================

fn unsafe_memory() {
    unsafe {
        let ptr: *const u32 = std::ptr::null();
        // Line: unsafe block - bypasses memory safety
        let _val = *ptr;
    }
}

unsafe fn unsafe_function(x: *const u32) -> u32 {
    // Line: unsafe fn - verify safety invariants
    *x
}

// ==================== RUST-SEC-002: Path Traversal (HIGH) ====================

fn read_user_file(user_path: &str) -> std::io::Result<String> {
    let content = fs::read_to_string("/static/".to_string() + user_path)?;
    // Line: fs::read_to_string path traversal
    Ok(content)
}

fn open_file(name: &str) {
    let path = Path::new("/data/").join(name);
    // Line: Path::new path traversal
    let _ = fs::read_to_string(&path);
}

// ==================== RUST-SEC-003: Weak Crypto (MEDIUM) ====================

fn hash_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
    // Line: md5 crate usage
}

fn weak_random() -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
    // Line: rand::random not crypto secure
}

// ==================== RUST-SEC-004: Information Disclosure (LOW) ====================

fn log_sensitive(password: &str) {
    println!("User password: {}", password);
    // Line: println with sensitive keyword
    eprintln!("SECRET: {}", std::env::var("SECRET").unwrap());
}

fn debug_log(token: &str) {
    dbg!("Auth token: {}", token);
    // Line: dbg! with sensitive data
}

// ==================== RUST-SEC-005: Hardcoded Secrets (HIGH) ====================

const API_KEY: &str = "sk-live-abc123xyz456secret789key12345"; // Line: hardcoded API key
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";                  // Line: hardcoded AWS key
const GITHUB_TOKEN: &str = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // Line: hardcoded GitHub token
let jwt_secret = "super_secret_jwt_key_do_not_use_in_prod";    // Line: hardcoded secret
let db_password = "MySecretPass123!";                           // Line: hardcoded password

// ==================== RUST-SEC-006: Command Injection (CRITICAL) ====================

fn run_cmd(user_arg: &str) {
    let output = Command::new("ls")
        .arg("-la")
        .arg(user_arg)
        .output();
    // Safe: args separated

    let bad = Command::new("sh")
        .arg("-c")
        .arg("ls ".to_string() + user_arg)
        .output();
    // Line: Command::new command injection
}

// ==================== RUST-SEC-007: Insecure TLS (HIGH) ====================

fn bad_https() {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
    // Line: dangerously_accept_invalid_certs bypasses TLS
}

// ==================== Clean code (no issues) ====================

fn safe_hash(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
    // SHA-256 - safe
}

fn safe_file(base: &str, name: &str) {
    let path = Path::new(base).join(name);
    let canonical = std::fs::canonicalize(&path).ok();
    // Safe: canonicalize validates path
}
