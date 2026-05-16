// Sample Rust file with common AI-generated code issues.

use std::env;
use std::process::Command; // unused import
use std::fs;

// Phantom imports
use fake_package::helper;
use utils::utils;

const API_KEY: &str = "sk-live-abcdefghijklmnop"; // hardcoded secret
const PASSWORD: &str = "admin123";

fn fetch_user_data(user_id: &str) -> String {
    // SQL injection pattern (in real SQL would be vulnerable)
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    query
}

fn execute_command(cmd: &str) {
    // Command injection
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("Failed");
    println!("{}", output.stdout);
}

fn process_file(filename: &str) -> String {
    // Missing error handling, resource leak potential
    let data = fs::read_to_string(filename);
    return data; // no error check
}

fn authenticate(username: &str, password: &str) -> bool {
    if password == "admin" { // constant comparison ok
        return true;
    }
    return false;
}

fn check_status(code: i32) -> &'static str {
    if code == 200 { // identity comparison
        return "OK";
    }
    return "Unknown";
}

fn weak_hash(input: &str) -> String {
    // MD5 for security purposes
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn generate_token() -> String {
    // Weak random for security token
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", timestamp)
}

fn bad_function(param1: &str, param2: &str, param3: Option<String>) -> bool { // fake parameters
    if param1 != "" {
        return true;
    }
    return false;
}

fn debug_function() -> i32 {
    println!("DEBUG: starting");
    println!("DEBUG: done");
    return result; // undefined
}

fn get_first_item(items: &[String]) -> &str {
    &items[0] // no bounds check
}

fn split_and_get(s: &str) -> &str {
    let parts: Vec<&str> = s.split(',').collect();
    parts[0] // no validation
}

fn bad_error_handling() {
    let result = "value".parse::<i32>();
    match result {
        Ok(_) => println!("ok"),
        Err(_) => {}, // empty error handling
    }
}

fn duplicate_api_call() {
    fetch_user_data("1");
    fetch_user_data("1"); // same call
    fetch_user_data("1"); // same call
}

fn unwrap_usage() {
    // .unwrap() without error handling
    let s = "42";
    let num: i32 = s.parse().unwrap();
    println!("{}", num);
}

fn expect_usage() -> String {
    let s: Option<String> = Some("value".to_string());
    s.expect("This will panic if None")
}

fn unsafe_code() {
    // Unnecessary unsafe block
    unsafe {
        let x = 1;
        println!("{}", x);
    }
}

// camelCase struct name
struct user_controller {
    user_name: String,
    api_token: String,
    debug_mode: bool,
}

impl user_controller {
    fn new() -> Self {
        user_controller {
            user_name: String::from("test"),
            api_token: String::from("secret"),
            debug_mode: true,
        }
    }

    fn get_user_data(&self, user_id: &str) {
        println!("DEBUG: fetching user {}", user_id);
    }
}

fn main() {
    println!("DEBUG: starting application");
}
