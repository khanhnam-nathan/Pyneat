//! Test utilities for benchmarks

use std::path::PathBuf;

/// Sample code snippets for benchmarking
pub const SAMPLE_PYTHON_CODE: &str = r#"
import utils

def process_data(data):
    param1 = data.get("key")
    if param1 != None:
        return param1
    return None
"#;

/// Create a temporary file for testing
#[allow(dead_code)]
pub fn create_temp_file(content: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, content.as_bytes()).unwrap();
    file
}

/// Get the test samples directory
#[allow(dead_code)]
pub fn get_samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_samples")
}
