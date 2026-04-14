//! Rule Benchmark
//!
//! Benchmarks for PyNeat security rules using the AiSecurityScanner.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

use pyneat_rs::ai_security::AiSecurityScanner;

const CODE_WITH_SECURITY_ISSUES: &str = r#"
import pickle
import os
import hashlib

def load_user_data(user_input):
    data = pickle.loads(user_input)
    return data

def execute_command(cmd):
    os.system(cmd)
    return "Done"

def hash_password(password):
    return hashlib.md5(password.encode())
"#;

const CODE_WITH_QUALITY_ISSUES: &str = r#"
import utils
import helpers

def process_data(data):
    param1 = data.get("key")
    if param1 != None:
        return param1
    return None

def calculate(x, y):
    if x is 200:
        return x + y
    return x - y
"#;

const CLEAN_CODE: &str = r#"
import os
import sys

def main():
    print("Hello World")
    return 0
"#;

fn bench_ai_security_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("ai_security");

    group.bench_function("scan_python", |b| {
        let scanner = AiSecurityScanner::new();
        b.iter(|| {
            let _ = scanner.scan(black_box(CODE_WITH_SECURITY_ISSUES), black_box("python"));
        });
    });

    group.finish();
}

fn bench_ai_security_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("ai_security_rules");

    let scanner = AiSecurityScanner::new();

    group.bench_function("detect_pickle", |b| {
        b.iter(|| {
            let findings = scanner.scan(black_box(CODE_WITH_SECURITY_ISSUES), "python");
            black_box(findings.len());
        });
    });

    group.finish();
}

fn bench_false_positive_rate(c: &mut Criterion) {
    let mut group = c.benchmark_group("false_positive");

    let scanner = AiSecurityScanner::new();

    group.bench_function("clean_code", |b| {
        b.iter(|| {
            let findings = scanner.scan(black_box(CLEAN_CODE), black_box("python"));
            black_box(findings.len());
        });
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    let scanner = AiSecurityScanner::new();

    group.bench_function("files_per_second", |b| {
        b.iter(|| {
            let _ = scanner.scan(black_box(CODE_WITH_QUALITY_ISSUES), black_box("python"));
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
        .sample_size(50);
    targets =
        bench_ai_security_scanner,
        bench_ai_security_rules,
        bench_false_positive_rate,
        bench_throughput,
}
criterion_main!(benches);
