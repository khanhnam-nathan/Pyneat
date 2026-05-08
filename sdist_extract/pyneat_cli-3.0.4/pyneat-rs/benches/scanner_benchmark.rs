//! Scanner Benchmark
//!
//! Benchmarks for the PyNeat Rust scanner components.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

use pyneat_rs::{RustScanner, JavaScriptScanner, GoScanner, LanguageScanner};

const SMALL_CODE: &str = r#"
def process():
    x = 1
    return x
"#;

const MEDIUM_CODE: &str = r#"
import os
import sys
import json

def initialize_app():
    config_path = "/etc/myapp/config.json"
    return config_path

def process_request(user_input):
    if user_input is not None:
        print(f"Processing: {user_input}")
    return True

def validate_data(data):
    if data is not None:
        return True
    return False

def calculate(x, y):
    if x is 200:
        return x + y
    return x - y
"#;

const LARGE_CODE: &str = r#"
import os
import sys
import json
import yaml
import pickle
import hashlib

class DataProcessor:
    def __init__(self, config_path):
        self.config_path = config_path
        self.results = []

    def load_config(self):
        with open(self.config_path, "r") as f:
            return json.load(f)

    def process(self, data):
        for item in data:
            if item.get("active"):
                self.results.append(item)

    def save_results(self, path):
        with open(path, "w") as f:
            json.dump(self.results, f)

def execute_command(cmd):
    os.system(cmd)
    return "Done"

def hash_password(password):
    return hashlib.md5(password.encode())

class UserManager:
    def __init__(self):
        self.users = []

    def add_user(self, name, email):
        user = {"name": name, "email": email}
        self.users.append(user)
        return user

    def find_user(self, email):
        for user in self.users:
            if user["email"] == email:
                return user
        return None
"#;

fn bench_rust_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("rust_scanner");

    group.bench_function("parse_small", |b| {
        let scanner = RustScanner::new();
        b.iter(|| {
            let _ = scanner.parse(black_box(SMALL_CODE));
        });
    });

    group.bench_function("parse_medium", |b| {
        let scanner = RustScanner::new();
        b.iter(|| {
            let _ = scanner.parse(black_box(MEDIUM_CODE));
        });
    });

    group.bench_function("parse_large", |b| {
        let scanner = RustScanner::new();
        b.iter(|| {
            let _ = scanner.parse(black_box(LARGE_CODE));
        });
    });

    group.finish();
}

fn bench_javascript_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("javascript_scanner");

    let js_code = r#"
const utils = require('utils');

function processData(data) {
    if (data != null) {
        console.log("Processing");
    }
    return data;
}

function calculate(x, y) {
    if (x === 200) {
        return x + y;
    }
    return x - y;
}
"#;

    group.bench_function("parse_js", |b| {
        let scanner = JavaScriptScanner;
        b.iter(|| {
            let _ = scanner.parse(black_box(js_code));
        });
    });

    group.finish();
}

fn bench_go_scanner(c: &mut Criterion) {
    let mut group = c.benchmark_group("go_scanner");

    let go_code = r#"
package main

import "fmt"

func process(data string) string {
    if data != "" {
        fmt.Println(data)
    }
    return data
}
"#;

    group.bench_function("parse_go", |b| {
        let scanner = GoScanner;
        b.iter(|| {
            let _ = scanner.parse(black_box(go_code));
        });
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(criterion::Throughput::Bytes(MEDIUM_CODE.len() as u64));

    let scanner = RustScanner::new();

    group.bench_function("mb_per_second", |b| {
        b.iter(|| {
            let _ = scanner.parse(black_box(MEDIUM_CODE));
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
        bench_rust_scanner,
        bench_javascript_scanner,
        bench_go_scanner,
        bench_throughput,
}
criterion_main!(benches);
