//! PyNEAT Language Server Protocol (LSP) Server
//!
//! Provides real-time security scanning as a Language Server for IDE integration.
//!
//! Usage:
//!     pyneat lsp --stdio
//!
//! This is a minimal stdio-based LSP server that speaks JSON-RPC over stdin/stdout.
#![allow(non_snake_case)]
//! No external LSP crates required — only serde_json for JSON parsing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

// --------------------------------------------------------------------------
// JSON-RPC types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    fn err(id: Value, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    fn new(method: &str, params: Value) -> Self {
        Self { jsonrpc: "2.0".into(), method: method.into(), params: Some(params) }
    }
}

// --------------------------------------------------------------------------
// LSP types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
    #[serde(skip_serializing_if = "Option::is_none", rename = "serverInfo")]
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    #[serde(rename = "textDocumentSync", skip_serializing_if = "Option::is_none")]
    pub text_document_sync: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TextDocumentItem {
    pub uri: String,
    #[serde(rename = "languageId")]
    pub language_id: String,
    pub version: i32,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidOpenParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentItem,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidChangeParams {
    #[serde(rename = "textDocument")]
    pub text_document: TextDocumentItem,
    #[serde(rename = "contentChanges")]
    pub content_changes: Vec<TextDocumentChange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TextDocumentChange {
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub range: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishDiagnosticsParams {
    pub uri: String,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

// --------------------------------------------------------------------------
// Server configuration
// --------------------------------------------------------------------------

/// LSP server configuration options.
#[derive(Debug, Clone, Default)]
pub struct LspConfig {
    /// Minimum severity: "critical", "high", "medium", "low", "info"
    pub severity_threshold: String,
    /// Scan on file save
    pub scan_on_save: bool,
    /// Debounce delay in ms for real-time scans
    pub debounce_ms: u64,
    /// Enable real-time scanning on keystroke
    pub enable_real_time: bool,
    /// Restrict to specific rule IDs. Empty = all rules.
    pub enabled_rules: Vec<String>,
}

impl LspConfig {
    fn min_severity(&self) -> i32 {
        // LSP DiagnosticSeverity: 1=Error, 2=Warning, 3=Info, 4=Hint
        match self.severity_threshold.as_str() {
            "critical" => 1,
            "high" => 2,
            "medium" => 3,
            "low" => 4,
            _ => 3,
        }
    }
}

// --------------------------------------------------------------------------
// Document state
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Document {
    uri: String,
    content: String,
    version: i32,
}

// --------------------------------------------------------------------------
// LSP Server
// --------------------------------------------------------------------------

pub struct PyneatLspServer {
    documents: Arc<Mutex<HashMap<String, Document>>>,
    config: LspConfig,
}

impl PyneatLspServer {
    pub fn new(config: LspConfig) -> Self {
        tracing_subscriber::fmt()
            .with_env_filter("pyneat=warn")
            .init();
        tracing::info!("PyNEAT LSP server starting on stdio...");

        Self {
            documents: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Run the main event loop. Reads JSON-RPC from stdin, writes to stdout.
    pub fn run(&self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut lines = stdin.lock().lines();

        while let Some(Ok(line)) = lines.next() {
            if line.trim().is_empty() {
                continue;
            }

            let req: Result<JsonRpcRequest, _> = serde_json::from_str(&line);

            if let Ok(req) = req {
                // Handle Content-Length header if present
                if req.method.is_empty() {
                    continue;
                }

                let response = self.handle_request(req);

                if let Some(response) = response {
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = stdout.write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes());
                        let _ = stdout.write_all(json.as_bytes());
                        let _ = stdout.write_all(b"\r\n");
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }

    fn handle_request(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        match req.method.as_str() {
            "initialize" => {
                tracing::info!("PyNEAT LSP: initialize request");
                let result = InitializeResult {
                    capabilities: ServerCapabilities {
                        text_document_sync: Some(1), // Full sync
                        diagnostics: Some(serde_json::json!({
                            "interFileDependencies": false,
                            "workspaceDiagnostics": false
                        })),
                    },
                    server_info: Some(ServerInfo {
                        name: "pyneat-lsp".into(),
                        version: Some(env!("CARGO_PKG_VERSION").into()),
                    }),
                };
                Some(JsonRpcResponse::ok(req.id, serde_json::to_value(result).unwrap()))
            }
            "shutdown" => {
                Some(JsonRpcResponse::ok(req.id, Value::Null))
            }
            "exit" => {
                tracing::info!("PyNEAT LSP server exiting");
                std::process::exit(0);
            }
            _ => None,
        }
    }

    fn handle_notification(&mut self, method: &str, params: Value) {
        match method {
            "textDocument/didOpen" => {
                if let Ok(p) = serde_json::from_value::<DidOpenParams>(params) {
                    self.on_document_open(p);
                }
            }
            "textDocument/didChange" => {
                if let Ok(p) = serde_json::from_value::<DidChangeParams>(params) {
                    self.on_document_change(p);
                }
            }
            "textDocument/didSave" => {
                if self.config.scan_on_save {
                    // Would need document URI from params
                }
            }
            _ => {}
        }
    }

    fn on_document_open(&mut self, params: DidOpenParams) {
        tracing::info!("PyNEAT LSP: opening document {}", params.text_document.uri);

        {
            let mut docs = self.documents.lock().unwrap();
            docs.insert(params.text_document.uri.clone(), Document {
                uri: params.text_document.uri.clone(),
                content: params.text_document.text,
                version: params.text_document.version,
            });
        }

        self.scan_and_publish_diagnostics(&params.text_document.uri);
    }

    fn on_document_change(&mut self, params: DidChangeParams) {
        let content = params.content_changes.into_iter()
            .map(|c| c.text)
            .collect::<String>();

        {
            let mut docs = self.documents.lock().unwrap();
            if let Some(doc) = docs.get_mut(&params.text_document.uri) {
                doc.content = content;
                doc.version = params.text_document.version;
            }
        }

        if self.config.enable_real_time {
            self.scan_and_publish_diagnostics(&params.text_document.uri);
        }
    }

    fn scan_and_publish_diagnostics(&self, uri: &str) {
        let (content, version) = {
            let docs = self.documents.lock().unwrap();
            match docs.get(uri) {
                Some(d) => (d.content.clone(), d.version),
                None => return,
            }
        };

        let findings = self.run_security_scan(&content);
        let min_sev = self.config.min_severity();

        let diagnostics: Vec<Diagnostic> = findings
            .into_iter()
            .map(|f| {
                let start_pos = position_from_offset(&content, f.start);
                let end_pos = position_from_offset(&content, f.end.min(content.len()));
                Diagnostic {
                    range: Range { start: start_pos, end: end_pos },
                    severity: Some(min_sev),
                    code: Some(serde_json::json!(&f.rule_id)),
                    source: Some("PyNEAT".into()),
                    message: f.problem,
                }
            })
            .collect();

        let params = PublishDiagnosticsParams {
            uri: uri.into(),
            diagnostics,
            version: Some(version),
        };

        let notif = JsonRpcNotification::new("textDocument/publishDiagnostics", serde_json::to_value(params).unwrap());

        if let Ok(json) = serde_json::to_string(&notif) {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes());
            let _ = handle.write_all(json.as_bytes());
            let _ = handle.write_all(b"\r\n");
            let _ = handle.flush();
        }
    }

    fn run_security_scan(&self, code: &str) -> Vec<crate::rules::base::Finding> {
        use crate::rules::security;
        use crate::scanner::tree_sitter;

        let tree = match tree_sitter::parse(code) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let rules: Vec<Box<dyn crate::rules::base::Rule + Send + Sync>> = vec![
            Box::new(security::CommandInjectionRule),
            Box::new(security::SqlInjectionRule),
        ];

        let mut all = Vec::new();
        for rule in rules {
            let findings = rule.detect(&tree, code);
            all.extend(findings);
        }
        all
    }
}

// --------------------------------------------------------------------------
// Utilities
// --------------------------------------------------------------------------

fn position_from_offset(content: &str, byte_offset: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    let mut pos = 0usize;

    for (i, c) in content.char_indices() {
        if pos >= byte_offset {
            break;
        }
        if c == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
        pos = i + c.len_utf8();
    }

    Position { line, character: col }
}

// --------------------------------------------------------------------------
// Public entry point
// --------------------------------------------------------------------------

/// Run the PyNEAT LSP server. Call this when `--lsp` flag is passed.
pub fn run_server() {
    let config = LspConfig::default();
    let server = PyneatLspServer::new(config);
    server.run();
}
