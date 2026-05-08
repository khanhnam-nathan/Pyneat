//! AST-aware AI Security Rules
//!
//! This module provides AST-aware implementations of AI security rules.
//! Instead of scanning raw code strings line-by-line, these rules use the
//! language-neutral AST (LnAst) to make precise, context-aware detections.
//!
//! Benefits:
//! - Reuses LnAst already parsed by the scanner (no redundant parsing)
//! - Knows function boundaries (only flag AI calls INSIDE the right function)
//! - Knows call context (llm.generate() inside a sensitive function = higher risk)
//! - Reduces false positives from comments, strings, or dead code
//! - Integrates with taint labels for cross-rule analysis

use crate::scanner::ln_ast::LnAst;
use crate::scanner::taint::labels::TaintLabel;

// --------------------------------------------------------------------------
// AST-aware findings
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AstAiFinding {
    pub rule_id: String,
    pub severity: String,
    pub vulnerability_type: String,
    pub problem: String,
    pub line: usize,
    pub end_line: usize,
    pub column: usize,
    pub snippet: String,
    pub fix_hint: String,
    pub confidence: f32,
    /// The LnAst function this finding belongs to (if any)
    pub in_function: Option<String>,
    /// Taint labels this finding introduces
    pub introduces_taint: Vec<TaintLabel>,
}

impl AstAiFinding {
    pub fn new(
        rule_id: &str,
        severity: &str,
        vuln_type: &str,
        problem: &str,
        line: usize,
        snippet: &str,
        fix_hint: &str,
        confidence: f32,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            vulnerability_type: vuln_type.to_string(),
            problem: problem.to_string(),
            line,
            end_line: line,
            column: 0,
            snippet: snippet.to_string(),
            fix_hint: fix_hint.to_string(),
            confidence,
            in_function: None,
            introduces_taint: Vec::new(),
        }
    }

    pub fn with_function(mut self, func_name: String) -> Self {
        self.in_function = Some(func_name);
        self
    }

    pub fn with_taint(mut self, label: TaintLabel) -> Self {
        self.introduces_taint.push(label);
        self
    }
}

// --------------------------------------------------------------------------
// AST-aware rule trait
// --------------------------------------------------------------------------

pub trait AstAwareAiSecurityRule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> &str;
    fn confidence(&self) -> f32;
    fn detect_ast(&self, ast: &LnAst, code: &str) -> Vec<AstAiFinding>;
}

// --------------------------------------------------------------------------
// Helper utilities
// --------------------------------------------------------------------------

#[allow(dead_code)]
fn extract_string_content(s: &str) -> String {
    s.trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string()
}

#[allow(dead_code)]
fn get_function_containing_line<'a>(ast: &'a LnAst, line: usize) -> Option<&'a str> {
    ast.functions
        .iter()
        .find(|f| line >= f.start_line && line <= f.end_line)
        .map(|f| f.name.as_str())
}

#[allow(dead_code)]
fn is_inside_function_with_decorator(ast: &LnAst, line: usize, decorator_names: &[&str]) -> bool {
    for f in &ast.functions {
        if line >= f.start_line && line <= f.end_line {
            // Check if function has any matching decorator
            // The LnAst doesn't store decorators, so we check by function name convention
            for dec in decorator_names {
                if f.name.to_lowercase().contains(dec) {
                    return true;
                }
            }
        }
    }
    false
}

#[allow(dead_code)]
fn has_sensitive_keyword_in_function(ast: &LnAst, func_name: &str, keywords: &[&str]) -> bool {
    for f in &ast.functions {
        if f.name == func_name {
            let func_snippet = format!("{} {}", f.name, f.params.join(", "));
            for kw in keywords {
                if func_snippet.to_lowercase().contains(kw) {
                    return true;
                }
            }
        }
    }
    false
}

// --------------------------------------------------------------------------
// Rule AI-010: Direct Prompt Injection (AST-aware)
// Detects: user input passed directly to LLM calls
// Old: regex on every line of raw code
// New: track call graph user_input -> llm.generate()
// --------------------------------------------------------------------------

pub struct AstDirectPromptInjectionRule;

impl AstDirectPromptInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstDirectPromptInjectionRule {
    fn id(&self) -> &str {
        "AI-010"
    }
    fn name(&self) -> &str {
        "Direct Prompt Injection (AST)"
    }
    fn description(&self) -> &str {
        "AST-aware detection of direct prompt injection: user input passed to LLM without sanitization"
    }
    fn severity(&self) -> &str {
        "high"
    }
    fn confidence(&self) -> f32 {
        0.90
    }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        // AI/ML call patterns (the "sink" — where prompts go)
        let llm_call_patterns = [
            "generate", "complete", "chat", "ask", "query",
            "openai", "anthropic", "gemini", "llm", "model",
            "invoke", "run", "execute",
        ];

        // User input sources (the "source")
        let user_input_patterns = [
            "input", "request", "params", "args", "body",
            "form", "query", "user", "prompt",
        ];

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_llm_call = llm_call_patterns.iter().any(|p| callee_lower.contains(p));

            if is_llm_call {
                // Check if any argument looks like user input
                for arg in &call.arguments {
                    let arg_lower = arg.to_lowercase();
                    let is_suspicious_arg = user_input_patterns
                        .iter()
                        .any(|p| arg_lower.contains(p))
                        || arg.contains("request")
                        || arg.contains("form")
                        || arg.contains("input");

                    if is_suspicious_arg && !arg.is_empty() && arg != "\"\"" && arg != "''" {
                        let func_name = get_function_containing_line(ast, call.start_line)
                            .map(|s| s.to_string());

                        let mut finding = AstAiFinding::new(
                            self.id(),
                            self.severity(),
                            "prompt_injection",
                            &format!(
                                "User input ('{}') passed directly to LLM call '{}' — potential prompt injection",
                                arg.trim(), call.callee
                            ),
                            call.start_line,
                            &format!("{}({})", call.callee, call.arguments.join(", ")),
                            "Sanitize user input before passing to LLM. Use input validation, allowlists, or prompt templating.",
                            self.confidence(),
                        );

                        if let Some(name) = func_name {
                            finding = finding.with_function(name);
                        }
                        finding = finding.with_taint(TaintLabel::PromptInjection);
                        findings.push(finding);
                    }
                }

                // Also flag string literals that contain injection patterns in function args
                for s in &ast.strings {
                    if s.value.to_lowercase().contains("ignore")
                        && s.value.to_lowercase().contains("instruction")
                    {
                        let func_name = get_function_containing_line(ast, s.start_line)
                            .map(|n| n.to_string());
                        let mut f = AstAiFinding::new(
                            self.id(),
                            self.severity(),
                            "prompt_injection",
                            &format!("Potential prompt injection directive in string: '{}'",
                                &s.value[..s.value.len().min(60)]),
                            s.start_line,
                            &s.value,
                            "Review and sanitize string literals used in LLM prompts.",
                            0.85,
                        );
                        if let Some(name) = func_name {
                            f = f.with_function(name);
                        }
                        findings.push(f);
                    }
                }
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-011: Context Confusion Attack (AST-aware)
// Detects: conversation termination patterns inside AI handling functions
// --------------------------------------------------------------------------

pub struct AstContextConfusionRule;

impl AstContextConfusionRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstContextConfusionRule {
    fn id(&self) -> &str { "AI-011" }
    fn name(&self) -> &str { "Context Confusion Attack (AST)" }
    fn description(&self) -> &str { "AST-aware detection of conversation context confusion attacks" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.78 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let suspicious_patterns = [
            ("ignore previous", "Prompt injection: 'ignore previous' directive"),
            ("forget everything", "Prompt injection: 'forget everything' directive"),
            ("end this conversation", "Context confusion: conversation termination attempt"),
            ("new persona", "Context confusion: persona override attempt"),
        ];

        for s in &ast.strings {
            let s_lower = s.value.to_lowercase();
            for (pattern, msg) in &suspicious_patterns {
                if s_lower.contains(pattern) {
                    let func_name = get_function_containing_line(ast, s.start_line)
                        .map(|n| n.to_string());
                    let mut f = AstAiFinding::new(
                        self.id(),
                        self.severity(),
                        "context_confusion",
                        msg,
                        s.start_line,
                        &s.value,
                        "Implement conversation state validation. Never process user directives that override system behavior.",
                        self.confidence(),
                    );
                    if let Some(name) = func_name {
                        f = f.with_function(name);
                    }
                    findings.push(f);
                }
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-020: Missing Confidence Threshold (AST-aware)
// Detects: LLM API calls without confidence/probability checks
// --------------------------------------------------------------------------

pub struct AstMissingConfidenceThresholdRule;

impl AstMissingConfidenceThresholdRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstMissingConfidenceThresholdRule {
    fn id(&self) -> &str { "AI-020" }
    fn name(&self) -> &str { "Missing Confidence Threshold (AST)" }
    fn description(&self) -> &str { "AST-aware detection of LLM usage without confidence/probability checks" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.80 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let llm_call_patterns = [
            "generate", "complete", "chat", "ask", "query",
            "openai", "anthropic", "gemini", "invoke",
        ];

        let has_confidence_check = ast.calls.iter().any(|c| {
            let lower = c.callee.to_lowercase();
            lower.contains("confidence") || lower.contains("probability")
                || lower.contains("threshold") || lower.contains("score")
        });

        let has_guard = ast.calls.iter().any(|c| {
            let lower = c.callee.to_lowercase();
            lower.contains("validate") || lower.contains("check")
                || lower.contains("verify") || lower.contains("assert")
        });

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_llm_call = llm_call_patterns.iter().any(|p| callee_lower.contains(p));

            if is_llm_call && !has_confidence_check && !has_guard {
                let func_name = get_function_containing_line(ast, call.start_line)
                    .map(|n| n.to_string());

                let mut f = AstAiFinding::new(
                    self.id(),
                    self.severity(),
                    "hallucination_guard",
                    "LLM output used without confidence/probability validation — hallucination risk",
                    call.start_line,
                    &format!("{}(...)", call.callee),
                    "Add confidence threshold validation: check confidence/probability scores before using LLM output for critical decisions.",
                    self.confidence(),
                );

                if let Some(name) = func_name {
                    f = f.with_function(name);
                }
                findings.push(f);
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-050: System Prompt Leakage (AST-aware)
// Detects: system prompts logged, returned, or exposed
// --------------------------------------------------------------------------

pub struct AstSystemPromptLeakageRule;

impl AstSystemPromptLeakageRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstSystemPromptLeakageRule {
    fn id(&self) -> &str { "AI-050" }
    fn name(&self) -> &str { "System Prompt Leakage (AST)" }
    fn description(&self) -> &str { "AST-aware detection of system prompt exposure" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.90 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let leakage_patterns = [
            ("print", "print returns/contains system prompt"),
            ("log", "logging system prompt"),
            ("return", "returning system prompt"),
            ("response", "exposing system prompt in response"),
        ];

        let is_sensitive_function = |name: &str| -> bool {
            let lower = name.to_lowercase();
            lower.contains("prompt") || lower.contains("system")
                || lower.contains("instruction") || lower.contains("llm")
                || lower.contains("generate") || lower.contains("chat")
        };

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let func_name = get_function_containing_line(ast, call.start_line);

            // Check if this is a leakage pattern inside a prompt-handling function
            let is_leakage = leakage_patterns.iter().any(|(pattern, _)| callee_lower.contains(pattern));
            let in_prompt_func = func_name.map(is_sensitive_function).unwrap_or(false);

            if is_leakage && in_prompt_func {
                let mut f = AstAiFinding::new(
                    self.id(),
                    self.severity(),
                    "system_prompt_leakage",
                    &format!("Potential system prompt leakage: '{}' in function '{}'",
                        call.callee, func_name.unwrap_or("?")),
                    call.start_line,
                    &format!("{}({})", call.callee, call.arguments.join(", ")),
                    "Never expose system prompts in logs, returns, or responses. Use secure secret management.",
                    self.confidence(),
                );
                if let Some(name) = func_name.map(|s| s.to_string()) {
                    f = f.with_function(name);
                }
                findings.push(f);
            }
        }

        // Also check strings that look like system prompts being returned
        for s in &ast.strings {
            let s_lower = s.value.to_lowercase();
            if s_lower.contains("system")
                && (s_lower.contains("prompt") || s_lower.contains("instruction"))
                && s.value.len() > 50
            {
                let func_name = get_function_containing_line(ast, s.start_line);
                let mut f = AstAiFinding::new(
                    self.id(),
                    self.severity(),
                    "system_prompt_leakage",
                    "Long system prompt string detected — ensure it's not exposed in logs/responses",
                    s.start_line,
                    &s.value[..s.value.len().min(80)],
                    "Move system prompts to secure config. Never hardcode sensitive instructions.",
                    0.88,
                );
                if let Some(name) = func_name.map(|s| s.to_string()) {
                    f = f.with_function(name);
                }
                findings.push(f);
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-052: Missing Output Guardrails (AST-aware)
// Detects: LLM output used directly without filtering
// --------------------------------------------------------------------------

pub struct AstMissingGuardrailsRule;

impl AstMissingGuardrailsRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstMissingGuardrailsRule {
    fn id(&self) -> &str { "AI-052" }
    fn name(&self) -> &str { "Missing Output Guardrails (AST)" }
    fn description(&self) -> &str { "AST-aware detection of LLM output used without content filtering" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.82 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let llm_call_patterns = [
            "generate", "complete", "chat", "ask", "query",
            "openai", "anthropic", "gemini", "llm", "model",
        ];

        let has_guardrails = ast.calls.iter().any(|c| {
            let lower = c.callee.to_lowercase();
            lower.contains("filter") || lower.contains("moderation")
                || lower.contains("safety") || lower.contains("validate")
                || lower.contains("sanitize") || lower.contains("clean")
        });

        // Check for sensitive sinks: database writes, file writes, network calls
        let sensitive_sinks = [
            "execute", "query", "insert", "update", "delete",
            "write", "save", "store", "send", "http", "post",
            "eval", "exec", "spawn",
        ];

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_llm_call = llm_call_patterns.iter().any(|p| callee_lower.contains(p));
            let is_sensitive = sensitive_sinks.iter().any(|p| callee_lower.contains(p));

            if is_llm_call && !has_guardrails {
                // Check if LLM output flows to a sensitive sink
                for arg in &call.arguments {
                    let arg_lower = arg.to_lowercase();
                    if sensitive_sinks.iter().any(|p| arg_lower.contains(p)) {
                        let func_name = get_function_containing_line(ast, call.start_line)
                            .map(|n| n.to_string());
                        let mut f = AstAiFinding::new(
                            self.id(),
                            self.severity(),
                            "missing_guardrails",
                            &format!("LLM output passed to sensitive sink '{}' without guardrails",
                                call.callee),
                            call.start_line,
                            &format!("{}({})", call.callee, call.arguments.join(", ")),
                            "Add output guardrails: content filtering, PII redaction, safety checks before sensitive operations.",
                            self.confidence(),
                        );
                        if let Some(name) = func_name {
                            f = f.with_function(name);
                        }
                        f = f.with_taint(TaintLabel::PromptInjection);
                        findings.push(f);
                    }
                }

                // Also flag if LLM output is assigned and then used directly
                if call.arguments.iter().any(|a| {
                    let lower = a.to_lowercase();
                    lower.contains("response") || lower.contains("result")
                        || lower.contains("output") || lower.contains("text")
                }) && is_sensitive {
                    let func_name = get_function_containing_line(ast, call.start_line)
                        .map(|n| n.to_string());
                    let mut f = AstAiFinding::new(
                        self.id(),
                        self.severity(),
                        "missing_guardrails",
                        "LLM output used in sensitive operation without guardrails",
                        call.start_line,
                        &format!("{}(...)", call.callee),
                        "Add content filtering and validation between LLM output and sensitive operations.",
                        self.confidence(),
                    );
                    if let Some(name) = func_name {
                        f = f.with_function(name);
                    }
                    findings.push(f);
                }
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-060: Temperature Misuse (AST-aware)
// Detects: dangerously high temperature values for deterministic tasks
// --------------------------------------------------------------------------

pub struct AstTemperatureMisuseRule;

impl AstTemperatureMisuseRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstTemperatureMisuseRule {
    fn id(&self) -> &str { "AI-060" }
    fn name(&self) -> &str { "Temperature Parameter Misuse (AST)" }
    fn description(&self) -> &str { "AST-aware detection of dangerously high LLM temperature values" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.85 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let llm_patterns = [
            "generate", "complete", "chat", "openai", "anthropic", "gemini",
        ];

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_llm_call = llm_patterns.iter().any(|p| callee_lower.contains(p));

            if is_llm_call {
                for arg in &call.arguments {
                    let arg_lower = arg.to_lowercase();
                    if arg_lower.contains("temperature") || arg_lower.contains("temp") {
                        // Check for high values: > 0.7 for deterministic, > 1.0 for any
                        let digits: String = arg.chars()
                            .filter(|c| c.is_ascii_digit() || *c == '.')
                            .collect();
                        if let Ok(val) = digits.parse::<f32>() {
                            if val > 0.7 {
                                let func_name = get_function_containing_line(ast, call.start_line)
                                    .map(|n| n.to_string());
                                let mut f = AstAiFinding::new(
                                    self.id(),
                                    self.severity(),
                                    "config_misuse",
                                    &format!("High temperature ({}) may cause unpredictable LLM behavior", val),
                                    call.start_line,
                                    &format!("temperature={}", val),
                                    if val > 1.0 {
                                        "Use temperature <= 1.0. For deterministic tasks, use <= 0.3."
                                    } else {
                                        "Use temperature <= 0.7 for balanced tasks, <= 0.3 for deterministic ones."
                                    },
                                    if val > 1.0 { 0.95 } else { 0.75 },
                                );
                                if let Some(name) = func_name {
                                    f = f.with_function(name);
                                }
                                findings.push(f);
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-100: MCP Tool Schema Injection (AST-aware)
// Detects: user input in MCP tool definitions
// --------------------------------------------------------------------------

pub struct AstMcpToolSchemaInjectionRule;

impl AstMcpToolSchemaInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstMcpToolSchemaInjectionRule {
    fn id(&self) -> &str { "AI-100" }
    fn name(&self) -> &str { "MCP Tool Schema Injection (AST)" }
    fn description(&self) -> &str { "AST-aware detection of user input in MCP tool schemas (CWE-79)" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.88 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let mcp_patterns = [
            "tool_name", "tool_description", "new Tool", "Tool(",
            "mcp", "schema", "tool_schema", "function_schema",
        ];

        let user_input_patterns = [
            "request", "input", "user", "params", "args", "body",
            "form", "query", "payload", "data",
        ];

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_mcp_related = mcp_patterns.iter().any(|p| callee_lower.contains(p));

            if is_mcp_related {
                for arg in &call.arguments {
                    let arg_lower = arg.to_lowercase();
                    let has_user_input = user_input_patterns.iter().any(|p| arg_lower.contains(p))
                        || arg.contains("request.")
                        || arg.contains("params.")
                        || arg.contains("body.");

                    if has_user_input {
                        let func_name = get_function_containing_line(ast, call.start_line)
                            .map(|n| n.to_string());
                        let mut f = AstAiFinding::new(
                            self.id(),
                            self.severity(),
                            "mcp_schema_injection",
                            &format!("User input ('{}') used in MCP tool definition — potential schema injection", arg),
                            call.start_line,
                            &format!("{}({})", call.callee, arg),
                            "Validate and sanitize all user input before using in tool schemas. Use allowlists for tool names.",
                            self.confidence(),
                        );
                        if let Some(name) = func_name {
                            f = f.with_function(name);
                        }
                        f = f.with_taint(TaintLabel::PromptInjection);
                        findings.push(f);
                    }
                }
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Rule AI-101: MCP Secret Exfiltration (AST-aware)
// Detects: MCP tools accessing sensitive environment data
// --------------------------------------------------------------------------

pub struct AstMcpSecretExfiltrationRule;

impl AstMcpSecretExfiltrationRule {
    pub fn new() -> Self {
        Self
    }
}

impl AstAwareAiSecurityRule for AstMcpSecretExfiltrationRule {
    fn id(&self) -> &str { "AI-101" }
    fn name(&self) -> &str { "MCP Secret Exfiltration (AST)" }
    fn description(&self) -> &str { "AST-aware detection of MCP tools accessing sensitive environment/credentials (CWE-200)" }
    fn severity(&self) -> &str { "critical" }
    fn confidence(&self) -> f32 { 0.92 }

    fn detect_ast(&self, ast: &LnAst, _code: &str) -> Vec<AstAiFinding> {
        let mut findings = Vec::new();

        let secret_patterns = [
            "environ", "getenv", "get_env", "secret", "credential",
            "password", "token", "api_key", "apikey", "auth",
            "aws_access", "aws_secret", "private_key",
            "dotenv", "load_dotenv", "process.env",
        ];

        for call in &ast.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_secret_access = secret_patterns.iter().any(|p| callee_lower.contains(p));

            if is_secret_access {
                let func_name = get_function_containing_line(ast, call.start_line)
                    .map(|n| n.to_string());

                let is_mcp_function = func_name.as_ref()
                    .map(|n| n.to_lowercase().contains("mcp") || n.to_lowercase().contains("tool"))
                    .unwrap_or(false);

                let severity = if is_mcp_function { "critical" } else { "high" };
                let mut f = AstAiFinding::new(
                    self.id(),
                    severity,
                    "mcp_secret_exfiltration",
                    &format!("Sensitive data access '{}' detected{}", call.callee,
                        if is_mcp_function { " in MCP tool" } else { "" }),
                    call.start_line,
                    &format!("{}({})", call.callee, call.arguments.join(", ")),
                    "Never expose secrets to MCP tools or LLMs. Use secure secret management and privilege separation.",
                    if is_mcp_function { 0.92 } else { 0.80 },
                );
                if let Some(name) = func_name {
                    f = f.with_function(name);
                }
                f = f.with_taint(TaintLabel::UserInput);
                findings.push(f);
            }
        }

        findings
    }
}

// --------------------------------------------------------------------------
// Build all AST-aware rules
// --------------------------------------------------------------------------

pub fn all_ast_aware_rules() -> Vec<Box<dyn AstAwareAiSecurityRule>> {
    vec![
        Box::new(AstDirectPromptInjectionRule::new()),
        Box::new(AstContextConfusionRule::new()),
        Box::new(AstMissingConfidenceThresholdRule::new()),
        Box::new(AstSystemPromptLeakageRule::new()),
        Box::new(AstMissingGuardrailsRule::new()),
        Box::new(AstTemperatureMisuseRule::new()),
        Box::new(AstMcpToolSchemaInjectionRule::new()),
        Box::new(AstMcpSecretExfiltrationRule::new()),
    ]
}
