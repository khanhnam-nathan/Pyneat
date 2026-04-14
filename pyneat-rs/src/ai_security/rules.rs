//! AI Security Rules Implementation
//!
//! Copyright (C) 2026 PyNEAT Authors

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --------------------------------------------------------------------------
// Shared Types (moved from mod.rs)
// --------------------------------------------------------------------------

/// Represents an AI-specific security vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFinding {
    pub rule_id: String,
    pub severity: String,
    pub vulnerability_type: AiVulnerabilityType,
    pub problem: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub fix_hint: String,
    pub auto_fix_available: bool,
    pub confidence: f32,
    pub attack_vector: Option<String>,
}

impl AiFinding {
    pub fn new(
        rule_id: &str,
        severity: &str,
        vuln_type: AiVulnerabilityType,
        problem: &str,
        line: usize,
        snippet: &str,
        fix_hint: &str,
        confidence: f32,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            vulnerability_type: vuln_type,
            problem: problem.to_string(),
            line,
            column: 0,
            snippet: snippet.to_string(),
            fix_hint: fix_hint.to_string(),
            auto_fix_available: false,
            confidence,
            attack_vector: None,
        }
    }
}

/// Types of AI-specific vulnerabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiVulnerabilityType {
    PromptInjection,
    HallucinationGuard,
    ModelExtraction,
    AdversarialInput,
    SystemPromptLeakage,
    ToolCallCollision,
    MissingGuardrails,
    ToxicOutput,
    ConfigMisuse,
    ContextWindowError,
    HallucinatedApi,
}

impl AiVulnerabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AiVulnerabilityType::PromptInjection => "prompt_injection",
            AiVulnerabilityType::HallucinationGuard => "hallucination_guard",
            AiVulnerabilityType::ModelExtraction => "model_extraction",
            AiVulnerabilityType::AdversarialInput => "adversarial_input",
            AiVulnerabilityType::SystemPromptLeakage => "system_prompt_leakage",
            AiVulnerabilityType::ToolCallCollision => "tool_call_collision",
            AiVulnerabilityType::MissingGuardrails => "missing_guardrails",
            AiVulnerabilityType::ToxicOutput => "toxic_output",
            AiVulnerabilityType::ConfigMisuse => "config_misuse",
            AiVulnerabilityType::ContextWindowError => "context_window_error",
            AiVulnerabilityType::HallucinatedApi => "hallucinated_api",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            AiVulnerabilityType::PromptInjection => "AI Input Security",
            AiVulnerabilityType::HallucinationGuard => "AI Output Security",
            AiVulnerabilityType::ModelExtraction => "AI Model Security",
            AiVulnerabilityType::AdversarialInput => "AI Input Security",
            AiVulnerabilityType::SystemPromptLeakage => "AI Configuration",
            AiVulnerabilityType::ToolCallCollision => "AI Integration",
            AiVulnerabilityType::MissingGuardrails => "AI Output Security",
            AiVulnerabilityType::ToxicOutput => "AI Output Security",
            AiVulnerabilityType::ConfigMisuse => "AI Configuration",
            AiVulnerabilityType::ContextWindowError => "AI Integration",
            AiVulnerabilityType::HallucinatedApi => "AI Output Security",
        }
    }
}

/// AI Security Scanner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSecurityConfig {
    pub detect_prompt_injection: bool,
    pub detect_hallucination: bool,
    pub detect_model_extraction: bool,
    pub detect_adversarial: bool,
    pub confidence_threshold: f32,
    pub system_prompt: Option<String>,
    pub api_endpoint: Option<String>,
}

impl Default for AiSecurityConfig {
    fn default() -> Self {
        Self {
            detect_prompt_injection: true,
            detect_hallucination: true,
            detect_model_extraction: true,
            detect_adversarial: true,
            confidence_threshold: 0.7,
            system_prompt: None,
            api_endpoint: None,
        }
    }
}

// --------------------------------------------------------------------------
// AI Security Rule Trait
// --------------------------------------------------------------------------

/// Trait for AI security rules.
pub trait AiSecurityRule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn vulnerability_type(&self) -> AiVulnerabilityType;
    fn description(&self) -> &str;
    fn severity(&self) -> &str;
    fn confidence(&self) -> f32;
    fn detect(&self, code: &str, language: &str) -> Vec<AiFinding>;
}

// --------------------------------------------------------------------------
// Prompt Injection Rules
// --------------------------------------------------------------------------

pub struct DirectPromptInjectionRule {
    patterns: Vec<Regex>,
}

impl DirectPromptInjectionRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)ignore\s+(previous|all|prior)\s+(instructions?|commands?|rules?)").unwrap(),
                Regex::new(r"(?i)forget\s+(everything|all|what)").unwrap(),
                Regex::new(r"(?i)you\s+are\s+now\s+(a|an)").unwrap(),
                Regex::new(r"(?i)new\s+(system|role|persona)").unwrap(),
                Regex::new(r"(?i)(you\s+are|act\s+as)\s+(admin|root|developer|god)").unwrap(),
                Regex::new(r"(?i)bypass\s+(safety|security|filter)").unwrap(),
                Regex::new(r"(?i)disable\s+(safety|security)").unwrap(),
                Regex::new(r"(?i)(system|assistant|user)\s*[:>]").unwrap(),
                Regex::new(r##"(?i)(```|<script>|\[INST\]|\[SYS\]|<<SYS>>)"##).unwrap(),
                Regex::new(r"(?i)dan\s+(mode|do\s+anything)").unwrap(),
                Regex::new(r"(?i)jailbreak").unwrap(),
                Regex::new(r"(?i)pretend\s+(you\s+)?(don't|do\s+not)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for DirectPromptInjectionRule {
    fn id(&self) -> &str { "AI-010" }
    fn name(&self) -> &str { "Direct Prompt Injection" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::PromptInjection }
    fn description(&self) -> &str { "Detects direct prompt injection patterns in user input" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.85 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        &format!("Potential prompt injection: '{}'", pattern.find(line).map(|m| m.as_str()).unwrap_or("")),
                        line_num + 1, line.trim(),
                        "Sanitize user input before passing to LLM. Use input validation and filtering.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct ContextConfusionRule {
    pattern: Regex,
}

impl ContextConfusionRule {
    pub fn new() -> Self {
        Self {
            pattern: Regex::new(r"(?i)(end|stop)\s+(this|that)\s+(turn|conversation|chat)").unwrap(),
        }
    }
}

impl AiSecurityRule for ContextConfusionRule {
    fn id(&self) -> &str { "AI-011" }
    fn name(&self) -> &str { "Context Confusion Attack" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::PromptInjection }
    fn description(&self) -> &str { "Detects multi-turn conversation context confusion attacks" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.70 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            if self.pattern.is_match(line) {
                findings.push(AiFinding::new(
                    self.id(), self.severity(), self.vulnerability_type(),
                    "Potential context confusion attack detected",
                    line_num + 1, line.trim(),
                    "Implement conversation state validation and clear context boundaries.",
                    self.confidence(),
                ));
            }
        }
        findings
    }
}

pub struct ProxyInjectionRule {
    patterns: Vec<Regex>,
}

impl ProxyInjectionRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)use\s+(the\s+)?(function|tool|api)\s+:\s*\w+").unwrap(),
                Regex::new(r"(?i)call\s+(the\s+)?(function|tool)\s+").unwrap(),
                Regex::new(r"(?i)execute\s+(bash|shell|command|system)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for ProxyInjectionRule {
    fn id(&self) -> &str { "AI-012" }
    fn name(&self) -> &str { "Proxy Injection via Tool Calls" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::PromptInjection }
    fn description(&self) -> &str { "Detects prompt injection through tool/function call manipulation" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.80 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential proxy injection via tool call manipulation",
                        line_num + 1, line.trim(),
                        "Validate and constrain LLM tool selection. Implement tool permission controls.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

// --------------------------------------------------------------------------
// Hallucination Guard Rules
// --------------------------------------------------------------------------

pub struct MissingConfidenceThresholdRule {
    patterns: Vec<Regex>,
}

impl MissingConfidenceThresholdRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)llm\.generate\s*\(").unwrap(),
                Regex::new(r"(?i)(openai|anthropic|gemini)").unwrap(),
                Regex::new(r"(?i)response\s*=\s*.*generate").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for MissingConfidenceThresholdRule {
    fn id(&self) -> &str { "AI-020" }
    fn name(&self) -> &str { "Missing Confidence Threshold" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::HallucinationGuard }
    fn description(&self) -> &str { "Detects LLM usage without confidence threshold checks" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.75 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_confidence = code.contains("confidence") || code.contains("probability");
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) && !has_confidence {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "LLM output used without confidence/probability check",
                        line_num + 1, line.trim(),
                        "Add confidence threshold validation before using LLM output for critical decisions.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct MissingFactCheckRule {
    patterns: Vec<Regex>,
}

impl MissingFactCheckRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)(facts?|information|data)\s*(should|must|need)\s*(be\s+)?verified").unwrap(),
                Regex::new(r"(?i)verify|cross.?check|validate").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for MissingFactCheckRule {
    fn id(&self) -> &str { "AI-021" }
    fn name(&self) -> &str { "Missing Fact-Checking Mechanism" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::HallucinationGuard }
    fn description(&self) -> &str { "Detects absence of fact-checking for LLM outputs" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.70 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_fact_check = code.contains("fact_check") || code.contains("verify_fact");
        if !has_fact_check {
            for (line_num, line) in code.lines().enumerate() {
                if (line.contains("llm") || line.contains("generate") || line.contains("response")) && !line.starts_with('#') {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "LLM output may be used without fact-checking",
                        line_num + 1, line.trim(),
                        "Implement a fact-checking mechanism for critical LLM outputs.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct UnguardedSensitiveOperationRule {
    sensitive_keywords: Vec<&'static str>,
}

impl UnguardedSensitiveOperationRule {
    pub fn new() -> Self {
        Self {
            sensitive_keywords: vec![
                "delete", "drop", "truncate", "remove",
                "execute", "run", "exec",
                "transfer", "payment", "send_money",
                "grant", "revoke", "access",
            ],
        }
    }
}

impl AiSecurityRule for UnguardedSensitiveOperationRule {
    fn id(&self) -> &str { "AI-022" }
    fn name(&self) -> &str { "Unguarded Sensitive Operation" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::HallucinationGuard }
    fn description(&self) -> &str { "Detects LLM-driven sensitive operations without guardrails" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.80 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_guard = code.contains("confirm") || code.contains("approve") ||
                        code.contains("verify") || code.contains("require_confirmation");
        for (line_num, line) in code.lines().enumerate() {
            let lower = line.to_lowercase();
            let has_sensitive = self.sensitive_keywords.iter().any(|kw| lower.contains(kw));
            let has_llm = lower.contains("llm") || lower.contains("generate") || lower.contains("ai");
            if has_sensitive && has_llm && !has_guard {
                findings.push(AiFinding::new(
                    self.id(), self.severity(), self.vulnerability_type(),
                    "Sensitive operation may be driven by LLM without confirmation",
                    line_num + 1, line.trim(),
                    "Add human-in-the-loop confirmation for sensitive LLM-driven operations.",
                    self.confidence(),
                ));
            }
        }
        findings
    }
}

// --------------------------------------------------------------------------
// Model Extraction Rules
// --------------------------------------------------------------------------

pub struct VerboseErrorRule {
    patterns: Vec<Regex>,
}

impl VerboseErrorRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)error.*detail").unwrap(),
                Regex::new(r"(?i)stack\s*trace").unwrap(),
                Regex::new(r"(?i)internal\s+(error|exception)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for VerboseErrorRule {
    fn id(&self) -> &str { "AI-030" }
    fn name(&self) -> &str { "Verbose Error Messages" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ModelExtraction }
    fn description(&self) -> &str { "Detects overly detailed error messages that could aid model extraction" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.75 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Verbose error may expose model details",
                        line_num + 1, line.trim(),
                        "Use generic error messages. Log detailed errors server-side only.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct MissingRateLimitRule {
    patterns: Vec<Regex>,
}

impl MissingRateLimitRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)(openai|anthropic|gemini|llm|api)\s*\(").unwrap(),
                Regex::new(r"(?i)chat_completion|completion|generate").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for MissingRateLimitRule {
    fn id(&self) -> &str { "AI-031" }
    fn name(&self) -> &str { "Missing API Rate Limiting" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ModelExtraction }
    fn description(&self) -> &str { "Detects LLM API calls without rate limiting" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.70 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_rate_limit = code.contains("rate_limit") || code.contains("RateLimiter") ||
                            code.contains("max_requests") || code.contains("throttle");
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) && !has_rate_limit {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "LLM API call without rate limiting may enable extraction attacks",
                        line_num + 1, line.trim(),
                        "Implement rate limiting to prevent model extraction via bulk queries.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct OverDetailedErrorRule {
    pattern: Regex,
}

impl OverDetailedErrorRule {
    pub fn new() -> Self {
        Self {
            pattern: Regex::new(r"(?i)(model|training|data)\s*(version|params|weights|architecture)").unwrap(),
        }
    }
}

impl AiSecurityRule for OverDetailedErrorRule {
    fn id(&self) -> &str { "AI-032" }
    fn name(&self) -> &str { "Overly Detailed System Information" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ModelExtraction }
    fn description(&self) -> &str { "Detects exposure of model architecture details" }
    fn severity(&self) -> &str { "low" }
    fn confidence(&self) -> f32 { 0.65 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            if self.pattern.is_match(line) {
                findings.push(AiFinding::new(
                    self.id(), self.severity(), self.vulnerability_type(),
                    "Detailed model information may aid extraction attempts",
                    line_num + 1, line.trim(),
                    "Use generic identifiers. Hide specific model details from client-facing code.",
                    self.confidence(),
                ));
            }
        }
        findings
    }
}

// --------------------------------------------------------------------------
// Adversarial Input Rules
// --------------------------------------------------------------------------

pub struct AdversarialInputRule {
    patterns: Vec<Regex>,
}

impl AdversarialInputRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)\x00|\x1a|\x7f").unwrap(),
                Regex::new(r"(?i)(null|nullbyte|empty)").unwrap(),
                Regex::new(r"(?i)(injection|bypass|sqli|xss)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for AdversarialInputRule {
    fn id(&self) -> &str { "AI-040" }
    fn name(&self) -> &str { "Potential Adversarial Input" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::AdversarialInput }
    fn description(&self) -> &str { "Detects potential adversarial input patterns" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.70 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential adversarial input pattern detected",
                        line_num + 1, line.trim(),
                        "Implement input sanitization and adversarial robustness testing.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct UnicodeHomographAttackRule {
    patterns: Vec<Regex>,
}

impl UnicodeHomographAttackRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"[\u00C0-\u00FF]").unwrap(),
                Regex::new(r"[\u0400-\u04FF]").unwrap(),
                Regex::new(r"[\u0590-\u05FF]").unwrap(),
                Regex::new(r"[\u0600-\u06FF]").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for UnicodeHomographAttackRule {
    fn id(&self) -> &str { "AI-041" }
    fn name(&self) -> &str { "Unicode Homograph Attack" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::AdversarialInput }
    fn description(&self) -> &str { "Detects potential unicode-based homograph attacks in prompts" }
    fn severity(&self) -> &str { "low" }
    fn confidence(&self) -> f32 { 0.60 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            let has_user_input = line.contains("input") || line.contains("user") || line.contains("prompt");
            for pattern in &self.patterns {
                if pattern.is_match(line) && has_user_input {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential unicode homograph attack vector",
                        line_num + 1, line.trim(),
                        "Normalize unicode input. Use punycode for domain validation.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

// --------------------------------------------------------------------------
// Configuration & System Rules
// --------------------------------------------------------------------------

pub struct SystemPromptLeakageRule {
    patterns: Vec<Regex>,
}

impl SystemPromptLeakageRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)system\s*prompt\s*[:=]").unwrap(),
                Regex::new(r"(?i)print\s*\(.*system").unwrap(),
                Regex::new(r"(?i)log\s*\(.*system").unwrap(),
                Regex::new(r"(?i)return\s+.*system\s*prompt").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for SystemPromptLeakageRule {
    fn id(&self) -> &str { "AI-050" }
    fn name(&self) -> &str { "System Prompt Leakage" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::SystemPromptLeakage }
    fn description(&self) -> &str { "Detects code that may leak system prompts" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.85 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential system prompt leakage",
                        line_num + 1, line.trim(),
                        "Never log or return system prompts. Use secure secret management.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct ToolCallCollisionRule {
    pattern: Regex,
}

impl ToolCallCollisionRule {
    pub fn new() -> Self {
        Self {
            pattern: Regex::new(r"(?i)(function|tool|api)\s*name\s*(collision|conflict|dup|overlap)").unwrap(),
        }
    }
}

impl AiSecurityRule for ToolCallCollisionRule {
    fn id(&self) -> &str { "AI-051" }
    fn name(&self) -> &str { "Tool Call Collision" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ToolCallCollision }
    fn description(&self) -> &str { "Detects potential tool call name collisions" }
    fn severity(&self) -> &str { "low" }
    fn confidence(&self) -> f32 { 0.65 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            if self.pattern.is_match(line) {
                findings.push(AiFinding::new(
                    self.id(), self.severity(), self.vulnerability_type(),
                    "Potential tool call name collision",
                    line_num + 1, line.trim(),
                    "Use unique, prefixed tool names to avoid collisions.",
                    self.confidence(),
                ));
            }
        }
        findings
    }
}

pub struct MissingGuardrailsRule {
    patterns: Vec<Regex>,
}

impl MissingGuardrailsRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)output\s*=.*llm").unwrap(),
                Regex::new(r"(?i)return\s+.*generate").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for MissingGuardrailsRule {
    fn id(&self) -> &str { "AI-052" }
    fn name(&self) -> &str { "Missing Output Guardrails" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::MissingGuardrails }
    fn description(&self) -> &str { "Detects LLM output used without content filtering" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.75 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_guardrails = code.contains("filter") && code.contains("output") ||
                            code.contains("content_moderation") || code.contains("safety_check");
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) && !has_guardrails {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "LLM output used without content filtering",
                        line_num + 1, line.trim(),
                        "Implement output guardrails: content filtering, toxicity detection, PII redaction.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct ToxicOutputRiskRule {
    patterns: Vec<Regex>,
}

impl ToxicOutputRiskRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)(toxic|harmful|inappropriate)\s*(content|output|result)").unwrap(),
                Regex::new(r"(?i)no\s+(filter|moderation|safety)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for ToxicOutputRiskRule {
    fn id(&self) -> &str { "AI-053" }
    fn name(&self) -> &str { "Toxic Output Risk" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ToxicOutput }
    fn description(&self) -> &str { "Detects code that may produce toxic/harmful outputs" }
    fn severity(&self) -> &str { "high" }
    fn confidence(&self) -> f32 { 0.80 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        let has_moderation = code.contains("moderation") || code.contains("toxicity");
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) && !has_moderation {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential for toxic/harmful output without moderation",
                        line_num + 1, line.trim(),
                        "Add content moderation and toxicity detection before output.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct TemperatureMisuseRule {
    patterns: Vec<Regex>,
}

impl TemperatureMisuseRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)temperature\s*[:=]\s*0\.9[5-9]").unwrap(),
                Regex::new(r"(?i)temperature\s*[:=]\s*1\.[0-9]").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for TemperatureMisuseRule {
    fn id(&self) -> &str { "AI-060" }
    fn name(&self) -> &str { "Temperature Parameter Misuse" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ConfigMisuse }
    fn description(&self) -> &str { "Detects dangerously high temperature values for LLM" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.75 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "High temperature value may cause unpredictable LLM behavior",
                        line_num + 1, line.trim(),
                        "Use temperature <= 0.7 for deterministic tasks.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct ContextWindowRule {
    patterns: Vec<Regex>,
}

impl ContextWindowRule {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)context.*window|truncat|pad").unwrap(),
                Regex::new(r"(?i)(system|user|assistant)\s*token").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for ContextWindowRule {
    fn id(&self) -> &str { "AI-061" }
    fn name(&self) -> &str { "Context Window Management" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::ContextWindowError }
    fn description(&self) -> &str { "Detects potential context window handling issues" }
    fn severity(&self) -> &str { "low" }
    fn confidence(&self) -> f32 { 0.60 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential context window handling issue",
                        line_num + 1, line.trim(),
                        "Implement proper context window management: chunking, summarization, or sliding window.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

pub struct HallucinatedApiRule {
    fake_api_patterns: Vec<Regex>,
}

impl HallucinatedApiRule {
    pub fn new() -> Self {
        Self {
            fake_api_patterns: vec![
                Regex::new(r"(?i)import\s+\w+.*ai").unwrap(),
                Regex::new(r"(?i)from\s+\w+\s+import\s+(generate|chat|complete)").unwrap(),
            ],
        }
    }
}

impl AiSecurityRule for HallucinatedApiRule {
    fn id(&self) -> &str { "AI-070" }
    fn name(&self) -> &str { "Hallucinated API Call" }
    fn vulnerability_type(&self) -> AiVulnerabilityType { AiVulnerabilityType::HallucinatedApi }
    fn description(&self) -> &str { "Detects potentially non-existent API calls" }
    fn severity(&self) -> &str { "medium" }
    fn confidence(&self) -> f32 { 0.55 }

    fn detect(&self, code: &str, _language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();
        for (line_num, line) in code.lines().enumerate() {
            for pattern in &self.fake_api_patterns {
                if pattern.is_match(line) {
                    findings.push(AiFinding::new(
                        self.id(), self.severity(), self.vulnerability_type(),
                        "Potential hallucinated/non-existent API call",
                        line_num + 1, line.trim(),
                        "Verify that the imported AI library/API actually exists.",
                        self.confidence(),
                    ));
                    break;
                }
            }
        }
        findings
    }
}
