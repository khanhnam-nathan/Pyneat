//! AI Security Scanner Module
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This module provides specialized security scanning for AI-generated code
//! and AI-powered applications, detecting:
//! - Prompt injection attacks
//! - Hallucination guard violations
//! - Model extraction vulnerabilities
//! - AI-specific security misconfigurations
//!
//! Two modes:
//! - `scan()`: Legacy regex-based scanning on raw code (backward compatible)
//! - `scan_with_ast()`: AST-aware scanning using LnAst (lower false positives, taint-aware)

mod ast_ai_security;
mod rules;

pub use rules::{AiSecurityRule, AiFinding, AiSecurityConfig, AiVulnerabilityType};
pub use ast_ai_security::{
    AstAwareAiSecurityRule, AstAiFinding, all_ast_aware_rules,
};

use serde::{Deserialize, Serialize};

// --------------------------------------------------------------------------
// AI Security Scanner
// --------------------------------------------------------------------------

/// Main AI Security Scanner.
pub struct AiSecurityScanner {
    pub(crate) config: AiSecurityConfig,
    pub(crate) rules: Vec<Box<dyn AiSecurityRule>>,
}

impl AiSecurityScanner {
    /// Create a new AI Security Scanner with default rules.
    pub fn new() -> Self {
        Self::with_config(AiSecurityConfig::default())
    }

    /// Create a scanner with custom configuration.
    pub fn with_config(config: AiSecurityConfig) -> Self {
        let rules = Self::build_rules(&config);
        Self { config, rules }
    }

    fn build_rules(config: &AiSecurityConfig) -> Vec<Box<dyn AiSecurityRule>> {
        let mut rules: Vec<Box<dyn AiSecurityRule>> = Vec::new();

        if config.detect_prompt_injection {
            rules.push(Box::new(rules::DirectPromptInjectionRule::new()));
            rules.push(Box::new(rules::ContextConfusionRule::new()));
            rules.push(Box::new(rules::ProxyInjectionRule::new()));
        }

        if config.detect_hallucination {
            rules.push(Box::new(rules::MissingConfidenceThresholdRule::new()));
            rules.push(Box::new(rules::MissingFactCheckRule::new()));
            rules.push(Box::new(rules::UnguardedSensitiveOperationRule::new()));
        }

        if config.detect_model_extraction {
            rules.push(Box::new(rules::VerboseErrorRule::new()));
            rules.push(Box::new(rules::MissingRateLimitRule::new()));
            rules.push(Box::new(rules::OverDetailedErrorRule::new()));
        }

        if config.detect_adversarial {
            rules.push(Box::new(rules::AdversarialInputRule::new()));
            rules.push(Box::new(rules::UnicodeHomographAttackRule::new()));
        }

        rules.push(Box::new(rules::SystemPromptLeakageRule::new()));
        rules.push(Box::new(rules::ToolCallCollisionRule::new()));
        rules.push(Box::new(rules::MissingGuardrailsRule::new()));
        rules.push(Box::new(rules::ToxicOutputRiskRule::new()));
        rules.push(Box::new(rules::TemperatureMisuseRule::new()));
        rules.push(Box::new(rules::ContextWindowRule::new()));
        rules.push(Box::new(rules::HallucinatedApiRule::new()));

        // MCP-specific security rules
        rules.push(Box::new(rules::McpToolSchemaInjectionRule::new()));
        rules.push(Box::new(rules::McpSecretExfiltrationRule::new()));
        rules.push(Box::new(rules::McpServerImpersonationRule::new()));
        rules.push(Box::new(rules::McpToolPoisoningRule::new()));
        rules.push(Box::new(rules::McpPromptInjectionRule::new()));

        rules
    }

    /// Scan code for AI-specific vulnerabilities (legacy regex-based, backward compatible).
    pub fn scan(&self, code: &str, language: &str) -> Vec<AiFinding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            let rule_findings = rule.detect(code, language);
            for f in rule_findings {
                if f.confidence >= self.config.confidence_threshold {
                    findings.push(f);
                }
            }
        }

        // Sort by severity and line number
        findings.sort_by(|a, b| {
            let sev_order = |s: &str| match s {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                _ => 1,
            };
            sev_order(&a.severity)
                .cmp(&sev_order(&b.severity))
                .then(a.line.cmp(&b.line))
        });

        findings
    }

    /// Scan using an already-parsed LnAst for AST-aware AI security analysis.
    ///
    /// This reuses the AST that was already parsed by the scanner (no redundant parsing).
    /// AST-aware rules know function boundaries, call context, and data flow relationships,
    /// which dramatically reduces false positives compared to regex-on-raw-code scanning.
    ///
    /// This method also introduces taint labels into `AstAiFinding` so that findings
    /// can be merged with the taint analysis layer (user_input -> llm.generate chain).
    pub fn scan_with_ast(&self, ast: &crate::scanner::ln_ast::LnAst, code: &str) -> Vec<AstAiFinding> {
        let ast_rules = ast_ai_security::all_ast_aware_rules();
        let mut findings = Vec::new();

        for rule in &ast_rules {
            let rule_findings = rule.detect_ast(ast, code);
            for f in rule_findings {
                if f.confidence >= self.config.confidence_threshold {
                    findings.push(f);
                }
            }
        }

        // Sort by severity then line
        findings.sort_by(|a, b| {
            let sev_order = |s: &str| match s {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                _ => 1,
            };
            sev_order(&a.severity)
                .cmp(&sev_order(&b.severity))
                .then(a.line.cmp(&b.line))
        });

        findings
    }

    /// Get all available AI security rules.
    pub fn available_rules(&self) -> Vec<AiRuleInfo> {
        self.rules
            .iter()
            .map(|r| AiRuleInfo {
                id: r.id().to_string(),
                name: r.name().to_string(),
                vuln_type: r.vulnerability_type().as_str().to_string(),
                category: r.vulnerability_type().category().to_string(),
                description: r.description().to_string(),
            })
            .collect()
    }
}

impl Default for AiSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an AI security rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRuleInfo {
    pub id: String,
    pub name: String,
    pub vuln_type: String,
    pub category: String,
    pub description: String,
}
