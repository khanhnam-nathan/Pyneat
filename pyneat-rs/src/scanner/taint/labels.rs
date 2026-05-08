//! Taint labels, sources, sinks, sanitizers, and propagators.
//!
//! These types define what constitutes a taint source, dangerous sink,
//! sanitizer, and custom propagation rule.

#[allow(dead_code)]

use std::collections::HashSet;

/// Represents different kinds of tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    /// Untrusted user input (request params, stdin, env vars, cookies)
    UserInput,
    /// Data from network/external sources
    Network,
    /// Filesystem input
    FileContent,
    /// Generic untrusted data
    Tainted,
    /// Command/script injection risk
    Command,
    /// SQL injection risk
    Sql,
    /// HTML/JavaScript injection risk
    Html,
    /// Path traversal risk
    Path,
    /// XML/XXE injection risk
    Xml,
    /// Cryptographic weakness
    Crypto,
    /// Format string injection risk
    Format,
    /// Mass assignment vulnerability risk
    MassAssign,
    /// Unsafe reflection risk
    Reflect,
    /// Type confusion / loose comparison risk
    TypeConfuse,
    /// Log injection risk
    LogInject,
    /// YAML unsafe deserialization risk
    YamlUnsafe,
    /// Prompt injection: user input that flows into LLM prompts
    PromptInjection,
    /// LLM output: data from LLM model responses
    LlmOutput,
    /// System prompt: internal prompt/instruction content
    SystemPrompt,
    /// Custom labeled taint
    Custom(String),
}

impl std::fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintLabel::UserInput => write!(f, "user_input"),
            TaintLabel::Network => write!(f, "network"),
            TaintLabel::FileContent => write!(f, "file_content"),
            TaintLabel::Tainted => write!(f, "tainted"),
            TaintLabel::Command => write!(f, "command"),
            TaintLabel::Sql => write!(f, "sql"),
            TaintLabel::Html => write!(f, "html"),
            TaintLabel::Path => write!(f, "path"),
            TaintLabel::Xml => write!(f, "xml"),
            TaintLabel::Crypto => write!(f, "crypto"),
            TaintLabel::Format => write!(f, "format"),
            TaintLabel::MassAssign => write!(f, "mass_assign"),
            TaintLabel::Reflect => write!(f, "reflect"),
            TaintLabel::TypeConfuse => write!(f, "type_confuse"),
            TaintLabel::LogInject => write!(f, "log_inject"),
            TaintLabel::YamlUnsafe => write!(f, "yaml_unsafe"),
            TaintLabel::PromptInjection => write!(f, "prompt_injection"),
            TaintLabel::LlmOutput => write!(f, "llm_output"),
            TaintLabel::SystemPrompt => write!(f, "system_prompt"),
            TaintLabel::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Pattern that matches a taint source in the AST.
#[derive(Debug, Clone)]
pub enum SourcePattern {
    /// Match any call whose callee starts with this prefix
    CallPrefix(String),
    /// Match any access (attribute/index) with this name
    PropertyAccess(String),
    /// Match AST nodes of a specific kind whose text matches a name hint
    AstKind { node_kind: String, name_hint: String },
    /// Match any identifier matching a regex-like pattern
    IdentifierPattern(String),
}

impl SourcePattern {
    /// Check if this pattern matches a given callee name or identifier.
    pub fn matches(&self, text: &str) -> bool {
        match self {
            SourcePattern::CallPrefix(prefix) => text.starts_with(prefix) || text.contains(prefix),
            SourcePattern::PropertyAccess(name) => text.contains(name),
            SourcePattern::AstKind { name_hint, .. } => {
                text.contains(name_hint) || name_hint == "*" || name_hint == ".*"
            }
            SourcePattern::IdentifierPattern(pattern) => {
                // Simple pattern: supports * wildcards
                let pattern = pattern.replace('*', "");
                text.contains(&pattern)
            }
        }
    }
}

/// A source of untrusted data — where taint enters the program.
#[derive(Debug, Clone)]
pub struct TaintSource {
    /// Rule ID that defined this source
    pub rule_id: String,
    /// Human-readable name
    pub name: String,
    /// The kind of taint this source produces
    pub label: TaintLabel,
    /// Patterns that identify this source
    pub patterns: Vec<SourcePattern>,
}

impl TaintSource {
    /// Check if a call matches any of the source patterns.
    pub fn matches_call(&self, callee: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(callee))
    }

    /// Check if an identifier matches any of the source patterns.
    pub fn matches_identifier(&self, identifier: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(identifier))
    }
}

/// Position of the sink relative to the expression.
#[derive(Debug, Clone)]
pub enum SinkPosition {
    /// The entire expression is the sink
    Entire,
    /// Only this 0-based argument index is the sink
    Argument(usize),
    /// A field access path (e.g., obj.sql_query)
    Field(Vec<String>),
    /// Return value of the call
    ReturnValue,
}

/// A sink — where dangerous operations occur that shouldn't receive untrusted data.
#[derive(Debug, Clone)]
pub struct TaintSink {
    /// Rule ID
    pub rule_id: String,
    /// Human-readable name
    pub name: String,
    /// Severity level
    pub severity: String,
    /// Description of the vulnerability
    pub description: String,
    /// Which part of the expression is the sink
    pub sink_arg: SinkPosition,
    /// Minimum taint labels required to trigger
    pub requires: Vec<TaintLabel>,
}

impl TaintSink {
    /// Check if a given callee matches this sink.
    pub fn matches_callee(&self, callee: &str) -> bool {
        let name_lower = self.name.to_lowercase();
        callee.to_lowercase().contains(&name_lower) || name_lower.contains(callee)
    }

    /// Check if this sink accepts the given taint label.
    pub fn accepts_taint(&self, label: &TaintLabel) -> bool {
        match label {
            // UserInput and Tainted are universal — user input can cause any vulnerability
            TaintLabel::UserInput | TaintLabel::Tainted => true,
            // Specific labels only match if the sink specifically requires them
            _ => self.requires.is_empty() || self.requires.iter().any(|r| r == label),
        }
    }

    /// Check if ANY label in the list is acceptable for this sink.
    pub fn accepts_any_label(&self, labels: &[TaintLabel]) -> bool {
        labels.iter().any(|l| self.accepts_taint(l))
    }
}

/// Pattern that matches a sanitizer.
#[derive(Debug, Clone)]
pub enum SanitizerPattern {
    /// Match any call with this prefix
    CallPrefix(String),
    /// Match AST node kind (e.g., "identifier")
    AstKind(String),
    /// Match a specific identifier name
    Identifier(String),
}

impl SanitizerPattern {
    pub fn matches(&self, text: &str) -> bool {
        match self {
            SanitizerPattern::CallPrefix(prefix) => text.contains(prefix),
            SanitizerPattern::AstKind(kind) => text.contains(kind),
            SanitizerPattern::Identifier(name) => text.contains(name),
        }
    }
}

/// A sanitizer — code that removes taint from data.
#[derive(Debug, Clone)]
pub struct TaintSanitizer {
    /// Rule ID
    pub rule_id: String,
    /// Patterns that identify the sanitizer
    pub pattern: SanitizerPattern,
    /// If true, taint is removed only from the assigned variable
    pub by_side_effect: bool,
}

impl TaintSanitizer {
    pub fn matches(&self, text: &str) -> bool {
        self.pattern.matches(text)
    }
}

/// A custom propagation rule (similar to Semgrep's pattern-propagators).
#[derive(Debug, Clone)]
pub struct TaintPropagator {
    /// Rule ID
    pub rule_id: String,
    /// Call pattern that triggers propagation
    pub trigger_pattern: String,
    /// Which argument carries the source taint
    pub from_arg: String,
    /// Which argument/return receives the propagated taint
    pub to_arg: String,
}

impl TaintPropagator {
    /// Check if this propagator matches a given callee.
    pub fn matches_callee(&self, callee: &str) -> bool {
        callee.contains(&self.trigger_pattern)
    }
}

/// A trait for taint analysis rules.
///
/// Each rule defines its own sources, sinks, sanitizers, and propagators.
pub trait TaintRule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> &'static str;

    /// Sources of untrusted data for this rule.
    fn sources(&self) -> Vec<TaintSource>;

    /// Dangerous sinks for this rule.
    fn sinks(&self) -> Vec<TaintSink>;

    /// Sanitizers that neutralize taint.
    fn sanitizers(&self) -> Vec<TaintSanitizer> {
        Vec::new()
    }

    /// Custom propagation rules.
    fn propagators(&self) -> Vec<TaintPropagator> {
        Vec::new()
    }

    /// Get all labels this rule is interested in.
    fn interested_labels(&self) -> HashSet<TaintLabel> {
        let mut labels = HashSet::new();
        for source in self.sources() {
            labels.insert(source.label.clone());
        }
        for sink in self.sinks() {
            for req in &sink.requires {
                labels.insert(req.clone());
            }
        }
        labels
    }
}
