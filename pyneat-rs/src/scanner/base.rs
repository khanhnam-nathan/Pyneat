//! LanguageScanner trait and LanguageRegistry.
//!
//! Provides a common interface for language-specific scanners,
//! each with their own parser and rules.

#![allow(dead_code)]
#![allow(unused_variables)]

use std::collections::HashMap;
use std::path::Path;

use super::ln_ast::LnAst;
use super::multilang::detect_language_from_extension;
pub use super::multilang::Language;
use super::ParseError;

/// A finding for language-specific rules (uses line numbers instead of byte offsets).
#[derive(Debug, Clone)]
pub struct LangFinding {
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    /// Byte offset start (for auto-fix)
    pub start_byte: usize,
    /// Byte offset end (for auto-fix)
    pub end_byte: usize,
    pub snippet: String,
    pub problem: String,
    pub fix_hint: String,
    /// Whether auto-fix is available for this finding
    pub auto_fix_available: bool,
}

impl LangFinding {
    /// Create a new finding without byte offsets (for line-based detection)
    pub fn new(rule_id: &str, severity: &str, line: usize, snippet: &str, problem: &str, fix_hint: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line,
            column: 0,
            start_byte: 0,
            end_byte: 0,
            snippet: snippet.to_string(),
            problem: problem.to_string(),
            fix_hint: fix_hint.to_string(),
            auto_fix_available: false,
        }
    }

    /// Create a finding with byte offsets (for AST-based detection)
    pub fn with_bytes(rule_id: &str, severity: &str, line: usize, start_byte: usize, end_byte: usize, snippet: &str, problem: &str, fix_hint: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line,
            column: 0,
            start_byte,
            end_byte,
            snippet: snippet.to_string(),
            problem: problem.to_string(),
            fix_hint: fix_hint.to_string(),
            auto_fix_available: false,
        }
    }
}

/// A fix for a language-specific finding.
#[derive(Debug, Clone)]
pub struct LangFix {
    pub rule_id: String,
    pub original: String,
    pub replacement: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub description: String,
}

/// Trait for language-specific rules that work with LnAst.
pub trait LangRule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> &'static str;

    /// Detect issues in the given AST.
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding>;

    /// Apply an auto-fix for a finding.
    ///
    /// Returns `None` if auto-fix is not available for this finding.
    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let _ = (finding, code);
        None
    }

    /// Check if this rule supports auto-fix.
    fn supports_auto_fix(&self) -> bool {
        false
    }
}

/// Trait for language-specific scanners.
/// Each language has its own parser and rules.
pub trait LanguageScanner: Send + Sync {
    /// The language this scanner handles.
    fn language(&self) -> Language;

    /// File extensions this scanner handles (without dot).
    fn extensions(&self) -> Vec<&'static str>;

    /// Parse source code into LN-AST.
    fn parse(&self, code: &str) -> Result<LnAst, ParseError>;

    /// Get rules specific to this language.
    fn rules(&self) -> Vec<Box<dyn LangRule>>;

    /// Detect issues using this language's rules.
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() {
            findings.extend(rule.detect(tree, code));
        }
        findings
    }
}

/// A registry of all language scanners.
pub struct LanguageRegistry {
    scanners: HashMap<Language, Box<dyn LanguageScanner>>,
}

impl LanguageRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            scanners: HashMap::new(),
        }
    }

    /// Register a scanner.
    pub fn register<S: LanguageScanner + 'static>(&mut self, scanner: S) {
        self.scanners.insert(scanner.language(), Box::new(scanner));
    }

    /// Get a scanner by language.
    pub fn for_language(&self, lang: Language) -> Option<&dyn LanguageScanner> {
        self.scanners.get(&lang).map(|b| b.as_ref())
    }

    /// Get a scanner by language name string.
    pub fn for_language_str(&self, lang: &str) -> Option<&dyn LanguageScanner> {
        let lang = Language::from_str(lang)?;
        self.for_language(lang)
    }

    /// Detect language from file extension and scan.
    pub fn scan_file(&self, code: &str, path: &Path) -> Result<LnAst, ParseError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| ParseError::LanguageError("Unknown extension".to_string()))?;

        let lang_name = detect_language_from_extension(ext)
            .ok_or_else(|| ParseError::LanguageError(format!("Unknown extension: {}", ext)))?;

        let lang = Language::from_str(&lang_name)
            .ok_or_else(|| ParseError::LanguageError(lang_name.clone()))?;

        let scanner = self.for_language(lang)
            .ok_or_else(|| ParseError::LanguageError(format!("No scanner for {}", lang_name)))?;

        scanner.parse(code)
    }

    /// Scan with explicit language name.
    pub fn scan(&self, code: &str, language: &str) -> Result<LnAst, ParseError> {
        let scanner = self.for_language_str(language)
            .ok_or_else(|| ParseError::LanguageError(format!("Unknown language: {}", language)))?;
        scanner.parse(code)
    }

    /// Get all registered languages.
    pub fn supported_languages(&self) -> Vec<Language> {
        self.scanners.keys().cloned().collect()
    }
}

impl Default for LanguageRegistry {
    fn default() -> Self {
        Self::new()
    }
}
