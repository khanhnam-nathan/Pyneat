//! JavaScript/TypeScript language scanner.
//!
//! Provides JavaScriptScanner and TypeScriptScanner that implement LanguageScanner trait.

pub mod parser;
pub mod rules;
pub mod quality_rules;
pub mod security_rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

/// JavaScript language scanner implementation.
pub struct JavaScriptScanner;

impl JavaScriptScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JavaScriptScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageScanner for JavaScriptScanner {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn extensions(&self) -> Vec<&'static str> {
        vec!["js", "jsx", "mjs", "cjs"]
    }

    fn parse(&self, code: &str) -> Result<LnAst, ParseError> {
        parser::parse_javascript(code)
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut r = rules::js_rules();
        r.extend(quality_rules::js_quality_rules());
        r.extend(security_rules::js_security_rules());
        r
    }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() {
            findings.extend(rule.detect(tree, code));
        }
        findings
    }
}

/// TypeScript language scanner implementation.
pub struct TypeScriptScanner;

impl TypeScriptScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypeScriptScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageScanner for TypeScriptScanner {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn extensions(&self) -> Vec<&'static str> {
        vec!["ts", "tsx"]
    }

    fn parse(&self, code: &str) -> Result<LnAst, ParseError> {
        parser::parse_typescript(code)
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut r = rules::js_rules();
        r.extend(quality_rules::js_quality_rules());
        r.extend(security_rules::js_security_rules());
        r
    }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() {
            findings.extend(rule.detect(tree, code));
        }
        findings
    }
}
