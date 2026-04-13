//! Rust language scanner.
//!
//! Provides RustScanner that implements LanguageScanner trait
//! for parsing and analyzing Rust source code.

#![allow(unused_variables)]

pub mod parser;
pub mod rules;
pub mod quality_rules;
pub mod security_rules;

use crate::scanner::ln_ast::LnAst;
use super::base::{LanguageScanner, Language, LangFinding, LangRule};
use crate::scanner::ParseError;

/// Rust language scanner implementation.
pub struct RustScanner;

impl RustScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageScanner for RustScanner {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn extensions(&self) -> Vec<&'static str> {
        vec!["rs"]
    }

    fn parse(&self, code: &str) -> Result<LnAst, ParseError> {
        parser::parse_rust(code)
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut r = rules::rust_rules();
        r.extend(quality_rules::rust_quality_rules());
        r.extend(security_rules::rust_security_rules());
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
