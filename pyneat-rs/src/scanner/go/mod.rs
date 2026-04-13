//! Go language scanner.
//!
//! Provides GoScanner that implements LanguageScanner trait.

#![allow(unused_variables)]

pub mod parser;
pub mod rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

/// Go language scanner implementation.
pub struct GoScanner;

impl GoScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageScanner for GoScanner {
    fn language(&self) -> Language {
        Language::Go
    }

    fn extensions(&self) -> Vec<&'static str> {
        vec!["go"]
    }

    fn parse(&self, code: &str) -> Result<LnAst, ParseError> {
        parser::parse_go(code)
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        rules::go_rules()
    }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() {
            findings.extend(rule.detect(tree, code));
        }
        findings
    }
}
