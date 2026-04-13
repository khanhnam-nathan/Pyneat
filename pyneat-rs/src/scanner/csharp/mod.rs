//! C# language scanner.

#![allow(unused_variables)]

pub mod parser;
pub mod rules;
pub mod quality_rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

pub struct CSharpScanner;

impl CSharpScanner {
    pub fn new() -> Self { Self }
}

impl Default for CSharpScanner {
    fn default() -> Self { Self::new() }
}

impl LanguageScanner for CSharpScanner {
    fn language(&self) -> Language { Language::CSharp }
    fn extensions(&self) -> Vec<&'static str> { vec!["cs"] }
    fn parse(&self, code: &str) -> Result<LnAst, ParseError> { parser::parse_csharp(code) }
    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut rules = rules::csharp_rules();
        rules.extend(quality_rules::csharp_quality_rules());
        rules
    }
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() { findings.extend(rule.detect(tree, code)); }
        findings
    }
}
