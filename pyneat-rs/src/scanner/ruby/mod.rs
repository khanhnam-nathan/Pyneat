//! Ruby language scanner.

#![allow(unused_variables)]

pub mod parser;
pub mod rules;
pub mod security_rules;
pub mod quality_rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

pub struct RubyScanner;

impl RubyScanner {
    pub fn new() -> Self { Self }
}

impl Default for RubyScanner {
    fn default() -> Self { Self::new() }
}

impl LanguageScanner for RubyScanner {
    fn language(&self) -> Language { Language::Ruby }
    fn extensions(&self) -> Vec<&'static str> { vec!["rb"] }
    fn parse(&self, code: &str) -> Result<LnAst, ParseError> { parser::parse_ruby(code) }
    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut rules = rules::ruby_rules();
        rules.extend(security_rules::ruby_security_rules());
        rules.extend(quality_rules::ruby_quality_rules());
        rules
    }
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() { findings.extend(rule.detect(tree, code)); }
        findings
    }
}
