//! Java language scanner.

pub mod parser;
pub mod rules;
pub mod security_rules;
pub mod quality_rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

pub struct JavaScanner;

impl JavaScanner {
    pub fn new() -> Self { Self }
}

impl Default for JavaScanner {
    fn default() -> Self { Self::new() }
}

impl LanguageScanner for JavaScanner {
    fn language(&self) -> Language { Language::Java }
    fn extensions(&self) -> Vec<&'static str> { vec!["java"] }
    fn parse(&self, code: &str) -> Result<LnAst, ParseError> { parser::parse_java(code) }
    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut r = rules::java_rules();
        r.extend(security_rules::java_security_rules());
        r.extend(quality_rules::java_quality_rules());
        r
    }
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() { findings.extend(rule.detect(tree, code)); }
        findings
    }
}
