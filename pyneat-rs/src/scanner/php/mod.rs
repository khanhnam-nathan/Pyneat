//! PHP language scanner.

#![allow(unused_variables)]

pub mod parser;
pub mod rules;
pub mod security_rules;
pub mod quality_rules;

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LanguageScanner, Language, LangRule, LangFinding};
use crate::scanner::ParseError;

pub struct PhpScanner;

impl PhpScanner {
    pub fn new() -> Self { Self }
}

impl Default for PhpScanner {
    fn default() -> Self { Self::new() }
}

impl LanguageScanner for PhpScanner {
    fn language(&self) -> Language { Language::Php }
    fn extensions(&self) -> Vec<&'static str> { vec!["php"] }
    fn parse(&self, code: &str) -> Result<LnAst, ParseError> { parser::parse_php(code) }
    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut rules = rules::php_rules();
        rules.extend(security_rules::php_security_rules());
        rules.extend(quality_rules::php_quality_rules());
        rules
    }
    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() { findings.extend(rule.detect(tree, code)); }
        findings
    }
}
