//! Enterprise Scanner
//!
//! Runs all enterprise-grade rules across any file type.

use crate::scanner::base::{LangRule, LangFinding};
use crate::scanner::ln_ast::LnAst;
use crate::scanner::ParseError;
use crate::scanner::multilang::Language;
use crate::scanner::enterprise::*;

pub struct EnterpriseScanner;

impl EnterpriseScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnterpriseScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::scanner::base::LanguageScanner for EnterpriseScanner {
    fn language(&self) -> Language {
        Language::Python // Dummy; enterprise rules run on all languages
    }

    fn extensions(&self) -> Vec<&'static str> {
        // Enterprise rules run on ALL file types
        vec!["py", "js", "ts", "tsx", "jsx", "go", "java", "rs", "cs", "php", "rb",
             "yaml", "yml", "json", "toml", "txt", "lock", "sum"]
    }

    fn parse(&self, _code: &str) -> Result<LnAst, ParseError> {
        Ok(LnAst::empty("enterprise"))
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        let mut all_rules: Vec<Box<dyn LangRule>> = vec![];
        all_rules.extend(gdpr_pii_rules());
        all_rules.extend(audit_trail_rules());
        all_rules.extend(oauth_sso_rules());
        all_rules.extend(rate_limit_rules());
        all_rules.extend(tenant_isolation_rules());
        all_rules.extend(data_exfil_rules());
        all_rules.extend(supply_chain_lock_rules());
        all_rules.extend(infrastructure_security_rules());
        all_rules
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        for rule in self.rules() {
            findings.extend(rule.detect(_tree, code));
        }
        findings
    }
}
