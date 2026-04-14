//! PyNeat Rust Security Scanner
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program. If not, see <https://www.gnu.org/licenses/>.

#![allow(unused_variables)]

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
