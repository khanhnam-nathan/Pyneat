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
