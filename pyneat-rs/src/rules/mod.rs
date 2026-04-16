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

pub mod base;
pub mod quality;
pub use base::{extract_snippet, Rule};

// Security rules organized into submodules:
// - security/ (security.rs) - core Python security rules (SEC-001 to SEC-059)
// - sec024.rs to sec044.rs - extended security rules
// - sec060.rs to sec072.rs - more extended rules
// - security/php.rs - PHP-specific rules (SEC-073 to SEC-090)
pub mod security;

// PHP-specific security rules (SEC-073 to SEC-090) in php_rules/ directory
pub mod php_rules;

pub mod sec024;
pub mod sec025;
pub mod sec026;
pub mod sec042;
pub mod sec043;
pub mod sec044;
// SEC-060 to SEC-072
pub mod sec060;
pub mod sec061;
pub mod sec062;
pub mod sec063;
pub mod sec064;
pub mod sec065;
pub mod sec066;
pub mod sec067;
pub mod sec068;
pub mod sec069;
pub mod sec070;
pub mod sec071;
pub mod sec072;
// SEC-073 to SEC-090 are now in security/php.rs (via security module)

// Extended security rules (SEC-073 to SEC-105+) in extended_security.rs
pub mod extended_security;

// AST-based security rules (semantic analysis on tree-sitter AST)
pub mod ast_rules;
