//! Rule system for pyneat-rs.
//!
//! This module defines the core Rule trait and implementations
//! for security, quality, and refactoring rules.

pub mod base;
pub mod quality;
pub use base::Rule;

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
