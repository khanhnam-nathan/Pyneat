//! Rule system for pyneat-rs.
//!
//! This module defines the core Rule trait and implementations
//! for security, quality, and refactoring rules.

pub mod base;
pub mod quality;
pub mod security;
pub mod sec024;
pub mod sec025;
pub mod sec026;
pub mod sec042;
pub mod sec043;
pub mod sec044;

pub use base::*;
pub use security::*;
pub use quality::*;
