//! Auto-fix system for pyneat-rs.
//!
//! Provides functions to apply fixes to code and generate diffs.

pub mod apply_fix;
pub mod diff;

pub use apply_fix::*;
pub use diff::*;
