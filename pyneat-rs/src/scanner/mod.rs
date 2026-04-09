//! Tree-sitter based AST parsing.
//!
//! This module provides AST parsing using tree-sitter-python grammar.

pub mod tree_sitter;

pub use tree_sitter::{parse, ParseError, NodeInfo, walk_tree};
