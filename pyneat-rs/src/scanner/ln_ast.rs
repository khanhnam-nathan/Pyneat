//! Language-Neutral AST (LN-AST) types.
//!
//! This module defines a language-agnostic AST representation that can
//! be serialized to JSON and consumed by the Python engine.
//!
//! Supported languages: Python, JavaScript, TypeScript, Go, Java, Rust, C#, PHP, Ruby

use serde::{Deserialize, Serialize};

/// A language-neutral function/method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnFunction {
    /// Function name
    pub name: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
    /// Byte offset in source
    pub start_byte: usize,
    /// Byte offset in source
    pub end_byte: usize,
    /// Parameter names
    pub params: Vec<String>,
    /// Is async function
    pub is_async: bool,
    /// Is a method (inside class)
    pub is_method: bool,
    /// Return type annotation (if present)
    pub return_type: Option<String>,
}

/// A language-neutral class/struct/interface definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnClass {
    /// Class name
    pub name: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
    /// Byte offset in source
    pub start_byte: usize,
    /// Byte offset in source
    pub end_byte: usize,
}

/// A language-neutral import/use/require statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnImport {
    /// Module path (e.g., "os.path", "react", "fmt")
    pub module: String,
    /// Imported name
    pub name: String,
    /// Alias if renamed (e.g., "from os import path as p")
    pub alias: Option<String>,
    /// Is default import (e.g., JS: `import X from 'y'`)
    pub is_default: bool,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A language-neutral variable assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnAssignment {
    /// Variable name
    pub name: String,
    /// Source text of RHS (for value analysis)
    pub value: Option<String>,
    /// Is a constant (const, final, let in upper case)
    pub is_constant: bool,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A language-neutral function/method call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnCall {
    /// Full call expression (e.g., "os.path.join", "console.log")
    pub callee: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
    /// Source texts of arguments
    pub arguments: Vec<String>,
}

/// A language-neutral string literal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnString {
    /// Raw value (quotes stripped)
    pub value: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A language-neutral comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnComment {
    /// Comment text (including comment markers)
    pub text: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A language-neutral catch/except block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnCatchBlock {
    /// Exception type caught (if specified)
    pub exception_type: Option<String>,
    /// Is body empty or just pass/continue?
    pub is_empty: bool,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A source comment/TODO/FIXME marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnTodo {
    /// Full comment text
    pub text: String,
    /// Marker type: "TODO", "FIXME", "HACK", "XXX", "NOTE"
    pub marker: String,
    /// Description after the marker
    pub description: String,
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line
    pub end_line: usize,
}

/// A deeply nested block for arrow anti-pattern detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnDeepNesting {
    /// 1-indexed line number
    pub line: usize,
    /// 0-indexed column
    pub column: usize,
    /// Nesting depth level
    pub depth: usize,
}

/// Complete LN-AST for a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnAst {
    /// Language identifier: "python", "javascript", "go", etc.
    pub language: String,
    /// MD5 hash of source for cache validation
    pub source_hash: String,
    /// All function/method definitions
    pub functions: Vec<LnFunction>,
    /// All class/struct/interface definitions
    pub classes: Vec<LnClass>,
    /// All import statements
    pub imports: Vec<LnImport>,
    /// All variable assignments
    pub assignments: Vec<LnAssignment>,
    /// All function/method calls
    pub calls: Vec<LnCall>,
    /// All string literals
    pub strings: Vec<LnString>,
    /// All comments
    pub comments: Vec<LnComment>,
    /// All catch/except blocks
    pub catch_blocks: Vec<LnCatchBlock>,
    /// All TODO/FIXME markers
    pub todos: Vec<LnTodo>,
    /// Lines with deep nesting (for arrow anti-pattern)
    pub deep_nesting: Vec<LnDeepNesting>,
}

impl LnAst {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }

    /// Create an empty LN-AST for a language.
    pub fn empty(language: &str) -> Self {
        Self {
            language: language.to_string(),
            source_hash: String::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            imports: Vec::new(),
            assignments: Vec::new(),
            calls: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
            catch_blocks: Vec::new(),
            todos: Vec::new(),
            deep_nesting: Vec::new(),
        }
    }
}
