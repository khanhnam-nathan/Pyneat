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

#![allow(dead_code)]

use tree_sitter::{Parser, Tree};

/// Get the tree-sitter-python language reference.
pub fn language() -> tree_sitter::Language {
    tree_sitter_python::LANGUAGE.into()
}

/// Parse Python source code into a tree-sitter Tree.
pub fn parse(code: &str) -> Result<Tree, ParseError> {
    let lang = language();
    let mut parser = Parser::new();

    parser
        .set_language(&lang)
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    parser
        .parse(code, None)
        .ok_or(ParseError::ParseFailed)
}

/// Parse error types.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Failed to set tree-sitter language.
    LanguageError(String),
    /// Parsing failed.
    ParseFailed,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::LanguageError(e) => write!(f, "Language error: {}", e),
            ParseError::ParseFailed => write!(f, "Failed to parse code"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Information about a captured node.
#[derive(Debug, Clone)]
pub struct NodeInfo<'a> {
    pub node_type: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_point: tree_sitter::Point,
    pub end_point: tree_sitter::Point,
    pub code: &'a str,
}

impl<'a> NodeInfo<'a> {
    /// Get the text content of this node.
    pub fn text(&self) -> &'a str {
        &self.code[self.start_byte..self.end_byte]
    }

    /// Get the line number (1-indexed) for the start of this node.
    pub fn start_line(&self) -> usize {
        self.start_point.row + 1
    }

    /// Get the line number (1-indexed) for the end of this node.
    pub fn end_line(&self) -> usize {
        self.end_point.row + 1
    }

    /// Get the column number (0-indexed) for the start.
    pub fn start_column(&self) -> usize {
        self.start_point.column
    }

    /// Get the column number (0-indexed) for the end.
    pub fn end_column(&self) -> usize {
        self.end_point.column
    }
}

/// Walk all nodes in the tree and call the visitor function.
pub fn walk_tree<F>(tree: &Tree, code: &str, mut visitor: F)
where
    F: FnMut(NodeInfo),
{
    let mut cursor = tree.walk();
    loop {
        let node = cursor.node();
        let info = NodeInfo {
            node_type: node.kind().to_string(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_point: node.start_position(),
            end_point: node.end_position(),
            code,
        };
        visitor(info);

        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                return;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_code() {
        let code = "x = 1";
        let tree = parse(code).expect("Failed to parse");
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn test_parse_with_function() {
        let code = r#"
def hello():
    print("Hello, World!")
"#;
        let tree = parse(code).expect("Failed to parse");
        assert_eq!(tree.root_node().kind(), "module");
    }
}
