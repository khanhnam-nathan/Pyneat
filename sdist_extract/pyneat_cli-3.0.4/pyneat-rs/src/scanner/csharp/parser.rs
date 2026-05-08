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

use tree_sitter::{Node, Parser};

use crate::scanner::ln_ast::{
    LnAst, LnCall, LnClass, LnComment, LnDeepNesting, LnFunction, LnImport, LnTodo,
    TODO_MARKERS,
};
use crate::scanner::ParseError;

pub fn parse_csharp(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("csharp");
    ast.source_hash = compute_md5(code);

    walk_csharp_tree(&tree.root_node(), code, &mut ast);
    extract_csharp_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

fn walk_csharp_tree(node: &Node, code: &str, ast: &mut LnAst) {
    let kind = node.kind();
    extract_csharp_node(node, code, kind, ast);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_csharp_tree(&child, code, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

fn extract_csharp_node(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method_declaration" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let params = get_csharp_params(node, code);
            ast.functions.push(LnFunction {
                name,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                params,
                is_async: false,
                is_method: true,
                return_type: None,
            });
        }
        "class_declaration" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            ast.classes.push(LnClass {
                name,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            });
        }
        "using_directive" => {
            if let Some(n) = node.child_by_field_name("name") {
                let t = get_text(&n, code);
                ast.imports.push(LnImport {
                    module: t.clone(),
                    name: t.split('.').last().unwrap_or(&t).to_string(),
                    alias: None,
                    is_default: false,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                });
            }
        }
        "invocation_expression" => {
            let func = node.child_by_field_name("function")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            ast.calls.push(LnCall {
                callee: func,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                arguments: vec![],
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment {
                text: text.clone(),
                start_line: sp.row + 1,
                end_line: ep.row + 1,
            });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo {
                    text,
                    marker,
                    description: desc,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                });
            }
        }
        _ => {}
    }
}

fn get_csharp_params(node: &Node, code: &str) -> Vec<String> {
    let mut params = vec![];
    if let Some(params_node) = node.child_by_field_name("parameters") {
        for child in params_node.children(&mut params_node.walk()) {
            if child.kind() == "identifier" {
                params.push(get_text(&child, code));
            }
        }
    }
    params
}

fn extract_csharp_deep_nesting(node: &Node, ast: &mut LnAst) {
    let nesting_kinds = vec![
        "if_statement", "for_statement", "while_statement",
        "switch_statement", "try_statement",
    ];
    extract_nesting_recursive(node, 0, 4, &nesting_kinds, ast);
}

fn extract_nesting_recursive(node: &Node, depth: usize, threshold: usize, kinds: &[&str], ast: &mut LnAst) {
    if kinds.contains(&node.kind()) {
        let new_depth = depth + 1;
        if new_depth >= threshold {
            let sp = node.start_position();
            ast.deep_nesting.push(LnDeepNesting {
                line: sp.row + 1, column: sp.column, depth: new_depth,
            });
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_nesting_recursive(&child, new_depth, threshold, kinds, ast);
        }
    } else {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_nesting_recursive(&child, depth, threshold, kinds, ast);
        }
    }
}

fn extract_todo_marker(text: &str) -> Option<(String, String)> {
    let markers = TODO_MARKERS;
    for marker in markers {
        if let Some(pos) = text.to_uppercase().find(marker) {
            let after_start = pos + marker.len();
            let after = text[after_start..].trim_start_matches(':').trim();
            let desc_end = after.find(|c: char| !c.is_alphanumeric() && c != ' ' && c != '-' && c != '_').unwrap_or(after.len());
            return Some((marker.to_uppercase(), after[..desc_end].trim().to_string()));
        }
    }
    None
}

fn compute_md5(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csharp_method() {
        let code = r#"
using System;

public class Hello {
    public void SayHello(string name) {
        Console.WriteLine("Hello, " + name);
    }
}
"#;
        let ast = parse_csharp(code).unwrap();
        assert_eq!(ast.language, "csharp");
        assert!(!ast.classes.is_empty());
    }
}
