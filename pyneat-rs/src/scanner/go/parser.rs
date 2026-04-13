//! Go parser using tree-sitter.
//!
//! Extracts LN-AST from Go source code.

use tree_sitter::{Node, Parser};

use crate::scanner::ln_ast::{
    LnAst, LnCall, LnComment, LnDeepNesting, LnFunction, LnImport, LnTodo,
};
use crate::scanner::ParseError;

/// Parse Go source code into LN-AST.
pub fn parse_go(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("go");
    ast.source_hash = compute_md5(code);

    walk_go_tree(&tree.root_node(), code, &mut ast);
    extract_go_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

fn walk_go_tree(node: &Node, code: &str, ast: &mut LnAst) {
    let kind = node.kind();
    extract_go_node(node, code, kind, ast);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_go_tree(&child, code, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

fn extract_go_node(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_declaration" | "method_declaration" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let params = get_go_params(node, code);
            ast.functions.push(LnFunction {
                name,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                params,
                is_async: false,
                is_method: kind == "method_declaration",
                return_type: None,
            });
        }
        "import_declaration" => {
            for child in node.children(&mut node.walk()) {
                if child.kind() == "import_specifier" {
                    let name = child.child_by_field_name("name")
                        .map(|n| get_text(&n, code))
                        .unwrap_or_default();
                    let alias = child.child_by_field_name("alias")
                        .map(|n| get_text(&n, code));
                    ast.imports.push(LnImport {
                        module: String::new(),
                        name,
                        alias,
                        is_default: false,
                        start_line: sp.row + 1,
                        end_line: ep.row + 1,
                    });
                }
            }
        }
        "call_expression" => {
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

fn get_go_params(node: &Node, code: &str) -> Vec<String> {
    let mut params = vec![];
    if let Some(params_node) = node.child_by_field_name("parameters") {
        for child in params_node.children(&mut params_node.walk()) {
            if child.kind() == "parameter_declaration" {
                if let Some(name) = child.child_by_field_name("name") {
                    params.push(get_text(&name, code));
                }
            }
        }
    }
    params
}

fn extract_go_deep_nesting(node: &Node, ast: &mut LnAst) {
    let nesting_kinds = vec![
        "if_statement",
        "for_statement",
        "switch_statement",
    ];
    extract_nesting_recursive(node, 0, 4, &nesting_kinds, ast);
}

fn extract_nesting_recursive(
    node: &Node,
    depth: usize,
    threshold: usize,
    kinds: &[&str],
    ast: &mut LnAst,
) {
    if kinds.contains(&node.kind()) {
        let new_depth = depth + 1;
        if new_depth >= threshold {
            let sp = node.start_position();
            ast.deep_nesting.push(LnDeepNesting {
                line: sp.row + 1,
                column: sp.column,
                depth: new_depth,
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
    let markers = ["TODO", "FIXME", "HACK", "XXX", "NOTE", "BUG"];
    for marker in markers {
        if let Some(pos) = text.to_uppercase().find(marker) {
            let after_start = pos + marker.len();
            let after = text[after_start..].trim_start_matches(':').trim();
            let desc_end = after
                .find(|c: char| !c.is_alphanumeric() && c != ' ' && c != '-' && c != '_')
                .unwrap_or(after.len());
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
    fn test_parse_go_function() {
        let code = r#"
package main

import "fmt"

func hello(name string) string {
    fmt.Println("Hello, " + name)
    return "Hello, " + name
}
"#;
        let ast = parse_go(code).unwrap();
        assert_eq!(ast.language, "go");
        assert!(!ast.functions.is_empty());
        assert_eq!(ast.functions[0].name, "hello");
    }

    #[test]
    fn test_parse_go_comments() {
        let code = r#"
// TODO: Implement this
func foo() {
    // FIXME: Handle error
}
"#;
        let ast = parse_go(code).unwrap();
        assert!(!ast.comments.is_empty());
        assert!(!ast.todos.is_empty());
    }
}
