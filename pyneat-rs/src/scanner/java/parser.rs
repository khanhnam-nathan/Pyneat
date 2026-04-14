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

/// Parse Java source code into LN-AST.
pub fn parse_java(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_java::LANGUAGE.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("java");
    ast.source_hash = compute_md5(code);

    walk_java_tree(&tree.root_node(), code, &mut ast);
    extract_java_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

fn walk_java_tree(node: &Node, code: &str, ast: &mut LnAst) {
    let kind = node.kind();
    extract_java_node(node, code, kind, ast);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_java_tree(&child, code, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

fn extract_java_node(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method_declaration" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let params = get_java_params(node, code);
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
        "class_declaration" | "interface_declaration" => {
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
        "import_declaration" => {
            if let Some(m) = node.child_by_field_name("module").map(|n| get_text(&n, code)) {
                ast.imports.push(LnImport {
                    module: m.clone(),
                    name: m.split('.').last().unwrap_or(&m).to_string(),
                    alias: None,
                    is_default: false,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                });
            }
        }
        "method_invocation" => {
            let func = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let arguments = extract_java_arguments(node, code);
            let object_text = node.child_by_field_name("object")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let callee = if object_text.is_empty() {
                func.clone()
            } else {
                format!("{}.{}", object_text, func)
            };
            ast.calls.push(LnCall {
                callee,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                arguments,
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
        "catch_clause" => {
            let param = node.child_by_field_name("parameter")
                .map(|n| get_text(&n, code));
            ast.comments.push(LnComment {
                text: format!("catch ({})", param.clone().unwrap_or_default()),
                start_line: sp.row + 1,
                end_line: ep.row + 1,
            });
        }
        "object_creation_expression" => {
            let type_node = node.child_by_field_name("type");
            let type_name = type_node
                .and_then(|n| n.child_by_field_name("name"))
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let constructor = type_node
                .and_then(|n| n.child_by_field_name("scoped_identifier"))
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            let callee = if constructor.is_empty() {
                type_name.clone()
            } else {
                constructor
            };
            if !callee.is_empty() {
                let arguments = extract_java_arguments(node, code);
                ast.calls.push(LnCall {
                    callee,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                    arguments,
                });
            }
        }
        "field_access" => {
            let object_node = node.child_by_field_name("object");
            let field_node = node.child_by_field_name("field");
            let object_text = object_node.map(|n| get_text(&n, code)).unwrap_or_default();
            let field_text = field_node.map(|n| get_text(&n, code)).unwrap_or_default();
            if !object_text.is_empty() && !field_text.is_empty() {
                let callee = format!("{}.{}", object_text, field_text);
                ast.calls.push(LnCall {
                    callee,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                    arguments: vec![],
                });
            }
        }
        _ => {}
    }
}

fn get_java_params(node: &Node, code: &str) -> Vec<String> {
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

/// Extract argument texts from a method invocation node.
fn extract_java_arguments(node: &Node, code: &str) -> Vec<String> {
    let mut args = vec![];
    if let Some(args_node) = node.child_by_field_name("arguments") {
        for child in args_node.children(&mut args_node.walk()) {
            let kind = child.kind();
            if kind == "string_literal"
                || kind == "identifier"
                || kind == "integer_literal"
                || kind == "decimal_integer_literal"
                || kind == "binary_expression"
                || kind == "method_invocation"
            {
                let text = get_text(&child, code);
                if !text.is_empty() {
                    args.push(text);
                }
            }
        }
    }
    args
}

fn extract_java_deep_nesting(node: &Node, ast: &mut LnAst) {
    let nesting_kinds = vec![
        "if_statement",
        "for_statement",
        "while_statement",
        "try_statement",
        "synchronized_statement",
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
    let markers = TODO_MARKERS;
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
    fn test_parse_java_method() {
        let code = r#"
public class Hello {
    public String hello(String name) {
        System.out.println("Hello, " + name);
        return "Hello, " + name;
    }
}
"#;
        let ast = parse_java(code).unwrap();
        assert_eq!(ast.language, "java");
        assert!(!ast.classes.is_empty());
        assert!(!ast.functions.is_empty());
    }

    #[test]
    fn test_parse_java_comments() {
        let code = r#"
class Foo {
    void bar() {}
}
"#;
        let ast = parse_java(code).unwrap();
        assert_eq!(ast.language, "java");
        assert!(!ast.classes.is_empty());
    }
}
