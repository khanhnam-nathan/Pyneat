//! JavaScript/TypeScript parser using tree-sitter.
//!
//! Extracts LN-AST from JavaScript and TypeScript source code.

use tree_sitter::{Node, Parser};

use crate::scanner::ln_ast::{
    LnAst, LnCall, LnClass, LnComment, LnDeepNesting, LnFunction, LnImport, LnTodo,
};
use crate::scanner::ParseError;

/// Parse JavaScript source code into LN-AST.
pub fn parse_javascript(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("javascript");
    ast.source_hash = compute_md5(code);

    walk_js_tree(&tree.root_node(), code, &mut ast);
    extract_js_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

/// Parse TypeScript source code into LN-AST.
pub fn parse_typescript(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("typescript");
    ast.source_hash = compute_md5(code);

    walk_js_tree(&tree.root_node(), code, &mut ast);
    extract_js_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

fn walk_js_tree(node: &Node, code: &str, ast: &mut LnAst) {
    let kind = node.kind();
    extract_js_node(node, code, kind, ast);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_js_tree(&child, code, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

fn extract_js_node(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_declaration" | "arrow_function" | "method_definition" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_else(|| "<anonymous>".to_string());
            let params = get_js_params(node, code);
            ast.functions.push(LnFunction {
                name,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                params,
                is_async: false,
                is_method: kind == "method_definition",
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
        "import_statement" | "import_declaration" => {
            let source = node.child_by_field_name("source")
                .map(|n| {
                    get_text(&n, code)
                        .trim_matches(|c| c == '\'' || c == '"')
                        .to_string()
                })
                .unwrap_or_default();
            for child in node.children(&mut node.walk()) {
                if child.kind() == "import_specifier" {
                    let name = child.child_by_field_name("name")
                        .map(|n| get_text(&n, code))
                        .unwrap_or_default();
                    let alias = child.child_by_field_name("alias")
                        .map(|n| get_text(&n, code));
                    ast.imports.push(LnImport {
                        module: source.clone(),
                        name,
                        alias,
                        is_default: false,
                        start_line: sp.row + 1,
                        end_line: ep.row + 1,
                    });
                } else if child.kind() == "identifier" {
                    let t = get_text(&child, code);
                    if !t.is_empty() && t != "import" {
                        ast.imports.push(LnImport {
                            module: source.clone(),
                            name: t,
                            alias: None,
                            is_default: true,
                            start_line: sp.row + 1,
                            end_line: ep.row + 1,
                        });
                    }
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
        "string" | "template_string" => {
            ast.comments.push(LnComment {
                text: get_text(node, code),
                start_line: sp.row + 1,
                end_line: ep.row + 1,
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
            let body = node.child_by_field_name("body");
            let _is_empty = body.map(|b| b.named_child_count() == 0).unwrap_or(true);
            ast.comments.push(LnComment {
                text: format!("catch ({})", param.clone().unwrap_or_default()),
                start_line: sp.row + 1,
                end_line: ep.row + 1,
            });
        }
        _ => {}
    }
}

fn get_js_params(node: &Node, code: &str) -> Vec<String> {
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

fn extract_js_deep_nesting(node: &Node, ast: &mut LnAst) {
    let nesting_kinds = vec![
        "if_statement",
        "for_statement",
        "for_in_statement",
        "for_of_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "try_statement",
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
    fn test_parse_js_function() {
        let code = r#"
function hello(name) {
    console.log("Hello, " + name + "!");
    return "Hello, " + name + "!";
}
"#;
        let ast = parse_javascript(code).unwrap();
        assert_eq!(ast.language, "javascript");
        assert!(!ast.functions.is_empty());
        assert_eq!(ast.functions[0].name, "hello");
    }

    #[test]
    fn test_parse_ts_function() {
        let code = r#"
function greet(name: string): string {
    console.log("Hello, " + name);
    return "Hello, " + name;
}
"#;
        let ast = parse_typescript(code).unwrap();
        assert_eq!(ast.language, "typescript");
        assert!(!ast.functions.is_empty());
    }

    #[test]
    fn test_parse_js_comments() {
        let code = r#"
// TODO: Implement this
function foo() {
    // FIXME: Handle error
}
"#;
        let ast = parse_javascript(code).unwrap();
        assert!(!ast.comments.is_empty());
        assert!(!ast.todos.is_empty());
    }

    #[test]
    fn test_parse_js_deep_nesting() {
        let code = r#"
if (true) {
    if (true) {
        if (true) {
            if (true) {
                console.log("too deep!");
            }
        }
    }
}
"#;
        let ast = parse_javascript(code).unwrap();
        assert!(!ast.deep_nesting.is_empty());
    }
}
