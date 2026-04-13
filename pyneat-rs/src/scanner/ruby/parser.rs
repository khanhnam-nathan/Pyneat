//! Ruby parser using tree-sitter.

use tree_sitter::{Node, Parser};

use crate::scanner::ln_ast::{
    LnAst, LnCall, LnClass, LnComment, LnDeepNesting, LnFunction, LnTodo,
};
use crate::scanner::ParseError;

pub fn parse_ruby(code: &str) -> Result<LnAst, ParseError> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_ruby::LANGUAGE.into())
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    let tree = parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)?;

    let mut ast = LnAst::empty("ruby");
    ast.source_hash = compute_md5(code);

    walk_ruby_tree(&tree.root_node(), code, &mut ast);
    extract_ruby_deep_nesting(&tree.root_node(), &mut ast);

    Ok(ast)
}

fn walk_ruby_tree(node: &Node, code: &str, ast: &mut LnAst) {
    let kind = node.kind();
    extract_ruby_node(node, code, kind, ast);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ruby_tree(&child, code, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

fn extract_ruby_node(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method" => {
            let name = node.child_by_field_name("name")
                .map(|n| get_text(&n, code))
                .unwrap_or_default();
            ast.functions.push(LnFunction {
                name,
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                params: vec![],
                is_async: false,
                is_method: false,
                return_type: None,
            });
        }
        "class" => {
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
        "call" | "command" => {
            // Ruby method calls: obj.method or method arg
            let func = get_text(node, code);
            if !func.is_empty() {
                ast.calls.push(LnCall {
                    callee: func,
                    start_line: sp.row + 1,
                    end_line: ep.row + 1,
                    arguments: vec![],
                });
            }
        }
        _ => {}
    }
}

fn extract_ruby_deep_nesting(node: &Node, ast: &mut LnAst) {
    let nesting_kinds = vec![
        "if_modifier", "unless_modifier", "case_statement", "when_clause",
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
    let markers = ["TODO", "FIXME", "HACK", "XXX", "NOTE", "BUG"];
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
    fn test_parse_ruby_class() {
        let code = r#"
class Hello
    def say_hello(name)
        puts "Hello, #{name}"
    end
end
"#;
        let ast = parse_ruby(code).unwrap();
        assert_eq!(ast.language, "ruby");
        assert!(!ast.classes.is_empty());
    }
}
