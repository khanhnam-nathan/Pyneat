//! LnAstConverter — converts tree-sitter nodes to language-neutral AST.
//!
//! Provides a unified way to extract code structures
//! (functions, classes, imports, calls) from any supported language,
//! converting them into LnAst structures that rules can consume uniformly.

use crate::scanner::ln_ast::{
    LnAssignment, LnAst, LnCall, LnCatchBlock, LnClass, LnComment, LnDeepNesting,
    LnFunction, LnImport, LnString, LnTodo, TODO_MARKERS,
};
use crate::scanner::tree_sitter::{walk_tree, NodeInfo};
use tree_sitter::Tree;
use std::collections::HashSet;

const LANGUAGES: &[&str] = &[
    "python", "javascript", "typescript", "java",
    "go", "rust", "csharp", "php", "ruby",
];

// --------------------------------------------------------------------------
// LnAstConverter
// --------------------------------------------------------------------------

/// Converts tree-sitter trees into language-neutral AST structures.
pub struct LnAstConverter {
    language: String,
}

impl LnAstConverter {
    /// Create a new converter for the given language.
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_string(),
        }
    }

    /// Convert a tree-sitter Tree into LnAst.
    pub fn convert(&self, tree: &Tree, code: &str) -> LnAst {
        let mut functions = Vec::new();
        let mut classes = Vec::new();
        let mut imports = Vec::new();
        let mut calls = Vec::new();
        let mut strings = Vec::new();
        let mut comments = Vec::new();
        let mut catch_blocks = Vec::new();
        let mut todos = Vec::new();
        let mut assignments = Vec::new();
        let mut deep_nesting = Vec::new();
        let mut nesting_depth = 0usize;

        walk_tree(tree, code, |info| {
            let kind = info.node_type.as_str();

            if matches!(kind, "class_definition" | "class_declaration" | "class") {
                if let Some(cls) = self.extract_class(&info) {
                    classes.push(cls);
                }
            }

            if matches!(
                kind,
                "function_definition"
                    | "async_function_definition"
                    | "function_declaration"
                    | "function_item"
                    | "method_declaration"
                    | "constructor_declaration"
                    | "def"
                    | "defs"
            ) {
                if let Some(f) = self.extract_function(&info) {
                    functions.push(f);
                }
            }

            if matches!(
                kind,
                "import_statement"
                    | "import_from_statement"
                    | "import"
                    | "require"
                    | "import_declaration"
                    | "namespace_use_directive"
                    | "use_declaration"
            ) {
                if let Some(imp) = self.extract_import(&info) {
                    imports.push(imp);
                }
            }

            if matches!(kind, "call") {
                if let Some(call) = self.extract_call(&info) {
                    calls.push(call);
                }
            }

            if matches!(
                kind,
                "string"
                    | "string_literal"
                    | "interpreted_string_literal"
                    | "concatenated_string"
                    | "heredoc_body"
            ) {
                if let Some(s) = self.extract_string(&info) {
                    strings.push(s);
                }
            }

            if matches!(kind, "comment") {
                if let Some(todo) = self.extract_todo(&info) {
                    todos.push(todo);
                } else {
                    comments.push(LnComment {
                        text: info.text().to_string(),
                        start_line: info.start_line(),
                        end_line: info.end_line(),
                    });
                }
            }

            if matches!(kind, "try_statement") {
                self.extract_catches(&info, &mut catch_blocks);
            }

            if matches!(
                kind,
                "assignment"
                    | "augmented_assignment"
                    | "local_variable_declaration"
                    | "variable_declarator"
            ) {
                if let Some(a) = self.extract_assignment(&info) {
                    assignments.push(a);
                }
            }

            if kind == "comment" || kind == "block_comment" {
                nesting_depth = 0;
            } else if matches!(
                kind,
                "if_statement"
                    | "for_statement"
                    | "while_statement"
                    | "with_statement"
                    | "block"
                    | "compound_statement"
            ) {
                nesting_depth += 1;
                if nesting_depth > 5 {
                    deep_nesting.push(LnDeepNesting {
                        line: info.start_line(),
                        column: info.start_column(),
                        depth: nesting_depth,
                    });
                }
            } else if kind.ends_with("_statement") || kind.ends_with("_declaration") {
                if nesting_depth > 0 {
                    nesting_depth -= 1;
                }
            }
        });

        let source_hash = format!("{:x}", md5_hash(code));

        LnAst {
            language: self.language.clone(),
            source_hash,
            functions,
            classes,
            imports,
            assignments,
            calls,
            strings,
            comments,
            catch_blocks,
            todos,
            deep_nesting,
        }
    }

    fn extract_function(&self, info: &NodeInfo) -> Option<LnFunction> {
        let text = info.text();
        let name = extract_function_name(&self.language, text);
        if name.is_empty() {
            return None;
        }
        let params = extract_params(&self.language, text);
        let is_async = text.contains("async")
            && matches!(
                self.language.as_str(),
                "python" | "javascript" | "typescript"
            );
        Some(LnFunction {
            name,
            start_line: info.start_line(),
            end_line: info.end_line(),
            start_byte: info.start_byte,
            end_byte: info.end_byte,
            params,
            is_async,
            is_method: false,
            return_type: extract_return_type(&self.language, text),
        })
    }

    fn extract_class(&self, info: &NodeInfo) -> Option<LnClass> {
        let text = info.text();
        let name = extract_class_name(&self.language, text);
        if name.is_empty() {
            return None;
        }
        Some(LnClass {
            name,
            start_line: info.start_line(),
            end_line: info.end_line(),
            start_byte: info.start_byte,
            end_byte: info.end_byte,
        })
    }

    fn extract_import(&self, info: &NodeInfo) -> Option<LnImport> {
        let text = info.text();
        let (module, name, alias, is_default) = match self.language.as_str() {
            "python" => extract_python_import(text),
            "javascript" | "typescript" => extract_js_import(text),
            "java" => extract_java_import(text),
            "go" => extract_go_import(text),
            "rust" => extract_rust_import(text),
            "ruby" => extract_ruby_import(text),
            "php" => extract_php_import(text),
            "csharp" => extract_csharp_import(text),
            _ => (String::new(), String::new(), None, false),
        };
        if module.is_empty() && name.is_empty() {
            return None;
        }
        Some(LnImport {
            module,
            name,
            alias,
            is_default,
            start_line: info.start_line(),
            end_line: info.end_line(),
        })
    }

    fn extract_call(&self, info: &NodeInfo) -> Option<LnCall> {
        let text = info.text();
        let callee = extract_callee(text);
        Some(LnCall {
            callee,
            start_line: info.start_line(),
            end_line: info.end_line(),
            arguments: Vec::new(),
        })
    }

    fn extract_string(&self, info: &NodeInfo) -> Option<LnString> {
        let text = info.text();
        let value = text.trim_matches(|c| c == '"' || c == '\'').to_string();
        Some(LnString {
            value,
            start_line: info.start_line(),
            end_line: info.end_line(),
        })
    }

    fn extract_todo(&self, info: &NodeInfo) -> Option<LnTodo> {
        let text = info.text();
        for marker in TODO_MARKERS {
            if let Some(pos) = text.find(marker) {
                let desc_raw = &text[pos + marker.len()..];
                let description = desc_raw
                    .trim_start_matches(':')
                    .trim_start_matches(' ')
                    .trim_start()
                    .to_string();
                return Some(LnTodo {
                    text: text.to_string(),
                    marker: marker.to_string(),
                    description,
                    start_line: info.start_line(),
                    end_line: info.end_line(),
                });
            }
        }
        None
    }

    fn extract_catches(&self, info: &NodeInfo, out: &mut Vec<LnCatchBlock>) {
        let text = info.text();
        if text.contains("except") || text.contains("catch") {
            out.push(LnCatchBlock {
                exception_type: None,
                is_empty: text.len() < 20,
                start_line: info.start_line(),
                end_line: info.end_line(),
            });
        }
    }

    fn extract_assignment(&self, info: &NodeInfo) -> Option<LnAssignment> {
        let text = info.text();
        let (name, value) = extract_assignment_info(&self.language, text);
        if name.is_empty() {
            return None;
        }
        let is_constant = name.chars().next().map_or(false, |c| c.is_uppercase())
            && !name.contains('_')
            || text.contains("const ")
            || text.contains("final ");
        Some(LnAssignment {
            name,
            value,
            is_constant,
            start_line: info.start_line(),
            end_line: info.end_line(),
        })
    }
}

// --------------------------------------------------------------------------
// Language-specific extractors
// --------------------------------------------------------------------------

fn extract_function_name(language: &str, text: &str) -> String {
    let first = text.lines().next().unwrap_or("");
    match language {
        "python" => first
            .trim_start()
            .strip_prefix("def ")
            .or_else(|| first.trim_start().strip_prefix("async def "))
            .and_then(|s| s.split('(').next())
            .map(|s| s.trim())
            .unwrap_or("")
            .to_string(),
        "javascript" | "typescript" => {
            if first.contains("function") {
                first.trim_start()
                    .strip_prefix("function ")
                    .or_else(|| first.trim_start().strip_prefix("async function "))
                    .and_then(|s| s.split('(').next())
                    .map(|s| s.trim())
                    .unwrap_or("")
                    .to_string()
            } else {
                String::new()
            }
        }
        "java" | "csharp" => first
            .split(|c| c == '(' || c == '{')
            .next()
            .and_then(|s| s.split_whitespace().last())
            .unwrap_or("")
            .to_string(),
        "go" => first
            .trim_start()
            .strip_prefix("func ")
            .and_then(|s| s.split('(').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        "rust" => first
            .trim_start()
            .strip_prefix("fn ")
            .and_then(|s| s.split(|c| c == '(' || c == '<').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        "ruby" => first
            .trim_start()
            .strip_prefix("def ")
            .or_else(|| first.trim_start().strip_prefix("defs "))
            .and_then(|s| s.split(|c| c == '(' || c == '.').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn extract_class_name(language: &str, text: &str) -> String {
    let first = text.lines().next().unwrap_or("");
    match language {
        "python" => first
            .trim_start()
            .strip_prefix("class ")
            .and_then(|s| s.split(':').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        "javascript" | "typescript" => first
            .trim_start()
            .strip_prefix("class ")
            .and_then(|s| s.split(|c| c == ' ' || c == '{').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        "java" | "csharp" => first
            .split(|c| c == ' ' || c == '{')
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string(),
        "ruby" => first
            .trim_start()
            .strip_prefix("class ")
            .or_else(|| first.trim_start().strip_prefix("module "))
            .and_then(|s| s.split(|c| c == '<' || c == ' ').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn extract_params(language: &str, text: &str) -> Vec<String> {
    if language != "python" {
        return Vec::new();
    }
    let first = text.lines().next().unwrap_or("");
    first
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| {
            s.split(',')
                .map(|p| {
                    p.trim()
                        .split(':')
                        .next()
                        .unwrap_or(p.trim())
                        .split('=')
                        .next()
                        .unwrap_or(p.trim())
                        .trim()
                        .to_string()
                })
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_return_type(language: &str, text: &str) -> Option<String> {
    let first = text.lines().next()?;
    match language {
        "typescript" => first
            .split("->")
            .nth(1)
            .or_else(|| first.rsplit(':').next())
            .map(|s| s.trim().trim_start_matches(|c: char| c.is_whitespace() || c == '{' || c == ')').to_string()),
        "rust" => first
            .split("->")
            .nth(1)
            .map(|s| s.split(|c| c == '{' || c == '(').next().unwrap_or(s).trim().to_string()),
        _ => None,
    }
}

fn extract_python_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim();
    if t.starts_with("import ") {
        let rest = t.strip_prefix("import ").unwrap().trim();
        let module = rest.split_whitespace().next().unwrap_or(rest).to_string();
        (module, String::new(), None, false)
    } else if t.starts_with("from ") {
        let rest = t.strip_prefix("from ").unwrap().trim();
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let module = parts.first().unwrap_or(&"").to_string();
        let name = parts.get(1).unwrap_or(&"").to_string();
        (module, name, None, false)
    } else {
        (String::new(), String::new(), None, false)
    }
}

fn extract_js_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim();
    if t.contains("from ") {
        let parts: Vec<&str> = t.split_whitespace().collect();
        let name = parts.get(1).unwrap_or(&"").trim_matches(|c| c == '\'' || c == '"').to_string();
        (String::new(), name, None, t.starts_with("import "))
    } else if t.contains("require(") {
        let inner = t.split("require(").nth(1).and_then(|s| s.split(')').next()).unwrap_or("");
        let module = inner.trim_matches(|c| c == '\'' || c == '"').to_string();
        (module, String::new(), None, false)
    } else {
        (String::new(), String::new(), None, false)
    }
}

fn extract_java_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim().strip_prefix("import ").unwrap_or(text).trim().trim_end_matches(';');
    let parts: Vec<&str> = t.rsplitn(2, '.').collect();
    let name = parts.first().unwrap_or(&"").to_string();
    let module = parts.get(1).map(|s| &s[..s.len().saturating_sub(1)]).unwrap_or("").to_string();
    (module, name, None, false)
}

fn extract_go_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim().strip_prefix("import ").unwrap_or(text).trim_matches('"').trim().to_string();
    (t, String::new(), None, false)
}

fn extract_rust_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim().strip_prefix("use ").unwrap_or(text).trim().trim_end_matches(';');
    let parts: Vec<&str> = t.split("::").collect();
    let name = parts.last().unwrap_or(&"").to_string();
    let module = parts[..parts.len().saturating_sub(1)].join("::");
    let alias = if t.contains(" as ") {
        t.split(" as ").nth(1).map(|s| s.trim().to_string())
    } else {
        None
    };
    (module, name, alias, false)
}

fn extract_ruby_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim();
    if t.starts_with("require ") || t.starts_with("require_relative ") {
        let rest = t.split_whitespace().nth(1).unwrap_or("").trim_matches(|c| c == '\'' || c == '"').to_string();
        (rest, String::new(), None, false)
    } else if t.starts_with("include ") || t.starts_with("extend ") {
        let rest = t.split_whitespace().nth(1).unwrap_or("");
        (String::new(), rest.to_string(), None, false)
    } else {
        (String::new(), String::new(), None, false)
    }
}

fn extract_php_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim().strip_prefix("use ").unwrap_or(text).trim_end_matches(';').trim();
    let parts: Vec<&str> = t.split("\\\\").collect();
    let name = parts.last().unwrap_or(&"").to_string();
    let module = parts[..parts.len().saturating_sub(1)].join("\\");
    (module, name, None, false)
}

fn extract_csharp_import(text: &str) -> (String, String, Option<String>, bool) {
    let t = text.trim().strip_prefix("using ").unwrap_or(text).trim_end_matches(';').trim().to_string();
    (t, String::new(), None, false)
}

fn extract_callee(text: &str) -> String {
    text.split('(')
        .next()
        .unwrap_or(text)
        .trim()
        .split_whitespace()
        .last()
        .unwrap_or("")
        .to_string()
}

fn extract_assignment_info(language: &str, text: &str) -> (String, Option<String>) {
    if language == "python" {
        if let Some(pos) = text.find('=') {
            if !text[..pos].contains("==") && !text[..pos].contains("!=") && !text[..pos].contains("<=") && !text[..pos].contains(">=") {
                let name = text[..pos].trim().to_string();
                let value = text[pos + 1..].trim().to_string();
                return (name, Some(value));
            }
        }
    } else {
        if let Some(pos) = text.find('=') {
            if !text[..pos].contains("==") && !text[..pos].contains("!=") {
                let name = text[..pos].trim().split_whitespace().last().unwrap_or("").to_string();
                let value = text[pos + 1..].trim().to_string();
                return (name, Some(value));
            }
        }
    }
    (String::new(), None)
}

fn md5_hash(text: &str) -> u128 {
    let mut hash: u128 = 0;
    for (i, byte) in text.bytes().enumerate() {
        hash = hash.wrapping_add((byte as u128).wrapping_mul(i as u128 + 1));
        hash = hash.rotate_left(1);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::tree_sitter::parse;

    #[test]
    fn test_convert_python_function() {
        let code = r#"
def greet(name):
    return f"Hello, {name}"

class User:
    def __init__(self, name):
        self.name = name
"#;
        let tree = parse(code).expect("parse failed");
        let converter = LnAstConverter::new("python");
        let ast = converter.convert(&tree, code);

        let fn_names: Vec<_> = ast.functions.iter().map(|f| f.name.clone()).collect();
        assert!(fn_names.contains(&"greet".to_string()), "expected greet, got {:?}", fn_names);
        assert!(fn_names.contains(&"__init__".to_string()), "expected __init__, got {:?}", fn_names);

        let class_names: Vec<_> = ast.classes.iter().map(|c| c.name.clone()).collect();
        assert!(class_names.contains(&"User".to_string()), "expected User, got {:?}", class_names);
    }

    #[test]
    fn test_extract_todo_markers() {
        let code = r#"
# TODO: implement authentication
# FIXME: memory leak here
# NOTE: this is a workaround
x = 1
"#;
        let tree = parse(code).expect("parse failed");
        let converter = LnAstConverter::new("python");
        let ast = converter.convert(&tree, code);

        assert!(ast.todos.len() == 3, "expected 3 todos, got {}", ast.todos.len());
        assert!(ast.todos.iter().any(|t| t.marker == "TODO"));
        assert!(ast.todos.iter().any(|t| t.marker == "FIXME"));
        assert!(ast.todos.iter().any(|t| t.marker == "NOTE"));
    }

    #[test]
    fn test_extract_imports() {
        let code = r#"
import os
from sys import path
import re as regex
"#;
        let tree = parse(code).expect("parse failed");
        let converter = LnAstConverter::new("python");
        let ast = converter.convert(&tree, code);

        assert!(ast.imports.len() >= 2, "expected >= 2 imports, got {}", ast.imports.len());
        assert!(ast.imports.iter().any(|i| i.module == "os"));
        assert!(ast.imports.iter().any(|i| i.module == "sys"));
    }
}
