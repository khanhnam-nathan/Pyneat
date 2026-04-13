//! Multi-language AST parsing via tree-sitter.

#![allow(dead_code)]

use std::collections::HashMap;

use tree_sitter::{Parser, Tree, Node};

use super::ln_ast::{
    LnAst, LnFunction, LnClass, LnImport, LnAssignment,
    LnCall, LnString, LnComment, LnCatchBlock, LnTodo, LnDeepNesting,
};
use super::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python, JavaScript, TypeScript, Go, Java, Rust, CSharp, Php, Ruby,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Python => write!(f, "Python"),
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::Go => write!(f, "Go"),
            Language::Java => write!(f, "Java"),
            Language::Rust => write!(f, "Rust"),
            Language::CSharp => write!(f, "C#"),
            Language::Php => write!(f, "PHP"),
            Language::Ruby => write!(f, "Ruby"),
        }
    }
}

impl Language {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "python" | "py" => Some(Language::Python),
            "javascript" | "js" | "jsx" => Some(Language::JavaScript),
            "typescript" | "ts" | "tsx" => Some(Language::TypeScript),
            "go" | "golang" => Some(Language::Go),
            "java" => Some(Language::Java),
            "rust" | "rs" => Some(Language::Rust),
            "csharp" | "cs" | "c#" => Some(Language::CSharp),
            "php" => Some(Language::Php),
            "ruby" | "rb" => Some(Language::Ruby),
            _ => None,
        }
    }
}

pub fn detect_language_from_extension(ext: &str) -> Option<String> {
    let ext = ext.trim_start_matches('.').to_lowercase();
    let mapping: HashMap<&str, &str> = [
        ("py", "python"), ("pyw", "python"),
        ("js", "javascript"), ("jsx", "javascript"),
        ("mjs", "javascript"), ("cjs", "javascript"),
        ("ts", "typescript"), ("tsx", "typescript"),
        ("go", "go"), ("java", "java"), ("rs", "rust"),
        ("cs", "csharp"), ("php", "php"), ("rb", "ruby"),
    ].into_iter().collect();
    mapping.get(ext.as_str()).map(|s| s.to_string())
}

pub fn parse_ln_ast(code: &str, language: &str) -> Result<LnAst, ParseError> {
    let lang = Language::from_str(language)
        .ok_or_else(|| ParseError::LanguageError(language.to_string()))?;

    let tree = parse_with_language(code, &lang)?;
    let mut ast = LnAst::empty(language);
    ast.source_hash = compute_md5(code);

    walk_tree_and_extract(&tree.root_node(), code, &lang, &mut ast);
    extract_deep_nesting(&tree.root_node(), &lang, &mut ast);

    Ok(ast)
}

fn parse_with_language(code: &str, lang: &Language) -> Result<Tree, ParseError> {
    let mut parser = Parser::new();
    #[allow(non_snake_case)]
    let lang_ref = match lang {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
    };
    parser.set_language(&lang_ref)
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;
    parser.parse(code, None).ok_or(ParseError::ParseFailed)
}

fn walk_tree_and_extract(node: &Node, code: &str, lang: &Language, ast: &mut LnAst) {
    let kind = node.kind();
    match lang {
        Language::Python => extract_python(node, code, kind, ast),
        Language::JavaScript | Language::TypeScript => extract_js(node, code, kind, ast),
        Language::Go => extract_go(node, code, kind, ast),
        Language::Java => extract_java(node, code, kind, ast),
        Language::Rust => extract_rust(node, code, kind, ast),
        Language::CSharp => extract_csharp(node, code, kind, ast),
        Language::Php => extract_php(node, code, kind, ast),
        Language::Ruby => extract_ruby(node, code, kind, ast),
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree_and_extract(&child, code, lang, ast);
    }
}

fn get_text(n: &Node, code: &str) -> String {
    n.utf8_text(code.as_bytes()).map(|s| s.to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

fn extract_python(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_definition" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            let params = get_python_params(node, code);
            let is_async = node.child_by_field_name("async").is_some();
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async, is_method: false, return_type: None,
            });
        }
        "class_definition" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "import_statement" => {
            for child in node.children(&mut node.walk()) {
                let t = get_text(&child, code);
                if !t.is_empty() {
                    ast.imports.push(LnImport {
                        module: t.clone(), name: t, alias: None, is_default: false,
                        start_line: sp.row + 1, end_line: ep.row + 1,
                    });
                }
            }
        }
        "import_from_statement" => {
            let module = node.child_by_field_name("module_name").map(|n| get_text(&n, code)).unwrap_or_default();
            if let Some(names) = node.child_by_field_name("names") {
                for child in names.children(&mut names.walk()) {
                    let t = get_text(&child, code);
                    if !t.is_empty() {
                        ast.imports.push(LnImport {
                            module: module.clone(), name: t, alias: None, is_default: false,
                            start_line: sp.row + 1, end_line: ep.row + 1,
                        });
                    }
                }
            }
        }
        "assignment" => {
            if let Some(targets) = node.child_by_field_name("targets") {
                let value_text = node.child_by_field_name("value").map(|n| get_text(&n, code));
                for child in targets.children(&mut targets.walk()) {
                    if child.kind() == "identifier" {
                        let t = get_text(&child, code);
                        ast.assignments.push(LnAssignment {
                            name: t, value: value_text.clone(), is_constant: false,
                            start_line: sp.row + 1, end_line: ep.row + 1,
                        });
                    }
                }
            }
        }
        "call" => {
            let func = node.child_by_field_name("function").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.calls.push(LnCall {
                callee: func, start_line: sp.row + 1, end_line: ep.row + 1, arguments: vec![],
            });
        }
        "string" => {
            ast.strings.push(LnString {
                value: get_text(node, code), start_line: sp.row + 1, end_line: ep.row + 1,
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment {
                text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1,
            });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo {
                    text, marker, description: desc,
                    start_line: sp.row + 1, end_line: ep.row + 1,
                });
            }
        }
        "except_clause" => {
            let exc_type = node.child_by_field_name("type").map(|n| get_text(&n, code));
            let body = node.child_by_field_name("body");
            let is_empty = body.map(|b| b.named_child_count() == 0).unwrap_or(true);
            ast.catch_blocks.push(LnCatchBlock {
                exception_type: exc_type.filter(|s| !s.is_empty()),
                is_empty, start_line: sp.row + 1, end_line: ep.row + 1,
            });
        }
        _ => {}
    }
}

fn get_python_params(node: &Node, code: &str) -> Vec<String> {
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

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

fn extract_js(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_declaration" | "arrow_function" | "method_definition" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_else(|| "<anonymous>".to_string());
            let params = get_js_params(node, code);
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async: false, is_method: kind == "method_definition", return_type: None,
            });
        }
        "class_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "import_statement" | "import_declaration" => {
            let source = node.child_by_field_name("source").map(|n| get_text(&n, code).trim_matches(|c| c == '\'' || c == '"').to_string()).unwrap_or_default();
            for child in node.children(&mut node.walk()) {
                if child.kind() == "import_specifier" {
                    let name = child.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
                    let alias = child.child_by_field_name("alias").map(|n| get_text(&n, code));
                    ast.imports.push(LnImport {
                        module: source.clone(), name, alias, is_default: false,
                        start_line: sp.row + 1, end_line: ep.row + 1,
                    });
                } else if child.kind() == "identifier" {
                    let t = get_text(&child, code);
                    if !t.is_empty() && t != "import" {
                        ast.imports.push(LnImport {
                            module: source.clone(), name: t, alias: None, is_default: true,
                            start_line: sp.row + 1, end_line: ep.row + 1,
                        });
                    }
                }
            }
        }
        "call_expression" => {
            let func = node.child_by_field_name("function").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.calls.push(LnCall {
                callee: func, start_line: sp.row + 1, end_line: ep.row + 1, arguments: vec![],
            });
        }
        "string" | "template_string" => {
            ast.strings.push(LnString {
                value: get_text(node, code), start_line: sp.row + 1, end_line: ep.row + 1,
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment {
                text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1,
            });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo {
                    text, marker, description: desc,
                    start_line: sp.row + 1, end_line: ep.row + 1,
                });
            }
        }
        "catch_clause" => {
            let param = node.child_by_field_name("parameter").map(|n| get_text(&n, code));
            let body = node.child_by_field_name("body");
            let is_empty = body.map(|b| b.named_child_count() == 0).unwrap_or(true);
            ast.catch_blocks.push(LnCatchBlock {
                exception_type: param, is_empty, start_line: sp.row + 1, end_line: ep.row + 1,
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

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

fn extract_go(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_declaration" | "method_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            let params = get_go_params(node, code);
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async: false, is_method: kind == "method_declaration", return_type: None,
            });
        }
        "import_declaration" => {
            for child in node.children(&mut node.walk()) {
                if child.kind() == "import_specifier" {
                    let name = child.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
                    let alias = child.child_by_field_name("alias").map(|n| get_text(&n, code));
                    ast.imports.push(LnImport {
                        module: String::new(), name, alias, is_default: false,
                        start_line: sp.row + 1, end_line: ep.row + 1,
                    });
                }
            }
        }
        "call_expression" => {
            // Go: call_expression has field "function" pointing to an identifier or selector_expression
            let func = node.child_by_field_name("function").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.calls.push(LnCall {
                callee: func, start_line: sp.row + 1, end_line: ep.row + 1, arguments: vec![],
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment {
                text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1,
            });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
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

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

fn extract_java(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            let params = get_java_params(node, code);
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async: false, is_method: true, return_type: None,
            });
        }
        "class_declaration" | "interface_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "import_declaration" => {
            if let Some(m) = node.child_by_field_name("module").map(|n| get_text(&n, code)) {
                ast.imports.push(LnImport {
                    module: m.clone(), name: m.split('.').last().unwrap_or(&m).to_string(),
                    alias: None, is_default: false, start_line: sp.row + 1, end_line: ep.row + 1,
                });
            }
        }
        "method_invocation" => {
            let func = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.calls.push(LnCall {
                callee: func, start_line: sp.row + 1, end_line: ep.row + 1, arguments: vec![],
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment { text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1 });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
            }
        }
        "catch_clause" => {
            let param = node.child_by_field_name("parameter").map(|n| get_text(&n, code));
            let body = node.child_by_field_name("body");
            let is_empty = body.map(|b| b.named_child_count() == 0).unwrap_or(true);
            ast.catch_blocks.push(LnCatchBlock {
                exception_type: param, is_empty, start_line: sp.row + 1, end_line: ep.row + 1,
            });
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

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

fn extract_rust(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_item" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            let params = get_rust_params(node, code);
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async: false, is_method: false, return_type: None,
            });
        }
        "impl_item" => {
            ast.classes.push(LnClass {
                name: "<impl>".to_string(), start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "use_declaration" => {
            if let Some(n) = node.child_by_field_name("name") {
                let t = get_text(&n, code);
                ast.imports.push(LnImport {
                    module: t.clone(), name: t.split("::").last().unwrap_or(&t).to_string(),
                    alias: None, is_default: false, start_line: sp.row + 1, end_line: ep.row + 1,
                });
            }
        }
        "macro_invocation" => {
            let name = node.child_by_field_name("macro").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.calls.push(LnCall {
                callee: name, start_line: sp.row + 1, end_line: ep.row + 1, arguments: vec![],
            });
        }
        "line_comment" | "block_comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment { text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1 });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
            }
        }
        _ => {}
    }
}

fn get_rust_params(node: &Node, code: &str) -> Vec<String> {
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

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

fn extract_csharp(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            let params = get_csharp_params(node, code);
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params, is_async: false, is_method: true, return_type: None,
            });
        }
        "class_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "using_directive" => {
            if let Some(n) = node.child_by_field_name("name") {
                let t = get_text(&n, code);
                ast.imports.push(LnImport {
                    module: t.clone(), name: t.split('.').last().unwrap_or(&t).to_string(),
                    alias: None, is_default: false, start_line: sp.row + 1, end_line: ep.row + 1,
                });
            }
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment { text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1 });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
            }
        }
        "catch_clause" => {
            let declaration = node.child_by_field_name("declaration");
            let exc_type = declaration.and_then(|d| d.child_by_field_name("type")).map(|n| get_text(&n, code));
            let body = node.child_by_field_name("body");
            let is_empty = body.map(|b| b.named_child_count() == 0).unwrap_or(true);
            ast.catch_blocks.push(LnCatchBlock {
                exception_type: exc_type, is_empty, start_line: sp.row + 1, end_line: ep.row + 1,
            });
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

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

fn extract_php(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "function_definition" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params: vec![], is_async: false, is_method: false, return_type: None,
            });
        }
        "class_declaration" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment { text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1 });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

fn extract_ruby(node: &Node, code: &str, kind: &str, ast: &mut LnAst) {
    let sp = node.start_position();
    let ep = node.end_position();

    match kind {
        "method" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.functions.push(LnFunction {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
                params: vec![], is_async: false, is_method: false, return_type: None,
            });
        }
        "class" => {
            let name = node.child_by_field_name("name").map(|n| get_text(&n, code)).unwrap_or_default();
            ast.classes.push(LnClass {
                name, start_line: sp.row + 1, end_line: ep.row + 1,
                start_byte: node.start_byte(), end_byte: node.end_byte(),
            });
        }
        "comment" => {
            let text = get_text(node, code);
            ast.comments.push(LnComment { text: text.clone(), start_line: sp.row + 1, end_line: ep.row + 1 });
            if let Some((marker, desc)) = extract_todo_marker(&text) {
                ast.todos.push(LnTodo { text, marker, description: desc, start_line: sp.row + 1, end_line: ep.row + 1 });
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Deep nesting
// ---------------------------------------------------------------------------

fn extract_deep_nesting(node: &Node, lang: &Language, ast: &mut LnAst) {
    let nesting_kinds: Vec<&str> = match lang {
        Language::Python => vec!["if_statement", "for_statement", "while_statement", "with_statement", "except_clause"],
        Language::JavaScript | Language::TypeScript => vec!["if_statement", "for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement", "switch_statement", "try_statement"],
        Language::Go => vec!["if_statement", "for_statement", "switch_statement"],
        Language::Java => vec!["if_statement", "for_statement", "while_statement", "try_statement", "synchronized_statement"],
        Language::Rust => vec!["if_expression", "match_expression", "for_expression", "while_expression", "loop_expression"],
        Language::CSharp => vec!["if_statement", "for_statement", "while_statement", "switch_statement", "try_statement"],
        Language::Php => vec!["if_statement", "for_statement", "foreach_statement", "while_statement", "switch_statement"],
        Language::Ruby => vec!["if_modifier", "unless_modifier", "case_statement", "when_clause"],
    };

    extract_nesting_recursive(node, lang, 0, 4, &nesting_kinds, ast);
}

fn extract_nesting_recursive(node: &Node, lang: &Language, depth: usize, threshold: usize, kinds: &[&str], ast: &mut LnAst) {
    if kinds.contains(&node.kind()) {
        let new_depth = depth + 1;
        if new_depth >= threshold {
            let sp = node.start_position();
            ast.deep_nesting.push(LnDeepNesting { line: sp.row + 1, column: sp.column, depth: new_depth });
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_nesting_recursive(&child, lang, new_depth, threshold, kinds, ast);
        }
    } else {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_nesting_recursive(&child, lang, depth, threshold, kinds, ast);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_todo_marker(text: &str) -> Option<(String, String)> {
    let markers = ["TODO", "FIXME", "HACK", "XXX", "NOTE", "BUG"];
    for marker in markers {
        if let Some(pos) = text.to_uppercase().find(marker) {
            let after = text[text[text.len()..].find(marker).unwrap_or(pos) + marker.len()..].trim_start_matches(':').trim();
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_lang() {
        assert_eq!(detect_language_from_extension(".py"), Some("python".to_string()));
        assert_eq!(detect_language_from_extension(".js"), Some("javascript".to_string()));
        assert_eq!(detect_language_from_extension(".go"), Some("go".to_string()));
    }

    #[test]
    fn test_parse_python() {
        let code = "def hello():\n    pass\n";
        let ast = parse_ln_ast(code, "python").unwrap();
        assert_eq!(ast.language, "python");
        assert!(!ast.functions.is_empty());
        assert_eq!(ast.functions[0].name, "hello");
    }

    #[test]
    fn test_parse_js() {
        let code = "function hello() { console.log('hi'); }\n";
        let ast = parse_ln_ast(code, "javascript").unwrap();
        assert_eq!(ast.language, "javascript");
        assert!(!ast.functions.is_empty());
    }

    #[test]
    fn test_deep_nesting() {
        let code = "if True:\n    if True:\n        if True:\n            if True:\n                pass\n";
        let ast = parse_ln_ast(code, "python").unwrap();
        assert!(!ast.deep_nesting.is_empty());
    }
}
