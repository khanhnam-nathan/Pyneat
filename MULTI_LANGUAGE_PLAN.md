# PyNeat Multi-Language Support — REVISED Implementation Plan

> **Version**: 2.0 — REVISED
> **Created**: 2026-04-12
> **Author**: AI agent review + rewrite
> **Status**: READY FOR IMPLEMENTATION
> **Estimated effort**: ~4-5 weeks total (slightly longer due to Rust layer, but better scalability)

---

## Changelog from v1.0

| Issue in v1.0 | Fix in v2.0 |
|---|---|
| `if language == "python":` branch duplicated entire engine | Parser abstraction — engine stays language-agnostic |
| `raw_node: Any` leaked abstraction in `CodeNode` | Rust returns LN-AST JSON — no raw_node needed |
| pyneat-rs ignored — missed acceleration opportunity | Rust handles ALL non-Python parsing via tree-sitter |
| "Universal rules" still called `get_debug_call_patterns()` (leaky) | Pure pattern-based detection + language-specific fix hints |
| No transformation pipeline design | Clear separation: Detect → Transform → Validate |
| 8 optional Python tree-sitter packages (dependency hell) | Single Rust binary — no Python tree-sitter packages |

---

## 1. CONTEXT — What is PyNeat?

PyNeat (v2.4.5) là AST-based Python code refactoring/cleaning tool. Nó có:

- **`pyneat/`** — Python engine với 30+ rules
- **`pyneat-rs/`** — Rust accelerator với tree-sitter + regex security scanner

**Mục tiêu**: Mở rộng PyNeat hỗ trợ 7 ngôn ngữ mới mà:
1. Không sửa đổi existing Python logic
2. Tận dụng Rust accelerator cho parsing performance
3. Giữ engine thật sự language-agnostic

---

## 2. REVISED ARCHITECTURE — 4 Layers

Thay vì Adapter Pattern truyền thống, dùng **4-layer pipeline**:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: PARSER (Rust-first)                              │
│  ┌──────────────┐  ┌──────────────────────────────────────┐ │
│  │ Python       │  │ pyneat-rs (tree-sitter)             │ │
│  │ libcst       │  │ JS/TS/Go/Java/Rust/C#/PHP/Ruby      │ │
│  └──────────────┘  └──────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON (LN-AST)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: NORMALIZED AST (Language-Neutral AST)             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Shared schema: functions, classes, calls, assignments   │  │
│  │ Extracted by Rust, consumed by Python engine          │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ CodeFile with ln_ast field
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: RULE ENGINE (UNCHANGED — truly language-agnostic) │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Rule.apply(CodeFile) — works on LN-AST, not raw AST  │  │
│  │ Python rules: libcst codegen                          │  │
│  │ Universal rules: LN-AST pattern matching              │  │
│  │ Language rules: language-specific LN-AST ops         │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Fix hints (byte ranges + replacement)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: TRANSFORMER (Rust)                                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ apply_fix_code(code, start, end, replacement)        │  │
│  │ Conflict resolution + semantic validation            │  │
│  │ Language-specific code generation                    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Tại sao 4 layers tốt hơn Adapter Pattern?

| Adapter Pattern (v1.0) | 4-Layer Pipeline (v2.0) |
|---|---|
| Mỗi adapter cần implement 10+ methods | Parser layer handle parsing, engine hoàn toàn shared |
| `raw_node` leak abstraction | Rust returns clean JSON, no raw access |
| "Universal rules" vẫn gọi `adapter.get_*()` (leaky) | Rules work on LN-AST dict, truly language-agnostic |
| Engine cần `if lang == "python":` branch | Engine hoàn toàn shared, no language branches |
| 8 optional Python packages | Single Rust binary handles all languages |

---

## 3. CURRENT CODEBASE ANALYSIS

### 3.1 Python Side (Không đụng)

```
pyneat/
├── core/
│   ├── engine.py        # RuleEngine — uses ast.parse() + libcst
│   └── types.py         # CodeFile có field language: str = "python"
├── rules/
│   ├── base.py          # Rule(ABC) — apply(CodeFile) → TransformationResult
│   └── *.py             # 30+ existing rules — UNCHANGED
└── __init__.py          # Public API — UNCHANGED
```

**Key observation**: `CodeFile` đã có `language` field. Engine chỉ cần thêm LN-AST parsing.

### 3.2 Rust Side (Mở rộng — cơ hội lớn)

```
pyneat-rs/
├── src/
│   ├── lib.rs              # PyO3 bindings: scan_security(), apply_auto_fix()
│   ├── scanner/
│   │   └── tree_sitter.rs  # parse(code) → Tree, walk_tree()
│   ├── rules/
│   │   ├── base.rs         # Rule trait: detect(), fix(), supports_auto_fix()
│   │   ├── security.rs     # 16 security rules (SEC-024 to SEC-072)
│   │   └── quality.rs      # Quality rules
│   └── fixer/
│       ├── apply_fix.rs    # apply_fix_code(), apply_multiple_fixes()
│       └── diff.rs         # Diff generation
└── Cargo.toml              # Dependencies: tree-sitter, rayon, serde
```

**Key observation**: Rust side đã có:
- tree-sitter infrastructure (parse, walk_tree, NodeInfo)
- Rule trait với detect/fix pattern
- Fix application với conflict resolution

**Missing**: Chỉ có tree-sitter-python. Cần thêm các ngôn ngữ khác vào Cargo.toml.

---

## 4. IMPLEMENTATION STRATEGY

### Phase 1: Rust Parser Layer (Week 1)

**Mục tiêu**: Rust parse ALL languages, return LN-AST JSON.

#### Step 1.1: Update `pyneat-rs/Cargo.toml`

```toml
[dependencies]
# ... existing deps ...

# Multi-language tree-sitter grammars
tree-sitter = "0.23"
tree-sitter-python = "0.23"
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"  # shares JS grammar
tree-sitter-go = "0.23"
tree-sitter-java = "0.23"
tree-sitter-rust = "0.23"        # parse Rust code
tree-sitter-c-sharp = "0.23"
tree-sitter-php = "0.23"
tree-sitter-ruby = "0.23"

# Multi-language parsing support
tree-sitter-all-langs = { version = "0.1", optional = true }
```

#### Step 1.2: Create `pyneat-rs/src/scanner/ln_ast.rs`

**Language-Neutral AST schema** — shared across all languages:

```rust
//! Language-Neutral AST (LN-AST) types.
//!
//! This module defines a language-agnostic AST representation that can
//! be serialized to JSON and consumed by the Python engine.

use serde::{Deserialize, Serialize};

/// A language-neutral function/method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnFunction {
    pub name: String,
    pub start_line: usize,      // 1-indexed
    pub end_line: usize,       // 1-indexed
    pub start_byte: usize,     // byte offset in source
    pub end_byte: usize,
    pub params: Vec<String>,
    pub is_async: bool,
    pub is_method: bool,
    pub return_type: Option<String>,
}

/// A language-neutral class/struct/interface definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnClass {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// A language-neutral import/use/require statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnImport {
    pub module: String,        // "os.path", "react", "fmt"
    pub name: String,           // imported name
    pub alias: Option<String>,  // "from os import path as p"
    pub is_default: bool,
    pub start_line: usize,
    pub end_line: usize,
}

/// A language-neutral variable assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnAssignment {
    pub name: String,
    pub value: Option<String>,  // source text of RHS
    pub is_constant: bool,
    pub start_line: usize,
    pub end_line: usize,
}

/// A language-neutral function/method call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnCall {
    pub callee: String,         // "os.path.join", "console.log"
    pub start_line: usize,
    pub end_line: usize,
    pub arguments: Vec<String>, // source texts of arguments
}

/// A language-neutral string literal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnString {
    pub value: String,         // raw value (quotes stripped)
    pub start_line: usize,
    pub end_line: usize,
}

/// A language-neutral comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnComment {
    pub text: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// A language-neutral catch/except block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnCatchBlock {
    pub exception_type: Option<String>,
    pub is_empty: bool,
    pub start_line: usize,
    pub end_line: usize,
}

/// A language-neutral source comment/TODO/FIXME marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnTodo {
    pub text: String,
    pub marker: String,         // "TODO", "FIXME", "HACK", "NOTE"
    pub start_line: usize,
    pub end_line: usize,
}

/// Complete LN-AST for a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnAst {
    pub language: String,           // "python", "javascript", "go", etc.
    pub source_hash: String,         // MD5 of source for cache validation
    pub functions: Vec<LnFunction>,
    pub classes: Vec<LnClass>,
    pub imports: Vec<LnImport>,
    pub assignments: Vec<LnAssignment>,
    pub calls: Vec<LnCall>,
    pub strings: Vec<LnString>,
    pub comments: Vec<LnComment>,
    pub catch_blocks: Vec<LnCatchBlock>,
    pub todos: Vec<LnTodo>,
    /// Lines with nesting depth >= threshold (for arrow anti-pattern)
    pub deep_nesting: Vec<(usize, usize, usize)>, // (line, column, depth)
}

impl LnAst {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}
```

#### Step 1.3: Create `pyneat-rs/src/scanner/multilang.rs`

**Core multi-language parser** — uses tree-sitter to extract LN-AST:

```rust
//! Multi-language AST parsing via tree-sitter.
//!
//! This module provides functions to parse any supported language into
//! a Language-Neutral AST (LN-AST) that can be consumed by the Python engine.

use tree_sitter::{Parser, Tree};

use super::ln_ast::{
    LnAst, LnFunction, LnClass, LnImport, LnAssignment,
    LnCall, LnString, LnComment, LnCatchBlock, LnTodo,
};
use super::ParseError;

/// Supported languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Rust,
    CSharp,
    Php,
    Ruby,
}

impl Language {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "python" | "py" => Some(Language::Python),
            "javascript" | "js" => Some(Language::JavaScript),
            "typescript" | "ts" => Some(Language::TypeScript),
            "go" | "golang" => Some(Language::Go),
            "java" => Some(Language::Java),
            "rust" | "rs" => Some(Language::Rust),
            "csharp" | "cs" | "c#" => Some(Language::CSharp),
            "php" => Some(Language::Php),
            "ruby" | "rb" => Some(Language::Ruby),
            _ => None,
        }
    }

    pub fn file_extensions(&self) -> &[&str] {
        match self {
            Language::Python => &["py", "pyw"],
            Language::JavaScript => &["js", "jsx", "mjs", "cjs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Go => &["go"],
            Language::Java => &["java"],
            Language::Rust => &["rs"],
            Language::CSharp => &["cs"],
            Language::Php => &["php"],
            Language::Ruby => &["rb"],
        }
    }
}

/// Parse source code into LN-AST.
pub fn parse_ln_ast(code: &str, language: &str) -> Result<LnAst, ParseError> {
    let lang = Language::from_str(language)
        .ok_or_else(|| ParseError::LanguageError(language.to_string()))?;

    let tree = parse_with_language(code, &lang)?;

    let mut functions = Vec::new();
    let mut classes = Vec::new();
    let mut imports = Vec::new();
    let mut assignments = Vec::new();
    let mut calls = Vec::new();
    let mut strings = Vec::new();
    let mut comments = Vec::new();
    let mut catch_blocks = Vec::new();
    let mut todos = Vec::new();
    let mut deep_nesting = Vec::new();

    // Walk tree and extract nodes based on language
    walk_tree_custom(&tree.root_node(), code, &lang, &mut |node| {
        match node.kind.as_str() {
            // Python-specific
            "function_definition" | "async_function_definition" => {
                if lang == Language::Python {
                    functions.push(extract_python_function(node, code));
                }
            }
            "class_definition" => {
                if lang == Language::Python {
                    classes.push(extract_python_class(node, code));
                }
            }
            // JavaScript/TypeScript
            "function_declaration" | "arrow_function" | "method_definition" => {
                if matches!(lang, Language::JavaScript | Language::TypeScript) {
                    functions.push(extract_js_function(node, code));
                }
            }
            "import_statement" | "import_declaration" => {
                if matches!(lang, Language::JavaScript | Language::TypeScript) {
                    imports.push(extract_js_import(node, code));
                }
            }
            // Go
            "function_declaration" | "method_declaration" => {
                if lang == Language::Go {
                    functions.push(extract_go_function(node, code));
                }
            }
            "import_declaration" => {
                if lang == Language::Go {
                    imports.push(extract_go_import(node, code));
                }
            }
            // (similar for Java, Rust, C#, PHP, Ruby)
            _ => {}
        }
    });

    Ok(LnAst {
        language: language.to_string(),
        source_hash: md5_hash(code),
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
    })
}

/// Parse with the correct tree-sitter grammar.
fn parse_with_language(code: &str, lang: &Language) -> Result<Tree, ParseError> {
    let mut parser = Parser::new();

    let language = match lang {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::CSharp => tree_sitter_csharp::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
    };

    parser.set_language(&language)
        .map_err(|e| ParseError::LanguageError(e.to_string()))?;

    parser.parse(code, None)
        .ok_or(ParseError::ParseFailed)
}

/// Detect language from file extension.
pub fn detect_language_from_extension(ext: &str) -> Option<String> {
    let ext = ext.trim_start_matches('.').to_lowercase();
    let mapping: std::collections::HashMap<&str, &str> = [
        ("py", "python"), ("pyw", "python"),
        ("js", "javascript"), ("jsx", "javascript"),
        ("mjs", "javascript"), ("cjs", "javascript"),
        ("ts", "typescript"), ("tsx", "typescript"),
        ("go", "go"),
        ("java", "java"),
        ("rs", "rust"),
        ("cs", "csharp"),
        ("php", "php"),
        ("rb", "ruby"),
    ].iter().cloned().collect();

    mapping.get(ext.as_str()).map(|s| s.to_string())
}
```

#### Step 1.4: Update `pyneat-rs/src/lib.rs`

Add new PyO3 functions:

```rust
use pyo3::prelude::*;

/// Parse source code into Language-Neutral AST (LN-AST) JSON.
#[pyfunction]
fn parse_ln_ast(code: &str, language: &str) -> PyResult<String> {
    match super::scanner::multilang::parse_ln_ast(code, language) {
        Ok(ast) => Ok(ast.to_json()),
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
    }
}

/// Detect language from file extension.
#[pyfunction]
fn detect_language(ext: &str) -> PyResult<Option<String>> {
    Ok(super::scanner::multilang::detect_language_from_extension(ext))
}

/// Python module definition
#[pymodule]
fn pyneat_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_security, m)?)?;
    m.add_function(wrap_pyfunction!(apply_auto_fix, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ln_ast, m)?)?;
    m.add_function(wrap_pyfunction!(detect_language, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(get_rules, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
```

---

### Phase 2: Python Engine Integration (Week 1-2)

**Mục tiêu**: Engine hoàn toàn language-agnostic, không có `if lang == "python":` branch.

#### Step 2.1: Update `pyneat/core/types.py`

Add LN-AST field to `CodeFile`:

```python
@dataclass(frozen=True)
class CodeFile:
    """Represents a code file with its content and metadata."""
    path: Path
    content: str
    language: str = "python"  # "python", "javascript", "go", etc.
    ast_tree: Optional[Any] = None   # Python: ast.AST
    cst_tree: Optional[Any] = None   # Python: libcst.Module
    ln_ast: Optional[Dict[str, Any]] = None  # Language-Neutral AST (JSON dict)
```

#### Step 2.2: Update `pyneat/core/engine.py`

**Minimal change** — chỉ thêm parsing logic ở đầu `process_code_file()`:

```python
def process_code_file(
    self,
    code_file: CodeFile,
    check_conflicts: bool = False,
) -> TransformationResult:
    """Process a CodeFile object with all enabled rules.

    Architecture:
    - Python: Uses libcst + ast (existing behavior)
    - Other languages: Uses Rust parser (pyneat-rs) → LN-AST → rules
    """
    cf = code_file

    if code_file.language == "python":
        # === EXISTING PYTHON LOGIC — UNCHANGED ===
        cached = self.get_cached_trees(code_file.content)
        if cached:
            cached_ast, cached_cst = cached
            object.__setattr__(cf, 'ast_tree', cached_ast)
            object.__setattr__(cf, 'cst_tree', cached_cst)
        else:
            try:
                ast_tree = ast.parse(code_file.content)
                cst_tree = cst.parse_module(code_file.content)
                self.cache_trees(code_file.content, ast_tree, cst_tree)
                object.__setattr__(cf, 'ast_tree', ast_tree)
                object.__setattr__(cf, 'cst_tree', cst_tree)
            except SyntaxError:
                pass  # cf stays without trees
    else:
        # === NEW: Non-Python via Rust parser ===
        try:
            import pyneat_rs
            ln_ast_json = pyneat_rs.parse_ln_ast(code_file.content, code_file.language)
            ln_ast = json.loads(ln_ast_json)
            object.__setattr__(cf, 'ln_ast', ln_ast)
        except Exception as e:
            return TransformationResult(
                original=code_file,
                transformed_content=code_file.content,
                changes_made=[],
                success=False,
                error=f"Failed to parse {code_file.language} code: {e}",
            )

    # === REST OF ENGINE IS IDENTICAL FOR ALL LANGUAGES ===
    # ... existing rule loop, conflict detection, etc.
```

**Key point**: Chỉ parsing logic khác nhau. Rule engine hoàn toàn shared.

#### Step 2.3: Update `pyneat/rules/base.py`

Add support for LN-AST in `Rule`:

```python
class Rule(ABC):
    """Base class for all code cleaning rules."""

    ALLOWED_SEMANTIC_NODES: Set[str] = set()

    def __init__(self, config: RuleConfig = None):
        self.config = config or RuleConfig()
        self.name = self.__class__.__name__

    @abstractmethod
    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule to the given code file."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule does."""
        pass

    @property
    @abstractmethod
    def supported_languages(self) -> List[str]:
        """List of languages this rule supports.

        Return ["*"] for universal rules that work on any language.
        Return ["python"] for Python-only rules.
        Return ["javascript", "typescript"] for JS/TS rules.
        """
        pass

    # --- Universal helpers (for rules that work on LN-AST) ---

    def get_ln_functions(self, code_file: CodeFile) -> List[Dict]:
        """Get functions from LN-AST. Returns [] for Python (uses ast instead)."""
        if code_file.ln_ast is not None:
            return code_file.ln_ast.get("functions", [])
        return []

    def get_ln_calls(self, code_file: CodeFile) -> List[Dict]:
        """Get function calls from LN-AST."""
        if code_file.ln_ast is not None:
            return code_file.ln_ast.get("calls", [])
        return []

    def get_ln_strings(self, code_file: CodeFile) -> List[Dict]:
        """Get string literals from LN-AST."""
        if code_file.ln_ast is not None:
            return code_file.ln_ast.get("strings", [])
        return []

    def get_ln_comments(self, code_file: CodeFile) -> List[Dict]:
        """Get comments from LN-AST."""
        if code_file.ln_ast is not None:
            return code_file.ln_ast.get("comments", [])
        return []
```

---

### Phase 3: Universal Rules (Week 2)

**Mục tiêu**: Rules thật sự universal — hoạt động trên LN-AST, không cần language-specific logic.

#### Step 3.1: Create `pyneat/rules/universal/base.py`

```python
"""Base class for universal (cross-language) rules.

Universal rules work on LN-AST (Language-Neutral AST) which is the
same format for all languages. No language-specific branching needed.
"""

from abc import abstractmethod
from typing import List, Dict, Any, Tuple
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class UniversalRule(Rule):
    """Base for rules that work across ALL supported languages.

    Universal rules receive LN-AST (a dict) and produce fix hints.
    The fix hints are byte offsets + replacement text, which the
    Rust fixer layer applies.
    """

    @property
    def supported_languages(self) -> List[str]:
        return ["*"]  # Matches all languages

    @abstractmethod
    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Finding]:
        """Analyze LN-AST and return list of findings.

        Each Finding is a dict with keys:
            - rule_id: str
            - start: int (byte offset)
            - end: int (byte offset)
            - severity: str
            - problem: str
            - fix_hint: str
            - auto_fix_available: bool
        """
        pass

    def apply(self, code_file: CodeFile) -> TransformationResult:
        """Apply this rule using LN-AST."""
        if code_file.ln_ast is None:
            # For Python, ln_ast is None — universal rules skip Python
            # (Python uses language-specific rules instead)
            return self._create_result(code_file, code_file.content, [])

        try:
            findings = self.analyze(code_file.content, code_file.ln_ast)

            if not findings:
                return self._create_result(code_file, code_file.content, [])

            # Apply fixes via Rust
            return self._apply_fixes(code_file, findings)
        except Exception as e:
            return self._create_error_result(code_file, str(e))

    def _apply_fixes(self, code_file: CodeFile, findings: List[Dict]) -> TransformationResult:
        """Apply fixes from findings using Rust fixer."""
        import pyneat_rs

        current = code_file.content
        applied = []

        for finding in findings:
            if not finding.get("auto_fix_available", False):
                continue

            start = finding["start"]
            end = finding["end"]
            replacement = finding.get("replacement", "")

            try:
                current = pyneat_rs.apply_auto_fix(
                    current,
                    json.dumps({
                        "start": start,
                        "end": end,
                        "replacement": replacement,
                    })
                )
                applied.append(f"[{finding['rule_id']}] {finding['problem']}")
            except Exception:
                pass  # Skip failed fixes

        return self._create_result(code_file, current, applied)
```

#### Step 3.2: Create universal rules

**`pyneat/rules/universal/hardcoded_secrets.py`**:

```python
"""Detect hardcoded passwords, API keys, tokens in any language."""

import re
from typing import List, Dict, Any
from pyneat.rules.universal.base import UniversalRule

SECRET_PATTERNS = re.compile(
    r'(password|passwd|pwd|secret|api_key|apikey|'
    r'access_token|auth_token|refresh_token|private_key|'
    r'secret_key|bearer_token)\s*[=:]\s*["\'][^"\']{3,}["\']',
    re.IGNORECASE
)

ENV_LOOKUP_PATTERNS = ["os.environ", "os.getenv", "getenv", "process.env", "System.getenv", "ENV[", " Bun"]


class HardcodedSecretsRule(UniversalRule):
    """Detect hardcoded secrets in any language."""

    @property
    def description(self) -> str:
        return "Detect hardcoded passwords, API keys, and tokens"

    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Dict]:
        findings = []
        # Pattern-based detection works across ALL languages
        for match in SECRET_PATTERNS.finditer(code):
            value = match.group()
            # Filter out env lookups
            if any(env in value for env in ENV_LOOKUP_PATTERNS):
                continue
            findings.append({
                "rule_id": "UNI-001",
                "start": match.start(),
                "end": match.end(),
                "severity": "high",
                "problem": f"Potential hardcoded secret: {match.group(1)}",
                "fix_hint": f"Replace with environment variable lookup",
                "auto_fix_available": False,
                "replacement": "",
            })
        return findings
```

**`pyneat/rules/universal/debug_artifacts.py`**:

```python
"""Detect debug print/log statements in any language."""

from typing import List, Dict, Any
from pyneat.rules.universal.base import UniversalRule

# Language-agnostic debug patterns (regex-based, works on source text)
DEBUG_PATTERNS = {
    "python": [r'\bprint\s*\(', r'\bpdb\.set_trace\s*\(', r'\bbreakpoint\s*\('],
    "javascript": [r'\bconsole\.(log|warn|error|debug|info|trace)\s*\('],
    "go": [r'\bfmt\.Print(?:f|ln)?\s*\(', r'\blog\.(Print|Fatal|Panic)\s*\('],
    "java": [r'\bSystem\.out\.println\s*\(', r'\bSystem\.err\.println\s*\('],
    "rust": [r'\bprintln!\s*\(', r'\beprintln!\s*\('],
    "csharp": [r'\bConsole\.(WriteLine|Write)\s*\('],
    "php": [r'\b(?:var_dump|print_r|echo|printf)\s*\('],
    "ruby": [r'\b(?:puts|p|pp)\s+', r'\bprint\s+'],
}

LANG_INDEPENDENT_DEBUG = [r'\bdebugger\s*;']  # Works in JS/TS/PHP


class DebugArtifactsRule(UniversalRule):
    """Detect debug print/log statements in any language."""

    @property
    def description(self) -> str:
        return "Detect and remove debug statements"

    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Dict]:
        findings = []
        lang = ln_ast.get("language", "")

        patterns = DEBUG_PATTERNS.get(lang, []) + LANG_INDEPENDENT_DEBUG
        import re
        for pattern in patterns:
            regex = re.compile(pattern)
            for match in regex.finditer(code):
                findings.append({
                    "rule_id": "UNI-002",
                    "start": match.start(),
                    "end": match.end(),
                    "severity": "low",
                    "problem": f"Debug statement: {match.group()[:50]}",
                    "fix_hint": "Remove or replace with proper logging",
                    "auto_fix_available": True,
                    "replacement": self._get_replacement(lang, match.group()),
                })
        return findings

    def _get_replacement(self, lang: str, matched: str) -> str:
        """Get language-appropriate replacement (comment out vs delete)."""
        if lang in ("python", "ruby"):
            return f"# {matched.strip()}"  # Comment out
        return ""  # Delete for others
```

**`pyneat/rules/universal/empty_catch.py`**:

```python
"""Detect empty except/catch blocks in any language."""

from typing import List, Dict, Any
from pyneat.rules.universal.base import UniversalRule


class EmptyCatchRule(UniversalRule):
    """Detect empty except/catch blocks that silently swallow errors."""

    @property
    def description(self) -> str:
        return "Detect empty catch/except blocks"

    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Dict]:
        findings = []
        for catch in ln_ast.get("catch_blocks", []):
            if catch.get("is_empty", False):
                # Find the line in source
                line = catch.get("start_line", 1)
                lines = code.split('\n')
                if 0 < line <= len(lines):
                    findings.append({
                        "rule_id": "UNI-003",
                        "start": 0,  # Will be refined
                        "end": 0,
                        "severity": "medium",
                        "problem": f"Empty catch block on line {line} — errors silently swallowed",
                        "fix_hint": "Add error handling or logging",
                        "auto_fix_available": False,
                        "replacement": "",
                    })
        return findings
```

**`pyneat/rules/universal/todos.py`**:

```python
"""Detect TODO/FIXME/HACK comments in any language."""

import re
from typing import List, Dict, Any
from pyneat.rules.universal.base import UniversalRule

TODO_PATTERN = re.compile(
    r'(#|//|/\*|--|<!--)\s*(TODO|FIXME|HACK|XXX|NOTE|BUG):?\s*(.*)',
    re.IGNORECASE | re.MULTILINE
)


class TodoCommentRule(UniversalRule):
    """Detect TODO/FIXME comments for cleanup."""

    @property
    def description(self) -> str:
        return "Detect TODO/FIXME comments"

    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Dict]:
        findings = []
        for match in TODO_PATTERN.finditer(code):
            findings.append({
                "rule_id": "UNI-004",
                "start": match.start(),
                "end": match.end(),
                "severity": "info",
                "problem": f"{match.group(2).upper()}: {match.group(3).strip()}",
                "fix_hint": "Address or remove the TODO comment",
                "auto_fix_available": True,
                "replacement": "",
            })
        return findings
```

**`pyneat/rules/universal/arrow_antipattern.py`**:

```python
"""Detect deeply nested if/else chains (arrow anti-pattern) in any language."""

from typing import List, Dict, Any
from pyneat.rules.universal.base import UniversalRule

NESTING_THRESHOLD = 4


class ArrowAntiPatternRule(UniversalRule):
    """Detect deeply nested control flow (arrow anti-pattern)."""

    @property
    def description(self) -> str:
        return "Detect deeply nested if/else chains"

    def analyze(self, code: str, ln_ast: Dict[str, Any]) -> List[Dict]:
        findings = []
        for line, col, depth in ln_ast.get("deep_nesting", []):
            if depth >= NESTING_THRESHOLD:
                findings.append({
                    "rule_id": "UNI-005",
                    "start": 0,
                    "end": 0,
                    "severity": "medium",
                    "problem": f"Nesting depth {depth} on line {line} (threshold: {NESTING_THRESHOLD})",
                    "fix_hint": "Extract inner logic into separate function or use early return",
                    "auto_fix_available": False,
                    "replacement": "",
                })
        return findings
```

---

### Phase 4: Language-Specific Rules (Week 2-3)

**Mục tiêu**: Rules cho từng ngôn ngữ dùng LN-AST + language-specific patterns.

#### Step 4.1: JavaScript/TypeScript rules

**`pyneat/rules/javascript/equality.py`**:

```python
"""Convert == to === and != to !== in JavaScript."""

import re
from typing import List, Dict, Any
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class StrictEqualityRule(Rule):
    """Convert loose equality to strict equality in JS/TS."""

    EQUALITY_PATTERN = re.compile(r'(?<![=!])={2,3}(?![=])')

    @property
    def description(self) -> str:
        return "Convert == to === and != to !== in JavaScript/TypeScript"

    @property
    def supported_languages(self) -> List[str]:
        return ["javascript", "typescript"]

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        current = code_file.content
        changes = []

        for match in self.EQUALITY_PATTERN.finditer(current):
            op = match.group()
            if op == "==":
                replacement = "==="
            else:
                replacement = "!=="

            try:
                import pyneat_rs
                current = pyneat_rs.apply_auto_fix(
                    current,
                    json.dumps({
                        "start": match.start(),
                        "end": match.end(),
                        "replacement": replacement,
                    })
                )
                changes.append(f"Converted {op} to {replacement}")
            except Exception:
                pass

        return self._create_result(code_file, current, changes)
```

**`pyneat/rules/javascript/var_to_const.py`**:

```python
"""Convert var to let/const in JavaScript."""

import re
from typing import List, Dict, Any
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class VarToConstRule(Rule):
    """Convert var declarations to let/const."""

    VAR_PATTERN = re.compile(r'\bvar\s+(\w+)', re.MULTILINE)

    @property
    def description(self) -> str:
        return "Convert var to let/const in JavaScript"

    @property
    def supported_languages(self) -> List[str]:
        return ["javascript", "typescript"]

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        current = code_file.content
        changes = []

        for match in self.VAR_PATTERN.finditer(current):
            var_name = match.group(1)
            # Use const by default (conservative)
            replacement = f"const {var_name}"

            try:
                import pyneat_rs
                current = pyneat_rs.apply_auto_fix(
                    current,
                    json.dumps({
                        "start": match.start(),
                        "end": match.end(),
                        "replacement": replacement,
                    })
                )
                changes.append(f"Converted var {var_name} to const")
            except Exception:
                pass

        return self._create_result(code_file, current, changes)
```

#### Step 4.2: Go rules

**`pyneat/rules/go/unchecked_error.py`**:

```python
"""Detect unchecked error returns in Go."""

import re
from typing import List, Dict, Any
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult


class UncheckedErrorRule(Rule):
    """Detect Go functions that return (value, error) where error is unchecked."""

    ERROR_ASSIGN_PATTERN = re.compile(
        r'(\w+),\s*_\s*:=\s*.*\berr\b',  # x, _ := foo() where foo returns err
    )

    @property
    def description(self) -> str:
        return "Detect unchecked error returns in Go"

    @property
    def supported_languages(self) -> List[str]:
        return ["go"]

    def apply(self, code_file: CodeFile) -> TransformationResult:
        if code_file.ln_ast is None:
            return self._create_result(code_file, code_file.content, [])

        findings = []
        current = code_file.content

        for match in self.ERROR_ASSIGN_PATTERN.finditer(current):
            findings.append({
                "rule_id": "GO-001",
                "start": match.start(),
                "end": match.end(),
                "severity": "medium",
                "problem": f"Unchecked error on line {current[:match.start()].count(chr(10)) + 1}",
                "fix_hint": "Handle the error: if err != nil { return err }",
                "auto_fix_available": False,
            })

        changes = [f"[GO-001] {f['problem']}" for f in findings]
        return self._create_result(code_file, current, changes)
```

#### Step 4.3: Other language rules (follow same pattern)

| Language | Rule File | Description |
|----------|-----------|-------------|
| Java | `java/raw_types.py` | Detect raw generic types |
| Java | `java/resource_leak.py` | AutoCloseable not in try-with-resources |
| Rust | `rust/unwrap_usage.py` | `.unwrap()` in non-test code |
| Rust | `rust/unsafe_audit.py` | Audit unsafe blocks |
| C# | `csharp/async_void.py` | `async void` instead of `async Task` |
| PHP | `php/var_dump.py` | Remove var_dump/print_r |
| Ruby | `ruby/binding_pry.py` | Remove binding.pry debugger |

---

### Phase 5: CLI + Config Integration (Week 3)

#### Step 5.1: Update `pyneat/cli.py`

Add `--language` option:

```python
@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--language', '-l',
              type=click.Choice(['auto', 'python', 'javascript', 'typescript',
                               'go', 'java', 'rust', 'csharp', 'php', 'ruby']),
              default='auto',
              help='Source language (default: auto-detect from extension)')
@click.option('--check', is_flag=True, help='Check mode — no changes made')
@click.option('--clean', is_flag=True, help='Clean mode — apply fixes')
def clean(path, language, check, clean):
    """Clean code in PATH with language auto-detection."""
    # Auto-detect language from extension if not specified
    if language == 'auto':
        ext = Path(path).suffix
        import pyneat_rs
        detected = pyneat_rs.detect_language(ext)
        language = detected or 'python'

    # Process with detected language
    # ...
```

#### Step 5.2: Update `pyneat/config.py`

Language-aware configuration:

```toml
# pyproject.toml
[tool.pyneat]
enabled_languages = ["python", "javascript", "typescript"]

[tool.pyneat.languages.javascript]
enable_strict_equality = true
enable_var_to_const = true

[tool.pyneat.languages.go]
enable_unchecked_error = true
```

---

### Phase 6: Testing (Week 3-4)

```
tests/
├── test_ln_ast.py              # Rust LN-AST extraction
├── test_rust_parser.py         # pyneat-rs multi-language parsing
├── test_universal_rules.py     # Universal rule tests (all languages)
├── test_javascript_rules.py     # JS/TS specific rules
├── test_go_rules.py           # Go specific rules
└── test_integration.py         # End-to-end multi-language scan
```

---

## 5. IMPLEMENTATION PRIORITY ORDER

```
=== Phase 1: Rust Layer (Week 1) ===
1.  pyneat-rs/Cargo.toml           ← Add all tree-sitter grammar deps
2.  pyneat-rs/src/scanner/ln_ast.rs ← LN-AST schema
3.  pyneat-rs/src/scanner/multilang.rs ← Multi-language parser
4.  pyneat-rs/src/lib.rs           ← Add parse_ln_ast(), detect_language()

=== Phase 2: Engine Integration (Week 1-2) ===
5.  pyneat/core/types.py            ← Add ln_ast field to CodeFile
6.  pyneat/core/engine.py          ← Branch: Python (libcst) vs non-Python (Rust)
7.  pyneat/rules/base.py           ← Add supported_languages, get_ln_* helpers

=== Phase 3: Universal Rules (Week 2) ===
8.  pyneat/rules/universal/base.py ← UniversalRule base class
9.  pyneat/rules/universal/hardcoded_secrets.py
10. pyneat/rules/universal/debug_artifacts.py
11. pyneat/rules/universal/empty_catch.py
12. pyneat/rules/universal/todos.py
13. pyneat/rules/universal/arrow_antipattern.py

=== Phase 4: Language-Specific Rules (Week 2-3) ===
14. pyneat/rules/javascript/equality.py
15. pyneat/rules/javascript/var_to_const.py
16. pyneat/rules/go/unchecked_error.py
17. pyneat/rules/java/raw_types.py
18. pyneat/rules/java/resource_leak.py
19. pyneat/rules/rust/unwrap_usage.py
20. pyneat/rules/rust/unsafe_audit.py
21. pyneat/rules/csharp/async_void.py
22. pyneat/rules/php/var_dump.py
23. pyneat/rules/ruby/binding_pry.py

=== Phase 5: CLI + Config (Week 3) ===
24. pyneat/cli.py                   ← --language flag, auto-detection
25. pyneat/config.py                 ← Language-aware config

=== Phase 6: Testing (Week 3-4) ===
26. Test Rust LN-AST extraction      ← Unit tests for each language
27. Test universal rules             ← Cross-language coverage
28. Test language-specific rules     ← Per-language coverage
29. Test CLI integration             ← End-to-end tests
30. Regression tests                 ← Python unchanged
```

---

## 6. DEPENDENCIES

### Rust side (required for non-Python):
```toml
# pyneat-rs/Cargo.toml additions:
tree-sitter-javascript = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-go = "0.23"
tree-sitter-java = "0.23"
tree-sitter-rust = "0.23"
tree-sitter-c-sharp = "0.23"
tree-sitter-php = "0.23"
tree-sitter-ruby = "0.23"
```

### Python side:
No new dependencies for Python users (tree-sitter is in Rust).

For `pip install pyneat-cli[multilang]`:
- Builds Rust extension with all grammar deps
- Installs `pyneat_rs` Python module

---

## 7. KEY DESIGN DECISIONS

### Q: Tại sao không đưa tất cả parsing vào Python adapters?

**A**: Python adapters với tree-sitter packages tạo ra:
1. Dependency hell (8 optional packages)
2. Import overhead mỗi lần chạy
3. Không tận dụng được Rust performance

**Solution**: Rust parse once, return JSON, Python consume.

### Q: Tại sao universal rules dùng regex trên source text thay vì LN-AST?

**A**: Một số patterns (debug statements, TODOs) hiệu quả hơn với regex trên source. LN-AST vẫn được dùng cho structural patterns (functions, classes, imports).

### Q: Làm sao để thêm ngôn ngữ mới?

**A**: Chỉ cần:
1. Thêm grammar vào `pyneat-rs/Cargo.toml`
2. Thêm parser logic trong `multilang.rs`
3. Thêm extension mapping trong `detect_language_from_extension()`
4. Không cần thay đổi engine hay rule base

### Q: Python rules vẫn dùng libcst?

**A**: Đúng. Python giữ nguyên behavior với libcst vì:
1. LibCST provides precise code transformation (not just detection)
2. Python rules are already mature and well-tested
3. No reason to rewrite working code

---

## 8. VERIFICATION CHECKLIST

### Python (No Regression)
- [ ] `pyneat clean test.py` works identically
- [ ] All existing tests pass
- [ ] `pip install pyneat-cli` works without Rust (Python-only mode)

### Multi-language
- [ ] `pyneat clean test.js --language javascript` detects console.log, ==/===
- [ ] `pyneat clean test.go --language go` detects unchecked errors
- [ ] `pyneat clean-dir ./src --language auto` auto-detects all languages
- [ ] `pyneat clean test.rs --language rust` detects unwrap() calls

### Engine Integration
- [ ] Python: uses libcst (verified by existing behavior)
- [ ] Non-Python: uses Rust parser → LN-AST → rules
- [ ] No `if lang == "python":` branches in rule loop

### Performance
- [ ] Rust parsing adds < 50ms overhead per file
- [ ] LN-AST JSON serialization < 10ms
- [ ] Universal rules work on pre-parsed LN-AST (no re-parsing)

---

## 9. FILE STRUCTURE (After Implementation)

```
pyneat/
├── core/
│   ├── engine.py              # Updated: Python vs Rust parsing branch
│   └── types.py              # Updated: CodeFile.ln_ast field
├── rules/
│   ├── base.py               # Updated: supported_languages, get_ln_* helpers
│   ├── universal/            # NEW: Universal rules
│   │   ├── __init__.py
│   │   ├── base.py           # UniversalRule base class
│   │   ├── hardcoded_secrets.py
│   │   ├── debug_artifacts.py
│   │   ├── empty_catch.py
│   │   ├── todos.py
│   │   └── arrow_antipattern.py
│   ├── javascript/            # NEW: JS/TS rules
│   │   ├── __init__.py
│   │   ├── equality.py
│   │   └── var_to_const.py
│   ├── go/                    # NEW: Go rules
│   │   ├── __init__.py
│   │   └── unchecked_error.py
│   └── ... (existing Python rules — UNCHANGED)
└── cli.py                     # Updated: --language flag

pyneat-rs/
├── Cargo.toml                 # Updated: +8 tree-sitter grammars
└── src/
    ├── lib.rs                 # Updated: parse_ln_ast(), detect_language()
    └── scanner/
        ├── ln_ast.rs          # NEW: LN-AST schema
        ├── multilang.rs       # NEW: Multi-language parser
        └── tree_sitter.rs     # Existing: Python parser
```

---

## 10. COMPARISON: v1.0 vs v2.0

| Aspect | v1.0 (Adapter Pattern) | v2.0 (4-Layer Pipeline) |
|--------|-------------------------|---------------------------|
| **Parsing** | Python: libcst, Others: tree-sitter Python packages | Python: libcst, Others: Rust tree-sitter |
| **AST Access** | `raw_node: Any` leaks abstraction | Clean JSON via LN-AST |
| **Engine** | `if lang == "python":` branch duplicates logic | Single code path, parsing abstracted |
| **Rules** | "Universal" rules still call `adapter.get_*()` | True universal: regex on source or LN-AST |
| **Dependencies** | 8 optional Python tree-sitter packages | Single Rust binary |
| **Adding language** | New adapter file + registry | Update Cargo.toml + multilang.rs |
| **Performance** | Python parsing per-language | Rust parallel parsing + JSON |
| **Code duplication** | High (every adapter reimplements same methods) | Low (single LN-AST schema) |

---

## 11. RISKS AND MITIGATIONS

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rust compilation slow | High | Use `cargo check` during dev, full build only for release |
| LN-AST schema changes | Medium | Version the schema, handle backward compat |
| New language parsing bugs | Medium | Exhaustive test coverage per language |
| Rust/Python version mismatch | Low | Use maturin for build, version pins |
| Performance regression | Low | Benchmark before/after, Rust is faster |
