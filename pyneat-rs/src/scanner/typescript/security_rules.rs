//! TypeScript Security and Quality Rules
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

use once_cell::sync::Lazy;
use regex::Regex;

// ─────────────────────────────────────────────────────────────────────────────
// TypeScript Finding Structure
// ─────────────────────────────────────────────────────────────────────────────

/// A finding from TypeScript security/quality rules.
#[derive(Debug, Clone)]
pub struct TsFinding {
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub problem: String,
    pub fix_hint: String,
    pub cwe: Option<String>,
}

impl TsFinding {
    pub fn new(rule_id: &str, severity: &str, line: usize, snippet: &str, problem: &str, fix_hint: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line,
            column: 0,
            snippet: snippet.to_string(),
            problem: problem.to_string(),
            fix_hint: fix_hint.to_string(),
            cwe: None,
        }
    }

    pub fn with_cwe(rule_id: &str, severity: &str, line: usize, snippet: &str, problem: &str, fix_hint: &str, cwe: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line,
            column: 0,
            snippet: snippet.to_string(),
            problem: problem.to_string(),
            fix_hint: fix_hint.to_string(),
            cwe: Some(cwe.to_string()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-compiled Regex Patterns
// ─────────────────────────────────────────────────────────────────────────────

/// TS-SEC-001: Type annotation with `any`
static RE_ANY_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r":\s*any\b").unwrap()
});

/// TS-SEC-002: Non-null assertion operator `!`
static RE_NON_NULL_ASSERTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"!\s*[,);}\]]|\w+!\s*[,);}\]]").unwrap()
});

/// TS-SEC-003: declare global block
static RE_DECLARE_GLOBAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"declare\s+global\s*\{").unwrap()
});

/// TS-SEC-004: Unsafe type cast with `as`
static RE_UNSAFE_CAST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bas\s+(?:any|unknown)\b").unwrap()
});

/// TS-SEC-005: Template literal with potential injection
static RE_TEMPLATE_INJECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"`[^`]*\$\{[^}]*(?:request|input|param|query|user|data|payload|body|cookie)[^}]*\}\s*`").unwrap()
});

/// TS-SEC-006: eval() or Function() usage
static RE_EVAL_FUNCTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:eval|Function)\s*\(").unwrap()
});

/// TS-SEC-007: Hardcoded secrets patterns
static RE_HARDCODED_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:api[_-]?key|password|passwd|pwd|secret|token|auth|bearer|credential|private[_-]?key)\s*[=:]\s*["'][^"']{4,}["']"#).unwrap()
});

/// TS-SEC-007: AWS keys pattern
static RE_AWS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"#).unwrap()
});

/// TS-SEC-008: React dangerouslySetInnerHTML
static RE_DANGEROUS_INNER_HTML: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"dangerouslySetInnerHTML\s*=\s*\{").unwrap()
});

/// TS-SEC-009: fetch() or axios with URL
static RE_SSRF_FETCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:fetch|axios)\s*\([^)]*(?:request|url|endpoint|href|src|uri)[^)]*\)"#).unwrap()
});

/// TS-SEC-010: SQL in template literals
static RE_SQL_TEMPLATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*`"#).unwrap()
});

/// TS-QUAL-001: @ts-ignore or @ts-nocheck
static RE_TS_IGNORE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//\s*@ts-ignore|//\s*@ts-nocheck|/\*\s*@ts-ignore").unwrap()
});

/// TS-QUAL-002: Empty catch block
static RE_EMPTY_CATCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bcatch\s*\([^)]*\)\s*\{\s*\}").unwrap()
});

/// TS-QUAL-003: Function returning `any`
static RE_ANY_RETURN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r":\s*any\s*=>").unwrap()
});

/// TS-AI-001: TODO/FIXME patterns
static RE_TODO_FIXME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)//\s*(TODO|FIXME|HACK|XXX|NOTE):").unwrap()
});

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

fn _get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.trim().to_string())
}

fn _check_user_input_in_expr(expr: &str) -> bool {
    let user_patterns = [
        "request", "input", "param", "query", "body",
        "header", "cookie", "user", "data", "payload",
        "location.search", "location.hash",
    ];
    user_patterns.iter().any(|p| expr.contains(p))
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeScript Security Rules (TS-SEC-001 to TS-SEC-010)
// ─────────────────────────────────────────────────────────────────────────────

/// TS-SEC-001: Any Type Used
/// Detects TypeScript type annotations using the `any` type.
/// CWE: CWE-710 (Incorrect Permission Assignment)
pub struct TsAnyTypeUsed;

impl TsAnyTypeUsed {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_ANY_TYPE.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-001",
                    "medium",
                    line_idx + 1,
                    line.trim(),
                    "TypeScript 'any' type disables type checking. This bypasses compile-time safety and can lead to runtime errors.",
                    "Use specific types, unknown with type guards, or define proper interfaces. Example: Use Record<string, string> instead of any.",
                    "CWE-710"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-002: Non-Null Assertion Abuse
/// Detects the `!` operator used for type assertions.
/// CWE: CWE-665 (Improper Initialization)
pub struct TsNonNullAssertion;

impl TsNonNullAssertion {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_NON_NULL_ASSERTION.is_match(line) && !line.contains("!==") && !line.contains("!=") {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-002",
                    "medium",
                    line_idx + 1,
                    line.trim(),
                    "Non-null assertion (!) bypasses TypeScript's null checking. This can cause runtime errors if the value is actually null/undefined.",
                    "Use optional chaining (?.) or explicit null checks instead. Example: value?.property or if (value) { ... }",
                    "CWE-665"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-003: Declare Global Side Effects
/// Detects side effects in declare global blocks.
/// CWE: CWE-664 (Improper Control of a Resource)
pub struct TsDeclareGlobalSideEffects;

impl TsDeclareGlobalSideEffects {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let lines: Vec<&str> = code.lines().collect();
        let mut in_global = false;
        let mut brace_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            if RE_DECLARE_GLOBAL.is_match(trimmed) {
                in_global = true;
                let _global_start = line_idx + 1;
                brace_count = 0;
            }

            if in_global {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                // Check for side effects inside declare global
                let has_side_effects = trimmed.contains("console.")
                    || trimmed.contains("document.")
                    || trimmed.contains("window.")
                    || trimmed.contains("localStorage")
                    || trimmed.contains("sessionStorage")
                    || (trimmed.contains("function") && trimmed.contains("("));

                if has_side_effects && brace_count > 0 {
                    findings.push(TsFinding::with_cwe(
                        "TS-SEC-003",
                        "high",
                        line_idx + 1,
                        trimmed,
                        "Side effects in 'declare global' block can cause unexpected behavior at module load time.",
                        "Move side effects out of declare global. Use explicit initialization or import statements instead.",
                        "CWE-664"
                    ));
                }

                if brace_count <= 0 && trimmed.contains('}') {
                    in_global = false;
                }
            }
        }
        findings
    }
}

/// TS-SEC-004: Unsafe Type Cast
/// Detects unsafe type casts using `as any` or `as unknown`.
/// CWE: CWE-710 (Incorrect Permission Assignment)
pub struct TsUnsafeCast;

impl TsUnsafeCast {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_UNSAFE_CAST.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-004",
                    "medium",
                    line_idx + 1,
                    line.trim(),
                    "Unsafe type cast to 'any' or 'unknown' bypasses TypeScript's type safety. This can lead to runtime errors.",
                    "Use proper type guards, type predicates, or narrowing. Example: if (typeof value === 'string') { ... }",
                    "CWE-710"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-005: Template Literal Injection
/// Detects template literals that may contain user-controlled input.
/// CWE: CWE-94 (Code Injection)
pub struct TsTemplateInjection;

impl TsTemplateInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_TEMPLATE_INJECTION.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-005",
                    "high",
                    line_idx + 1,
                    line.trim(),
                    "Template literal contains user-controlled input. This can lead to code injection if the input is not properly sanitized.",
                    "Validate and sanitize user input before using in template literals. Use allowlists for permitted values.",
                    "CWE-94"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-006: Eval / Function Injection
/// Detects dynamic code execution via eval() or Function().
/// CWE: CWE-95 (Dynamic Code Execution)
pub struct TsEvalFunction;

impl TsEvalFunction {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_EVAL_FUNCTION.is_match(line) {
                let severity = if line.contains("eval") { "critical" } else { "high" };
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-006",
                    severity,
                    line_idx + 1,
                    line.trim(),
                    "Dynamic code execution via eval() or Function() is a severe security risk. Attackers can inject and execute arbitrary code.",
                    "Avoid eval() and Function() entirely. Use safer alternatives like JSON.parse() for data, or use Web Workers for code generation.",
                    "CWE-95"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-007: Hardcoded Secrets
/// Detects hardcoded API keys, passwords, tokens, and credentials.
/// CWE: CWE-798 (Use of Hard-coded Credentials)
pub struct TsHardcodedSecrets;

impl TsHardcodedSecrets {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_HARDCODED_SECRET.is_match(line) || RE_AWS_KEY.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-007",
                    "high",
                    line_idx + 1,
                    line.trim(),
                    "Hardcoded secrets detected. These credentials can be extracted from source code and used for unauthorized access.",
                    "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Example: process.env.API_KEY",
                    "CWE-798"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-008: React XSS via dangerouslySetInnerHTML
/// Detects dangerous React patterns for XSS attacks.
/// CWE: CWE-79 (Cross-site Scripting)
pub struct TsReactXss;

impl TsReactXss {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_DANGEROUS_INNER_HTML.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-008",
                    "high",
                    line_idx + 1,
                    line.trim(),
                    "dangerouslySetInnerHTML can introduce XSS vulnerabilities. User-controlled data rendered this way can execute malicious scripts.",
                    "Use DOMPurify.sanitize() to sanitize HTML before rendering, or use a safer alternative like React's textContent.",
                    "CWE-79"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-009: SSRF via fetch() / axios
/// Detects URL fetching with potentially user-controlled URLs.
/// CWE: CWE-918 (Server-Side Request Forgery)
pub struct TsSsrf;

impl TsSsrf {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_SSRF_FETCH.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-009",
                    "high",
                    line_idx + 1,
                    line.trim(),
                    "URL fetching with user-controlled input can lead to SSRF attacks. Attackers can probe internal services or exfiltrate data.",
                    "Validate URLs against an allowlist of permitted domains. Use URL parsing to verify the protocol is http/https only.",
                    "CWE-918"
                ));
            }
        }
        findings
    }
}

/// TS-SEC-010: SQL Injection via Template Literals
/// Detects SQL queries constructed using template strings.
/// CWE: CWE-89 (SQL Injection)
pub struct TsSqlInjection;

impl TsSqlInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_SQL_TEMPLATE.is_match(line) {
                findings.push(TsFinding::with_cwe(
                    "TS-SEC-010",
                    "critical",
                    line_idx + 1,
                    line.trim(),
                    "SQL query constructed from template literal. This can lead to SQL injection if the interpolated values contain user input.",
                    "Use parameterized queries or an ORM. Example: db.query('SELECT * FROM users WHERE id = ?', [userId])",
                    "CWE-89"
                ));
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeScript Quality Rules (TS-QUAL-001 to TS-QUAL-003)
// ─────────────────────────────────────────────────────────────────────────────

/// TS-QUAL-001: @ts-ignore / @ts-nocheck
/// Detects TypeScript suppression directives.
pub struct TsTypeIgnore;

impl TsTypeIgnore {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_TS_IGNORE.is_match(line) {
                let directive = if line.contains("@ts-nocheck") { "@ts-nocheck" } else { "@ts-ignore" };
                findings.push(TsFinding::new(
                    "TS-QUAL-001",
                    "medium",
                    line_idx + 1,
                    line.trim(),
                    &format!("{} suppresses TypeScript errors. This hides type safety issues that should be fixed.", directive),
                    "Fix the underlying type error instead of suppressing it. Use proper types or type guards to resolve the issue.",
                ));
            }
        }
        findings
    }
}

/// TS-QUAL-002: Empty Catch Block
/// Detects empty catch blocks that silently swallow errors.
pub struct TsEmptyCatch;

impl TsEmptyCatch {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_EMPTY_CATCH.is_match(line) {
                findings.push(TsFinding::new(
                    "TS-QUAL-002",
                    "low",
                    line_idx + 1,
                    line.trim(),
                    "Empty catch block silently ignores errors. This can hide bugs and make debugging difficult.",
                    "Add error handling logic to the catch block, or log the error for debugging. Example: catch (e) { console.error(e); }",
                ));
            }
        }
        findings
    }
}

/// TS-QUAL-003: Any Return Type on Public API
/// Detects `any` return types in function declarations.
pub struct TsAnyReturnType;

impl TsAnyReturnType {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_ANY_RETURN.is_match(line) && (line.contains("function") || line.contains("=>")) {
                findings.push(TsFinding::new(
                    "TS-QUAL-003",
                    "medium",
                    line_idx + 1,
                    line.trim(),
                    "Function returns 'any' type, losing type safety on the API boundary. Callers won't benefit from TypeScript's type checking.",
                    "Define a proper return type or use generics. Example: function foo(): Promise<User[]> { ... }",
                ));
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AI-Specific Rules (TS-AI-001)
// ─────────────────────────────────────────────────────────────────────────────

/// TS-AI-001: AI TODO/FIXME Patterns
/// Detects TODO/FIXME comments commonly left in AI-generated code.
pub struct TsAiTodo;

impl TsAiTodo {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        for (line_idx, line) in code.lines().enumerate() {
            if RE_TODO_FIXME.is_match(line) {
                findings.push(TsFinding::new(
                    "TS-AI-001",
                    "low",
                    line_idx + 1,
                    line.trim(),
                    "TODO/FIXME comment found. This may indicate incomplete implementation or placeholder code.",
                    "Review and address TODO items before production deployment. Replace with proper implementation or remove if resolved.",
                ));
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ESLint Interlace / eslint-plugin-security Rules (TS-SEC-015 to TS-SEC-025)
// These rules cover common JS/TS security patterns from eslint-plugin-security
// and related security linting tools. Derived from OWASP, Node.js Security,
// and common vulnerability patterns in JavaScript/TypeScript applications.
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-015: Detect `eval()` and similar dangerous code execution
pub struct TsEvalInterlace;

impl TsEvalInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"eval\s*\("#, "eval() with string — arbitrary code execution"),
            (r#"new\s+Function\s*\("#, "new Function() — arbitrary code execution"),
            (r#"setTimeout\s*\(\s*["\'][^"\']{20,}"#, "setTimeout with string — indirect eval risk"),
            (r#"setInterval\s*\(\s*["\'][^"\']{20,}"#, "setInterval with string — indirect eval risk"),
            (r#"execScript\s*\("#, "execScript() — IE-only code execution"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-015", "critical", line, line_text.trim(),
                        format!("Dangerous code execution: {}.", problem).as_str(),
                        "Avoid eval(), new Function(), and setTimeout/setInterval with strings. \
                         Use JSON.parse() for JSON, import() for dynamic modules.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-016: Detect `path.join` or `fs` operations with user input (path traversal)
pub struct TsPathTraversalInterlace;

impl TsPathTraversalInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?:path|Paths)\.(?:join|resolve)\s*\([^)]*req\."#, "path.join with request data — path traversal"),
            (r#"fs\.(?:readFile|writeFile|readFileSync|writeFileSync|unlink)\s*\([^)]*req\."#, "fs op with request data — path traversal"),
            (r#"import\s*\(\s*req\."#, "Dynamic import with request data — path traversal"),
            (r#"fs\.(?:createReadStream|createWriteStream)\s*\([^)]*req\."#, "fs stream with request path — path traversal"),
            (r#"sendFile\s*\(\s*req\."#, "res.sendFile with request data — path traversal"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-016", "high", line, line_text.trim(),
                        format!("Path Traversal: {}.", problem).as_str(),
                        "Always validate and sanitize file paths. Use path.normalize() and verify \
                         the resolved path is within the intended directory.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-017: Detect SQL injection patterns in JS/TS (knex, sequelize, mysql)
pub struct TsSqlInjectionInterlace;

impl TsSqlInjectionInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?:mysql|pg|mysql2)\.(?:query|execute)\s*\(\s*`[^`]*\$\{"#, "SQL template literal with interpolation — SQL injection"),
            (r#"knex\s*\(\s*['"][^'"]*\+[^)]+\)"#, "Knex raw query with concatenation — SQL injection"),
            (r#"(?:sequelize|prisma)\.\$query\s*\([^)]*\+[^)]+\)"#, "ORM raw query with concatenation — SQL injection"),
            (r#"pool\.query\s*\(`[^`]*\$\{"#, "DB pool query with template interpolation — SQL injection"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-017", "high", line, line_text.trim(),
                        format!("SQL Injection: {}.", problem).as_str(),
                        "Use parameterized queries or prepared statements. \
                         Never concatenate user input into SQL strings.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-018: Detect command injection via child_process with user input
pub struct TsCommandInjectionInterlace;

impl TsCommandInjectionInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"child_process\.(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\+[^)]*req\."#, "child_process with req concatenation — command injection"),
            (r#"(?:exec|execSync|spawn|spawnSync)\s*\(`[^`]*\$\{"#, "Shell command with template interpolation — command injection"),
            (r#"popen\s*\([^)]*\+[^)]+\)"#, "popen with concatenation — command injection"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-018", "critical", line, line_text.trim(),
                        format!("Command Injection: {}.", problem).as_str(),
                        "Never pass user input to shell commands. Use execFile with an argument array \
                         instead of a shell string.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-019: Detect insecure HTTP/TLS configurations
pub struct TsInsecureTlsInterlace;

impl TsInsecureTlsInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"rejectUnauthorized\s*:\s*(?:false|0)"#, "rejectUnauthorized: false — TLS validation disabled"),
            (r#"secure\s*:\s*(?:false|0)"#, "Cookie secure: false — sent over HTTP"),
            (r#"TLS\s*\(\s*\{[^}]*secureProtocol\s*:"[^"]*(?:SSLv3|TLSv1)"#, "Insecure TLS protocol version"),
            (r#"axios\s*\(\s*\{[^}]*secure\s*:\s*(?:false|0)"#, "Axios with secure: false"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-019", "high", line, line_text.trim(),
                        format!("Insecure TLS/HTTP: {}.", problem).as_str(),
                        "Always enable TLS verification. Use rejectUnauthorized: true (default). \
                         Use TLS 1.2 or higher.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-020: Detect hardcoded credentials and secrets in JS/TS
pub struct TsHardcodedSecretsInterlace;

impl TsHardcodedSecretsInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}"#, "Hardcoded password"),
            (r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}"#, "Hardcoded API key"),
            (r#"(?i)(?:secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}"#, "Hardcoded secret/token"),
            (r#"(?i)(?:aws[_-]?(?:access[_-]?key|secret))\s*[:=]\s*['\"][^'\"]+"#, "Hardcoded AWS credentials"),
            (r#"Bearer\s+[A-Za-z0-9_\-\.]{16,}"#, "Hardcoded Bearer token"),
            (r#"Basic\s+[A-Za-z0-9+\/=]{16,}"#, "Hardcoded Basic auth credentials"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-020", "critical", line, line_text.trim(),
                        format!("Hardcoded Secret: {}.", problem).as_str(),
                        "Never hardcode secrets. Use environment variables: \
                         process.env.SECRET_KEY or a secrets manager.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-021: Detect regex DoS (ReDoS) patterns
pub struct TsRegexDosInterlace;

impl TsRegexDosInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"/\(\?:[^)]*\+{2,}[^)]*\)\*\*/"#, "Nested quantifiers: (?:a+)+ — catastrophic backtracking"),
            (r#"/\(\?:[^)]*\*\)\+\*/"#, "Nested * and + quantifiers — ReDoS risk"),
            (r#"/\(\.[^)]*\+\)\+/"#, "Repeated optional groups: (.+)+ — ReDoS"),
            (r#"/\(\[\^[^]]*\]\+\)\+/"#, "Negated char class with + quantifier — ReDoS"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-021", "medium", line, line_text.trim(),
                        format!("Regex DoS: {}.", problem).as_str(),
                        "Refactor to avoid nested quantifiers. Break complex patterns into simpler ones.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-022: Detect XSS vulnerabilities in template rendering
pub struct TsXssInterlace;

impl TsXssInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?:innerHTML|dangerouslySetInnerHTML)\s*=\s*(?:req\.|body\.|params\.)"#, "innerHTML/dangerouslySetInnerHTML with user data — XSS"),
            (r#"document\.write\s*\([^)]*req\."#, "document.write with request data — XSS"),
            (r#"(?:res|response)\.(?:send|write|end)\s*\(\s*req\."#, "Response with request data — potential XSS"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-022", "high", line, line_text.trim(),
                        format!("XSS Risk: {}.", problem).as_str(),
                        "Always escape user input in templates. Never use innerHTML with unescaped user data. \
                         Use textContent or template literals safely.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-023: Detect Server-Side Request Forgery (SSRF)
pub struct TsSsrfInterlace;

impl TsSsrfInterlace {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?:axios|got|node-fetch|fetch|request)\s*\([^)]*req\."#, "HTTP client with request URL — SSRF risk"),
            (r#"new\s+URL\s*\([^)]*req\."#, "new URL with request data — SSRF via URL constructor"),
            (r#"(?:res\.redirect)\s*\(\s*req\."#, "Redirect with request URL — SSRF risk"),
            (r#"import\s*\(\s*req\."#, "Dynamic import with request URL — SSRF risk"),
            (r#"dns\.lookup\s*\([^)]*req\."#, "DNS lookup with request data — DNS rebinding SSRF"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-023", "high", line, line_text.trim(),
                        format!("SSRF: {}.", problem).as_str(),
                        "Always validate and allowlist destination URLs. \
                         Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-024: Detect insecure cookie configuration
pub struct TsInsecureCookie;

impl TsInsecureCookie {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"cookie\s*\(\s*\{[^}]*httpOnly\s*:\s*(?:false|0)[^}]*\}"#, "Cookie without httpOnly — XSS session hijacking"),
            (r#"cookie\s*\(\s*\{[^}]*secure\s*:\s*(?:false|0)[^}]*\}"#, "Cookie secure: false — sent over HTTP"),
            (r#"cookie\s*\(\s*\{[^}]*sameSite\s*:\s*(?:false|null)["\s,}]"#, "Cookie sameSite disabled — CSRF risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-024", "medium", line, line_text.trim(),
                        format!("Insecure Cookie: {}.", problem).as_str(),
                        "Always set httpOnly: true, secure: true (HTTPS), and sameSite: 'strict' or 'lax'.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-025: Detect HTTP Parameter Pollution (HPP)
pub struct TsHttpParamPollution;

impl TsHttpParamPollution {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"(?:req|request)\.query\.\w+\s*(?:===?|!==?)\s*(?:req|request)\.body\.\w+"#, "Query/body parameter collision — HPP risk"),
            (r#"Object\.assign\s*\([^,]+\s*,\s*(?:req|request)\.(?:query|body|params)\)"#, "Object.assign merging request data — HPP bypass"),
            (r#"\{[^}]*\.\.\.(?:req|request)\.(?:query|body|params)[^}]*\}"#, "Spread operator with request data — HPP risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-025", "medium", line, line_text.trim(),
                        format!("HTTP Parameter Pollution: {}.", problem).as_str(),
                        "Validate and sanitize merged request parameters. Use explicit parameter extraction.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT Security Rules (TS-SEC-026 to TS-SEC-030)
// Detect JWT vulnerabilities: weak algorithms, none algorithm, missing verification
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-026: JWT with none algorithm (CWE-347)
pub struct TsJwtNoneAlgorithm;

impl TsJwtNoneAlgorithm {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:jwt\.sign|jwt\.encode)\s*\([^)]*algorithm\s*:\s*['"]none['"]"##,
             "JWT signed with algorithm 'none' — tokens are unsigned and unauthenticated"),
            (r##"(?i)(?:jwt\.sign|jwt\.encode)\s*\([^)]*algorithm\s*:\s*['"]None['"]"##,
             "JWT signed with algorithm 'None' — tokens are unsigned"),
            (r##"(?i)(?:jsonwebtoken|jwt)\s*\.\s*sign\s*\([^)]*\{[^}]*algorithm\s*:\s*['\"]n['"]"##,
             "JWT with short 'n' algorithm — likely 'none' bypass"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-026", "critical", line, line_text.trim(),
                        format!("JWT none algorithm: {}.", problem).as_str(),
                        "Never use algorithm 'none' in JWT. Always use RS256 or ES256. \
                         Explicitly specify the expected algorithm during verification.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-027: JWT with weak or asymmetric algorithm confusion
pub struct TsJwtWeakAlgorithm;

impl TsJwtWeakAlgorithm {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:jwt\.verify|jwt\.decode)\s*\([^)]*\{[^}]*algorithms\s*:\s*\[[^\]]*['"]HS256['"]"##,
             "JWT verification accepting HS256 — potential algorithm confusion if RS256 key is used as HMAC"),
            (r##"(?i)(?:jwt\.verify|jwt\.decode)\s*\([^)]*\{[^}]*algorithms\s*:\s*\[[^\]]*['"]RS256['"]"##,
             "JWT accepting RS256 — verify key type matches algorithm"),
            (r##"(?i)(?:jwt\.sign|jwt\.encode)\s*\([^)]*algorithm\s*:\s*['"](?:HS[12]56|RS[123]56|PS[123]56|ES[123]456)"##,
             "JWT with algorithm — verify this matches your key type"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-027", "high", line, line_text.trim(),
                        format!("JWT algorithm concern: {}.", problem).as_str(),
                        "Use RS256 or ES256 for asymmetric signing. Never accept multiple algorithms \
                         without strict validation. Verify key type matches algorithm.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-028: JWT missing expiration (exp) claim
pub struct TsJwtMissingExp;

impl TsJwtMissingExp {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)jwt\.sign\s*\(\s*\{[^}]*(?:\bno?[_\-]expir|no?[_\-]exp|expires[_\-]?in\s*:\s*false)"##,
             "JWT signed without expiration — tokens never expire"),
            (r##"(?i)jwt\.sign\s*\(\s*\{[^}]*(?!\bexp\b)[^}]*\}[^)]*(?:\.sign)?\s*\)\s*;?\s*$"##,
             "JWT signed — verify exp (expiration) claim is present"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-028", "medium", line, line_text.trim(),
                        format!("JWT missing expiration: {}.", problem).as_str(),
                        "Always include 'exp' claim in JWT. Set reasonable expiration times. \
                         Use short-lived tokens (15-60 min) for access tokens.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-029: JWT verification disabled
pub struct TsJwtNoVerify;

impl TsJwtNoVerify {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)jwt\.verify\s*\([^,)]+,\s*(?:null|undefined|['\"][^'\"]*['"]\s*\)"##,
             "jwt.verify with null/false secret — signature verification disabled"),
            (r##"(?i)\.verify\s*\([^)]*,\s*\{[^}]*verifySignature\s*:\s*(?:false|0)"##,
             "JWT verifySignature disabled — tokens not validated"),
            (r##"(?i)\.decode\s*\([^)]*\{\s*[^}]*complete\s*:\s*true[^}]*\}\)"##,
             "jwt.decode with complete:true but no verify — signature not checked"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-029", "critical", line, line_text.trim(),
                        format!("JWT verification disabled: {}.", problem).as_str(),
                        "Always verify JWT signatures with a trusted secret or public key. \
                         Never skip signature verification in production.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-030: JWT with user-controlled payload (alg: none bypass via kid header)
pub struct TsJwtKidInjection;

impl TsJwtKidInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)jwt\.sign\s*\([^)]*\{[^}]*(?:kid|keyid)[^}]*\}\s*,"##,
             "JWT with kid (key ID) from user-controlled source — key confusion risk"),
            (r##"(?i)jwt\.sign\s*\([^)]*payload[^)]*params\."##,
             "JWT payload from request params — verify this is server-controlled"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-030", "high", line, line_text.trim(),
                        format!("JWT key injection: {}.", problem).as_str(),
                        "Validate and sanitize 'kid' JWT header. Use jku/x5u headers with allowlist. \
                         Never use kid to select keys from untrusted input without validation.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB NoSQL Injection Rules (TS-SEC-031 to TS-SEC-033)
// Detect MongoDB query injection patterns
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-031: MongoDB NoSQL injection via query operators
pub struct TsNosqlInjectionMongo;

impl TsNosqlInjectionMongo {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:collection|db)\.(?:find|findOne|update|delete)\s*\(\s*\{[^}]*(?:where|query)\s*:\s*req\."##,
             "MongoDB query with request data directly — NoSQL injection risk"),
            (r##"(?i)(?:collection|db)\.(?:find|findOne)\s*\(\s*\{\s*\$where\s*:\s*["\']"##,
             "MongoDB $where with string — code injection risk"),
            (r##"(?i)new\s+mongo\.ObjectId\s*\(\s*req\."##,
             "ObjectId constructed from request — verify input is sanitized"),
            (r##"(?i)(?:collection|db)\.(?:aggregate|mapReduce)\s*\([^)]*req\."##,
             "MongoDB aggregate/mapReduce with request data — NoSQL injection risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-031", "high", line, line_text.trim(),
                        format!("NoSQL Injection: {}.", problem).as_str(),
                        "Use MongoDB sanitization or schema validation. Never pass raw request data to MongoDB queries. \
                         Use parameterized queries or mongoose schema validation.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-032: MongoDB $where with user input enables code injection
pub struct TsNosqlWhereInjection;

impl TsNosqlWhereInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)\$where\s*:\s*["\`][^"\`]*\$\{"##,
             "MongoDB $where with template interpolation — code injection"),
            (r##"(?i)\$where\s*:\s*function\s*\([^)]*\)\s*\{[^}]*(?:params|request|req\.)"##,
             "MongoDB $where function with request data — code injection"),
            (r##"(?i)\$expr\s*:\s*\{[^}]*(?:params|request|req\.)"##,
             "MongoDB $expr with request data — expression injection"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-032", "critical", line, line_text.trim(),
                        format!("NoSQL $where injection: {}.", problem).as_str(),
                        "Never use $where with user input. Use standard MongoDB query operators \
                         with proper type validation. Replace $where with $eq, $gt, $regex with strict anchoring.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-033: MongoDB regex with user input (ReDoS)
pub struct TsNosqlRegexInjection;

impl TsNosqlRegexInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)\.find\s*\(\s*\{[^}]*\$regex\s*:\s*["\'][^"\']*\$\{"##,
             "MongoDB regex with interpolation — NoSQL injection + ReDoS risk"),
            (r##"(?i)\.find\s*\(\s*\{[^}]*\$regex\s*:\s*req\."##,
             "MongoDB regex with request data — ReDoS risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-033", "medium", line, line_text.trim(),
                        format!("NoSQL regex injection: {}.", problem).as_str(),
                        "Escape special regex characters in user input. Use allowlist validation for regex patterns. \
                         Add regex timeout if your MongoDB driver supports it.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Express/NestJS Security Rules (TS-SEC-034 to TS-SEC-038)
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-034: Express without rate limiting
pub struct TsExpressNoRateLimit;

impl TsExpressNoRateLimit {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let has_express = code.contains("express()") || code.contains("require('express')");
        if !has_express { return findings; }

        let has_rate_limit = code.contains("rate-limit") ||
                            code.contains("express-rate-limit") ||
                            code.contains("rateLimit") ||
                            code.contains("ratelimit");
        if has_rate_limit { return findings; }

        let patterns = [
            (r##"(?i)app\.(?:use|get|post|put|delete|patch)\s*\([^)]*"##,
             "Express route without rate limiting middleware"),
        ];
        for (pat, _problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-034", "medium", line, line_text.trim(),
                        "Express application has no rate limiting — susceptible to brute force and DoS attacks.".into(),
                        "Add rate limiting middleware: express-rate-limit. \
                         Apply per-IP or per-user limits on sensitive endpoints.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-035: Missing Helmet.js security headers
pub struct TsMissingHelmet;

impl TsMissingHelmet {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let has_express = code.contains("express()") || code.contains("require('express')");
        if !has_express { return findings; }

        let has_helmet = code.contains("helmet()") ||
                         code.contains("require('helmet')") ||
                         code.contains("'helmet'");
        if has_helmet { return findings; }

        let patterns = [
            (r##"(?i)app\.use\s*\(\s*\)"##,
             "Express app.use() without helmet() — security headers missing"),
        ];
        for (pat, _problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-035", "low", line, line_text.trim(),
                        "Express app missing helmet() middleware — security headers not set.".into(),
                        "Add helmet() middleware early in the Express chain. \
                         It sets security-related HTTP headers: X-Frame-Options, CSP, HSTS, etc.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-036: CORS misconfiguration
pub struct TsCorsMisconfiguration;

impl TsCorsMisconfiguration {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?"##,
             "CORS with origin: '*' — allows any website to make requests"),
            (r##"(?i)cors\s*\(\s*\{[^}]*credentials\s*:\s*(?:true|1)[^}]*origin\s*:\s*['\"]?\*['\"]?"##,
             "CORS with credentials:true AND origin:'*' — browser rejects (CVE-like pattern)"),
            (r##"(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|1)[^}]*\}"##,
             "CORS origin:true — reflects request Origin header (origin spoofing risk)"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-036", "medium", line, line_text.trim(),
                        format!("CORS misconfiguration: {}.", problem).as_str(),
                        "Use specific allowed origins: origin: ['https://trusted.com']. \
                         Never use '*' with credentials:true. Use environment variables for allowed origins.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-037: Express trust proxy disabled
pub struct TsTrustProxy;

impl TsTrustProxy {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let has_express = code.contains("express()") || code.contains("require('express')");
        if !has_express { return findings; }

        let patterns = [
            (r##"(?i)app\.set\s*\(\s*['"]trust[_\-]proxy['"]\s*,\s*(?:false|0|['"]\s*['\"])"##,
             "trust_proxy disabled — req.ip, req.protocol may be spoofed behind reverse proxy"),
            (r##"(?i)(?:app|express)\s*\(\s*\{[^}]*trustProxy\s*:\s*(?:false|0)"##,
             "trustProxy: false — IP-based rate limiting and auth may be bypassed"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-037", "medium", line, line_text.trim(),
                        format!("Trust proxy issue: {}.", problem).as_str(),
                        "Enable trust proxy when behind a reverse proxy (nginx, CDN, load balancer): \
                         app.set('trust proxy', 1) or app.set('trust proxy', 'loopback').".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-038: Method-override security bypass
pub struct TsMethodOverride;

impl TsMethodOverride {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)methodOverride\s*\([^)]*query\s*:\s*['\"]?_method"##,
             "method-override with query:_method — CSRF protection may be bypassed"),
            (r##"(?i)methodOverride\s*\([^)]*header\s*:\s*['\"]?x-http-method-override"##,
             "method-override via header — verify CSRF tokens are checked on all methods"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-038", "medium", line, line_text.trim(),
                        format!("Method override: {}.", problem).as_str(),
                        "Ensure CSRF protection is applied after method override middleware. \
                         Use token-based CSRF validation on state-changing operations.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL Security Rules (TS-SEC-039 to TS-SEC-045)
// Detect PostgreSQL-specific vulnerabilities in Node.js/TypeScript apps
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-039: PostgreSQL connection string with hardcoded credentials
pub struct TsPgHardcodedCredentials;

impl TsPgHardcodedCredentials {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|mysql2|mariadb|postgres)\.(?:connect|createPool)\s*\(\s*['\"]postgres://[^:]+:[^@]+@"##,
             "Database connection with credentials in URI — hardcoded password"),
            (r##"(?i)(?:pg|mysql2)\.(?:connect|createPool)\s*\(\s*\{[^}]*(?:password|user|host)[^}]*:\s*['\"][^'\"]{3,}"##,
             "DB config object with hardcoded password/user — credentials in source"),
            (r##"(?i)connectionString\s*[=:]\s*['\"][^'\"]*://[^:]+:[^@]+@"##,
             "Connection string with embedded credentials — hardcoded password"),
            (r##"(?i)DATABASE_URL\s*[=:]\s*['\"][^'\"]*://[^:]+:[^@]+@"##,
             "DATABASE_URL env var assigned literal — hardcoded password"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-039", "critical", line, line_text.trim(),
                        format!("Hardcoded DB credentials: {}.", problem).as_str(),
                        "Never embed credentials in source code. Use environment variables: \
                         process.env.DATABASE_URL or connection details from a secrets manager.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-040: PostgreSQL query without parameterized values
pub struct TsPgSqlInjection;

impl TsPgSqlInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.query\s*\(`[^`]*\$\{"##,
             "pg.query with template literal interpolation — SQL injection"),
            (r##"(?i)(?:pg|postgres)\.query\s*\(['\"][^'\"]*%s[^'\"]*['\"]\s*,\s*\["##,
             "pg.query with format string and array — verify parameterized"),
            (r##"(?i)(?:pg|postgres)\.query\s*\(\s*['\"][^'\"]*\$1[^'\"]*['\"]"##,
             "pg.query with positional parameter — this is generally safe if values are passed separately"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-040", "high", line, line_text.trim(),
                        format!("PostgreSQL injection: {}.", problem).as_str(),
                        "Always use parameterized queries: \
                         pg.query('SELECT * FROM users WHERE id = $1', [userId]). \
                         Never interpolate user input into SQL strings.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-041: PostgreSQL SSL disabled
pub struct TsPgNoSsl;

impl TsPgNoSsl {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.(?:connect|createPool)\s*\(\s*\{[^}]*ssl\s*:\s*(?:false|0|{[^}]*rejectUnauthorized\s*:\s*(?:false|0))[^}]*\}"##,
             "PostgreSQL connection with SSL disabled — data transmitted unencrypted"),
            (r##"(?i)(?:pg|postgres)\.(?:connect|createPool)\s*\(\s*['\"][^'\"]*sslmode=disable[^'\"]*['\"]"##,
             "PostgreSQL connection string with sslmode=disable — TLS disabled"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-041", "high", line, line_text.trim(),
                        format!("PostgreSQL SSL disabled: {}.", problem).as_str(),
                        "Always enforce SSL for database connections. Use sslmode=require or sslmode=verify-full. \
                         Set rejectUnauthorized appropriately for your TLS setup.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-042: PostgreSQL prepared statement misuse
pub struct TsPgPreparedStatement;

impl TsPgPreparedStatement {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.prepare\s*\(['\"][^'\"]*['\"]\s*,\s*['\"][^'\"]*\$\{"##,
             "Prepared statement with interpolation in query — SQL injection"),
            (r##"(?i)(?:pg|postgres)\.(?:prepare|query)\s*\([^)]*\+[^)]*(?:req|params|body)"##,
             "Prepared statement with string concatenation — SQL injection"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-042", "high", line, line_text.trim(),
                        format!("PostgreSQL prepared statement misuse: {}.", problem).as_str(),
                        "Use parameterized values in prepared statements: \
                         client.query('INSERT INTO users(name) VALUES($1)', [name]). \
                         Never concatenate into the query string.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-043: PostgreSQL connection pool without limits
pub struct TsPgPoolNoLimits;

impl TsPgPoolNoLimits {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.createPool\s*\(\s*\{[^}]*\}(?:\s*,\s*\{[^}]*\})?(?!\s*\*\s*,\s*\d)"##,
             "Connection pool created without max connection limits — resource exhaustion risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-043", "medium", line, line_text.trim(),
                        format!("PostgreSQL pool limits: {}.", problem).as_str(),
                        "Configure pool limits: max: 20, idleTimeoutMillis: 30000. \
                         Prevent unbounded connection growth under load.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-044: PostgreSQL schema from user input
pub struct TsPgSchemaInjection;

impl TsPgSchemaInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.(?:query|connect)\s*\([^)]*"schema"[^)]*req\."##,
             "PostgreSQL schema set from request data — schema injection"),
            (r##"(?i)SET\s+(?:search_path|schema)[^;]*(?:\+[^;]*)"##,
             "SET search_path with string concatenation — SQL injection in schema"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-044", "high", line, line_text.trim(),
                        format!("PostgreSQL schema injection: {}.", problem).as_str(),
                        "Never use user input in schema names. Use a whitelist of allowed schemas. \
                         Always quote identifiers: identifier = 'my_schema'; \
                         client.query('SET search_path = $1', [identifier]).".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-045: PostgreSQL advisory lock misuse
pub struct TsPgAdvisoryLock;

impl TsPgAdvisoryLock {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:pg|postgres)\.(?:query|connect)\s*\([^)]*pg_advisory_lock\s*\([^)]*\+[^)]+\)"##,
             "pg_advisory_lock with concatenation — lock key injection"),
            (r##"(?i)SELECT\s+pg_advisory_(?:un)?lock[^;]*req\."##,
             "PostgreSQL advisory lock with user input — denial of service risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-045", "medium", line, line_text.trim(),
                        format!("PostgreSQL advisory lock: {}.", problem).as_str(),
                        "Use deterministic integer keys for advisory locks. \
                         Derive lock keys from stable app identifiers, not user input. \
                         Consider Redis for distributed locking.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS Lambda Security Rules (TS-SEC-046 to TS-SEC-053)
// Detect AWS Lambda and cloud security misconfigurations
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-046: Lambda overprivileged IAM role
pub struct TsLambdaOverprivilegedIam;

impl TsLambdaOverprivilegedIam {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)Lambda\.(?:createFunction|updateFunctionConfiguration)\s*\([^)]*Role\s*:\s*['\"]arn:aws:iam::[^:]+:role/Admin"##,
             "Lambda with Admin IAM role — principle of least privilege violated"),
            (r##"(?i)\{[^}]*Effect\s*:\s*['\"]Allow[^}]*Action\s*:\s*['\"]\*['\"][^}]*\}"##,
             "IAM policy with Action: '*' — overly permissive"),
            (r##"(?i)\{[^}]*Resource\s*:\s*['\"]\*['\"][^}]*Effect\s*:\s*['\"]Allow"##,
             "IAM policy with Resource: '*' — overly permissive"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-046", "high", line, line_text.trim(),
                        format!("Lambda overprivileged IAM: {}.", problem).as_str(),
                        "Apply least privilege: create specific IAM roles with only required actions. \
                         Use aws:SourceAccount and aws:SourceArn conditions. \
                         Regularly audit Lambda IAM roles.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-047: Lambda environment variables with secrets
pub struct TsLambdaEnvSecrets;

impl TsLambdaEnvSecrets {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)Environment\s*:\s*\{[^}]*Variables\s*:\s*\{[^}]*(?:API[_-]?KEY|SECRET[_-]?KEY|PASSWORD|TOKEN|PRIVATE)"##,
             "Lambda environment variables contain sensitive secrets — exposed in function configuration"),
            (r##"(?i)process\.env\.(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)"##,
             "Lambda accessing sensitive env vars — verify these are set securely, not via plaintext config"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-047", "critical", line, line_text.trim(),
                        format!("Lambda env secrets: {}.", problem).as_str(),
                        "Never store secrets in Lambda environment variables directly. \
                         Use AWS Secrets Manager or Systems Manager Parameter Store. \
                         Access via IAM roles: AWS_LAMBDA_FUNCTION_NAME and AWS_SESSION_TOKEN.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-048: Lambda SSRF via AWS metadata endpoint (IMDSv1)
pub struct TsLambdaSsrfImds;

impl TsLambdaSsrfImds {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)http://169\.254\.169\.254"##,
             "Lambda accessing AWS IMDSv1 metadata endpoint — SSRF risk if user input reaches this URL"),
            (r##"(?i)aws:meta service/(?:iam/security-credentials|latest/meta-data/instance-id)"##,
             "AWS metadata service access — verify this can't be triggered by user-controlled input"),
            (r##"(?i)(?:axios|fetch|request|got)\s*\([^)]*169\.254\.169\.254"##,
             "HTTP client fetching from IMDS endpoint — SSRF risk if URL is user-controlled"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-048", "high", line, line_text.trim(),
                        format!("Lambda IMDS SSRF: {}.", problem).as_str(),
                        "Disable IMDSv1: set aws:vpc:resource-tag/instance:RequiredTag or use ec2:MetadataNoToken. \
                         Prefer IMDSv2 which requires session tokens. \
                         Restrict outbound traffic from Lambda using VPC security groups.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-049: Lambda with public S3 access
pub struct TsLambdaPublicS3Access;

impl TsLambdaPublicS3Access {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)S3\(\s*\{[^}]*acl\s*:\s*['\"]?(?:public-read|public-read-write|authenticated-read)"##,
             "S3 bucket/object with public ACL — data exposure risk"),
            (r##"(?i)(?:putObject|getObject|upload)\s*\([^)]*\{[^}]*ACL\s*:\s*['\"]?(?:public-read)"##,
             "S3 operation with public ACL — publicly accessible object"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-049", "high", line, line_text.trim(),
                        format!("Lambda S3 public access: {}.", problem).as_str(),
                        "Use bucket policies and IAM policies instead of ACLs. \
                         Enable S3 Block Public Access. \
                         Use presigned URLs for temporary access to private objects.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-050: Lambda Cognito misconfiguration
pub struct TsCognitoMisconfig;

impl TsCognitoMisconfig {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)CognitoUserPool[^;]*allow_.*(?:?:email|phone_number|username)\s*:\s*(?:true|1)"##,
             "Cognito: email/phone number verification disabled — account takeover risk"),
            (r##"(?i)AdminCreateUser[^;]*AutoConfirmUser\s*:\s*(?:true|1)"##,
             "Cognito AdminCreateUser with auto-confirm — skip email verification"),
            (r##"(?i)Cognito[^;]*PasswordPolicy[^;]*MinimumLength\s*:\s*[0-7]\b"##,
             "Cognito password policy too weak — less than 8 characters"),
            (r##"(?i)InitiateAuth[^;]*AuthFlow\s*:\s*['\"]USER_PASSWORD_AUTH['\"]"##,
             "Cognito USER_PASSWORD_AUTH flow — passwords transmitted to server"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-050", "medium", line, line_text.trim(),
                        format!("Cognito misconfiguration: {}.", problem).as_str(),
                        "Enforce email/phone verification. Use USER_SRP_AUTH or USER_AUTH flows. \
                         Set strong password policy (min 16 chars, complexity). \
                         Enable MFA for sensitive operations.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-051: Lambda cloudwatch log exposure
pub struct TsCloudwatchLogExposure;

impl TsCloudwatchLogExposure {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:console\.(?:log|debug|info)\s*\([^)]*(?:password|secret|token|key|credential)"##,
             "Logging sensitive data — credentials may appear in CloudWatch logs"),
            (r##"(?i)(?:log|logger)\.(?:debug|info|warn|error)\s*\([^)]*(?:req\.body|request\.body|params)"##,
             "Logging full request body — sensitive user data in CloudWatch"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-051", "medium", line, line_text.trim(),
                        format!("CloudWatch log exposure: {}.", problem).as_str(),
                        "Never log sensitive data (passwords, tokens, PII). \
                         Use structured logging with explicit field allowlists. \
                         Enable CloudWatch log encryption with KMS.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-052: Lambda wildcard resource policy
pub struct TsLambdaWildcardResource;

impl TsLambdaWildcardResource {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)Statement\s*:\s*\[.*Effect\s*:\s*['\"]Allow['\"].*Resource\s*:\s*['\"]\*['\"]"##,
             "IAM policy with Resource: '*' allowing all resources — overly permissive"),
            (r##"(?i)Action\s*:\s*['\"]\*['\"].*Resource\s*:\s*['\"]\*['\"]"##,
             "IAM policy with Action: '*' and Resource: '*' — grants full access"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-052", "high", line, line_text.trim(),
                        format!("Lambda wildcard resource: {}.", problem).as_str(),
                        "Restrict IAM to specific resources. Use ARNs with wildcards only for specific service actions. \
                         Example: 'arn:aws:lambda:*:*:function:my-function'. \
                         Audit policies with 'Resource': '*' regularly.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-053: Lambda secrets manager access without encryption
pub struct TsLambdaSecretsManagerPlaintext;

impl TsLambdaSecretsManagerPlaintext {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)SecretsManager[^;]*\.getSecretValue\s*\([^)]*\)(?!\s*\*\s*\.KmsKeyId)"##,
             "Secrets Manager access without KMS key — secrets retrieved in plaintext"),
            (r##"(?i)getSecretValue[^;]*\.SecretString[^;]*\.KmsKeyId"##,
             "Verify KMS key is used to encrypt retrieved secrets"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-053", "medium", line, line_text.trim(),
                        format!("Lambda secrets manager: {}.", problem).as_str(),
                        "Enable KMS encryption for secrets: use SecretsManager with KmsKeyId. \
                         Rotate secrets regularly using AWS Secrets Manager rotation. \
                         Grant minimal access to secrets via IAM.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Node.js Core Security Rules (TS-SEC-054 to TS-SEC-070)
// Detect Node.js-specific vulnerabilities: crypto, events, HTTP, security
// ─────────────────────────────────────────────────────────────────────────────

// TS-SEC-054: Node.js crypto with weak algorithm
pub struct TsNodeWeakCrypto;

impl TsNodeWeakCrypto {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)crypto\.createCipher\s*\(\s*\)"##,
             "crypto.createCipher() deprecated — use crypto.createCipheriv() with explicit IV"),
            (r##"(?i)crypto\.createDecipher\s*\(\s*\)"##,
             "crypto.createDecipher() deprecated — use crypto.createDecipheriv() with explicit IV"),
            (r##"(?i)(?:createHash|createHmac)\s*\(\s*['\"](?:md5|sha1|des|rc4| Blowfish|blowfish)['\"]"##,
             "Weak hash algorithm (MD5, SHA1, DES, RC4, Blowfish) used for security"),
            (r##"(?i)crypto\.randomBytes\s*\(\s*[0-7]\b"##,
             "crypto.randomBytes with less than 8 bytes — insufficient randomness"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-054", "high", line, line_text.trim(),
                        format!("Node.js weak crypto: {}.", problem).as_str(),
                        "Use SHA-256+ for hashing, AES-256-GCM for encryption. \
                         Use crypto.randomBytes(32) for tokens. \
                         Replace deprecated createCipher/createDecipher with createCipheriv/createDecipheriv.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-055: Node.js EventEmitter memory leak (maxListeners)
pub struct TsEventEmitterLeak;

impl TsEventEmitterLeak {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:on|addListener|once|prependListener)\s*\(\s*['\"][^'\"]+['\"][^;]*\)\s*(?:;|\n)(?!.*setMaxListeners)"##,
             "EventEmitter listener added without setMaxListeners — potential memory leak"),
            (r##"(?i)\.on\s*\([^)]*req\."##,
             "Dynamic event listener with request data — verify this doesn't accumulate listeners"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-055", "medium", line, line_text.trim(),
                        format!("EventEmitter leak: {}.", problem).as_str(),
                        "Set maxListeners or use { once: true } for one-time handlers. \
                         Remove listeners when done: emitter.off('event', handler). \
                         Use AbortController for request-scoped resources.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-056: Node.js prototype pollution
pub struct TsPrototypePollution;

impl TsPrototypePollution {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)Object\.assign\s*\([^,]+,\s*(?:req\.|body\.|params\.)"##,
             "Object.assign with request data — prototype pollution risk"),
            (r##"(?i)\.\.\.(?:req|request|params|body|query)\b"##,
             "Spread operator with request object — prototype pollution risk"),
            (r##"(?i)(?:merge|deepMerge|extend)\s*\([^)]*\.(?:req|body|params)\."##,
             "Lodash/utility merge with request data — prototype pollution"),
            (r##"(?i)(?:__proto__|constructor|prototype)\s*:"##,
             "__proto__, constructor, or prototype in object — potential prototype pollution"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-056", "high", line, line_text.trim(),
                        format!("Prototype pollution: {}.", problem).as_str(),
                        "Block dangerous keys: const blocked = ['__proto__', 'constructor', 'prototype']; \
                         if (blocked.includes(key)) return; \
                         Use Object.freeze() on sensitive objects. \
                         Consider using a schema validator (Joi, Zod, Yup).".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-057: Node.js glob pattern DoS
pub struct TsGlobDos;

impl TsGlobDos {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:glob|fast-glob|minimatch)\s*\([^)]*req\."##,
             "Glob/minimatch with user-controlled pattern — directory traversal or DoS risk"),
            (r##"(?i)(?:glob|fast-glob)\s*\(\s*\{[^}]*nosort\s*:\s*(?:false|0)[^}]*\}"##,
             "Glob with nosort disabled — potential filesystem enumeration"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-057", "medium", line, line_text.trim(),
                        format!("Glob DoS: {}.", problem).as_str(),
                        "Never use user input directly as glob patterns. \
                         Validate and sanitize patterns. Limit scope to known directories. \
                         Use readdir with depth limits instead of glob.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-058: Node.js vm module sandbox escape
pub struct TsVmSandboxEscape;

impl TsVmSandboxEscape {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)vm\.runInNewContext\s*\([^,)]+\s*,\s*\{[^}]*\}\s*(?:\,\s*\{[^}]*\})?"##,
             "vm.runInNewContext with sandbox — verify context is properly isolated"),
            (r##"(?i)new\s+vm\.Context\s*\(\s*\{"##,
             "vm.Context created — verify it's used as sandbox and not to expose Node.js APIs"),
            (r##"(?i)vm\.runInVM\s*\([^)]+\)"##,
             "vm.runInVM executes unsandboxed code — arbitrary code execution"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-058", "high", line, line_text.trim(),
                        format!("VM sandbox escape: {}.", problem).as_str(),
                        "The vm module does not provide secure sandboxing. \
                         Use worker_threads with sandboxed VMSnapshot. \
                         Consider vm2 with proper security options or isolated-vm. \
                         Never evaluate user-controlled code in vm.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-059: Node.js takewhile / timing attack
pub struct TsTimingAttack;

impl TsTimingAttack {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:bcrypt|scrypt|argon2)\.compareSync\s*\("##,
             "Synchronous password comparison — timing attack risk on bcrypt.compare (use async)"),
            (r##"(?i)if\s*\([^)]*\s*===\s*[^)]*(?:password|token|secret|key)"##,
             "Direct string comparison for auth — vulnerable to timing attacks"),
            (r##"(?i)(?:crypto\.timingSafeEqual|hmac\.verify)\s*\([^)]*\)(?!\s*\.then)"##,
             "Verify timing-safe comparison is used correctly"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-059", "medium", line, line_text.trim(),
                        format!("Timing attack: {}.", problem).as_str(),
                        "Use crypto.timingSafeEqual() for constant-time comparison of secrets. \
                         Always use async bcrypt.compare() instead of compareSync(). \
                         Use HMAC.verify() for constant-time MAC verification.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-060: Node.js path traversal via symlinks
pub struct TsSymlinkTraversal;

impl TsSymlinkTraversal {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)fs\.readlink\s*\([^)]*req\."##,
             "fs.readlink with user-controlled path — symlink traversal risk"),
            (r##"(?i)fs\.readFileSync\s*\([^)]*fs\.readlink\s*\("##,
             "Following symlinks to read files — verify symlinks are validated"),
            (r##"(?i)fs\.(?:createReadStream|createWriteStream|readFile)\s*\([^)]*path\.join\([^)]*req\."##,
             "fs operation with path.join and request data — verify no symlink traversal"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-060", "high", line, line_text.trim(),
                        format!("Symlink traversal: {}.", problem).as_str(),
                        "Check symlinks before following: fs.lstatSync(path).isDirectory(). \
                         Use realpath() to resolve symlinks. \
                         Set chroot jail or use restricted file access patterns.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-061: Node.js stream manipulation
pub struct TsStreamManipulation;

impl TsStreamManipulation {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)stream\.pipeline\s*\([^)]*(?:req|request|body)\.pipe"##,
             "Stream piping from request — verify stream source is trusted"),
            (r##"(?i)\.pipe\s*\([^)]*res\)(?:\s*\.pipe)?"##,
             "Stream piping to response — verify proper error handling"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-061", "medium", line, line_text.trim(),
                        format!("Stream manipulation: {}.", problem).as_str(),
                        "Use stream.pipeline() instead of pipe() for proper error propagation. \
                         Always handle stream errors: pipeline(src, dest, callback). \
                         Set appropriate highWaterMark for backpressure.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-062: Node.js glob parent directory escape
pub struct TsGlobParentEscape;

impl TsGlobParentEscape {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:glob|fast-glob)\s*\([^)]*['\"][^'\"]*\.\.\/["\']"##,
             "Glob pattern with '../' — parent directory escape risk"),
            (r##"(?i)(?:glob|fast-glob)\s*\([^)]*base\s*:\s*['\"][^'\"]+['\"][^)]*["\']\*\*\/\*\*["\']"##,
             "Glob with double-star matching from base — may escape intended directory"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-062", "high", line, line_text.trim(),
                        format!("Glob parent escape: {}.", problem).as_str(),
                        "Always set a base directory for glob operations. \
                         Validate resolved paths stay within allowed directory: \
                         const resolved = path.resolve(base, match); \
                         if (!resolved.startsWith(base)) return;.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-063: Node.js insecure child_process options
pub struct TsChildProcessOptions;

impl TsChildProcessOptions {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)spawn\s*\([^)]*\{[^}]*shell\s*:\s*(?:true|1)"##,
             "child_process.spawn with shell:true — enables shell interpretation of args"),
            (r##"(?i)exec\s*\([^)]*['\"][^'\"]*(?:\||\;|\&|\$\()[^)\"\']*"##,
             "child_process.exec with shell metacharacters in command — command injection"),
            (r##"(?i)(?:spawn|exec|execFile)\s*\([^)]*\{[^}]*cwd\s*:\s*['\"]\/["\']"##,
             "child_process running from root directory — dangerous if compromised"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-063", "high", line, line_text.trim(),
                        format!("Insecure child_process: {}.", problem).as_str(),
                        "Use spawn/execFile with explicit argument arrays: \
                         spawn('ls', ['-la', dir], { shell: false }). \
                         Never pass user input as shell commands. \
                         Set cwd to a known-safe directory.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-064: Node.js buffer instantiation from user input
pub struct TsBufferOverflow;

impl TsBufferOverflow {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)new\s+Buffer\s*\(\s*(?:req\.|params\.|body\.)"##,
             "Buffer created from user input — potential buffer overflow or data corruption"),
            (r##"(?i)Buffer\.allocUnsafe\s*\(\s*(?:req\.|params\.)"##,
             "Buffer.allocUnsafe with user-controlled size — uninitialized memory exposure"),
            (r##"(?i)buffer\.write\s*\([^)]*req\."##,
             "Buffer write with user input — verify bounds and type safety"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-064", "medium", line, line_text.trim(),
                        format!("Buffer overflow: {}.", problem).as_str(),
                        "Use Buffer.from() or Buffer.alloc() instead of Buffer() constructor. \
                         Validate sizes before buffer allocation. \
                         Use TypedArrays (Uint8Array) for type-safe buffer operations.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-065: Node.js improper TLS certificate validation
pub struct TsTlsCertValidation;

impl TsTlsCertValidation {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)https\.request\s*\(\s*\{[^}]*rejectUnauthorized\s*:\s*(?:false|0)"##,
             "HTTPS request with rejectUnauthorized: false — MITM attack risk"),
            (r##"(?i)process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]"##,
             "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS validation globally"),
            (r##"(?i)tls\.connect\s*\([^)]*rejectUnauthorized\s*:\s*(?:false|0)"##,
             "TLS connection with cert validation disabled — MITM risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-065", "critical", line, line_text.trim(),
                        format!("TLS cert validation disabled: {}.", problem).as_str(),
                        "Never disable TLS certificate validation. Always verify certificates. \
                         Use proper CA store. In development, use a mock server with valid certs. \
                         NEVER set NODE_TLS_REJECT_UNAUTHORIZED=0 in production.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-066: Node.js missing security headers (generic)
pub struct TsMissingSecurityHeaders;

impl TsMissingSecurityHeaders {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let has_express = code.contains("express()");
        if !has_express { return findings; }

        let has_helmet = code.contains("helmet()");
        if has_helmet { return findings; }

        let patterns = [
            (r##"(?i)app\.use\s*\("##,
             "Express app without helmet() — security headers not set"),
        ];
        for (pat, _problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-066", "low", line, line_text.trim(),
                        "Express app missing helmet() — important security headers not set.".into(),
                        "Add helmet() middleware early in your Express chain: \
                         const helmet = require('helmet'); app.use(helmet()); \
                         It sets X-Frame-Options, X-Content-Type-Options, CSP, HSTS, and more.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-067: Node.js regex injection (ReDoS)
pub struct TsRegexInjection;

impl TsRegexInjection {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:new\s+RegExp|RegExp\s*\()\s*\([^)]*\+[^)]+\)"##,
             "RegExp constructed from concatenation — user input in regex enables ReDoS"),
            (r##"(?i)(?:new\s+RegExp|RegExp\s*\()\s*\([^)]*req\."##,
             "RegExp constructed from request data — ReDoS risk"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-067", "medium", line, line_text.trim(),
                        format!("Regex injection: {}.", problem).as_str(),
                        "Never construct RegExp from user input. Validate and sanitize regex patterns. \
                         Use safe-pattern libraries. Add regex timeout if possible.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-068: Node.js unsafe_redirect without validation
pub struct TsUnsafeRedirect;

impl TsUnsafeRedirect {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:res\.)?redirect\s*\(\s*(?:req\.|params\.|query\.)"##,
             "redirect() with user-controlled URL — open redirect vulnerability"),
            (r##"(?i)redirect\s*\(\s*['\"]https?://"##,
             "redirect() to absolute URL — verify this is intentional"),
            (r##"(?i)res\.writeHead\s*\([^)]*Location\s*:\s*(?:req\.|params\.)"##,
             "writeHead with Location header from user — CRLF injection/open redirect"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-068", "medium", line, line_text.trim(),
                        format!("Unsafe redirect: {}.", problem).as_str(),
                        "Always validate redirect URLs against a whitelist. \
                         Check URL is relative: url.startsWith('/') && !url.startsWith('//'). \
                         For external redirects, validate hostname against allowlist.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-069: Node.js missing process error handlers
pub struct TsUncaughtException;

impl TsUncaughtException {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:process|process\.on)\s*\(\s*['\"]unhandledRejection['\"](?!\s*,"##,
             "Unhandled rejection without handler — unhandled promise rejections can crash process"),
            (r##"(?i)(?:process|process\.on)\s*\(\s*['\"]uncaughtException['\"](?!\s*,"##,
             "uncaughtException handler missing or improper — process may be in inconsistent state"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-069", "low", line, line_text.trim(),
                        format!("Uncaught exception: {}.", problem).as_str(),
                        "Add proper error handlers: \
                         process.on('unhandledRejection', (reason, promise) => { ... }); \
                         process.on('uncaughtException', (err) => { ...; process.exit(1); }); \
                         Log errors and gracefully shut down.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// TS-SEC-070: Node.js hardcoded IP addresses
pub struct TsHardcodedIp;

impl TsHardcodedIp {
    pub fn detect(&self, code: &str) -> Vec<TsFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:host|hostname|ip)\s*[=:]\s*['\"]?(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+|192\.168\.\d+)"##,
             "Hardcoded private IP address — verify this is intentional and not exposing internal services"),
            (r##"(?i)(?:ALLOWED_HOSTS|whitelist)\s*[=:]"##,
             "Allowed hosts/whitelist defined — verify it's not too permissive (* or empty)"),
        ];
        for (pat, problem) in patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let line_text = code.lines().nth(line - 1).unwrap_or_default();
                    findings.push(TsFinding::new(
                        "TS-SEC-070", "low", line, line_text.trim(),
                        format!("Hardcoded IP: {}.", problem).as_str(),
                        "Use environment variables for IP allowlists. \
                         Regularly review and rotate whitelisted IPs. \
                         Use domain names for flexibility.".into(),
                    ));
                }
            }
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeScript Security Scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates all TypeScript security and quality rules.
pub struct TypeScriptSecurityScanner {
    rules: Vec<Box<dyn Fn(&str) -> Vec<TsFinding> + Send + Sync>>,
}

impl TypeScriptSecurityScanner {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Fn(&str) -> Vec<TsFinding> + Send + Sync>> = vec![
            Box::new(|code| TsAnyTypeUsed.detect(code)),
            Box::new(|code| TsNonNullAssertion.detect(code)),
            Box::new(|code| TsDeclareGlobalSideEffects.detect(code)),
            Box::new(|code| TsUnsafeCast.detect(code)),
            Box::new(|code| TsTemplateInjection.detect(code)),
            Box::new(|code| TsEvalFunction.detect(code)),
            Box::new(|code| TsHardcodedSecrets.detect(code)),
            Box::new(|code| TsReactXss.detect(code)),
            Box::new(|code| TsSsrf.detect(code)),
            Box::new(|code| TsSqlInjection.detect(code)),
            Box::new(|code| TsTypeIgnore.detect(code)),
            Box::new(|code| TsEmptyCatch.detect(code)),
            Box::new(|code| TsAnyReturnType.detect(code)),
            Box::new(|code| TsAiTodo.detect(code)),
            // ESLint Interlace rules
            Box::new(|code| TsEvalInterlace.detect(code)),
            Box::new(|code| TsPathTraversalInterlace.detect(code)),
            Box::new(|code| TsSqlInjectionInterlace.detect(code)),
            Box::new(|code| TsCommandInjectionInterlace.detect(code)),
            Box::new(|code| TsInsecureTlsInterlace.detect(code)),
            Box::new(|code| TsHardcodedSecretsInterlace.detect(code)),
            Box::new(|code| TsRegexDosInterlace.detect(code)),
            Box::new(|code| TsXssInterlace.detect(code)),
            Box::new(|code| TsSsrfInterlace.detect(code)),
            Box::new(|code| TsInsecureCookie.detect(code)),
            Box::new(|code| TsHttpParamPollution.detect(code)),
            // JWT security rules
            Box::new(|code| TsJwtNoneAlgorithm.detect(code)),
            Box::new(|code| TsJwtWeakAlgorithm.detect(code)),
            Box::new(|code| TsJwtMissingExp.detect(code)),
            Box::new(|code| TsJwtNoVerify.detect(code)),
            Box::new(|code| TsJwtKidInjection.detect(code)),
            // MongoDB NoSQL injection rules
            Box::new(|code| TsNosqlInjectionMongo.detect(code)),
            Box::new(|code| TsNosqlWhereInjection.detect(code)),
            Box::new(|code| TsNosqlRegexInjection.detect(code)),
            // Express/NestJS security rules
            Box::new(|code| TsExpressNoRateLimit.detect(code)),
            Box::new(|code| TsMissingHelmet.detect(code)),
            Box::new(|code| TsCorsMisconfiguration.detect(code)),
            Box::new(|code| TsTrustProxy.detect(code)),
            Box::new(|code| TsMethodOverride.detect(code)),
            // PostgreSQL security rules
            Box::new(|code| TsPgHardcodedCredentials.detect(code)),
            Box::new(|code| TsPgSqlInjection.detect(code)),
            Box::new(|code| TsPgNoSsl.detect(code)),
            Box::new(|code| TsPgPreparedStatement.detect(code)),
            Box::new(|code| TsPgPoolNoLimits.detect(code)),
            Box::new(|code| TsPgSchemaInjection.detect(code)),
            Box::new(|code| TsPgAdvisoryLock.detect(code)),
            // AWS Lambda security rules
            Box::new(|code| TsLambdaOverprivilegedIam.detect(code)),
            Box::new(|code| TsLambdaEnvSecrets.detect(code)),
            Box::new(|code| TsLambdaSsrfImds.detect(code)),
            Box::new(|code| TsLambdaPublicS3Access.detect(code)),
            Box::new(|code| TsCognitoMisconfig.detect(code)),
            Box::new(|code| TsCloudwatchLogExposure.detect(code)),
            Box::new(|code| TsLambdaWildcardResource.detect(code)),
            Box::new(|code| TsLambdaSecretsManagerPlaintext.detect(code)),
            // Node.js core security rules
            Box::new(|code| TsNodeWeakCrypto.detect(code)),
            Box::new(|code| TsEventEmitterLeak.detect(code)),
            Box::new(|code| TsPrototypePollution.detect(code)),
            Box::new(|code| TsGlobDos.detect(code)),
            Box::new(|code| TsVmSandboxEscape.detect(code)),
            Box::new(|code| TsTimingAttack.detect(code)),
            Box::new(|code| TsSymlinkTraversal.detect(code)),
            Box::new(|code| TsStreamManipulation.detect(code)),
            Box::new(|code| TsGlobParentEscape.detect(code)),
            Box::new(|code| TsChildProcessOptions.detect(code)),
            Box::new(|code| TsBufferOverflow.detect(code)),
            Box::new(|code| TsTlsCertValidation.detect(code)),
            Box::new(|code| TsMissingSecurityHeaders.detect(code)),
            Box::new(|code| TsRegexInjection.detect(code)),
            Box::new(|code| TsUnsafeRedirect.detect(code)),
            Box::new(|code| TsUncaughtException.detect(code)),
            Box::new(|code| TsHardcodedIp.detect(code)),
        ];
        Self { rules }
    }

    /// Scan TypeScript code and return all findings.
    pub fn scan(&self, code: &str) -> Vec<TsFinding> {
        use rayon::prelude::*;
        self.rules
            .par_iter()
            .flat_map(|rule| rule(code))
            .collect()
    }

    /// Get all rule IDs this scanner implements.
    pub fn rule_ids(&self) -> Vec<&'static str> {
        vec![
            "TS-SEC-001", "TS-SEC-002", "TS-SEC-003", "TS-SEC-004", "TS-SEC-005",
            "TS-SEC-006", "TS-SEC-007", "TS-SEC-008", "TS-SEC-009", "TS-SEC-010",
            "TS-SEC-015", "TS-SEC-016", "TS-SEC-017", "TS-SEC-018", "TS-SEC-019",
            "TS-SEC-020", "TS-SEC-021", "TS-SEC-022", "TS-SEC-023", "TS-SEC-024",
            "TS-SEC-025", "TS-SEC-026", "TS-SEC-027", "TS-SEC-028", "TS-SEC-029",
            "TS-SEC-030", "TS-SEC-031", "TS-SEC-032", "TS-SEC-033", "TS-SEC-034",
            "TS-SEC-035", "TS-SEC-036", "TS-SEC-037", "TS-SEC-038", "TS-SEC-039",
            "TS-SEC-040", "TS-SEC-041", "TS-SEC-042", "TS-SEC-043", "TS-SEC-044",
            "TS-SEC-045", "TS-SEC-046", "TS-SEC-047", "TS-SEC-048", "TS-SEC-049",
            "TS-SEC-050", "TS-SEC-051", "TS-SEC-052", "TS-SEC-053", "TS-SEC-054",
            "TS-SEC-055", "TS-SEC-056", "TS-SEC-057", "TS-SEC-058", "TS-SEC-059",
            "TS-SEC-060", "TS-SEC-061", "TS-SEC-062", "TS-SEC-063", "TS-SEC-064",
            "TS-SEC-065", "TS-SEC-066", "TS-SEC-067", "TS-SEC-068", "TS-SEC-069",
            "TS-SEC-070",
            "TS-QUAL-001", "TS-QUAL-002", "TS-QUAL-003",
            "TS-AI-001",
        ]
    }
}

impl Default for TypeScriptSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_type_detection() {
        let scanner = TypeScriptSecurityScanner::new();
        let code = r#"
const value: any = getData();
function process(input: any): any {
    return input;
}
"#;
        let findings = scanner.scan(code);
        assert!(findings.iter().any(|f| f.rule_id == "TS-SEC-001"));
    }

    #[test]
    fn test_eval_detection() {
        let scanner = TypeScriptSecurityScanner::new();
        let code = r#"
eval(userInput);
new Function(code);
"#;
        let findings = scanner.scan(code);
        assert!(findings.iter().any(|f| f.rule_id == "TS-SEC-006" && f.severity == "critical"));
    }

    #[test]
    fn test_empty_catch_detection() {
        let scanner = TypeScriptSecurityScanner::new();
        let code = r#"
try {
    doSomething();
} catch (e) {}
"#;
        let findings = scanner.scan(code);
        assert!(findings.iter().any(|f| f.rule_id == "TS-QUAL-002"));
    }

    #[test]
    fn test_ts_ignore_detection() {
        let scanner = TypeScriptSecurityScanner::new();
        let code = r#"
// @ts-ignore
const x: number = "string";
"#;
        let findings = scanner.scan(code);
        assert!(findings.iter().any(|f| f.rule_id == "TS-QUAL-001"));
    }
}
