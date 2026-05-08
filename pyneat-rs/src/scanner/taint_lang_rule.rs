//! Taint-based security scanner.
//!
//! Wraps the TaintEngine as a LanguageScanner so it plugs into the main scan pipeline.
//! Performs data-flow-based vulnerability detection (vs pattern-based rules).

#[allow(dead_code)]

use crate::scanner::base::{LangFinding, LangRule, LanguageScanner};
use crate::scanner::ln_ast::LnAst;
use crate::scanner::multilang::parse_ln_ast;
use crate::scanner::taint::engine::{TaintEngine, TaintFinding};
use crate::scanner::taint::interproc::InterProceduralEngine;
use crate::scanner::taint::labels::TaintRule;
use crate::scanner::taint::rules::all_taint_rules;
use crate::scanner::ParseError;
use crate::scanner::Language;

/// A scanner that runs the full TaintEngine (all 20 taint rules) on source code.
pub struct TaintLangScanner {
    lang: String,
}

impl TaintLangScanner {
    pub fn new(language: &str) -> Self {
        Self {
            lang: language.to_string(),
        }
    }

    pub fn for_extension(ext: &str) -> Option<Self> {
        let lang = match ext {
            "py" => "python",
            "js" | "mjs" | "cjs" | "jsx" => "javascript",
            "ts" | "tsx" => "typescript",
            "go" => "go",
            "java" => "java",
            "rs" => "rust",
            "cs" => "csharp",
            "php" => "php",
            "rb" => "ruby",
            _ => return None,
        };
        Some(Self::new(lang))
    }

    fn convert_finding(f: &TaintFinding) -> LangFinding {
        let rule_id = &f.rule_id;
        let severity = f.severity.to_lowercase();
        LangFinding {
            rule_id: rule_id.clone(),
            severity,
            line: f.line,
            column: f.column,
            start_byte: f.start_byte,
            end_byte: f.end_byte,
            snippet: f.snippet.clone(),
            problem: f.problem.clone(),
            fix_hint: Self::fix_hint_for(rule_id),
            auto_fix_available: false,
            replacement: f.replacement.clone(),
        }
    }

    fn fix_hint_for(rule_id: &str) -> String {
        match rule_id {
            "TAINT-SQL001" => {
                "Use parameterized/prepared queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)) — never concatenate user input into SQL strings.".to_string()
            }
            "TAINT-CMD001" => {
                "Validate input with allowlist. Use subprocess.run([...], shell=False) with args list, or shlex.quote() for strings.".to_string()
            }
            "TAINT-XSS001" => {
                "Use textContent instead of innerHTML, or DOMPurify.sanitize() before rendering user input.".to_string()
            }
            "TAINT-PATH001" => {
                "Validate path with basename(), realpath(), and block traversal patterns (../). Use an allowlist of permitted paths.".to_string()
            }
            "TAINT-NOSQL001" => {
                "Use MongoDB query operators with validated input. Avoid string concatenation in NoSQL queries.".to_string()
            }
            "TAINT-SSRF001" => {
                "Validate and allowlist URLs. Block internal IPs (127.0.0.1, 169.254.169.254), use urlparse to verify scheme is http/https.".to_string()
            }
            "TAINT-XXE001" => {
                "Disable DTDs and external entities in XML parsers. For Java: set FEATURE_SECURE_PROCESSING=true. For Python: use defusedxml.".to_string()
            }
            "TAINT-SSTI001" => {
                "Never pass user input directly to template render functions. Use render_template (not render_template_string) with proper context.".to_string()
            }
            "TAINT-DES001" => {
                "Use SafeResolver for YAML. Never use pickle, Marshal.load, or unserialize() with untrusted data. Use JSON for untrusted data.".to_string()
            }
            "TAINT-RE001" => {
                "Validate regex patterns with length/complexity limits. Use re.compile with a timeout wrapper, or a sandboxed regex engine.".to_string()
            }
            "TAINT-HC001" => {
                "Store credentials in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Never hardcode secrets.".to_string()
            }
            "TAINT-WCRYPTO001" => {
                "Use SHA-256+ for hashing, AES-256-GCM for encryption, and crypto.getRandomValues()/secrets module for random generation.".to_string()
            }
            "TAINT-INSEC001" => {
                "Always enable TLS certificate verification. Set verify=True, InsecureSkipVerify=false, rejectUnauthorized=true, and check_hostname=True.".to_string()
            }
            "TAINT-LDAP001" => {
                "Escape special LDAP characters in user input: *, (, ), \\, NUL. Use a validated/allowlisted DN format instead of raw user input.".to_string()
            }
            "TAINT-FORMAT001" => {
                "Never use user input as a format string. Use proper argument substitution: print('Hello, {}'.format(user_name)) instead of print(user_name). For logging, pass user input as a structured argument, not the format string.".to_string()
            }
            "TAINT-MASS001" => {
                "Use explicit field allowlisting for data binding. Never pass raw user input to object constructors or update methods without validating each field. In Python: define explicit field lists; In JS: use Object.fromEntries with allowlist; In Java: use @Valid with explicit DTOs; In PHP: never use extract() on user input.".to_string()
            }
            "TAINT-REFLECT001" => {
                "Never pass user input to reflection APIs (getattr, Class.forName, Method.invoke, etc.). Use an allowlist of permitted classes/methods. For dynamic imports in Python, validate against a known list of modules.".to_string()
            }
            "TAINT-TYPE001" => {
                "Use strict comparison (=== / !== in JS/PHP, == / != in Python) with explicit type casting. For PHP, always use in_array($val, $arr, true). Validate and cast user input to expected type before comparison.".to_string()
            }
            "TAINT-LOG001" => {
                "Sanitize user input before logging: strip newlines (\\n, \\r) and control characters. Use structured logging with typed fields instead of string interpolation: logger.info('user action', {user: sanitize(user_input)}). For Python, use %s placeholders instead of f-strings.".to_string()
            }
            "TAINT-YAML001" => {
                "Always use the safe YAML loader: Python: yaml.safe_load(); Ruby: YAML.safe_load(); Java: set RootNode to null and restrict class construction; PHP: use yaml_parse() with YAML_NULLABLE tag only. Never load untrusted YAML without a sandboxed loader.".to_string()
            }
            _ => "Sanitize user input before using in sensitive operations.".to_string(),
        }
    }

    /// Run intra-procedural taint analysis (fast, single file).
    /// Uses the worklist-based TaintEngine within each function.
    #[allow(dead_code)]
    fn run_taint(&self, code: &str) -> Vec<LangFinding> {
        let ast_json = parse_ln_ast(code, &self.lang);

        let taint_rules: Vec<Box<dyn TaintRule>> = all_taint_rules();
        let mut engine = TaintEngine::new(code);
        for rule in taint_rules {
            engine.add_rule(rule);
        }
        engine.analyze_with_ast(&ast_json);

        let mut results: Vec<LangFinding> = engine
            .findings()
            .iter()
            .map(Self::convert_finding)
            .collect();

        results.sort_by_key(|f| f.line);
        results
    }

    /// Run inter-procedural taint analysis (cross-function).
    /// Builds a call graph and propagates taint across function boundaries.
    /// For single files, it analyzes all functions in the file.
    /// For multi-file projects, pass multiple (path, ast) pairs.
    pub fn run_taint_interproc(&self, code: &str) -> Vec<LangFinding> {
        let ast = parse_ln_ast(code, &self.lang);

        let mut engine = InterProceduralEngine::new(code);
        engine.build_call_graph(&ast);
        engine.analyze();

        let mut results: Vec<LangFinding> = engine
            .findings()
            .iter()
            .map(Self::convert_finding)
            .collect();

        results.sort_by_key(|f| f.line);
        results
    }

    /// Run inter-procedural analysis across multiple files.
    ///
    /// This is the recommended entry point for project-wide scans.
    /// It builds a unified call graph across all files, enabling
    /// taint tracking across function boundaries even when functions
    /// are defined in different files.
    pub fn run_taint_multi_file(&self, files: &[(String, LnAst)]) -> Vec<LangFinding> {
        if files.is_empty() {
            return Vec::new();
        }

        // Use the language of the first file
        let mut engine = InterProceduralEngine::new("");
        engine.build_from_files(files);
        engine.analyze();

        let mut results: Vec<LangFinding> = engine
            .findings()
            .iter()
            .map(Self::convert_finding)
            .collect();

        results.sort_by_key(|f| f.line);
        results
    }
}

impl LanguageScanner for TaintLangScanner {
    fn language(&self) -> Language {
        Language::from_str(&self.lang).unwrap_or(Language::Python)
    }

    fn extensions(&self) -> Vec<&'static str> {
        match self.lang.as_str() {
            "python" => vec!["py", "pyw", "pyi"],
            "javascript" => vec!["js", "mjs", "cjs", "jsx"],
            "typescript" => vec!["ts", "tsx"],
            "go" => vec!["go"],
            "java" => vec!["java"],
            "rust" => vec!["rs"],
            "csharp" => vec!["cs"],
            "php" => vec!["php"],
            "ruby" => vec!["rb"],
            _ => vec![],
        }
    }

    fn parse(&self, code: &str) -> Result<LnAst, ParseError> {
        Ok(parse_ln_ast(code, &self.lang))
    }

    fn rules(&self) -> Vec<Box<dyn LangRule>> {
        Vec::new()
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        // Use inter-procedural analysis for better cross-function vulnerability detection.
        // This tracks taint across function boundaries using a call graph.
        self.run_taint_interproc(code)
    }
}
