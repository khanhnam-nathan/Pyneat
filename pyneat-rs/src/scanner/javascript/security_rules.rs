//! JavaScript/TypeScript-specific security rules for pyneat-rs.
//!
//! Implements JS-SEC-001 through JS-SEC-015 for security vulnerabilities
//! in AI-generated JavaScript/TypeScript code.

use std::collections::HashSet;

use regex::Regex;

use super::super::ln_ast::LnAst;
use super::super::base::{LangRule, LangFinding, LangFix};

/// Helper: get line byte offsets (0-indexed lines).
fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' {
            current_line += 1;
        }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' {
            line_end = line_start + i + 1;
            break;
        }
    }
    if line_end == line_start {
        line_end = code.len();
    }
    (line_start, line_end)
}

/// Helper: get full line text from line number (1-indexed)
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-001: DOM XSS (innerHTML/outerHTML with user input)
// Severity: critical | CWE-79
// AI uses innerHTML with user input (most common XSS vector)
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsDomXss;

impl LangRule for JsDomXss {
    fn id(&self) -> &str { "JS-SEC-001" }
    fn name(&self) -> &str { "DOM XSS (innerHTML/outerHTML with User Input)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_sinks: HashSet<&str> = [
            "innerHTML", "outerHTML", "insertAdjacentHTML",
            "document.write", "document.writeln",
        ].into_iter().collect();

        let user_input_patterns = [
            "request", "input", "param", "query", "body",
            "header", "cookie", "user", "data", "payload",
            "location.search", "location.hash", "URL",
            "document.cookie", "localStorage", "sessionStorage",
        ];

        for call in &tree.calls {
            if dangerous_sinks.iter().any(|sink| call.callee.ends_with(sink)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                            || a.contains("eval")
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "DOM XSS: '{}' with likely user-controlled input. CWE-79: \
                            Attackers can inject malicious scripts via this sink.",
                            call.callee
                        ),
                        fix_hint: "Use safe DOM APIs: textContent, innerText instead of innerHTML. \
                            Sanitize HTML with DOMPurify before insertion. \
                            Example: element.textContent = userInput; \
                            Or: element.innerHTML = DOMPurify.sanitize(userInput);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also detect direct patterns
        let dom_xss_pattern = Regex::new(
            r#"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*\([^)]*(?:request|input|param|query|user|data|location)"#
        ).unwrap();

        for m in dom_xss_pattern.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            if !findings.iter().any(|f: &LangFinding| f.line == line) {
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "DOM XSS: innerHTML/outerHTML with user-controlled data. CWE-79.".to_string(),
                    fix_hint: "Use textContent instead of innerHTML, or sanitize with DOMPurify.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-002: Prototype Pollution
// Severity: high | CWE-1321
// AI merges objects with __proto__, constructor, prototype
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsPrototypePollution;

impl LangRule for JsPrototypePollution {
    fn id(&self) -> &str { "JS-SEC-002" }
    fn name(&self) -> &str { "Prototype Pollution Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let pollute_patterns = [
            (r#"__proto__"#, "__proto__"),
            (r#"constructor\s*\["#, "constructor[]"),
            (r#"prototype\s*\["#, "prototype[]"),
            (r#"Object\.assign\s*\([^,]+[^,{]"#, "Object.assign without filter"),
            (r#"Object\.merge\s*\([^,]+[^,{]"#, "Object.merge without filter"),
        ];

        let has_user_input = tree.calls.iter().any(|call| {
            call.arguments.iter().any(|a| {
                a.contains("request") || a.contains("input")
                    || a.contains("param") || a.contains("body")
                    || a.contains("query")
            })
        });

        if !has_user_input {
            return findings;
        }

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, name) in &pollute_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Prototype pollution risk: '{}' in code that processes user input. \
                                CWE-1321: Attackers can pollute Object.prototype to modify application behavior.",
                                name
                            ),
                            fix_hint: "Use safe object merging: Object.freeze(Object.assign({}, defaultObj, userObj)). \
                                Validate keys against allowlist. Use schema validation (Joi, Yup). \
                                Avoid merging user-controlled objects directly.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-003: Eval/Function Injection
// Severity: critical | CWE-95
// AI uses eval(), Function(), setTimeout/setInterval with strings
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsEvalInjection;

impl LangRule for JsEvalInjection {
    fn id(&self) -> &str { "JS-SEC-003" }
    fn name(&self) -> &str { "Eval / Function Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_calls: HashSet<&str> = [
            "eval", "Function", "setTimeout", "setInterval",
            "execScript", "new Function",
        ].into_iter().collect();

        let user_input_patterns = [
            "request", "input", "param", "query", "body",
            "header", "user", "data", "payload",
        ];

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            if dangerous_calls.iter().any(|dc| callee_lower.contains(dc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                let (start, end) = get_line_offsets(code, call.start_line);
                let line_text = get_line_text(code, call.start_line)
                    .unwrap_or_default();

                let severity = if has_user_input { "critical" } else { "high" };

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: severity.to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!(
                        "{} execution: '{}' {} user-controlled input. CWE-95: \
                        Arbitrary code can be executed if input is malicious.",
                        if has_user_input { "CRITICAL: eval with" } else { "eval with potential" },
                        call.callee,
                        if has_user_input { "with" } else { "potentially with" }
                    ),
                    fix_hint: "NEVER use eval() with user input. Use JSON.parse() for JSON. \
                        For dynamic code, use WebAssembly or sandboxed iframes. \
                        If you must evaluate expressions, use a safe expression parser like expr-eval.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = get_line_text(code, finding.line)?;
        let trimmed = line_text.trim();

        // For JSON parsing with eval, suggest JSON.parse
        if trimmed.contains("eval(") && trimmed.contains("JSON") {
            let indent = &line_text[..line_text.len() - line_text.trim_start().len()];
            let suggested = format!("{}// FIXME: [JS-SEC-003] Use JSON.parse() instead of eval() for JSON", indent);
            Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text,
                replacement: suggested,
                start_byte: finding.start_byte,
                end_byte: finding.end_byte,
                description: "Replace eval with JSON.parse".to_string(),
            })
        } else {
            None
        }
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-004: Path Traversal
// Severity: high | CWE-22
// AI uses fs.readFile with user-controlled path
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsPathTraversal;

impl LangRule for JsPathTraversal {
    fn id(&self) -> &str { "JS-SEC-004" }
    fn name(&self) -> &str { "Path Traversal / Arbitrary File Read" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let fs_imports = [
            "fs", "fs/promises", "fs-extra", "path",
        ];

        let dangerous_calls: HashSet<&str> = [
            "readFile", "readFileSync", "readdir", "readdirSync",
            "createReadStream", "open", "access", "stat",
            "readFile", "writeFile", "appendFile", "copyFile",
        ].into_iter().collect();

        let has_fs = tree.imports.iter().any(|imp| {
            fs_imports.iter().any(|fs| imp.module.contains(fs))
        });

        if !has_fs {
            return findings;
        }

        let sanitization_patterns = ["path.resolve", "path.normalize", "path.join"];

        for call in &tree.calls {
            if dangerous_calls.iter().any(|dc| call.callee.ends_with(dc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        a.contains("request") || a.contains("input")
                            || a.contains("param") || a.contains("filename")
                            || a.contains("path") || a.contains("user")
                    });

                let has_sanitization = sanitization_patterns.iter().any(|sp| {
                    tree.calls.iter().any(|c| c.callee.contains(sp))
                });

                if has_user_input && !has_sanitization {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "File operation '{}' with likely user-controlled path. CWE-22: \
                            Path traversal — attackers can use '../' to read arbitrary files.",
                            call.callee
                        ),
                        fix_hint: "Use path.join() and path.resolve() to construct safe paths. \
                            Validate the final path stays within an allowed directory. \
                            Example: const safePath = path.join(ALLOWED_DIR, userPath);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-005: Hardcoded Secrets
// Severity: critical | CWE-798
// AI generates code with hardcoded API keys, tokens, passwords
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsHardcodedSecret;

impl LangRule for JsHardcodedSecret {
    fn id(&self) -> &str { "JS-SEC-005" }
    fn name(&self) -> &str { "Hardcoded Secrets / Credentials" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let secret_patterns = [
            (r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|bearer|jwt|private[_-]?key|aws[_-]?secret)\s*[=:]\s*["'][^'"]{4,}["']"#, "hardcoded credential"),
            (r#"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#, "hardcoded JWT/bearer token"),
            (r#"(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*["'][^'"]{10,}["']"#, "hardcoded AWS credentials"),
            (r#"(?i)(?:stripe[_-]?key|paypal[_-]?secret|github[_-]?token|slack[_-]?token)\s*[=:]\s*["'][^'"]{8,}["']"#, "hardcoded payment/API token"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, desc) in &secret_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        for m in re.find_iter(line) {
                            let (start_byte, _) = get_line_offsets(code, line_num);
                            let abs_start = start_byte + line.len() - line.trim_start().len();
                            let abs_end = abs_start + line.len();

                            findings.push(LangFinding {
                                rule_id: self.id().to_string(),
                                severity: self.severity().to_string(),
                                line: line_num,
                                column: m.start(),
                                start_byte: abs_start,
                                end_byte: abs_end,
                                snippet: m.as_str().to_string(),
                                problem: format!(
                                    "Hardcoded secret detected: {}. CWE-798: Secrets in source code \
                                    can be extracted from repositories, bundled JS, or network calls.",
                                    desc
                                ),
                                fix_hint: "Move secrets to environment variables: process.env.API_KEY. \
                                    Use secure vaults (AWS Secrets Manager, HashiCorp Vault). \
                                    In frontend, use HTTP-only cookies or proxy servers.".to_string(),
                                auto_fix_available: false,
                            });
                        }
                    }
                }
            }
        }

        // Check string literals that look like API keys/tokens
        for string_lit in &tree.strings {
            let val = &string_lit.value;
            // Long alphanumeric strings that look like keys
            if val.len() >= 20
                && (val.starts_with("sk_") || val.starts_with("pk_")
                    || val.starts_with("ghp_") || val.starts_with("xoxb-")
                    || val.starts_with("AIza") || val.contains("-----BEGIN")
                    || (val.starts_with("eyJ") && val.contains(".")))
                && !val.to_lowercase().contains("example")
                && !val.to_lowercase().contains("test")
            {
                let (start, end) = get_line_offsets(code, string_lit.start_line);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: string_lit.start_line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: format!("\"{}...\"", &val[..val.len().min(30)]),
                    problem: "Potential hardcoded API key or token detected. CWE-798.".to_string(),
                    fix_hint: "Move to environment variables: process.env.KEY_NAME.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-006: Weak Cryptography (Math.random, MD5/SHA1)
// Severity: high | CWE-327
// AI uses Math.random for security, or weak hash algorithms
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsWeakCrypto;

impl LangRule for JsWeakCrypto {
    fn id(&self) -> &str { "JS-SEC-006" }
    fn name(&self) -> &str { "Weak / Insecure Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for Math.random in security context
        let security_keywords = [
            "password", "token", "key", "session", "id", "captcha",
            "otp", "verification", "crypt", "nonce", "salt",
        ];

        let has_security_context = security_keywords.iter().any(|kw| {
            code.to_lowercase().contains(kw)
        });

        if has_security_context {
            let math_random = Regex::new(r"Math\.random\s*\(\s*\)").unwrap();
            for m in math_random.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Math.random() used in security context. CWE-338: Math.random() \
                        is not cryptographically secure. Attackers can predict values.".to_string(),
                    fix_hint: "Use crypto.getRandomValues() for secure random values: \
                        const array = new Uint32Array(1); crypto.getRandomValues(array); \
                        For Node.js: require('crypto').randomBytes(16).toString('hex');".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        // Check for weak hash algorithm imports
        let weak_algos = ["md5", "sha1", "des", "rc4"];
        for imp in &tree.imports {
            for algo in &weak_algos {
                if imp.module.to_lowercase().contains(algo) {
                    let (start, end) = get_line_offsets(code, imp.start_line);

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: imp.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: imp.module.clone(),
                        problem: format!(
                            "Weak cryptography algorithm '{}' detected. CWE-327: This algorithm \
                            is cryptographically weak and should not be used for security.",
                            algo
                        ),
                        fix_hint: "Use modern algorithms: SHA-256 or SHA-3 for hashing. \
                            For passwords: use bcrypt, scrypt, or Argon2. \
                            Use Web Crypto API: crypto.subtle.digest('SHA-256', data).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Check for crypto.createCipher (deprecated in Node.js)
        let deprecated_crypto = Regex::new(r"crypto\.create(?:Cipher|Cipheriv|Decipher|Decipheriv)\b").unwrap();
        for m in deprecated_crypto.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();

            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: "Deprecated crypto API (createCipher/createDecipher). CWE-327: These APIs \
                    use weak algorithms by default and are deprecated.".to_string(),
                fix_hint: "Use crypto.createCipheriv() and crypto.createDecipheriv() with explicit \
                    algorithms. Prefer Web Crypto API for browser code.".to_string(),
                auto_fix_available: false,
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-007: Open Redirect
// Severity: medium | CWE-601
// AI redirects based on user input without validation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsOpenRedirect;

impl LangRule for JsOpenRedirect {
    fn id(&self) -> &str { "JS-SEC-007" }
    fn name(&self) -> &str { "Open Redirect Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let redirect_calls: HashSet<&str> = [
            "location.href", "location.assign", "location.replace",
            "window.location", "redirect", "router.push",
            "Router.push", "history.push", "res.redirect",
            "Response.redirect",
        ].into_iter().collect();

        let user_input_patterns = [
            "request", "input", "param", "query", "body",
            "url", "next", "redirect", "return", "callback",
        ];

        for call in &tree.calls {
            if redirect_calls.iter().any(|rc| call.callee.ends_with(rc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Open redirect: '{}' with user-controlled input. CWE-601: \
                            Attackers can redirect users to phishing or malicious sites.",
                            call.callee
                        ),
                        fix_hint: "Validate URLs against an allowlist of permitted domains. \
                            Never redirect based on raw user input. Check if URL is relative \
                            or from trusted domain. Example: \
                            if (isAllowedUrl(url)) { window.location.href = url; }".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        // Also detect regex for URL validation
        let unsafe_redirect = Regex::new(
            r#"(?:redirect|href|location)\s*=\s*[^;]*(?:request|input|param|query|url)"#
        ).unwrap();

        for m in unsafe_redirect.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            if !findings.iter().any(|f: &LangFinding| f.line == line) {
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "Potentially unsafe redirect with user input. CWE-601.".to_string(),
                    fix_hint: "Validate redirect URLs against an allowlist.".to_string(),
                    auto_fix_available: false,
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-008: SSRF (Server-Side Request Forgery)
// Severity: high | CWE-918
// AI uses fetch/axios with user-controlled URLs
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsSsrf;

impl LangRule for JsSsrf {
    fn id(&self) -> &str { "JS-SEC-008" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_calls: HashSet<&str> = [
            "fetch", "axios", "request", "http.request",
            "https.request", "got", "node-fetch", "superagent",
            "ajax", "$.ajax", "$.get", "$.post",
        ].into_iter().collect();

        let user_input_patterns = [
            "request", "input", "param", "query", "body",
            "url", "uri", "src", "href", "dest", "endpoint",
        ];

        for call in &tree.calls {
            if http_calls.iter().any(|hc| call.callee.to_lowercase().contains(hc)) {
                let has_user_input = !call.arguments.is_empty()
                    && call.arguments.iter().any(|a| {
                        user_input_patterns.iter().any(|p| a.contains(p))
                    });

                if has_user_input {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "SSRF risk: '{}' with user-controlled URL. CWE-918: \
                            Attackers can make the server request internal resources, \
                            cloud metadata (169.254.169.254), or internal APIs.",
                            call.callee
                        ),
                        fix_hint: "Validate URLs against an allowlist of permitted domains. \
                            Block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x). \
                            Use URL parser to check hostname before fetching. \
                            Example: const url = new URL(input); if (isAllowedHost(url.hostname)) fetch(url);".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-009: SQL Injection (string concatenation in query)
// Severity: critical | CWE-89
// AI builds SQL queries with string concatenation
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsSqlInjection;

impl LangRule for JsSqlInjection {
    fn id(&self) -> &str { "JS-SEC-009" }
    fn name(&self) -> &str { "SQL Injection (String Concatenation)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let db_imports = [
            "mysql", "postgres", "mssql", "oracle",
            "sqlite", "mongodb", "redis", "mysql2",
            "pg", "mongoose", "sequelize", "typeorm",
            "better-sqlite3", "tedious", "oracledb",
        ];

        let has_db = tree.imports.iter().any(|imp| {
            db_imports.iter().any(|db| imp.module.contains(db))
        });

        if !has_db {
            return findings;
        }

        let sql_keywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
            "ALTER", "CREATE", "GRANT", "REVOKE",
        ];

        let sql_pattern = Regex::new(r#"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.+\+.+|"[^"]*"\s*\+"#).unwrap();

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_query = callee_lower.contains("query")
                || callee_lower.contains("execute")
                || callee_lower.contains("raw")
                || callee_lower.contains("sql");

            if is_query && !call.arguments.is_empty() {
                for arg in &call.arguments {
                    // Check for string concatenation with SQL keywords
                    if sql_keywords.iter().any(|kw| arg.to_uppercase().contains(kw))
                        && arg.contains('+')
                    {
                        let (start, end) = get_line_offsets(code, call.start_line);
                        let line_text = get_line_text(code, call.start_line)
                            .unwrap_or_default();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: call.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text.trim().to_string(),
                            problem: format!(
                                "SQL injection risk: SQL query built via string concatenation. \
                                CWE-89: '{}'. Attackers can manipulate queries to access, \
                                modify, or delete data.",
                                call.callee
                            ),
                            fix_hint: "Use parameterized queries / prepared statements: \
                                db.query('SELECT * FROM users WHERE id = ?', [userId]). \
                                Never concatenate user input directly into SQL strings.".to_string(),
                            auto_fix_available: false,
                        });
                        break;
                    }
                }
            }
        }

        // Also check for raw string patterns with SQL
        if sql_pattern.is_match(code) {
            for m in sql_pattern.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                if !findings.iter().any(|f: &LangFinding| f.line == line) {
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: "SQL query with string concatenation detected. CWE-89.".to_string(),
                        fix_hint: "Use parameterized queries.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-010: JWT with "none" Algorithm
// Severity: critical | CWE-347
// AI generates JWT code with algorithm "none" (insecure)
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsJwtNoneAlgorithm;

impl LangRule for JsJwtNoneAlgorithm {
    fn id(&self) -> &str { "JS-SEC-010" }
    fn name(&self) -> &str { "JWT with 'none' Algorithm" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let jwt_patterns = [
            (r#"(?i)jwt|json[_-]?web[_-]?token"#, "JWT usage detected"),
            (r#"(?i)algorithm\s*[=:]\s*["']?none["']?"#, "algorithm: none"),
            (r#"(?i)sign\s*\([^)]*\{[^}]*alg\s*:\s*["']?none["']?"#, "sign with none algorithm"),
        ];

        let has_jwt_import = tree.imports.iter().any(|imp| {
            imp.module.to_lowercase().contains("jsonwebtoken")
                || imp.module.to_lowercase().contains("jwt")
        });

        if !has_jwt_import {
            return findings;
        }

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, name) in &jwt_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        let severity = if pattern.contains("none") { "critical" } else { "high" };

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: severity.to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "JWT security issue: {}. CWE-347: Using 'none' algorithm or \
                                not specifying algorithm allows attackers to forge tokens.",
                                name
                            ),
                            fix_hint: "Always specify a secure algorithm (HS256, RS256, ES256). \
                                Verify algorithm in token: jwt.verify(token, secret, { algorithms: ['HS256'] }). \
                                Never accept 'none' algorithm.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-011: No Rate Limiting
// Severity: medium | CWE-307
// AI generates API endpoints without rate limiting
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsNoRateLimit;

impl LangRule for JsNoRateLimit {
    fn id(&self) -> &str { "JS-SEC-011" }
    fn name(&self) -> &str { "Missing Rate Limiting on API Endpoint" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let rate_limit_imports = [
            "express-rate-limit", "rate-limiter-flexible",
            "rate-limit", "slowdown", "ratelimit",
        ];

        let has_rate_limit = tree.imports.iter().any(|imp| {
            rate_limit_imports.iter().any(|rl| imp.module.contains(rl))
        });

        let has_api_keywords = tree.functions.iter().any(|f| {
            let name_lower = f.name.to_lowercase();
            name_lower.contains("api")
                || name_lower.contains("endpoint")
                || name_lower.contains("route")
                || name_lower.contains("handler")
                || name_lower.contains("controller")
        });

        if has_api_keywords && !has_rate_limit {
            // Look for route/endpoint definitions without rate limiting
            let route_patterns = [
                r#"(?:app|router|express)\.(?:get|post|put|patch|delete)\s*\("#,
                r#"@app\.(?:get|post|put|patch|delete)\s*\("#,
                r#"@router\.(?:get|post|put|patch|delete)\s*\("#,
                r#"@app\.route\s*\(["']"#,
                r#"Fastify\.(?:get|post|put|patch|delete)\s*\("#,
            ];

            for (line_idx, line) in code.lines().enumerate() {
                let line_num = line_idx + 1;
                for pattern in &route_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(line) {
                            // Check if rate limiter is nearby (within 5 lines)
                            let lines: Vec<&str> = code.lines().collect();
                            let has_rl_nearby = lines.iter()
                                .skip(line_num.saturating_sub(1))
                                .take(5)
                                .any(|l| l.contains("rateLimit") || l.contains("rateLimit"));

                            if !has_rl_nearby {
                                let (start, end) = get_line_offsets(code, line_num);

                                findings.push(LangFinding {
                                    rule_id: self.id().to_string(),
                                    severity: self.severity().to_string(),
                                    line: line_num,
                                    column: 0,
                                    start_byte: start,
                                    end_byte: end,
                                    snippet: line.trim().to_string(),
                                    problem: "API endpoint without rate limiting detected. \
                                        CWE-307: Without rate limiting, endpoints are vulnerable to \
                                        brute force attacks, credential stuffing, and DoS.".to_string(),
                                    fix_hint: "Add rate limiting middleware: \
                                        const rateLimit = require('express-rate-limit'); \
                                        const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 }); \
                                        app.use('/api/', limiter);".to_string(),
                                    auto_fix_available: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-012: Sensitive Data Exposure (stack traces, errors)
// Severity: high | CWE-552
// AI exposes stack traces or error details to users
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsSensitiveDataExposure;

impl LangRule for JsSensitiveDataExposure {
    fn id(&self) -> &str { "JS-SEC-012" }
    fn name(&self) -> &str { "Sensitive Data Exposure (Error Details)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let error_exposure_patterns = [
            (r#"(?:console\.)?(?:log|error|warn)\s*\([^)]*\.stack"#, "stack trace in console"),
            (r#"res\.(?:json|send|write)\s*\([^)]*error"#, "error object sent to client"),
            (r#"throw\s+(?:new\s+)?(?:Error|Exception)[^;]*toString"#, "error.toString() thrown"),
            (r#"process\.env\.DEBUG"#, "DEBUG mode exposing internals"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, name) in &error_exposure_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Error details exposure: {}. CWE-552: Stack traces, error messages, \
                                and internal details can help attackers understand your system.",
                                name
                            ),
                            fix_hint: "Log errors server-side but return generic messages to clients. \
                                Use custom error classes with safe error messages. \
                                Example: res.status(500).json({ error: 'Internal server error' }); \
                                logger.error(err); // log full details internally".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-013: Insecure Cookie Settings
// Severity: medium | CWE-614
// AI sets cookies without HttpOnly, Secure flags
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsInsecureCookie;

impl LangRule for JsInsecureCookie {
    fn id(&self) -> &str { "JS-SEC-013" }
    fn name(&self) -> &str { "Insecure Cookie Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let cookie_calls: HashSet<&str> = [
            "cookie", "res.cookie", "response.cookie",
            "set-cookie", "document.cookie",
        ].into_iter().collect();

        let has_cookie_import = tree.imports.iter().any(|imp| {
            imp.module.contains("cookie")
                || imp.module.contains("cookie-parser")
                || imp.module.contains("express")
        });

        if !has_cookie_import {
            return findings;
        }

        for call in &tree.calls {
            if cookie_calls.iter().any(|cc| call.callee.ends_with(cc)) {
                let has_httponly = call.callee.contains("httpOnly")
                    || code.contains("httpOnly: true")
                    || code.contains("'httpOnly': true")
                    || code.contains("\"httpOnly\": true");

                let has_secure = call.callee.contains("secure")
                    || code.contains("secure: true")
                    || code.contains("'secure': true")
                    || code.contains("\"secure\": true");

                let has_samesite = call.callee.contains("sameSite")
                    || code.contains("sameSite")
                    || code.contains("SameSite");

                if !has_httponly || !has_secure || !has_samesite {
                    let (start, end) = get_line_offsets(code, call.start_line);
                    let line_text = get_line_text(code, call.start_line)
                        .unwrap_or_default();

                    let mut issues = vec![];
                    if !has_httponly { issues.push("HttpOnly"); }
                    if !has_secure { issues.push("Secure"); }
                    if !has_samesite { issues.push("SameSite"); }

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Insecure cookie: missing {}. CWE-614: Without HttpOnly, cookies are \
                            accessible via JavaScript (XSS theft). Without Secure, cookies sent over HTTP.",
                            issues.join(", ")
                        ),
                        fix_hint: "Always set secure cookie options: \
                            res.cookie('name', 'value', { httpOnly: true, secure: true, sameSite: 'strict' });".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-014: Regex DoS (ReDoS)
// Severity: medium | CWE-1333
// AI creates regex that can cause catastrophic backtracking
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsRegexDos;

impl LangRule for JsRegexDos {
    fn id(&self) -> &str { "JS-SEC-014" }
    fn name(&self) -> &str { "Regex DoS (ReDoS) Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Patterns that can cause catastrophic backtracking
        let redos_patterns = [
            (r#"\([^)]*\*[^)]*\)\{"#, "nested quantifier: (a*)"),
            (r#"\([^)]*\+[^)]*\)\{"#, "nested quantifier: (a+)"),
            (r#"\(\.\*\)\{"#, "greedy .* in group with quantifier"),
            (r#"\([^)]+\|\)"#, "alternation with empty branch"),
            (r#"(?:[^ ]+){N,}"#, "long repetition without atomic grouping"),
        ];

        let has_user_input = tree.calls.iter().any(|call| {
            call.arguments.iter().any(|a| {
                a.contains("request") || a.contains("input")
                    || a.contains("param") || a.contains("query")
                    || a.contains("user") || a.contains("data")
            })
        });

        // Only flag regex patterns if there's user input context
        if !has_user_input && !code.contains("RegExp") && !code.contains("new RegExp") {
            return findings;
        }

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;

            // Skip comments
            if line.trim().starts_with("//") || line.trim().starts_with("/*") {
                continue;
            }

            for (pattern, desc) in &redos_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) && (line.contains("RegExp") || line.contains("new RegExp") || has_user_input) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Potential ReDoS: {}. CWE-1333: This regex can cause exponential \
                                backtracking on malicious input, leading to denial of service.",
                                desc
                            ),
                            fix_hint: "Avoid nested quantifiers. Use atomic groups or possessive \
                                quantifiers. Simplify regex patterns. Consider using a regex engine \
                                with timeout support.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS-SEC-015: Insecure CORS Policy
// Severity: medium | CWE-942
// AI sets overly permissive CORS
// ─────────────────────────────────────────────────────────────────────────────
pub struct JsInsecureCors;

impl LangRule for JsInsecureCors {
    fn id(&self) -> &str { "JS-SEC-015" }
    fn name(&self) -> &str { "Insecure CORS Policy" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let insecure_cors_patterns = [
            (r#"origin\s*[=:]\s*["']\*["']"#, "'*' wildcard origin"),
            (r#"Access-Control-Allow-Origin\s*:\s*\*"#, "CORS header with *"),
            (r#"(?:cors|express)\s*\([^)]*origin\s*:\s*\*,", "CORS config with wildcard"),
            (r#"credentials\s*[=:]\s*true[^}]*(?:origin\s*[=:]\s*\*)"#, "credentials + wildcard origin"),
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let line_num = line_idx + 1;
            for (pattern, name) in &insecure_cors_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(line) {
                        let (start, end) = get_line_offsets(code, line_num);

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.trim().to_string(),
                            problem: format!(
                                "Insecure CORS: {}. CWE-942: Using wildcard '*' origin allows \
                                any website to make requests to your API, enabling CSRF attacks.",
                                name
                            ),
                            fix_hint: "Use specific origins instead of '*': \
                                origin: 'https://yourdomain.com'. \
                                For multiple origins, use an allowlist array. \
                                Never set credentials: true with origin: '*'.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn fix(&self, _finding: &LangFinding, _code: &str) -> Option<LangFix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry function
// ─────────────────────────────────────────────────────────────────────────────

/// All JavaScript security rules.
pub fn js_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(JsDomXss),
        Box::new(JsPrototypePollution),
        Box::new(JsEvalInjection),
        Box::new(JsPathTraversal),
        Box::new(JsHardcodedSecret),
        Box::new(JsWeakCrypto),
        Box::new(JsOpenRedirect),
        Box::new(JsSsrf),
        Box::new(JsSqlInjection),
        Box::new(JsJwtNoneAlgorithm),
        Box::new(JsNoRateLimit),
        Box::new(JsSensitiveDataExposure),
        Box::new(JsInsecureCookie),
        Box::new(JsRegexDos),
        Box::new(JsInsecureCors),
    ]
}
