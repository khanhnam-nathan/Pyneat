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

use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding};
use regex::Regex;

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

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

// Rust rules start below

fn get_line_from_byte(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

/// RUBY-SEC-001: SQL Injection
pub struct RubySqlInjection;

impl LangRule for RubySqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-001" }
    fn name(&self) -> &str { "SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\.find_by_sql\s*\(\s*['\""].*#\{"##, "ActiveRecord find_by_sql with interpolation"),
            (r##"\.execute\s*\(\s*['\""].*#\{"##, "ActiveRecord execute with interpolation"),
            (r##"\.exec\s*\(\s*['\""].*#\{"##, "ActiveRecord exec with interpolation"),
            (r##"\.query\s*\(\s*['\""].*#\{"##, "ActiveRecord query with interpolation"),
            (r##"find_by_sql\s*\(\s*['\""].*#\{"##, "find_by_sql with interpolation"),
            (r##"connection\.execute\s*\([^)]*#\{"##, "connection.execute with interpolation"),
            (r##"ActiveRecord::Base\.connection\.execute\s*\([^)]*#\{"##, "AR Base.connection.execute with interpolation"),
            (r##"['\"""].*SELECT.*['\"""].*\+["'""##, "SQL with string concatenation (SELECT)"),
            (r##"['\"""].*INSERT.*['\"""].*\+["'""##, "SQL with string concatenation (INSERT)"),
            (r##"['\"""].*UPDATE.*['\"""].*\+["'""##, "SQL with string concatenation (UPDATE)"),
            (r##"['\"""].*DELETE.*['\"""].*\+["'""##, "SQL with string concatenation (DELETE)"),
            (r##"\.where\s*\(\s*['\"""].*#\{"##, "where() with string interpolation"),
            (r##"Model\.where\s*\([^)]*\+["'""##, "Model.where with string concatenation"),
            (r##"\.delete\s*\(\s*params\[[""'""##, "delete() with params"),
            (r##"\.destroy\s*\(\s*params\[[""'""##, "destroy() with params"),
            (r##"SQL\s*\(\s*['\""].*%s["'""##, "SQL() with %s format string"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("SQL Injection (CWE-89): {} detected.", desc),
                        fix_hint: "Use parameterized queries. In ActiveRecord: User.where(email: params[:email]). In raw SQL: use ? placeholders.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-002: OS Command Injection
pub struct RubyCommandInjection;

impl LangRule for RubyCommandInjection {
    fn id(&self) -> &str { "RUBY-SEC-002" }
    fn name(&self) -> &str { "OS Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"system\s*\([^)]*#\{"##, "system() with string interpolation"),
            (r##"`[^`]*#\{[^}]+\}`"##, "Backtick command with interpolation"),
            (r##"%x\[.+#\{.+}\]"##, "%x[] with interpolation"),
            (r##"exec\s*\([^)]*#\{"##, "exec() with string interpolation"),
            (r##"spawn\s*\([^)]*shell:\s*true"##, "spawn() with shell: true"),
            (r##"IO\.popen\s*\([^)]*#\{"##, "IO.popen with string interpolation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Command Injection (CWE-78): {} detected.", desc),
                        fix_hint: "Avoid shell commands with user input. Use direct exec with array args.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-003: YAML Unsafe Load
pub struct RubyYamlUnsafeLoad;

impl LangRule for RubyYamlUnsafeLoad {
    fn id(&self) -> &str { "RUBY-SEC-003" }
    fn name(&self) -> &str { "YAML Unsafe Load" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"YAML\.load\s*\("##, "YAML.load() - can deserialize arbitrary Ruby objects"),
            (r##"YAML\[\]?\s*\("##, "YAML[] alias for YAML.load"),
            (r##"Psych\.load\s*\("##, "Psych.load() - YAML parser underlying method"),
            (r##"YAML\.load_stream\s*\("##, "YAML.load_stream - can execute arbitrary code"),
            (r##"YAML\.unsafe_load\s*\("##, "YAML.unsafe_load - explicitly unsafe"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("YAML Deserialization (CWE-502): {} detected.", desc),
                        fix_hint: "Use YAML.safe_load with permitted_classes whitelist.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-004: Hardcoded Secrets
pub struct RubyHardcodedSecrets;

impl LangRule for RubyHardcodedSecrets {
    fn id(&self) -> &str { "RUBY-SEC-004" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)password\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded password"),
            (r##"(?i)secret\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded secret"),
            (r##"(?i)api[_-]?key\s*[=:]\s*['\"""][^'\"]{4,}['\"""]"##, "Hardcoded API key"),
            (r##"(?i)token\s*[=:]\s*['\"""][A-Za-z0-9_\-]{10,}['\"""]"##, "Hardcoded token"),
            (r##"AKIA[A-Z0-9]{16}"##, "AWS Access Key ID"),
            (r##"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"##, "Private Key"),
            (r##"eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"##, "JWT Token"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Hardcoded Secret (CWE-798): {} detected.", desc),
                        fix_hint: "Use environment variables: ENV['API_KEY'].".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-005: Eval Usage
pub struct RubyEvalUsage;

impl LangRule for RubyEvalUsage {
    fn id(&self) -> &str { "RUBY-SEC-005" }
    fn name(&self) -> &str { "Dangerous Eval Usage" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let eval_patterns: Vec<(&str, &str)> = vec![
            (r##"\beval\s*\("##, "eval()"),
            (r##"\binstance_eval\s*\("##, "instance_eval()"),
            (r##"\bclass_eval\s*\("##, "class_eval()"),
            (r##"\bmodule_eval\s*\("##, "module_eval()"),
            (r##"\bsend\s*\(\s*:[\w]+\s*,\s*['\"""](?:eval|exec|system)['\"""]"##, ".send with eval/exec/system"),
        ];
        for (pattern, desc) in &eval_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Dangerous Code Evaluation (CWE-95): {} detected.", desc),
                        fix_hint: "Avoid eval. Use safer alternatives like JSON for data serialization.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-006: Weak Cryptography
pub struct RubyWeakCrypto;

impl LangRule for RubyWeakCrypto {
    fn id(&self) -> &str { "RUBY-SEC-006" }
    fn name(&self) -> &str { "Weak Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)rc4|arc4|arcfour|arcfour"##, "RC4 cipher - deprecated and broken"),
            (r##"Digest::MD5\.new"##, "MD5 hash - insecure for cryptographic use"),
            (r##"Digest::SHA1\.new"##, "SHA1 hash - deprecated"),
            (r##"OpenSSL::Cipher\.new\s*\(['\"""](?:des|rc4|rc2|blowfish)['\"""]"##, "Weak cipher algorithm"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Weak Cryptography (CWE-327): {} detected.", desc),
                        fix_hint: "Use SHA-256/SHA-3 for hashing. For encryption, use AES-256-GCM.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-007: Mass Assignment
pub struct RubyMassAssignment;

impl LangRule for RubyMassAssignment {
    fn id(&self) -> &str { "RUBY-SEC-007" }
    fn name(&self) -> &str { "Mass Assignment" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"Model\.new\s*\(\s*params\)\s*(?!.*permit)"##, "Model.new(params) without permit"),
            (r##"Model\.create\s*\(\s*params\)\s*(?!.*permit)"##, "Model.create(params) without permit"),
            (r##"Model\.update\s*\(\s*params\)\s*(?!.*permit)"##, "Model.update(params) without permit"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Mass Assignment (CWE-915): {} detected.", desc),
                        fix_hint: "Use strong parameters: Model.new(permit_params) where permit_params = params.require(:model).permit(:field1, :field2)".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-008: LDAP Injection
pub struct RubyLdapInjection;

impl LangRule for RubyLdapInjection {
    fn id(&self) -> &str { "RUBY-SEC-008" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"ldap\.search\s*\([^)]*params"##, "LDAP search with user-controlled filter"),
            (r##"(?i)distinguished_name\s*[=:]\s*['\"""].*#\{"##, "LDAP DN with string interpolation"),
            (r##"(?i)ldap.*base.*#\{"##, "LDAP base with user input"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("LDAP Injection (CWE-90): {} detected.", desc),
                        fix_hint: "Escape or sanitize LDAP special characters: * ( ) \\ NUL.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-009: Session Security
pub struct RubySessionSecurity;

impl LangRule for RubySessionSecurity {
    fn id(&self) -> &str { "RUBY-SEC-009" }
    fn name(&self) -> &str { "Weak Session Management" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"session\s*\(\s*[:\w]+\s*=>\s*[^,)\n]+,\s*(?!.*secure)"##, "Session cookie without secure flag"),
            (r##"cookies\[.*\]\s*=\s*[^,)\n]+,\s*(?!.*httponly)"##, "Cookie without HttpOnly flag"),
            (r##"cookies\[.*\]\s*=\s*[^,)\n]+,\s*(?!.*secure)"##, "Cookie without secure flag"),
            (r##"session_store\s*[=:]\s*CookieStore"##, "CookieStore without encryption config"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Weak Session Management (CWE-384): {}", desc),
                        fix_hint: "Set secure: true, httponly: true for cookies.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-010: Open Redirect
pub struct RubyOpenRedirect;

impl LangRule for RubyOpenRedirect {
    fn id(&self) -> &str { "RUBY-SEC-010" }
    fn name(&self) -> &str { "Open Redirect" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"redirect_to\s*\(\s*params\[[""'""##, "redirect_to with params"),
            (r##"redirect_to\s*\(\s*request\.referer"##, "redirect_to with request referer"),
            (r##"redirect_to\s*\(\s*[^,)\n]*\+["'""##, "redirect_to with string concatenation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Open Redirect (CWE-601): {} detected.", desc),
                        fix_hint: "Validate redirect URLs against allowlist of permitted domains.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-011: Information Disclosure
pub struct RubyInfoDisclosure;

impl LangRule for RubyInfoDisclosure {
    fn id(&self) -> &str { "RUBY-SEC-011" }
    fn name(&self) -> &str { "Information Disclosure" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"puts\s+ENV"##, "Environment variables printed"),
            (r##"print\s+ENV"##, "Environment variables printed"),
            (r##"logger\.(?:debug|info)\s*\([^)]*params\)"##, "Logging params directly"),
            (r##"Rails\.logger\.debug\s*\([^)]*request\.env\)"##, "Logging full request env"),
            (r##"byebug"##, "byebug debugger left in code"),
            (r##"binding\.pry"##, "pry debugger left in code"),
            (r##"debugger"##, "debugger statement left in code"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: format!("Information Disclosure: {}", desc),
                        fix_hint: "Remove debug statements before production.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-012: Missing CSRF Protection
pub struct RubyMissingCsrf;

impl LangRule for RubyMissingCsrf {
    fn id(&self) -> &str { "RUBY-SEC-012" }
    fn name(&self) -> &str { "Missing CSRF Protection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_csrf = code.contains("protect_from_forgery")
            || code.contains("csrf_token")
            || code.contains("verify_authenticity_token");
        let has_post = code.contains("post :") || code.contains("\"post\"");
        let has_form = code.contains("form_for") || code.contains("form_tag") || code.contains("form_with");

        if (has_post || has_form) && !has_csrf {
            if let Ok(re) = regex::Regex::new(r#"def\s+\w+\s*\n\s*end"#) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: "Controller action detected".to_string(),
                        problem: "Missing CSRF protection in Rails controller".to_string(),
                        fix_hint: "Ensure protect_from_forgery is in ApplicationController.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-013: Unsafe File Access (Path Traversal)
pub struct RubyUnsafeFileAccess;

impl LangRule for RubyUnsafeFileAccess {
    fn id(&self) -> &str { "RUBY-SEC-013" }
    fn name(&self) -> &str { "Unsafe File Access (Path Traversal)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"File\.read\s*\([^)]*\+\s*params"#, "File.read with user input concatenation"),
            (r#"File\.open\s*\([^)]*\+\s*params"#, "File.open with user input concatenation"),
            (r#"File\.read\s*\(\s*params\["#, "File.read with direct params access"),
            (r#"send_file\s*\(\s*params\["#, "send_file with user-controlled path"),
            (r#"render\s*\(\s*file:"#, "render file with potential traversal"),
            (r#"\.\.\/"#, "Path traversal sequence ../ detected"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use File.basename() to strip directories, validate path against base directory.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-014: Regex DoS (ReDoS)
pub struct RubyRegexDos;

impl LangRule for RubyRegexDos {
    fn id(&self) -> &str { "RUBY-SEC-014" }
    fn name(&self) -> &str { "Regex DoS (ReDoS) Vulnerability" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r#"\(\.\*\)\{2,\}"#, "Nested quantifier: (.*){2,} - catastrophic backtracking"),
            (r#"\(\.\+\)\{2,\}"#, "Nested quantifier: (.+){2,} - catastrophic backtracking"),
            (r#"\(\.\?\)\{2,\}"#, "Nested quantifier: (.?){2,} - catastrophic backtracking"),
            (r#"\(\[.*?\]\+\)\{2,\}"#, "Nested character class quantifier - catastrophic backtracking"),
            (r#"Regexp\.new\s*\(\s*params"#, "Regexp from user input - ReDoS risk"),
            (r#"eval\s*\(\s*\/.*\/"#, "Regex evaluated from string - potential ReDoS"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: m.as_str().to_string(),
                        problem: desc.to_string(),
                        fix_hint: "Use atomic groups, possessive quantifiers, or simplify regex to prevent backtracking.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-015: AI-Hallucinated Dependency (Slopsquatting)
pub struct RubySlopsquatting;

impl LangRule for RubySlopsquatting {
    fn id(&self) -> &str { "RUBY-SEC-015" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "fakerlib", "jsonify", "rubyserialize", "railsify", "mongomagic",
            "fake-org/dataframe-utils", "test-package-xyz", "mock-gem",
        ];
        for import in &tree.imports {
            for fake in &hallucinated {
                if import.module.contains(fake) || import.name.contains(fake) {
                    let (start, end) = get_line_offsets(_code, import.start_line);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: import.start_line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: import.module.clone(),
                        problem: format!("Slopsquatting Risk: The gem '{}' appears to be a hallucinated package name.", import.module),
                        fix_hint: "Verify this gem exists at rubygems.org before installing.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-AI-001: AI-Generated Code Marker
pub struct RubyAiGenComment;

impl LangRule for RubyAiGenComment {
    fn id(&self) -> &str { "RUBY-AI-001" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)generated by (chatgpt|claude|copilot|gemini|llm|gpt|ai|openai|anthropic)"##, "AI generation marker"),
            (r##"(?i)written by (chatgpt|claude|copilot|gemini|llm)"##, "AI authorship claim"),
            (r##"(?i)code generated by (cursor|github|replit)"##, "Code assistant marker"),
            (r##"(?i)AI[_-]?generated"##, "AI-generated marker"),
        ];
        for comment in &tree.comments {
            for (pattern, _) in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(&comment.text) {
                        let (start, end) = get_line_offsets(code, comment.start_line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: comment.start_line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: comment.text.clone(),
                            problem: "AI-Generated Code Detected".to_string(),
                            fix_hint: "Review AI-generated code carefully before production use.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-016: Format String Vulnerability (CWE-134)
// Severity: high | OWASP A03:2021
// sprintf with user input, "%s" % params[:x]
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyFormatString;

impl LangRule for RubyFormatString {
    fn id(&self) -> &str { "RUBY-SEC-024" }
    fn name(&self) -> &str { "Format String Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)sprintf\s*\([^,)]*\$(?:REQUEST|POST|GET|PARAMS|INPUT)"##, "sprintf with user input"),
            (r##"(?i)%[wdxs]\s*%[^,)]*\$(?:REQUEST|POST|GET|PARAMS|INPUT)"##, "Format string with user input"),
            (r##"(?i)printf\s*\([^,)]*\$_(?:GET|POST|REQUEST|COOKIE)"##, "printf with user input"),
            (r##"(?i)\bputs\s*%[^,)]*\$"##, "puts with format string and user input"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-016".to_string(),
                        severity: "high".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Format string vulnerability: {}. User-controlled format strings can leak memory addresses or cause crashes.", problem),
                        fix_hint: "Never use user input as format strings. Use argument-based formatting: sprintf('%s', user_input) instead of sprintf(user_input).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-017: XSS in Rails Views (CWE-79)
// Severity: high | OWASP A03:2021
// raw(), .html_safe without sanitization, content_tag with user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyXssInRails;

impl LangRule for RubyXssInRails {
    fn id(&self) -> &str { "RUBY-SEC-025" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS) in Rails Views" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)\braw\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "raw() with user input - bypasses HTML escaping"),
            (r##"(?i)\.html_safe\b"##, ".html_safe called - disables escaping"),
            (r##"(?i)content_tag\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "content_tag with user input without escaping"),
            (r##"(?i)link_to\s*\([^,)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "link_to with unsanitized user input in URL"),
            (r##"(?i)<%=?\s*[^%]*\.(?:html_safe|raw)\s*%>"##, "ERB template with raw/html_safe bypass"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-017".to_string(),
                        severity: "high".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("XSS vulnerability in Rails: {}. This can allow attackers to inject malicious scripts.", problem),
                        fix_hint: "Remove raw() and html_safe() calls with user input. Use the default auto-escaping. If you must allow HTML, use a sanitizer like sanitize() or DOMPurify.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-018: Insecure Deserialization - Marshal (CWE-502)
// Severity: critical | OWASP A08:2021
// Marshal.load, YAML.load on user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyMarshalDeserialization;

impl LangRule for RubyMarshalDeserialization {
    fn id(&self) -> &str { "RUBY-SEC-026" }
    fn name(&self) -> &str { "Insecure Deserialization (Marshal / YAML)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)Marshal\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Marshal.load with user input"),
            (r##"(?i)Marshal\.restore\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Marshal.restore with user input"),
            (r##"(?i)YAML\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "YAML.load with user input (unsafe)"),
            (r##"(?i)Psych\.load\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "Psych.load (YAML) with user input"),
            (r##"(?i)YAML\.parse\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|PARAMS)"##, "YAML.parse with user input"),
            (r##"(?i)Marshal\.dump\s*\([^)]*\)\s*(?!\s*#).*$"##, "Marshal.dump used (less dangerous but worth reviewing)"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: "RUBY-SEC-018".to_string(),
                        severity: "critical".to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!("Insecure deserialization: {}. Marshal/YAML can execute arbitrary Ruby code when deserializing untrusted data.", problem),
                        fix_hint: "Never use Marshal.load or YAML.load on untrusted data. Use JSON for data exchange. If you must deserialize, use safe YAML loading with permitted classes: YAML.safe_load(data, permitted_classes: [SpecificClass]).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-019: Race Condition in Transactions
// Severity: medium | CWE-362
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyRaceConditionTransaction;

impl LangRule for RubyRaceConditionTransaction {
    fn id(&self) -> &str { "RUBY-SEC-027" }
    fn name(&self) -> &str { "Race Condition in ActiveRecord Transactions" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let has_transaction = code.contains(".transaction") || code.contains("Transaction.");
        let has_lock = code.contains(".lock") || code.contains("with_lock");

        if has_transaction && !has_lock {
            let re = Regex::new(r"(?m)^\s*\.transaction\b").unwrap();
            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: code.lines().nth(line - 1).unwrap_or("").trim().to_string(),
                    problem: "ActiveRecord transaction without row-level locking.".to_string(),
                    fix_hint: "Add .lock or use pessimistic locking: Model.lock.find(id).".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-002: AI Hardcoded Secrets
// Severity: high | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiHardcodedSecrets;

impl LangRule for RubyAiHardcodedSecrets {
    fn id(&self) -> &str { "RUBY-AI-002" }
    fn name(&self) -> &str { "AI: Hardcoded Secrets in Code" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns = [
            (r##"(?i)(?:password|secret|api[_-]?key|token)\s*[=:]\s*['"][^'"]{4,}['"]"##, "Hardcoded secret"),
            (r##"(?i)ENV\s*\[\s*['"][^'"]+['"]\s*\]\s*=\s*['"][^'"]{4,}['"]"##, "ENV variable set to hardcoded value"),
        ];
        for (pat, desc) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(line - 1).unwrap_or("").trim().to_string(),
                        problem: format!("AI-generated code contains hardcoded {}: credentials exposed.", desc),
                        fix_hint: "Use ENV['KEY'] = nil pattern and require secrets from ENV.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-003: AI SQL Injection via String Interpolation
// Severity: critical | CWE-89
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiSqlInjection;

impl LangRule for RubyAiSqlInjection {
    fn id(&self) -> &str { "RUBY-AI-003" }
    fn name(&self) -> &str { "AI: SQL Injection via String Interpolation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["find_by_sql", "execute", "query", "where("];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                if args_str.contains("#{") || args_str.contains("\"#") || args_str.contains("'") {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                        problem: "AI-generated SQL query with string interpolation.".to_string(),
                        fix_hint: "Use parameterized queries: Model.where(user_id: params[:id]).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-004: AI Command Injection
// Severity: critical | CWE-78
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiCommandInjection;

impl LangRule for RubyAiCommandInjection {
    fn id(&self) -> &str { "RUBY-AI-004" }
    fn name(&self) -> &str { "AI: Command Injection - system/exec" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["system(", "`", "%x{", "exec("];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                let args_str = call.arguments.join(" ");
                let user_input = ["params", "request", "ENV"];
                if user_input.iter().any(|u| args_str.contains(u)) {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                        problem: "AI-generated command execution with user input.".to_string(),
                        fix_hint: "Validate and escape all user input. Use Shellwords.escape().".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-005: AI YAML unsafe_load
// Severity: critical | CWE-502
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyAiYamlUnsafeLoad;

impl LangRule for RubyAiYamlUnsafeLoad {
    fn id(&self) -> &str { "RUBY-AI-005" }
    fn name(&self) -> &str { "AI: YAML.unsafe_load Usage" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous = ["YAML.unsafe_load", "YAML.load", "YAML.parse"];
        for call in &tree.calls {
            if dangerous.iter().any(|d| call.callee.contains(d)) {
                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: call.start_line,
                    column: 0,
                    start_byte: 0,
                    end_byte: 0,
                    snippet: code.lines().nth(call.start_line - 1).unwrap_or("").trim().to_string(),
                    problem: "YAML loading without safe loading. Deserialization vulnerability.".to_string(),
                    fix_hint: "Use YAML.safe_load with permitted classes.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-020: Server-Side Request Forgery (SSRF)
// Severity: high | CWE-918 | OWASP A10:2021
// HTTP requests with user-controlled URLs or internal IP access
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySsrfDeep;

impl LangRule for RubySsrfDeep {
    fn id(&self) -> &str { "RUBY-SEC-020" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // HTTP library calls with user input in URL/params
            (r##"(?i)Net::HTTP\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Net::HTTP with user-controlled URL/params"),
            (r##"(?i)OpenURI\.open_uri\s*\([^)]*params"##, "OpenURI.open_uri with user input"),
            (r##"(?i)RestClient\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "RestClient with user-controlled URL/params"),
            (r##"(?i)Faraday\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Faraday with user-controlled URL/params"),
            (r##"(?i)HTTParty\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "HTTParty with user-controlled URL/params"),
            (r##"(?i)Excon\.(?:get|post|put|delete|patch|head)\s*\([^)]*params"##, "Excon with user-controlled URL/params"),
            // Internal IP/hostname access patterns
            (r##"169\.254\.169\.254"##, "AWS metadata endpoint access (169.254.169.254)"),
            (r##"(?i)127\.0\.0\.1|localhost"##, "Localhost/internal IP in URL"),
            // User input sources in HTTP calls
            (r##"(?i)Net::HTTP\.[a-z]+\s*\([^)]*request\.(?:params|query_parameters|url|fullpath)"##, "Net::HTTP with request parameter"),
            (r##"(?i)RestClient\.[a-z]+\s*\([^)]*request\.(?:params|query_parameters|url|fullpath)"##, "RestClient with request parameter"),
            (r##"(?i)open\s*\([^)]*params\[:url\]"##, "open() with params[:url] - SSRF risk"),
            (r##"(?i)open\s*\([^)]*params\[:uri\]"##, "open() with params[:uri] - SSRF risk"),
            (r##"(?i)open\s*\([^)]*request\.(?:params|query_parameters)"##, "open() with request params - SSRF risk"),
            // ENV-based query string access
            (r##"(?i)Net::HTTP\.[a-z]+\s*\([^)]*ENV\['QUERY_STRING'\]"##, "Net::HTTP with ENV['QUERY_STRING']"),
            (r##"(?i)RestClient\.[a-z]+\s*\([^)]*ENV\['QUERY_STRING'\]"##, "RestClient with ENV['QUERY_STRING']"),
            (r##"(?i)query_string"##, "query_string variable used in HTTP request"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
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
                        problem: format!("SSRF vulnerability (CWE-918): {}. Attackers can make requests to internal services or metadata endpoints.", problem),
                        fix_hint: "Validate and sanitize all URL inputs against an allowlist of permitted domains. Never use user input directly to construct URLs, especially for internal services.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-AI-006: Slopsquatting via Gem Name Typos
// Severity: critical | CWE-1595
// Detect typo variants of popular Ruby gems that may be hallucinated dependencies
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySlopsquattingTypo;

impl LangRule for RubySlopsquattingTypo {
    fn id(&self) -> &str { "RUBY-AI-006" }
    fn name(&self) -> &str { "AI Slopsquatting: Gem Name Typos" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern: gem 'name' or gem "name" in Gemfile
        let gem_pattern = Regex::new(r##"(?i)gem\s+['"]([^'"]+)['"]"##).unwrap();

        // Popular gem typos - organized by original gem name
        let typo_patterns: Vec<(&str, Vec<&str>)> = vec![
            ("rails", vec!["railes", "railz", "ralls", "raild", "raile", "rail"]),
            ("rubygems", vec!["rubygem", "rubygmes", "rubgem", "rubgems", "rubyjgems"]),
            ("nokogiri", vec!["nokogiri", "nokogiri", "nokogir1", "nokogir", "nokogiri", "nokogiri"]),
            ("devise", vec!["devsie", "devis", "devie", "devies", "devise", "devis", "devies"]),
            ("sidekiq", vec!["sidekiq", "sidekig", "sidkq", "sideki", "sidekik", "sidekiq"]),
            ("puma", vec!["pumna", "pumla", "pumaa", "pumm", "puma", "pumna"]),
            ("rspec", vec!["rspeck", "respec", "rspc", "rsep", "rsper", "rspec", "rspeck"]),
            ("factory_bot", vec!["factory_girl", "factorybot", "factory_bot", "factoy_bot"]),
            ("activeadmin", vec!["active_admn", "activ admin", "active_admn", "activeadmn", "activeadmin"]),
            ("carrierwave", vec!["carrier_wave", "carrirwave", "carrierave", "carrierwave"]),
            ("will_paginate", vec!["will_pagante", "willpaginate", "will_paginate", "willpag"]),
            ("bootstrap", vec!["bootstap", "boostrap", "bootstrap", "bootstap", "boostrap"]),
            ("paperclip", vec!["paper_clip", "paperclp", "paperclup", "paperclip"]),
            (" cancancan", vec!["cancan", "cancancan", "can_can", "cancan", "cancancan"]),
            ("pundit", vec!["pundlt", "pundt", "pundlt", "pundit"]),
            ("kaminari", vec!["kaminrai", "kaminari", "kaminarii", "kaminarl"]),
            ("simple_form", vec!["simpleform", "simple_form", "simple_from", "simple_forms"]),
            ("friendly_id", vec!["friendl_id", "friendlyid", "friendlly_id", "friendly_id"]),
            ("redis", vec!["redia", "reds", "reddis", "redsi", "redis"]),
            ("mysql2", vec!["mysq2", "mysql", "mysl2", "mysql", "mysql2"]),
            ("pg", vec!["gp", "pog", "pg", "pgg"]),
            ("sqlite3", vec!["sqlte3", "sqltie3", "sqlte", "sqlite", "sqlite3"]),
            ("aws-sdk", vec!["aws-ssk", "aws_ssk", "aws-sdk", "awssdk", "aws-s3"]),
            ("jwt", vec!["jtw", "jwt", "jwr", "jtw", "jwt"]),
            ("bcrypt", vec!["bcript", "bcrypt", "bcryt", "bycrpt", "bcrypt"]),
            ("whenever", vec!["whnever", "whenver", "whenve", "whenever"]),
            ("dotenv", vec!["dot_env", "dotenv", "dotenv", "doten", "dotenv"]),
            ("figaro", vec!["figaro", "figaro", "figaro", "fgaro", "figaro"]),
            ("httparty", vec!["httpart", "httparty", "httpparty", "httpart", "httparty"]),
            ("faraday", vec!["farady", "faradday", "farady", "faraday"]),
            ("rest-client", vec!["restclient", "rest_client", "rest-client", "restlient"]),
        ];

        for caps in gem_pattern.captures_iter(code) {
            if let Some(gem_match) = caps.get(1) {
                let gem_name = gem_match.as_str().to_lowercase();

                // Skip if it's the real gem
                let is_real_gem = typo_patterns.iter().any(|(real, _)| gem_name == *real);
                if is_real_gem {
                    continue;
                }

                // Check against all typo patterns
                for (real_gem, typos) in &typo_patterns {
                    if typos.iter().any(|typo| gem_name == *typo) {
                        let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
                        let (start, end) = get_line_offsets(code, line);
                        let line_text = code.lines().nth(line - 1).unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text,
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of popular gem '{}'. This may be an AI-hallucinated package name.", gem_name, real_gem),
                            fix_hint: format!("Verify '{}' exists on rubygems.org before installing. Did you mean '{}'?", gem_name, real_gem),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        // Also check require statements
        let require_pattern = Regex::new(r##"(?i)require\s+['"]([^'"]+)['"]"##).unwrap();
        for caps in require_pattern.captures_iter(code) {
            if let Some(req_match) = caps.get(1) {
                let req_name = req_match.as_str().to_lowercase();

                // Skip if it's the real gem/library
                let is_real = typo_patterns.iter().any(|(real, _)| req_name == *real);
                if is_real {
                    continue;
                }

                // Check against all typo patterns
                for (real_lib, typos) in &typo_patterns {
                    if typos.iter().any(|typo| req_name == *typo) {
                        let line = code[..caps.get(0).unwrap().start()].matches('\n').count() + 1;
                        let (start, end) = get_line_offsets(code, line);
                        let line_text = code.lines().nth(line - 1).unwrap_or("").trim().to_string();

                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line_text,
                            problem: format!("Slopsquatting detected: '{}' looks like a typo of '{}'. This may be an AI-hallucinated dependency.", req_name, real_lib),
                            fix_hint: format!("Verify '{}' exists before requiring. Did you mean '{}'?", req_name, real_lib),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-021: Weak JWT Verification
// Severity: critical | CWE-345
// JWT.decode with nil/false key, JWT.verify with nil, etc.
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyWeakJwt;

impl LangRule for RubyWeakJwt {
    fn id(&self) -> &str { "RUBY-SEC-021" }
    fn name(&self) -> &str { "Weak JWT Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"JWT\.decode\s*\([^,]+,\s*nil"##, "JWT.decode with nil key - no signature verification"),
            (r##"JWT\.decode\s*\([^,]+,\s*false"##, "JWT.decode with false key - no signature verification"),
            (r##"JWT\.decode\s*\([^,]+,\s*["']["']"##, "JWT.decode with empty string key"),
            (r##"JWT\.verify\s*\([^,]+,\s*nil"##, "JWT.verify with nil key"),
            (r##"JWT::Verification\.verify\s*\([^,]+,\s*nil"##, "JWT::Verification.verify with nil key"),
            (r##"JWT::Base64\.url_decode\s*\([^)]*\)\s*\."##, "JWT Base64 decode in chain - verify signing"),
        ];

        for (pat, problem) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                for m in re.find_iter(code) {
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
                        problem: format!("Weak JWT verification: {}. Tokens can be forged without proper signature verification.", problem),
                        fix_hint: "Provide a valid secret key or public key for JWT verification. Use ENV['JWT_SECRET'] or retrieve from a secrets manager. Never pass nil or false as the verification key.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-022: SQL Injection (Sequel ORM / String Interpolation)
// Severity: critical | CWE-89
// Sequel ORM queries or ActiveRecord with string interpolation of user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubySequelSqlInjection;

impl LangRule for RubySequelSqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-022" }
    fn name(&self) -> &str { "SQL Injection (Sequel ORM / String Interpolation)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let db_imports = ["sequel", "sqlite3", "pg", "mysql2", "mysql"];
        let has_db = tree.imports.iter().any(|imp| {
            db_imports.iter().any(|d| imp.module.contains(d))
        });

        if !has_db && !code.contains("DB[:") && !code.contains("Sequel.") {
            return findings;
        }

        let dangerous_patterns = vec![
            // Sequel raw SQL with string interpolation
            (r#"DB\[.*?\]\.from.*?\.\s*sql\s*\(['\"][^'\"]*%\{[^}]*(?:params|request|input|post|get)"#, "Sequel SQL with string interpolation of user input"),
            (r#"DB\[.*?\]\.\s*(?:select|from|where|order|group)\s*\(\s*['\"][^'\"]*\#\{[^}]*(?:params|request|input|post|get)"#, "Sequel query with string interpolation"),
            (r#"DB\.run\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "Sequel DB.run with string interpolation"),
            (r#"DB\[.*?\]\.\s*get?\s*\([^)]*\+[^)]*(?:params|request|input|post|get)"#, "Sequel get with string concatenation of user input"),
            // ActiveRecord string interpolation (additional to existing)
            (r#"ActiveRecord::Base\.connection\.execute\s*\([^)]*\+[^)]*(?:params|request|input)"#, "ActiveRecord connection.execute with string concat"),
            (r#"find_by_sql\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "find_by_sql with string interpolation of user input"),
            (r#"by_sql\s*\(['\"][^'\"]*\#\{[^}]*(?:params|request|input)"#, "by_sql with string interpolation"),
            (r#"order\s*\([^)]*\#\{[^}]*(?:params|request|input)"#, "ActiveRecord order() with string interpolation — ORDER BY injection"),
            (r#"select\s*\([^)]*\#\{[^}]*(?:params|request|input)"#, "ActiveRecord select() with string interpolation — column injection"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
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
                        problem: format!(
                            "SQL injection (Sequel/ActiveRecord): {}. CWE-89: Database query built with \
                            string interpolation allows attackers to manipulate SQL logic.",
                            desc
                        ),
                        fix_hint: "Use parameterized queries in Sequel: DB[:users].where(name: params[:name]). \
                            In ActiveRecord: User.where(name: params[:name]). \
                            For ORDER BY: whitelist column names. Never use string interpolation in SQL.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-023: Command Injection (system / backticks / exec)
// Severity: critical | CWE-78
// Shell commands executed with user input via system(), backticks, or exec()
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyCommandInjectionDeep;

impl LangRule for RubyCommandInjectionDeep {
    fn id(&self) -> &str { "RUBY-SEC-023" }
    fn name(&self) -> &str { "Command Injection (system/backticks/exec)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            // system() with user input
            (r#"system\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env|ARGV)"#, "system() with string concatenation of user input"),
            (r#"system\s*\(`[^`]*\#\{[^}]*(?:params|request|input|post|get)"#, "system() with backtick interpolation of user input"),
            // Backticks with user input
            (r#"`[^`]*\#\{[^}]*(?:params|request|input|post|get|env)"#, "Backtick command with string interpolation of user input"),
            (r#"%x\[.*?\#\{[^}]*(?:params|request|input|post|get|env)"#, "%x[] command with user input interpolation"),
            // exec with user input
            (r#"exec\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env|ARGV)"#, "exec() with string concatenation of user input"),
            (r#"exec\s*\(`[^`]*\#\{[^}]*(?:params|request|input)"#, "exec() with backtick interpolation"),
            // popen with user input
            (r#"IO\.popen\s*\([^)]*\+[^)]*(?:params|request|input|post|get|env)"#, "IO.popen() with string concatenation — command injection"),
            (r#"Open3\.popen3\s*\([^)]*\+[^)]*(?:params|request|input)"#, "Open3.popen3 with string concatenation"),
            // Kernel.system alias
            (r#"`\s*\#\{[^}]*(?:params|request|input|post|get|env|ARGV)"#, "Kernel backtick operator with user input interpolation"),
            // Shellwords bypass
            (r#"system\s*\(\s*shellwords\s*\([^)]*\)\s*\.\s*join"#, "system(shellwords(...).join) — can be bypassed with careful quoting"),
            (r#"system\s*\([^)]*split\s*\(\s*['\"][^'\"]*['\"]\s*\)\s*\."#, "system(array.split) — array split from user input is unsafe"),
        ];

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
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
                        problem: format!(
                            "Command injection: {}. CWE-78: User input passed to shell command execution \
                            allows attackers to run arbitrary commands on the host.",
                            desc
                        ),
                        fix_hint: "Never pass user input to system(), exec(), backticks, or popen(). \
                            Use absolute paths with explicit arguments: system('/path/to/cmd', arg1, arg2). \
                            Validate all input against a strict whitelist of allowed values. \
                            For file names: use File.expand_path and verify the path stays within allowed directory.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-028: SQL Injection in ActiveRecord (Extended)
// Severity: critical | CWE-89
// .where(), .find_by_sql() with string interpolation (additional patterns)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyActiveRecordSqlInjection;

impl LangRule for RubyActiveRecordSqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-028" }
    fn name(&self) -> &str { "SQL Injection in ActiveRecord - where/find_by_sql" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this file uses ActiveRecord
        let has_ar = tree.imports.iter().any(|imp| {
            imp.module.contains("active_record") || imp.module.contains("activerecord")
        });

        if !has_ar && !code.contains("ActiveRecord::") && !code.contains("ApplicationRecord") {
            return findings;
        }

        let patterns = vec![
            // where() with string interpolation
            (r##"\.where\s*\(\s*['\""].*#\{"##, "where() with string interpolation"),
            (r##"Model\.where\s*\([^)]*\+["'\""##, "Model.where with string concatenation"),
            (r##"\.where\s*\(\s*params\["##, "where() with direct params access"),
            // find_by_sql with interpolation
            (r##"find_by_sql\s*\(\s*['\""].*#\{"##, "find_by_sql with string interpolation"),
            (r##"find_by_sql\s*\(\s*['\""].*%s["\""##, "find_by_sql with %s format string"),
            // Additional dangerous patterns
            (r##"\.find\s*\(\s*params\["##, "find() with direct params - potential IDOR"),
            (r##"Model\.first\s*\(\s*params\["##, "Model.first with params"),
            (r##"Model\.last\s*\(\s*params\["##, "Model.last with params"),
            (r##"\.\s*order\s*\(\s*['\""].*#\{"##, "order() with string interpolation - ORDER BY injection"),
            (r##"\.\s*select\s*\(\s*['\""].*#\{"##, "select() with string interpolation - column injection"),
            // Sanitizor bypass
            (r##"sanitize_sql\s*\([^)]*\#\{"##, "sanitize_sql with interpolation - potential bypass"),
            (r##"quote\s*\(\s*params\["##, "quote() with params - manual SQL building"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
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
                        problem: format!(
                            "SQL injection in ActiveRecord (CWE-89): {}. String interpolation in SQL \
                            queries allows attackers to manipulate query logic.",
                            desc
                        ),
                        fix_hint: "Use parameterized queries: User.where(email: params[:email]). \
                            For dynamic columns, use allowlist validation. Never interpolate user input directly.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-029: Command Injection with Shell Metacharacters
// Severity: critical | CWE-78
// system(), backticks, exec() with shell metacharacters in user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyCommandInjectionShellMetachar;

impl LangRule for RubyCommandInjectionShellMetachar {
    fn id(&self) -> &str { "RUBY-SEC-029" }
    fn name(&self) -> &str { "Command Injection - Shell Metacharacters" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Dangerous command functions
        let cmd_funcs = ["system(", "exec(", "`", "%x{", "popen", "spawn"];
        let shell_metachar_patterns = vec![
            // Shell metacharacters
            r#"[;&|`$(){}[\]\\!~*?<>"\s]+"#,
            // Common dangerous patterns
            r#"(?:&&|\|\||;)\s*\w+"#,
            r#"\|\s*\w+"#,
            r#">\s*/dev/"#,
            r#"<\s*/etc/"#,
            // Input from user sources
            r#"(?:params|request|ENV|ARGV)\s*\["#,
        ];

        for call in &tree.calls {
            let callee_lower = call.callee.to_lowercase();
            let is_cmd = cmd_funcs.iter().any(|f| callee_lower.contains(f));

            if is_cmd {
                let args_str = call.arguments.join(" ");
                // Check for user input sources combined with command execution
                let has_user_input = args_str.contains("params")
                    || args_str.contains("request")
                    || args_str.contains("ENV")
                    || args_str.contains("ARGV")
                    || args_str.contains("session")
                    || args_str.contains("cookies");

                if has_user_input {
                    let line_text = get_line_text(code, call.start_line).unwrap_or_default();
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: call.start_line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Command injection (CWE-78): {} with user input. Shell metacharacters \
                            in user input can be exploited to run arbitrary commands.",
                            call.callee
                        ),
                        fix_hint: "Never pass unsanitized user input to system(), exec(), or backticks. \
                            Use Shellwords.escape() or pass arguments as an array to avoid shell interpretation.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Additional regex-based patterns for shell metacharacter detection
        let shell_patterns = vec![
            (r##"system\s*\([^)]*['\"][^'\"]*[;&|`$(){}[\]\\!~*<>][^'\"]*['\"]"##, "system() with shell metacharacters"),
            (r##"exec\s*\([^)]*['\"][^'\"]*[;&|`$(){}[\]\\!~*<>][^'\"]*['\"]"##, "exec() with shell metacharacters"),
            (r##"`[^`]*[;&|`$(){}[\]\\!~*<>][^`]*`"##, "Backtick command with shell metacharacters"),
        ];

        for (pattern, desc) in &shell_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
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
                        problem: format!(
                            "Command injection (CWE-78): {}. Shell metacharacters detected in command execution.",
                            desc
                        ),
                        fix_hint: "Escape shell metacharacters using Shellwords.escape() or avoid shell commands entirely.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-030: YAML Unsafe Load (Extended)
// Severity: high | CWE-502
// YAML.load() without SafeLoader - can deserialize arbitrary Ruby objects
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyYamlUnsafeLoadExtended;

impl LangRule for RubyYamlUnsafeLoadExtended {
    fn id(&self) -> &str { "RUBY-SEC-030" }
    fn name(&self) -> &str { "YAML Unsafe Load - Extended Detection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if YAML is used
        let has_yaml = tree.imports.iter().any(|imp| {
            imp.module.contains("yaml") || imp.module.contains("psych")
        });

        if !has_yaml && !code.contains("YAML.") && !code.contains("Psych.") {
            return findings;
        }

        let patterns = vec![
            // Unsafe YAML methods
            (r##"YAML\.load\s*\("##, "YAML.load() - deserializes arbitrary Ruby objects"),
            (r##"YAML\[\s*\("##, "YAML[] alias for YAML.load - unsafe"),
            (r##"Psych\.load\s*\("##, "Psych.load() - underlying YAML parser method"),
            (r##"YAML\.load_stream\s*\("##, "YAML.load_stream - can execute arbitrary code"),
            (r##"YAML\.unsafe_load\s*\("##, "YAML.unsafe_load - explicitly unsafe"),
            (r##"YAML\.load_documents\s*\("##, "YAML.load_documents - unsafe"),
            (r##"YAML\.parse_documents\s*\("##, "YAML.parse_documents - unsafe"),
            // Safe alternatives (should not trigger)
            (r##"YAML\.safe_load\s*\("##, "YAML.safe_load - SAFE (whitelist-based)"),
            (r##"Psych\.safe_load\s*\("##, "Psych.safe_load - SAFE"),
            (r##"YAML\.safe_load\s*\([^)]*permitted_classes\s*:"##, "YAML.safe_load with permitted_classes - SAFE"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    // Skip safe_load patterns - they are false positives
                    if desc.contains("SAFE") {
                        continue;
                    }
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
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
                        problem: format!(
                            "YAML deserialization vulnerability (CWE-502): {}. \
                            YAML can deserialize arbitrary Ruby objects, leading to RCE.",
                            desc
                        ),
                        fix_hint: "Use YAML.safe_load with permitted_classes whitelist: \
                            YAML.safe_load(data, permitted_classes: [SpecificClass]). \
                            Never use YAML.load or YAML.unsafe_load on untrusted data.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-031: Insecure Cookie Configuration
// Severity: medium | CWE-614
// Cookies without secure, httponly, or samesite flags
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyInsecureCookie;

impl LangRule for RubyInsecureCookie {
    fn id(&self) -> &str { "RUBY-SEC-031" }
    fn name(&self) -> &str { "Insecure Cookie Configuration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this is a Rails app
        let is_rails = code.contains("Rails")
            || tree.imports.iter().any(|imp| {
                imp.module.contains("action_controller") || imp.module.contains("rails")
            });

        let patterns = vec![
            // Cookie without secure flag
            (r##"cookies?\s*\[\s*[:\w]+\s*\]\s*=\s*[^,)\n]+,\s*(?!.*secure)"##,
             "Cookie without secure flag - data can be sent over HTTP"),
            // Cookie without httponly flag
            (r##"cookies?\s*\[\s*[:\w]+\s*\]\s*=\s*[^,)\n]+,\s*(?!.*httponly)"##,
             "Cookie without HttpOnly flag - accessible to JavaScript (XSS risk)"),
            // Cookie without samesite
            (r##"cookies?\s*\[\s*[:\w]+\s*\]\s*=\s*[^,)\n]+,\s*(?!.*samesite)"##,
             "Cookie without SameSite flag - CSRF vulnerability"),
            // Session cookie configuration
            (r##"session\s*\(\s*[:\w]+\s*=>\s*[^,)\n]+,\s*(?!.*secure)"##,
             "Session cookie without secure flag"),
            (r##"session\s*\(\s*[:\w]+\s*=>\s*[^,)\n]+,\s*(?!.*httponly)"##,
             "Session cookie without HttpOnly flag"),
            // Rails 5.2+ encrypted cookies
            (r##"cookies\.encrypted\s*\[\s*[:\w]+\s*\]\s*=\s*[^,)\n]+,\s*(?!.*samesite)"##,
             "Encrypted cookie without SameSite flag"),
            // Application controller before action
            (r##"before_action\s*:verify_authenticity_token"##, "CSRF protection present"),
        ];

        let has_csrf = code.contains("protect_from_forgery")
            || code.contains("verify_authenticity_token")
            || code.contains("skip_before_action :verify_authenticity_token");

        for (pattern, desc) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = code[..m.start()].matches('\n').count() + 1;
                    if findings.iter().any(|f: &LangFinding| f.line == line) {
                        continue;
                    }
                    let (start, end) = get_line_offsets(code, line);
                    let line_text = get_line_text(code, line).unwrap_or_default();

                    // Skip if CSRF protection is present (false positive reduction)
                    if has_csrf && desc.contains("CSRF") {
                        continue;
                    }

                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line_text.trim().to_string(),
                        problem: format!(
                            "Insecure cookie configuration (CWE-614): {}. \
                            Missing security flags expose cookies to theft and CSRF attacks.",
                            desc
                        ),
                        fix_hint: "Set all cookie security flags: cookies[:name] = value, \
                            secure: true, httponly: true, samesite: :strict. \
                            Use SameSite=Lax or SameSite=Strict for CSRF protection.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Rails specific: check session store configuration
        if is_rails {
            let session_store_patterns = vec![
                (r##"config\.session_store\s+:cookie_store,\s*(?!.*secure)"##,
                 "CookieStore session without secure configuration"),
                (r##"config\.force_ssl\s*=\s*false"##,
                 "SSL/TLS force disabled - cookies vulnerable to interception"),
            ];

            for (pattern, desc) in &session_store_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    for m in re.find_iter(code) {
                        let line = code[..m.start()].matches('\n').count() + 1;
                        if findings.iter().any(|f: &LangFinding| f.line == line) {
                            continue;
                        }
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
                            problem: format!("Insecure session configuration: {}", desc),
                            fix_hint: "Enable SSL: config.force_ssl = true. \
                                Configure secure session cookies in environment config.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                    }
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-032: Security/JSONLoad (RuboCop Security Cop)
// Severity: high | CWE-502
// JSON.load / JSON.restore / JSON.load_all without create_additions: false
// RuboCop rule: Security/JSONLoad
// Safe: JSON.load(data, create_additions: false) or JSON.parse()
// Unsafe: JSON.load(data) or JSON.load(data, create_additions: true)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyJsonLoad;

impl LangRule for RubyJsonLoad {
    fn id(&self) -> &str { "RUBY-SEC-032" }
    fn name(&self) -> &str { "Security/JSONLoad" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // JSON.load without safe flags
            (
                r"JSON\.load\s*\(\s*[^)]+\s*\)",
                "JSON.load() called — can deserialize arbitrary Ruby objects"
            ),
            (
                r"JSON\[\s*\(\s*[^)]+\s*\)",
                "JSON[] alias for JSON.load — unsafe"
            ),
            (
                r"JSON\.restore\s*\(\s*[^)]+\s*\)",
                "JSON.restore() — deserializes arbitrary Ruby objects"
            ),
            (
                r"JSON\.load_all\s*\(\s*[^)]+\s*\)",
                "JSON.load_all() — deserializes all objects"
            ),
            (
                r"JSON\.json_load\s*\(\s*[^)]+\s*\)",
                "JSON.json_load alias for JSON.load — unsafe"
            ),
        ];

        for (pat, problem) in &patterns {
            let re = match Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;

                // Check if this call has safe flags
                let full_match = m.as_str();
                let has_safe_flags =
                    full_match.contains("create_additions:")
                    || full_match.contains("create_additions :")
                    || full_match.contains(" symbolize_names:")
                    || full_match.contains("object_class:")
                    || full_match.contains("object_class :");

                if has_safe_flags {
                    continue;
                }

                // Additional check: is this JSON.parse (safe)?
                if full_match.contains("JSON.parse") {
                    continue;
                }

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
                    problem: format!(
                        "Security/JSONLoad (CWE-502): {}. \
                        JSON.load can deserialize arbitrary Ruby objects, leading to RCE.",
                        problem
                    ),
                    fix_hint: "Use JSON.parse() for untrusted data. \
                        If you must deserialize classes, pass create_additions: false: \
                        JSON.load(data, create_additions: false). \
                        From json gem 2.8+, use JSON.load with explicit flags or JSON.parse.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-033: Security/IoMethods (RuboCop Security Cop)
// Severity: medium | CWE-78
// IO.read / IO.write / IO.binread / IO.binwrite / IO.foreach / IO.readlines
// called with a path argument starting with pipe character '|'
// RuboCop rule: Security/IoMethods
// Safe: IO.read('/path/to/file'), File.read('/path/to/file')
// Unsafe: IO.read('| command') — subprocess invocation
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyIoMethods;

impl LangRule for RubyIoMethods {
    fn id(&self) -> &str { "RUBY-SEC-033" }
    fn name(&self) -> &str { "Security/IoMethods" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Match: IO.method('| command') or IO.method("| command")
        let pipe_pattern = Regex::new(r##"IO\.(?:read|write|binread|binwrite|foreach|readlines)\s*\(\s*['"]\|[^'"]+['"]"##).unwrap();

        for m in pipe_pattern.find_iter(code) {
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
                problem: "Security/IoMethods (CWE-78): IO.read/write/foreach called with pipe prefix '|'. \
                    This enables subprocess invocation, allowing command injection if the path is user-controlled.".to_string(),
                fix_hint: "Use File.read() for file access: File.read('/path/to/file'). \
                    Never construct IO paths from user input. If subprocess invocation is intentional, \
                    use explicit shell command separation: Open3.popen3(['cmd', arg1, arg2]) instead.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-034: Security/CompoundHash (RuboCop Security Cop)
// Severity: medium | CWE-385
// Custom hash method that combines values instead of delegating to Array#hash
// RuboCop rule: Security/CompoundHash
// Safe: def hash; [@foo, @bar].hash; end
// Unsafe: def hash; @foo ^ @bar; end (collision-prone, not Array#hash safe)
// ─────────────────────────────────────────────────────────────────────────────
pub struct RubyCompoundHash;

impl LangRule for RubyCompoundHash {
    fn id(&self) -> &str { "RUBY-SEC-034" }
    fn name(&self) -> &str { "Security/CompoundHash" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect: def hash ... end blocks that use XOR (^) or other unsafe combinators
        // Pattern: def hash\n  ... ^ ...\n  ... ^ ...\nend
        let hash_method_pattern = Regex::new(
            r"def\s+hash\s*\n(.*?)\n\s*end"
        ).unwrap();

        for caps in hash_method_pattern.captures_iter(code) {
            if let Some(body) = caps.get(1) {
                let hash_body = body.as_str();

                // Check if the hash method delegates to Array#hash
                let delegates_to_array =
                    hash_body.contains("[") && hash_body.contains("].hash")
                    || hash_body.contains(".hash") && !hash_body.contains("^")
                        && !hash_body.contains("*")
                        && !hash_body.contains("+");

                if delegates_to_array {
                    continue;
                }

                // Check for unsafe combinator operators in hash method
                let has_unsafe_ops =
                    hash_body.contains(" ^ ")    // XOR
                    || hash_body.contains("\t^")
                    || hash_body.contains(" ^")
                    || hash_body.contains("^ ")
                    || hash_body.contains(" ^\n")
                    || hash_body.contains(".*")   // Array#hash returns int, XOR is unsafe
                    || hash_body.contains("|")    // Bitwise OR
                    || (hash_body.contains("%") && hash_body.contains("hash"));

                if !has_unsafe_ops {
                    continue;
                }

                let full_match = caps.get(0).unwrap();
                let start_byte = full_match.start();
                let line = code[..start_byte].matches('\n').count() + 1;
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
                    problem: format!(
                        "Security/CompoundHash (CWE-385): Custom hash method uses unsafe value combination. \
                        Found: {}. This can lead to hash collisions and denial of service attacks.",
                        full_match.as_str().trim().replace('\n', " ")
                    ),
                    fix_hint: "Delegate to Array#hash: def hash; [@foo, @bar].hash; end. \
                        Manually combining hash values with ^ or other operators is error-prone and can \
                        produce hash collisions. Array#hash delegates to Ruby's built-in hash algorithm.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// Brakeman Rails Security Rules
// These rules detect Rails-specific vulnerabilities covered by Brakeman.
// Implemented independently from Brakeman's Ruby source, based on Brakeman's
// documented checks and Rails security patterns.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-035: Brakeman CheckSQL — SQL Injection in ActiveRecord
// Severity: critical | CWE-89
// Brakeman: Checks for SQL injection via .where(), .find(), .execute() with string interpolation
// Safe: Model.where(["name = ?", user_input]) or Model.where(name: user_input)
// Unsafe: Model.where("name = '#{user_input}'") or Model.find_by_sql(params[:sql])
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanSqlInjection;

impl LangRule for BrakemanSqlInjection {
    fn id(&self) -> &str { "RUBY-SEC-035" }
    fn name(&self) -> &str { "Brakeman: SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // ActiveRecord unsafe patterns
        let patterns = [
            // Direct string interpolation in queries
            (r##"(?i)\.where\s*\(\s*["\'][\s\w]*\#\{"##,
             ".where() with string interpolation — SQL injection risk"),
            (r##"(?i)\.find_by_sql\s*\(\s*["\'][\s\w]*\#\{"##,
             ".find_by_sql() with interpolation — SQL injection"),
            (r##"(?i)\.execute\s*\([^)]*\#\{"##,
             ".execute() with interpolation — raw SQL injection"),
            (r##"(?i)\.order\s*\(\s*["\'][\s\w]*\#\{"##,
             ".order() with interpolation — ORDER BY injection"),
            (r##"(?i)\.group\s*\(\s*["\'][\s\w]*\#\{"##,
             ".group() with interpolation — GROUP BY injection"),
            (r##"(?i)\.joins?\s*\(\s*["\'][\s\w]*\#\{"##,
             ".joins() with interpolation — JOIN injection"),
            (r##"(?i)\.select\s*\(\s*["\'][\s\w]*\#\{"##,
             ".select() with interpolation — column injection"),
            // find_or_create_by with interpolation
            (r##"(?i)\.find_or_create_by\s*\(\s*["\'][\s\w]*\#\{"##,
             ".find_or_create_by() with interpolation"),
            // update_all / delete_all with interpolation
            (r##"(?i)\.update_all\s*\(\s*["\'][\s\w]*\#\{"##,
             ".update_all() with interpolation"),
            (r##"(?i)\.delete_all\s*\(\s*["\'][\s\w]*\#\{"##,
             ".delete_all() with interpolation"),
            // Sanitized: Model.where(["name = ?", user]) — safe
            // Unsafe: Model.where("name = '#{user}'")
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman SQL Injection (CWE-89): {}. \
                        String interpolation in SQL queries allows attackers to manipulate query logic.", problem),
                    fix_hint: "Use parameterized queries: \
                        Model.where(\"name = ?\", user_input) or \
                        Model.where(name: user_input). \
                        Never interpolate user input directly into SQL strings. \
                        For dynamic column/table names, use whitelist validation.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-036: Brakeman CheckXSS — XSS via inline template rendering
// Severity: high | CWE-79
// Brakeman: Checks for XSS via inline template rendering (render :inline)
// Safe: render 'template', layout: false
// Unsafe: render inline: params[:template]
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanXssInlineTemplate;

impl LangRule for BrakemanXssInlineTemplate {
    fn id(&self) -> &str { "RUBY-SEC-036" }
    fn name(&self) -> &str { "Brakeman: XSS Inline Template" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // render :inline with user input
            (r##"(?i)render\s*\(\s*:inline\s*=>\s*params\["##,
             "render :inline with params — user can inject arbitrary ERB template"),
            (r##"(?i)render\s*\(\s*:inline\s*=>\s*request\["##,
             "render :inline with request — user can inject ERB template"),
            (r##"(?i)render\s*\(\s*inline:\s*params\["##,
             "render inline: params[:tpl] — user-controlled template rendering"),
            (r##"(?i)render\s*\(\s*text:\s*params\["##,
             "render text: params[:data] — potential XSS in raw text output"),
            // raw output with user input
            (r##"(?i)\.html_safe\s*\(\s*params\["##,
             ".html_safe(params[:x]) — bypasses HTML escaping for user input"),
            (r##"(?i)raw\s*\(\s*params\["##,
             "raw(params[:x]) — disables HTML escaping for user input"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman XSS (CWE-79): {}. \
                        Rendering user input as HTML without escaping enables cross-site scripting attacks.", problem),
                    fix_hint: "Never render user input as a template or mark it as HTML-safe. \
                        Always escape user data: <%= h(user_input) %> in ERB. \
                        Use sanitize() helper for permitted HTML. \
                        Avoid render :inline with user-controlled content.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-037: Brakeman CheckCommandInjection — Command injection in Rails
// Severity: critical | CWE-78
// Brakeman: system(), exec(), popen3(), `%x{}` with user input
// Safe: system(cmd, arg1, arg2) with validated args
// Unsafe: system("ls #{params[:dir]}")
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanCommandInjection;

impl LangRule for BrakemanCommandInjection {
    fn id(&self) -> &str { "RUBY-SEC-037" }
    fn name(&self) -> &str { "Brakeman: Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)system\s*\(\s*["\'][^"\']*\#\{"##,
             "system() with string interpolation — command injection"),
            (r##"(?i)exec\s*\(\s*["\'][^"\']*\#\{"##,
             "exec() with string interpolation — command injection"),
            (r##"(?i)`[^`]*\#\{[^}]+\}`"##,
             "Backtick command with interpolation — command injection"),
            (r##"(?i)Open3\.(?:popen3|capture[23]?|pipeline)\s*\(\s*["\'][^"\']*\#\{"##,
             "Open3 with string interpolation — command injection"),
            (r##"(?i)%x\{[^}]*\#\{[^}]+\}\}"##,
             "%x{} with interpolation — command injection"),
            (r##"(?i)send_file\s*\(\s*params\["##,
             "send_file with params[:path] — path traversal command injection risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman Command Injection (CWE-78): {}. \
                        Passing user input to shell commands allows arbitrary command execution.", problem),
                    fix_hint: "Use argument arrays instead of shell strings: \
                        system('ls', '-la', directory) instead of system(\"ls #{directory}\"). \
                        Validate and whitelist all user input before use in commands. \
                        Use Ruby's built-in Dir methods for file operations instead of shell commands.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-038: Brakeman CheckMassAssignment — Mass assignment vulnerability
// Severity: high | CWE-915
// Brakeman: Model.new(params) or Model.create(params) without attr_accessible
// Safe: Model.new(permitted_params) or strong_params pattern
// Unsafe: Model.new(params) with unprotected params[:admin]
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanMassAssignment;

impl LangRule for BrakemanMassAssignment {
    fn id(&self) -> &str { "RUBY-SEC-038" }
    fn name(&self) -> &str { "Brakeman: Mass Assignment" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // Model.new(params) or Model.create(params) without strong params
            (r##"(?i)\.new\s*\(\s*params\)\.save"##,
             "Model.new(params) without strong params — mass assignment"),
            (r##"(?i)\.create\s*\(\s*params\)\s*(?:\.|$)"##,
             "Model.create(params) without strong params — mass assignment"),
            (r##"(?i)\.create!\s*\(\s*params\)\s*(?:\.|$)"##,
             "Model.create!(params) without strong params — mass assignment"),
            (r##"(?i)\.update_attributes?\s*\(\s*params\)\s*(?:\.|$)"##,
             "update_attributes(params) without strong params — mass assignment"),
            (r##"(?i)\.assign_attributes?\s*\(\s*params\)\s*(?:\.|$)"##,
             "assign_attributes(params) without strong params — mass assignment"),
            // Model.first_or_create / find_or_create_by with params
            (r##"(?i)\.first_or_create\s*\(\s*params"##,
             "first_or_create(params) without strong params"),
            (r##"(?i)\.find_or_initialize_by.*params\)\.save"##,
             "find_or_initialize_by(params).save without strong params"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check if strong params method is used
                let uses_strong_params =
                    line_text.contains("params.require") ||
                    line_text.contains("params.permit") ||
                    line_text.contains("permit(") ||
                    line_text.contains("require(");

                if uses_strong_params {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman Mass Assignment (CWE-915): {}. \
                        Passing raw params allows attackers to modify protected attributes like admin flag or role.", problem),
                    fix_hint: "Use strong parameters: \
                        params.require(:model).permit(:name, :email). \
                        In Rails 4+, always wrap params in require + permit. \
                        Remove attr_accessible from models — it's deprecated.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-039: Brakeman CheckRedirect — Open redirect in Rails
// Severity: medium | CWE-601
// Brakeman: redirect_to with params, request, or referer without validation
// Safe: redirect_to validated_url(params[:url])
// Unsafe: redirect_to params[:url]
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanOpenRedirect;

impl LangRule for BrakemanOpenRedirect {
    fn id(&self) -> &str { "RUBY-SEC-039" }
    fn name(&self) -> &str { "Brakeman: Open Redirect" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)redirect_to\s*\(\s*params\["##,
             "redirect_to with params[:key] — open redirect risk"),
            (r##"(?i)redirect_to\s*\(\s*request\."##,
             "redirect_to with request object — open redirect risk"),
            (r##"(?i)redirect_to\s*\(\s*session\["##,
             "redirect_to with session data — open redirect risk"),
            (r##"(?i)redirect_to\s*\(\s*cookies\["##,
             "redirect_to with cookie data — open redirect risk"),
            (r##"(?i)redirect_to\s*\(\s*:back\s*\)"##,
             "redirect_to :back — relies on Referer header which can be spoofed"),
            (r##"(?i)redirect_to\s+\#\{[^}]+\}"##,
             "redirect_to with string interpolation — open redirect risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check for safe redirect validation
                let has_validation =
                    line_text.contains("verify_redirect") ||
                    line_text.contains("allowed_host") ||
                    line_text.contains("validate_redirect") ||
                    line_text.contains("uri?");

                if has_validation {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman Open Redirect (CWE-601): {}. \
                        Redirecting to user-controlled URLs allows phishing and credential theft.", problem),
                    fix_hint: "Always validate redirect URLs: \
                        1) Use allowed_hosts list: ALLOWED_HOSTS.include?(uri.host). \
                        2) Use redirect_to_or_default('/'). \
                        3) For external redirects, require HTTPS and validate against whitelist. \
                        Never redirect to fully user-controlled URLs.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-040: Brakeman CheckSQL LIKE — SQL LIKE injection
// Severity: high | CWE-89
// Brakeman: LIKE queries with unsanitized user input
// Safe: .where("name LIKE ?", "%#{sanitize}%")
// Unsafe: .where("name LIKE '%#{params[:search]}%'")
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanSqlLikeInjection;

impl LangRule for BrakemanSqlLikeInjection {
    fn id(&self) -> &str { "RUBY-SEC-040" }
    fn name(&self) -> &str { "Brakeman: SQL LIKE Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // LIKE/LIKE queries with raw interpolation
            (r##"(?i)LIKE\s+['\"][^'\"]*%\#\{"##,
             "LIKE query with string interpolation — LIKE injection"),
            (r##"(?i)\.where.*LIKE.*\#\{"##,
             ".where with LIKE and interpolation — SQL injection"),
            (r##"(?i)\.order.*params\["##,
             ".order() with params — potential ORDER BY injection"),
            // LIKE without escaping special chars
            (r##"(?i)\.where.*['\"]%\#\{"##,
             "LIKE '%#{...}' without escape — LIKE injection risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check if sanitized
                let is_safe =
                    line_text.contains("sanitize_sql_like") ||
                    line_text.contains("escape()") ||
                    line_text.contains("connection.quote_column_name");

                if is_safe {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman SQL LIKE Injection (CWE-89): {}. \
                        LIKE wildcards (%, _) in user input can be manipulated for SQL injection.", problem),
                    fix_hint: r#"Escape LIKE special characters: \
                        term = params[:q].to_s.gsub("%", "\\\\%").gsub("_", "\\\\_") \
                        Model.where("name LIKE ?", "%#{term}%"). \
                        Or use sanitize_sql_like(params[:q])."#.to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-041: Brakeman CheckSendFile — Path traversal in send_file
// Severity: high | CWE-22
// Brakeman: send_file with user-controlled filename
// Safe: send_file verified_path(params[:file])
// Unsafe: send_file params[:path]
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanSendFileTraversal;

impl LangRule for BrakemanSendFileTraversal {
    fn id(&self) -> &str { "RUBY-SEC-041" }
    fn name(&self) -> &str { "Brakeman: send_file Path Traversal" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)send_file\s*\(\s*params\["##,
             "send_file(params[:file]) — path traversal risk"),
            (r##"(?i)send_file\s*\(\s*request\."##,
             "send_file with request data — path traversal risk"),
            (r##"(?i)send_data\s*\(\s*params\["##,
             "send_data with params — path traversal risk"),
            (r##"(?i)send_file\s*\(\s*File\."##,
             "send_file(File.join(...)) — check for path traversal in path construction"),
            (r##"(?i)send_file\s*\(\s*["\'][^"\']*\.\.\/["\']"##,
             "send_file with ../ in path — confirmed path traversal"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman send_file Traversal (CWE-22): {}. \
                        User-controlled file paths in send_file allow reading arbitrary server files.", problem),
                    fix_hint: "Always validate and sanitize file paths: \
                        1) Use Base name: File.basename(params[:file]). \
                        2) Verify path is within allowed directory. \
                        3) Use safe_join: Rails.application.routes.url_helpers.safe_join(\n                          Rails.root, 'private', params[:file]). \
                        4) Check file existence before sending.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-042: Brakeman CheckXML XXE — XML External Entity in REXML/Nokogiri
// Severity: high | CWE-611
// Brakeman: REXML or Nokogiri parsing with user-controlled XML without XXE protection
// Safe: REXML::Document.new(xml,:raw =>false,:prohibit_dtd =>true)
// Unsafe: REXML::Document.new(params[:xml])
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanXmlXxe;

impl LangRule for BrakemanXmlXxe {
    fn id(&self) -> &str { "RUBY-SEC-042" }
    fn name(&self) -> &str { "Brakeman: XML XXE Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // REXML parsing without safe options
            (r##"(?i)REXML::Document\.new\s*\(\s*params\["##,
             "REXML::Document.new(params[:xml]) — XXE risk without safe options"),
            (r##"(?i)REXML::Document\.new\s*\(\s*request\."##,
             "REXML::Document.new with request data — XXE risk"),
            (r##"(?i)REXML::Document\.new\s*\([^)]*\)\s*(?:;|\n|$)(?!.*(?:prohibit_dtd|raw_false|security_xxe))"##,
             "REXML::Document.new without XXE protection flags"),
            // Nokogiri without NOBLANKNS
            (r##"(?i)Nokogiri::XML\s*\(\s*params\["##,
             "Nokogiri::XML(params[:xml]) — XXE risk if external entities enabled"),
            (r##"(?i)Nokogiri::HTML\s*\(\s*params\["##,
             "Nokogiri::HTML(params[:html]) — potential XXE/SSRF risk"),
            (r##"(?i)Savon\.client|Feedjira\.parse|HTTParty\.get.*\.xml"##,
             "XML parsing from HTTP response — XXE risk if DTD enabled"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check for XXE-safe options
                let is_safe =
                    line_text.contains("prohibit_dtd") ||
                    line_text.contains("raw_false") ||
                    line_text.contains("NOENT") ||
                    line_text.contains("NOBLANKS") ||
                    line_text.contains("NOCDATA") ||
                    line_text.contains("XXE") ||
                    line_text.contains("xxe") ||
                    line_text.contains("NOKOGIRI_NO_XXE");

                if is_safe {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman XXE Injection (CWE-611): {}. \
                        XML parsers with external entity access enabled can read server files or perform SSRF.", problem),
                    fix_hint: "Disable external entities in XML parsers: \
                        REXML: REXML::Document.new(xml, :prohibit_dtd => true, :raw => false). \
                        Nokogiri: Nokogiri::XML(xml, nil, Nokogiri::XML::ParseOptions::NOENT.to_i & ~XXE_FLAGS). \
                        Use deny list for known dangerous entities.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-043: Brakeman CheckDetailedExceptions — Verbose exceptions in production
// Severity: low | CWE-209
// Brakeman: config/environments/production.rb without consider_all_requests_local = false
// or with config.consider_all_requests_local = true in production
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanDetailedExceptions;

impl LangRule for BrakemanDetailedExceptions {
    fn id(&self) -> &str { "RUBY-SEC-043" }
    fn name(&self) -> &str { "Brakeman: Detailed Exceptions in Production" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let is_production = code.contains("production");

        // Only check if this looks like a Rails environment config
        if !code.contains("Rails.application.configure") &&
           !code.contains("config/application.rb") &&
           !code.contains("environment") {
            return findings;
        }

        let patterns = [
            // consider_all_requests_local set to true
            (r##"consider_all_requests_local\s*=\s*true"##,
             "consider_all_requests_local = true — stack traces exposed to users"),
            // debug_exception_view_prefix enabled
            (r##"debug_exception_view_prefix\s*="##,
             "debug_exception_view_prefix enabled — error page details exposed"),
            // Show detailed exceptions for specific paths
            (r##"config\.(?:action_controller|action_dispatch)\.show_exceptions\s*=\s*['\"]all['\"]"##,
             "show_exceptions = 'all' — detailed errors exposed"),
            // Exception handler exposing details
            (r##"rescue\s+=>\s*e\s+.*\.(?:message|backtrace|to_s|inspect)\b"##,
             "Exception handler may expose internal details"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman Detailed Exceptions (CWE-209): {}. \
                        Stack traces and internal paths exposed to users reveal application internals.", problem),
                    fix_hint: "In production.rb: \
                        config.consider_all_requests_local = false; \
                        config.action_controller.raise_on_missing_callbacks = true; \
                        Use a logging service (Sentry, Airbrake) for error tracking. \
                        Remove debug views from production.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-044: Brakeman CheckContentTag — XSS via content_tag with unsafe HTML
// Severity: high | CWE-79
// Brakeman: content_tag with options that bypass HTML escaping
// Safe: content_tag(:div, user_data, class: 'item')
// Unsafe: content_tag(:div, raw(user_data))
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanContentTagXss;

impl LangRule for BrakemanContentTagXss {
    fn id(&self) -> &str { "RUBY-SEC-044" }
    fn name(&self) -> &str { "Brakeman: XSS via content_tag" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // content_tag with raw() inside
            (r##"(?i)content_tag\s*\([^)]*raw\s*\("##,
             "content_tag with raw() — XSS bypass of HTML escaping"),
            (r##"(?i)content_tag\s*\([^)]*\.html_safe"##,
             "content_tag with .html_safe — XSS bypass"),
            // tag() with raw content
            (r##"(?i)tag\s*\([^)]*raw\s*\("##,
             "tag() with raw() content — XSS bypass"),
            (r##"(?i)tag\s*\([^)]*\.html_safe"##,
             "tag() with .html_safe — XSS bypass"),
            // div_for with raw content
            (r##"(?i)div_for\s*\([^)]*raw"##,
             "div_for with raw() — XSS bypass"),
            // link_to with javascript: or onclick with params
            (r##"(?i)link_to\s*\([^)]*javascript:"##,
             "link_to with javascript: URL — XSS/mouseover attack"),
            (r##"(?i)link_to\s*\([^)]*params\["##,
             "link_to with params — URL injection risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman content_tag XSS (CWE-79): {}. \
                        Using raw() or .html_safe with user input in content_tag bypasses HTML escaping.", problem),
                    fix_hint: "Never use raw() or .html_safe with unvalidated user input in content_tag. \
                        content_tag(:div, user_text) automatically escapes. \
                        If HTML is intentional, use sanitize() helper first: \
                        content_tag(:div, sanitize(user_html), class: 'item').".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-045: Brakeman CheckSelectTag — XSS in select_tag options
// Severity: medium | CWE-79
// Brakeman: select_tag with options_for_select containing unsanitized user data
// Safe: options_for_select([['Label', value]], selected)
// Unsafe: options_for_select([params[:name], params[:value]])
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanSelectTagXss;

impl LangRule for BrakemanSelectTagXss {
    fn id(&self) -> &str { "RUBY-SEC-045" }
    fn name(&self) -> &str { "Brakeman: XSS in select_tag Options" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // select_tag with params directly
            (r##"(?i)select_tag\s*\([^)]*params\["##,
             "select_tag with params directly — user data in select options"),
            (r##"(?i)options_for_select\s*\(\s*params\["##,
             "options_for_select(params[:options]) — XSS in select options"),
            (r##"(?i)collection_select\s*\([^)]*params\["##,
             "collection_select with params — user-controlled select options"),
            (r##"(?i)grouped_options_for_select\s*\([^)]*params\["##,
             "grouped_options_for_select with params — XSS in optgroup labels"),
            // raw in options
            (r##"(?i)options_for_select\s*\([^)]*raw"##,
             "options_for_select with raw() — XSS bypass in select options"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman select_tag XSS (CWE-79): {}. \
                        User input in select_tag options can enable XSS if options are rendered unsafely.", problem),
                    fix_hint: "Always sanitize user input in select options: \
                        options_for_select(items.map {{ |n| [sanitize(n), n] }}). \
                        Validate option values against a whitelist. \
                        Use collection_select with model associations for known values.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-046: Brakeman CheckRenderPath — Path traversal in render partial
// Severity: high | CWE-22
// Brakeman: render with dynamic partial path containing user input
// Safe: render 'shared/item'
// Unsafe: render "shared/#{params[:item]}"
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanRenderPathTraversal;

impl LangRule for BrakemanRenderPathTraversal {
    fn id(&self) -> &str { "RUBY-SEC-046" }
    fn name(&self) -> &str { "Brakeman: render Path Traversal" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // render with string interpolation
            (r##"(?i)render\s+["\'][^"\']*\#\{"##,
             "render with string interpolation in path — path traversal risk"),
            (r##"(?i)render\s*\(\s*partial:\s*["\'][^"\']*\#\{"##,
             "render partial: with interpolation — path traversal risk"),
            (r##"(?i)render\s*\(\s*:partial\s*=>\s*["\'][^"\']*\#\{"##,
             "render :partial => '...' with interpolation — path traversal risk"),
            // render with params directly
            (r##"(?i)render\s*\(\s*partial:\s*params\["##,
             "render partial: params[:partial] — arbitrary template rendering"),
            (r##"(?i)render\s*\(\s*template:\s*params\["##,
             "render template: params[:tpl] — arbitrary template rendering"),
            // render file: with user path
            (r##"(?i)render\s*\(\s*file:\s*params\["##,
             "render file: with params — path traversal risk"),
            // layout with params
            (r##"(?i)layout\s*\(\s*params\["##,
             "layout with params — template injection risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman render Path Traversal (CWE-22): {}. \
                        Dynamic template paths allow attackers to render arbitrary views, potentially exposing sensitive data.", problem),
                    fix_hint: "Never use user input in render paths. \
                        Use whitelisted template names: TEMPLATES.include?(name) ? render(name) : render('default'). \
                        Use constant strings for partial names: render 'shared/item'. \
                        Avoid render file: with user-controlled paths.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-047: Brakeman CheckQuoteTableName — SQL via table/column name interpolation
// Severity: high | CWE-89
// Brakeman: sanitize_sql_array not used for table/column names
// Safe: ActiveRecord::Base.connection.quote_column_name(name)
// Unsafe: Model.where("#{column_name} = ?", value)
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanQuoteTableName;

impl LangRule for BrakemanQuoteTableName {
    fn id(&self) -> &str { "RUBY-SEC-047" }
    fn name(&self) -> &str { "Brakeman: SQL via Table/Column Name Interpolation" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // Table name in interpolation
            (r##"(?i)from\s*\(\s*["\'][\s\w]*\#\{"##,
             "Model.from() with interpolation — table name injection"),
            (r##"(?i)\.order\s*\(\s*["\'][\s\w]*\#\{"##,
             ".order() with column interpolation — SQL injection"),
            (r##"(?i)\.pluck\s*\(\s*["\'][\s\w]*\#\{"##,
             ".pluck() with column interpolation — SQL injection"),
            (r##"(?i)\.select\s*\(\s*["\'][\s\w]*\#\{"##,
             ".select() with column interpolation — SQL injection"),
            (r##"(?i)\.group\s*\(\s*["\'][\s\w]*\#\{"##,
             ".group() with column interpolation — SQL injection"),
            (r##"(?i)reorder\s*\(\s*["\'][\s\w]*\#\{"##,
             ".reorder() with column interpolation — SQL injection"),
            // Model.connection.quote with unvalidated input
            (r##"(?i)quote_table_name\s*\([^)]*params\["##,
             "quote_table_name with params — table name injection"),
            (r##"(?i)quote_column_name\s*\([^)]*params\["##,
             "quote_column_name with params — column name injection"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check if properly quoted
                let is_safe =
                    line_text.contains("quote_table_name") ||
                    line_text.contains("quote_column_name") ||
                    line_text.contains("connection.quote");

                if is_safe {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman Quote Table Name (CWE-89): {}. \
                        Table/column names from user input can enable SQL injection if not properly quoted.", problem),
                    fix_hint: r#"Always quote table/column names with Rails' connection methods: \
                        col = connection.quote_column_name(user_input); \
                        Model.order(col + ' DESC'). \
                        Validate against a whitelist of allowed column/table names. \
                        For sort columns, use a hash map: sorts = { "name" => "name ASC", "date" => "created_at DESC" }; \
                        Model.order(sorts[params[:sort]] || "id ASC")."#.to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-048: Brakeman CheckModelAttributes — Sensitive attributes exposed in JSON
// Severity: medium | CWE-200
// Brakeman: Model serialized to JSON without excluding sensitive attributes
// Safe: Model.first.as_json(except: [:password_digest, :token])
// Unsafe: render json: @user
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanModelAttributes;

impl LangRule for BrakemanModelAttributes {
    fn id(&self) -> &str { "RUBY-SEC-048" }
    fn name(&self) -> &str { "Brakeman: Model Attributes Exposed in JSON" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // render json: @user or to_json without exclusions
        let patterns = [
            (r##"(?i)render\s+json:\s*@\w+\s*$"##,
             "render json: @model without exclusions — sensitive attrs exposed"),
            (r##"(?i)render\s+json:\s*@[\w:]+\s*(?!\.(?:as_json|to_json|only|except))"##,
             "render json: @object without as_json options — sensitive attrs exposed"),
            (r##"(?i)respond_to\s*\(\s*format:\s*json\s*\)"##,
             "respond_to format: :json — may expose model attrs without filtering"),
            // to_json without exclusions
            (r##"(?i)\.to_json\s*\(\s*\)\s*(?:;|\n|\.save|\.create|\.update)"##,
             ".to_json() without exclusions — all attributes serialized"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let (start, end) = get_line_offsets(code, line);
                let line_text = get_line_text(code, line).unwrap_or_default();

                // Check for proper exclusions
                let has_exclusions =
                    line_text.contains("except:") ||
                    line_text.contains("only:") ||
                    line_text.contains("as_json") ||
                    line_text.contains("include:") ||
                    line_text.contains("methods:");

                if has_exclusions {
                    continue;
                }

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: format!("Brakeman Model Attributes Exposed (CWE-200): {}. \
                        Serializing ActiveRecord models to JSON without filtering can expose sensitive \
                        attributes like passwords, tokens, and internal IDs.", problem),
                    fix_hint: "Always specify which attributes to include in JSON responses: \
                        render json: @user.as_json(except: [:password_digest, :reset_token, :api_key]). \
                        Or whitelist: render json: @user.as_json(only: [:id, :name, :email]). \
                        Use ActiveModel Serializers or Jbuilder for complex JSON. \
                        Define to_json in model with sensitive attrs excluded.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-049: Brakeman CheckSessionManipulation — Session value tampering
// Severity: medium | CWE-20
// Brakeman: Session values used directly without validation
// Unsafe: session[:role] = params[:role]; redirect_to admin_path if session[:admin]
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanSessionManipulation;

impl LangRule for BrakemanSessionManipulation {
    fn id(&self) -> &str { "RUBY-SEC-049" }
    fn name(&self) -> &str { "Brakeman: Session Manipulation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // Setting session from params
            (r##"(?i)session\s*\[.*\]\s*=\s*params\["##,
             "session[key] = params[:x] — session tampering risk"),
            (r##"(?i)session\s*\[.*\]\s*=\s*request\."##,
             "session[key] = request.data — session tampering risk"),
            // Reading session for authorization
            (r##"(?i)if\s+session\s*\[.*(?:admin|role|user|account)"##,
             "Authorization check on session value — verify session is server-side"),
            (r##"(?i)redirect_to.*if\s+session\s*\[.*(?:admin|role|user)"##,
             "Redirect based on session — verify session cannot be manipulated"),
            // Session[:user_id] used directly without lookup
            (r##"(?i)User\.find\s*\(\s*session\s*\[.*id.*\]"##,
             "User lookup from session without server-side validation"),
            // Flash from params
            (r##"(?i)flash\s*\[.*\]\s*=\s*params\["##,
             "flash[key] = params[:x] — flash injection risk"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman Session Manipulation (CWE-20): {}. \
                        Session values from user input can be manipulated for privilege escalation.", problem),
                    fix_hint: "Never trust session data for authorization without server-side validation. \
                        1) Always re-validate session data from server: current_user = User.find(session[:user_id]). \
                        2) Use a server-side session store (Redis, DB) not cookie-based. \
                        3) For role checks: current_user.admin? (via DB lookup) not session[:admin]. \
                        4) Use a proper auth framework (Devise, Clearance) for session management.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUBY-SEC-050: Brakeman CheckUnsafeReflection — Unsafe reflection with user input
// Severity: medium | CWE-470
// Brakeman: constantize, send, public_send with user input
// Unsafe: params[:model].constantize.find(params[:id])
// ─────────────────────────────────────────────────────────────────────────────
pub struct BrakemanUnsafeReflection;

impl LangRule for BrakemanUnsafeReflection {
    fn id(&self) -> &str { "RUBY-SEC-050" }
    fn name(&self) -> &str { "Brakeman: Unsafe Reflection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            // constantize with params
            (r##"(?i)[\w:]+(?:\s*::)?\.constantize\s*\(\s*params\["##,
             "constantize(params[:class]) — arbitrary class instantiation"),
            (r##"(?i)[\w:]+(?:\s*::)?\.constantize\s*\(\s*request\."##,
             "constantize with request data — arbitrary class instantiation"),
            // send / public_send with params
            (r##"(?i)\.send\s*\(\s*params\["##,
             ".send(params[:method]) — arbitrary method call"),
            (r##"(?i)\.public_send\s*\(\s*params\["##,
             ".public_send(params[:method]) — arbitrary public method call"),
            // eval with params
            (r##"(?i)eval\s*\(\s*params\["##,
             "eval(params[:code]) — arbitrary code execution"),
            (r##"(?i)class_eval\s*\(\s*params\["##,
             "class_eval with params — arbitrary code execution"),
            // const_get with params
            (r##"(?i)const_get\s*\(\s*params\["##,
             "const_get with params — arbitrary constant access"),
            // Kernel.send
            (r##"(?i)Kernel\.send\s*\(\s*params\["##,
             "Kernel.send(params[:method]) — arbitrary kernel method call"),
        ];

        for (pat, problem) in &patterns {
            let re = match regex::Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in re.find_iter(code) {
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
                    problem: format!("Brakeman Unsafe Reflection (CWE-470): {}. \
                        User input in reflection methods allows arbitrary class/method access, leading to RCE.", problem),
                    fix_hint: "Never pass user input to reflection methods without strict validation: \
                        ALLOWED_METHODS = %w[index show create].freeze; \
                        if ALLOWED_METHODS.include?(params[:action]) then model.send(params[:action]) end. \
                        For constantize: validate against ApplicationRecord.descendants.map(&:name). \
                        Avoid eval(), send(), constantize() with user input entirely.".to_string(),
                    auto_fix_available: false,
                        replacement: String::new(),
                });
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-051: CSRF Missing protect_from_forgery
/// CWE-352: Cross-Site Request Forgery - No protect_from_forgery in ApplicationController
pub struct RubyCsrfProtectFromForgery;

impl LangRule for RubyCsrfProtectFromForgery {
    fn id(&self) -> &str { "RUBY-SEC-051" }
    fn name(&self) -> &str { "CSRF: Missing protect_from_forgery" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check if this is an ApplicationController
        let is_app_controller = code.contains("class ApplicationController") ||
            code.contains("class < ApplicationController") ||
            code.contains("ApplicationController <");

        if !is_app_controller {
            return findings;
        }

        // If it is an ApplicationController, it MUST have protect_from_forgery
        if !code.contains("protect_from_forgery") {
            // Find the class declaration line
            let lines: Vec<&str> = code.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.contains("class ApplicationController") ||
                   line.contains("class < ApplicationController") {
                    let line_num = i + 1;
                    let (start, end) = get_line_offsets(code, line_num);
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line: line_num,
                        column: 0,
                        start_byte: start,
                        end_byte: end,
                        snippet: line.to_string(),
                        problem: "CSRF Protection (CWE-352): ApplicationController missing protect_from_forgery.".to_string(),
                        fix_hint: "Add 'protect_from_forgery' inside ApplicationController to enable CSRF tokens for all actions.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                    break;
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-052: Default Routes Enabled
/// CWE-698: Mass Assignment / Exposure via default Rails routing
pub struct RubyDefaultRoutes;

impl LangRule for RubyDefaultRoutes {
    fn id(&self) -> &str { "RUBY-SEC-052" }
    fn name(&self) -> &str { "Default Routes Enabled" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)match\s+['\"]?:controller(?:/:\s*action(?:/:\s*id)?)?['\"]"##,
             "match ':controller(/:action(/:id))' — exposes all controller actions"),
            (r##"(?i)get\s+['\"].*:\s*controller.*:\s*action"##,
             "GET route with generic controller/action pattern"),
            (r##"(?i)post\s+['\"].*:\s*controller.*:\s*action"##,
             "POST route with generic controller/action pattern"),
            (r##"(?i)put\s+['\"].*:\s*controller.*:\s*action"##,
             "PUT route with generic controller/action pattern"),
            (r##"(?i)delete\s+['\"].*:\s*controller.*:\s*action"##,
             "DELETE route with generic controller/action pattern"),
            (r##"(?i)patch\s+['\"].*:\s*controller.*:\s*action"##,
             "PATCH route with generic controller/action pattern"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Default Routes (CWE-698): {} detected in routes.rb.", desc),
                        fix_hint: "Remove default catch-all routes. Use explicit resource routes like 'resources :users' instead.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-053: Session Manipulation via User Input
/// CWE-20: Input Validation — Reading/writing session keys from user input
pub struct RubySessionAccess;

impl LangRule for RubySessionAccess {
    fn id(&self) -> &str { "RUBY-SEC-053" }
    fn name(&self) -> &str { "Session Access via User Input" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"session\s*\[.*params\["##,
             "session[key] indexed by params — user can read arbitrary session values"),
            (r##"session\s*\[.*request\."##,
             "session[key] indexed by request data — user-controlled session access"),
            (r##"session\.fetch\s*\(\s*params\["##,
             "session.fetch with params key — unsafe session access pattern"),
            (r##"session\[[^\]]+\]\s*=.*(?:params|request|cookies)\["##,
             "session[...] assigned from user input — session poisoning risk"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Session Manipulation (CWE-20): {} detected.", desc),
                        fix_hint: "Never use user-controlled values as session keys. Use server-defined session keys only.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-054: Session Cookie HttpOnly Missing
/// CWE-1004: Sensitive Cookie Without HttpOnly Flag
pub struct RubySessionCookieHttpOnly;

impl LangRule for RubySessionCookieHttpOnly {
    fn id(&self) -> &str { "RUBY-SEC-054" }
    fn name(&self) -> &str { "Session Cookie Missing HttpOnly Flag" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Look for session_store config without http_only
        let has_session_store = code.contains("session_store") || code.contains("Rails.application.config.session_store");

        if has_session_store {
            // Check if http_only is explicitly set to false or missing
            let has_explicit_false = regex::Regex::new(r##"http_only\s*:\s*false"##)
                .map(|re| re.is_match(code))
                .unwrap_or(false);
            let has_http_only_true = regex::Regex::new(r##"http_only\s*:\s*true"##)
                .map(|re| re.is_match(code))
                .unwrap_or(false);

            if has_explicit_false || !has_http_only_true {
                let lines: Vec<&str> = code.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains("session_store") {
                        let line_num = i + 1;
                        let (start, end) = get_line_offsets(code, line_num);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line: line_num,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: line.to_string(),
                            problem: "Session Cookie HttpOnly (CWE-1004): Session store config missing http_only: true.".to_string(),
                            fix_hint: "Set http_only: true in session_store config to prevent JavaScript access to session cookies.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
                        });
                        break;
                    }
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-055: Format Validation with Invalid Regex Anchors
/// CWE-185: Incorrect Regular Expression — validates_format_of using ^$ instead of \A\z
pub struct RubyFormatValidationAnchor;

impl LangRule for RubyFormatValidationAnchor {
    fn id(&self) -> &str { "RUBY-SEC-055" }
    fn name(&self) -> &str { "Format Validation: Invalid Regex Anchors (^$ instead of \\A\\z)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)validates_format_of\s*:[^,]+,\s*with\s*:\s*['\"]?\^[^'\"]+\$['\"]?"##,
             "validates_format_of with ^...$ anchors — can be bypassed by newlines in Ruby regex"),
            (r##"(?i)validates_format_of\s*:[^,]+,\s*with\s*=>\s*/\^[^/]+\$/"##,
             "validates_format_of with /^...$/ pattern — line anchors allow bypass"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Invalid Regex Anchors (CWE-185): {} detected. Use \\\\A and \\\\z instead.", desc),
                        fix_hint: "Replace ^...$ with \\A...\\z in validates_format_of patterns. Use Ruby's \\A (absolute start) and \\z (absolute end) instead of ^ and $.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-056: Dynamic Render Path
/// CWE-73: File/Path Traversal — render with user-controlled template or action
pub struct RubyDynamicRenderPath;

impl LangRule for RubyDynamicRenderPath {
    fn id(&self) -> &str { "RUBY-SEC-056" }
    fn name(&self) -> &str { "Dynamic Render Path (Template/Action from User Input)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"render\s*\(\s*params\["##,
             "render(params[:x]) — template path from user input"),
            (r##"render\s*\(\s*action\s*:\s*params\["##,
             "render action: params[:x] — action name from user input"),
            (r##"render\s*\(\s*file\s*:\s*params\["##,
             "render file: params[:x] — file path from user input"),
            (r##"render\s*\(\s*template\s*:\s*params\["##,
             "render template: params[:x] — template path from user input"),
            (r##"render\s*\(\s*['\""].*\#\{params"##,
             "render with interpolated params in template path"),
            (r##"render\s+\|\s*\|.*params"##,
             "render block with params — verify template is not user-controlled"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Dynamic Render Path (CWE-73): {} detected.", desc),
                        fix_hint: "Never pass user input directly to render. Use a whitelist of permitted template names.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-057: Regex DoS (ReDoS)
/// CWE-1333: Regular Expression Denial of Service — catastrophic backtracking
pub struct RubyRegexDosAdvanced;

impl LangRule for RubyRegexDosAdvanced {
    fn id(&self) -> &str { "RUBY-SEC-057" }
    fn name(&self) -> &str { "Regex DoS (ReDoS): Catastrophic Backtracking" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Dynamic regex with user input
        let dynamic_patterns = [
            (r##"Regexp\.new\s*\(\s*params\["##,
             "Regexp.new with params — user can control regex pattern"),
            (r##"Regexp\.new\s*\(\s*request\."##,
             "Regexp.new with request data — user can control regex pattern"),
            (r##"Regexp\.new\s*\(\s*[^)]*\#\{"##,
             "Regexp.new with string interpolation — dynamic regex"),
            // Catastrophic backtracking patterns
            (r##"\(\.\*\+?\)\{"##,
             "Greedy quantifier in nested group — catastrophic backtracking risk"),
            (r##"\(\.\+\)\*\{"##,
             "Nested quantifiers (.+)* — catastrophic backtracking risk"),
            (r##"\(\.\*\)\*\{"##,
             "Nested quantifiers (.*)* — catastrophic backtracking risk"),
            (r##"\(\.\+\?\)\{"##,
             "Nested quantifiers with reluctant quantifier — backtracking risk"),
            (r##"\|[^\]]*\*\+\|"##,
             "Alternation with repeated group — catastrophic backtracking risk"),
            (r##"\([^)]*\+\)\{"##,
             "Nested quantifiers — catastrophic backtracking pattern"),
        ];

        for (pattern, desc) in &dynamic_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("ReDoS (CWE-1333): {} detected.", desc),
                        fix_hint: "Avoid nested quantifiers and alternation with overlapping patterns. Use atomic grouping or possessive quantifiers where possible. Never construct regex from user input.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-058: Symbol DoS
/// CWE-400: Uncontrolled Resource Consumption — to_sym on user input (Ruby < 3.2)
pub struct RubySymbolDos;

impl LangRule for RubySymbolDos {
    fn id(&self) -> &str { "RUBY-SEC-058" }
    fn name(&self) -> &str { "Symbol DoS: to_sym on User Input (Ruby < 3.2)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)params\[[^\]]+\]\s*\.to_sym"##,
             "params[:x].to_sym — user input converted to symbol"),
            (r##"(?i)request\.[^\(]+\.to_sym"##,
             "request data to_sym — user input converted to symbol"),
            (r##"(?i)request\.parameters\s*\.to_sym"##,
             "request.parameters.to_sym — all params converted to symbols"),
            (r##"(?i)env\[[^\]]+\]\s*\.to_sym"##,
             "env[...].to_sym — environment variable to symbol"),
            (r##"(?i)\.to_sym\s+if\s+(?:params|request|cookies)"##,
             "Conditional to_sym on user input"),
            (r##"(?i)\.send\s*\(\s*['\""].*to_sym"##,
             ".send('to_sym') on user input — dynamic symbol creation"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Symbol DoS (CWE-400): {} detected. Symbols are not garbage-collected (pre-Ruby 3.2).", desc),
                        fix_hint: "Avoid converting user input to symbols. Use strings for dynamic keys or upgrade to Ruby 3.2+ which garbage-collects symbols.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-059: Dangerous Send / Public Send
/// CWE-78: OS Command Injection via dynamic method dispatch
pub struct RubyDangerousSend;

impl LangRule for RubyDangerousSend {
    fn id(&self) -> &str { "RUBY-SEC-059" }
    fn name(&self) -> &str { "Dangerous Send: Dynamic Method Invocation with User Input" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"\.send\s*\(\s*params\["##,
             ".send(params[:x]) — method name from user input"),
            (r##"\.send\s*\(\s*request\."##,
             ".send() with request data — method name from user input"),
            (r##"\.send\s*\(\s*[^)]*\#\{"##,
             ".send() with string interpolation — dynamic method name"),
            (r##"\.public_send\s*\(\s*params\["##,
             ".public_send(params[:x]) — method name from user input"),
            (r##"\.public_send\s*\(\s*request\."##,
             ".public_send() with request data — method name from user input"),
            (r##"\.send\s*\(\s*['\""].*['\""].*params"##,
             ".send() with string concatenation from params"),
            (r##"\[\s*params\["##,
             "Dynamic method call via [] with params key"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Dangerous Send (CWE-78): {} detected. Arbitrary method execution risk.", desc),
                        fix_hint: "Never use user input for method names. Use a whitelist of permitted method names via a case/when or hash lookup.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-060: Mail Header Injection
/// CWE-88: Improper Neutralization of Argument Delimiters — user-controlled mail headers
pub struct RubyMailHeaderInjection;

impl LangRule for RubyMailHeaderInjection {
    fn id(&self) -> &str { "RUBY-SEC-060" }
    fn name(&self) -> &str { "Mail Header Injection" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)mail\s*\([^)]*params\["##,
             "mail() call with params — headers may be user-controlled"),
            (r##"(?i)\.headers\s*\[.*\]\s*="##,
             "Setting mail headers directly — verify values are sanitized"),
            (r##"(?i)Mailer.*\.deliver\s*\([^)]*params"##,
             "Mailer delivery with params in headers"),
            (r##"(?i)mail\s*\(\s*:to\s*=>\s*params\["##,
             "mail :to => params[:x] — recipient from user input"),
            (r##"(?i)mail\s*\(\s*:from\s*=>\s*params\["##,
             "mail :from => params[:x] — sender from user input"),
            (r##"(?i)mail\s*\(\s*:reply_to\s*=>\s*params\["##,
             "mail :reply_to => params[:x] — reply-to from user input"),
            (r##"(?i)headers\s*\[\s*['\""](?:to|from|reply-to|bcc|cc|subject)"##,
             "Setting mail header directly with user-supplied value"),
            (r##"(?i)mail\s*\(\s*[^)]*\+params"##,
             "mail() with string concatenation from params in headers"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Mail Header Injection (CWE-88): {} detected.", desc),
                        fix_hint: "Validate and sanitize all mail header values. Use allowlists for header content. Remove newline characters (\\r\\n) from user input before including in headers.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-061: Marshal.load / Marshal.restore
/// CWE-502: Deserialization of Untrusted Data — Marshal deserialization vulnerabilities
pub struct RubyMarshalLoad;

impl LangRule for RubyMarshalLoad {
    fn id(&self) -> &str { "RUBY-SEC-061" }
    fn name(&self) -> &str { "Marshal Deserialization of Untrusted Data" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"Marshal\.load\s*\("##,
             "Marshal.load() — unsafe deserialization of untrusted data"),
            (r##"Marshal\.restore\s*\("##,
             "Marshal.restore() — alias for Marshal.load, unsafe"),
            (r##"Marshal\.load\s*\(\s*params\["##,
             "Marshal.load(params[:x]) — deserializing user input"),
            (r##"Marshal\.load\s*\(\s*request\."##,
             "Marshal.load with request data — deserializing user input"),
            (r##"Marshal\.load\s*\(\s*cookies\["##,
             "Marshal.load(cookies[:x]) — deserializing cookie data"),
            (r##"Marshal\.load\s*\(\s*session\["##,
             "Marshal.load(session[:x]) — deserializing session data"),
            (r##"Marshal\.load\s*\(\s*File\."##,
             "Marshal.load(File.read) — ensure file source is trusted"),
            (r##"Marshal\.load\s*\(\s*URI\.open"##,
             "Marshal.load from URI.open — loading from remote/source"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Marshal Deserialization (CWE-502): {} — can execute arbitrary Ruby code.", desc),
                        fix_hint: "Never use Marshal.load on untrusted data. Use JSON, YAML.safe_load with allowlists, or MessagePack instead.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-062: Open3 Command Injection
/// CWE-78: OS Command Injection via Open3 popen methods
pub struct RubyOpen3CommandInjection;

impl LangRule for RubyOpen3CommandInjection {
    fn id(&self) -> &str { "RUBY-SEC-062" }
    fn name(&self) -> &str { "Open3 Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"Open3\.popen3\s*\([^)]*#\{"##,
             "Open3.popen3 with string interpolation — command injection risk"),
            (r##"Open3\.popen4\s*\([^)]*#\{"##,
             "Open3.popen4 with string interpolation — command injection risk"),
            (r##"Open3\.capture\s*\([^)]*#\{"##,
             "Open3.capture with string interpolation — command injection risk"),
            (r##"Open3\.capture2\s*\([^)]*#\{"##,
             "Open3.capture2 with string interpolation — command injection risk"),
            (r##"Open3\.capture3\s*\([^)]*#\{"##,
             "Open3.capture3 with string interpolation — command injection risk"),
            (r##"Open3\.pipeline\s*\([^)]*#\{"##,
             "Open3.pipeline with string interpolation — command injection risk"),
            (r##"Open3\.(?:popen3|popen4|capture[23]?|pipeline)\s*\(\s*params\["##,
             "Open3 method with params — user-controlled command"),
            (r##"Open3\.(?:popen3|popen4|capture[23]?|pipeline)\s*\(\s*request\."##,
             "Open3 method with request data — user-controlled command"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Open3 Command Injection (CWE-78): {} detected.", desc),
                        fix_hint: "Use array form for Open3 commands: ['cmd', arg1, arg2]. Never interpolate user input into shell commands.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-063: Raw Output / Unsafe HTML
/// CWE-79: Cross-Site Scripting — marking user input as HTML-safe
pub struct RubyRawOutputXss;

impl LangRule for RubyRawOutputXss {
    fn id(&self) -> &str { "RUBY-SEC-063" }
    fn name(&self) -> &str { "Raw Output: XSS via html_safe / raw with User Input" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"\.html_safe\s*"##,
             ".html_safe called — verify input is sanitized first"),
            (r##"(?i)\.html_safe\s*\(\s*params\["##,
             ".html_safe(params[:x]) — user input marked safe directly"),
            (r##"(?i)\.html_safe\s*\(\s*request\."##,
             ".html_safe(request.data) — user input marked safe directly"),
            (r##"(?i)\.html_safe\s*\(\s*[^)]*\#\{"##,
             ".html_safe with interpolation — verify sanitization"),
            (r##"(?i)raw\s*\(\s*params\["##,
             "raw(params[:x]) — user input output raw without escaping"),
            (r##"(?i)raw\s*\(\s*request\."##,
             "raw(request.data) — user input output raw without escaping"),
            (r##"(?i)raw\s*\(\s*[^)]*\#\{"##,
             "raw with interpolation — verify sanitization"),
            (r##"(?i)content_tag\s*\([^)]*params\["##,
             "content_tag with params — user input in HTML tag"),
            (r##"(?i)content_tag\s*\([^)]*\#\{"##,
             "content_tag with interpolation — verify input is sanitized"),
            (r##"(?i)\.sanitize\s*\([^)]*params\["##,
             "sanitize called on params — verify sanitization is sufficient"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Raw Output XSS (CWE-79): {} detected.", desc),
                        fix_hint: "Never mark user input as html_safe. Use proper output escaping in templates: <%=h user_input %> or sanitize helper with allowlist.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-064: Mass Assignment without Whitelist
/// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
pub struct RubyMassAssignmentUnsafe;

impl LangRule for RubyMassAssignmentUnsafe {
    fn id(&self) -> &str { "RUBY-SEC-064" }
    fn name(&self) -> &str { "Mass Assignment without Attribute Whitelist" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"(?i)params\.permit!"##,
             "params.permit! — allows all params without whitelist"),
            (r##"(?i)params\.slice!"##,
             "params.slice! — modifies params without attribute control"),
            (r##"(?i)params\.reject!"##,
             "params.reject! — removes params without attribute control"),
            (r##"(?i)params\.delete_if"##,
             "params.delete_if — modifies params without attribute control"),
            (r##"(?i)update_attributes\s*\(\s*params"##,
             "update_attributes(params) — mass assignment risk"),
            (r##"(?i)update_columns\s*\(\s*params"##,
             "update_columns(params) — mass assignment risk"),
            (r##"(?i)assign_attributes\s*\(\s*params"##,
             "assign_attributes(params) — mass assignment risk"),
            (r##"(?i)Model\.create\s*\(\s*params"##,
             "Model.create(params) — mass assignment risk"),
            (r##"(?i)\.new\s*\(\s*params[^)]*\)\s*(?:\.save|\.save!)"##,
             "Model.new(params).save — mass assignment risk"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("Mass Assignment (CWE-915): {} — sensitive attributes may be modified.", desc),
                        fix_hint: "Use strong parameters with explicit permit: params.permit(:name, :email). Add attr_accessible or use ActiveRecord enums for sensitive fields.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// RUBY-SEC-065: IO.read Pipe / Backtick Command Injection
/// CWE-78: OS Command Injection via IO methods with pipe or backticks
pub struct RubyIoReadPipe;

impl LangRule for RubyIoReadPipe {
    fn id(&self) -> &str { "RUBY-SEC-065" }
    fn name(&self) -> &str { "IO.read Pipe / Backtick Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let patterns = [
            (r##"IO\.read\s*\(\s*['\""]\|"##,
             "IO.read with pipe — executes shell command"),
            (r##"IO\.write\s*\(\s*['\""]\|"##,
             "IO.write with pipe — executes shell command"),
            (r##"File\.read\s*\(\s*['\""]\|"##,
             "File.read with pipe — executes shell command"),
            (r##"File\.write\s*\(\s*['\""]\|"##,
             "File.write with pipe — executes shell command"),
            (r##"\`[^`]*\#\{[^}]+\}`"##,
             "Backtick command with interpolation — command injection risk"),
            (r##"%x\[.+#\{.+}\]"##,
             "%x[] with interpolation — command injection risk"),
            (r##"IO\.read\s*\(\s*['\""]\|[^'\"]*\#\{"##,
             "IO.read with pipe and interpolation — command injection risk"),
            (r##"IO\.popen\s*\([^)]*\#\{"##,
             "IO.popen with interpolation — command injection risk"),
        ];

        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
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
                        snippet: m.as_str().to_string(),
                        problem: format!("IO Pipe / Command Injection (CWE-78): {} detected.", desc),
                        fix_hint: "Never use pipes (|command) or backticks with user input. Use direct file paths and system calls with explicit arguments.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

/// Get all Ruby security rules.
pub fn ruby_security_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(RubySqlInjection),
        Box::new(RubyCommandInjection),
        Box::new(RubyYamlUnsafeLoad),
        Box::new(RubyHardcodedSecrets),
        Box::new(RubyEvalUsage),
        Box::new(RubyWeakCrypto),
        Box::new(RubyMassAssignment),
        Box::new(RubyLdapInjection),
        Box::new(RubySessionSecurity),
        Box::new(RubyOpenRedirect),
        Box::new(RubyInfoDisclosure),
        Box::new(RubyMissingCsrf),
        Box::new(RubyUnsafeFileAccess),
        Box::new(RubyRegexDos),
        Box::new(RubySlopsquatting),
        Box::new(RubyAiGenComment),
        // New rules RUBY-SEC-016 to RUBY-SEC-018
        Box::new(RubyFormatString),
        Box::new(RubyXssInRails),
        Box::new(RubyMarshalDeserialization),
        Box::new(RubyRaceConditionTransaction),
        Box::new(RubyAiHardcodedSecrets),
        Box::new(RubyAiSqlInjection),
        Box::new(RubyAiCommandInjection),
        Box::new(RubyAiYamlUnsafeLoad),
        Box::new(RubySsrfDeep),
        Box::new(RubySlopsquattingTypo),
        // New rule RUBY-SEC-021
        Box::new(RubyWeakJwt),
        // RUBY-SEC-022 to RUBY-SEC-023: Vulnerable Sink Detection (Reverse-Engineered from hackingtool)
        // RUBY-SEC-022: Sequel ORM SQL Injection
        Box::new(RubySequelSqlInjection),
        // RUBY-SEC-023: Command Injection (system/backticks)
        Box::new(RubyCommandInjectionDeep),
        // RUBY-SEC-028 to RUBY-SEC-031: Additional Ruby Security Rules
        Box::new(RubyActiveRecordSqlInjection),
        Box::new(RubyCommandInjectionShellMetachar),
        Box::new(RubyYamlUnsafeLoadExtended),
        Box::new(RubyInsecureCookie),
        // RUBY-SEC-032 to RUBY-SEC-034: RuboCop Security Cops
        // RUBY-SEC-032: Security/JSONLoad — JSON.load without create_additions: false
        Box::new(RubyJsonLoad),
        // RUBY-SEC-033: Security/IoMethods — IO.read/write with pipe prefix
        Box::new(RubyIoMethods),
        // RUBY-SEC-034: Security/CompoundHash — Custom hash with unsafe combinators
        Box::new(RubyCompoundHash),
        // Brakeman Rails Security Rules (RUBY-SEC-035 to RUBY-SEC-050)
        // RUBY-SEC-035: Brakeman CheckSQL — SQL Injection in ActiveRecord
        Box::new(BrakemanSqlInjection),
        // RUBY-SEC-036: Brakeman CheckXSS — XSS via render inline template
        Box::new(BrakemanXssInlineTemplate),
        // RUBY-SEC-037: Brakeman CheckCommandInjection — Command injection via system/exec
        Box::new(BrakemanCommandInjection),
        // RUBY-SEC-038: Brakeman CheckMassAssignment — Mass assignment vulnerability
        Box::new(BrakemanMassAssignment),
        // RUBY-SEC-039: Brakeman CheckRedirect — Open redirect via redirect_to with user input
        Box::new(BrakemanOpenRedirect),
        // RUBY-SEC-040: Brakeman CheckSQL LIKE — SQL injection in LIKE queries
        Box::new(BrakemanSqlLikeInjection),
        // RUBY-SEC-041: Brakeman CheckSendFile — Path traversal in send_file/send_data
        Box::new(BrakemanSendFileTraversal),
        // RUBY-SEC-042: Brakeman CheckXML XXE — XML External Entity in REXML/Nokogiri
        Box::new(BrakemanXmlXxe),
        // RUBY-SEC-043: Brakeman CheckDetailedExceptions — Verbose exception pages in production
        Box::new(BrakemanDetailedExceptions),
        // RUBY-SEC-044: Brakeman CheckContentTag — XSS via content_tag with unsafe HTML
        Box::new(BrakemanContentTagXss),
        // RUBY-SEC-045: Brakeman CheckSelectTag — XSS in select_tag options
        Box::new(BrakemanSelectTagXss),
        // RUBY-SEC-046: Brakeman CheckRenderPath — Path traversal in render partial
        Box::new(BrakemanRenderPathTraversal),
        // RUBY-SEC-047: Brakeman CheckQuoteTableName — SQL injection via table/column name interpolation
        Box::new(BrakemanQuoteTableName),
        // RUBY-SEC-048: Brakeman CheckModelAttributes — Sensitive attributes exposed in JSON
        Box::new(BrakemanModelAttributes),
        // RUBY-SEC-049: Brakeman CheckSessionManipulation — Session value tampering
        Box::new(BrakemanSessionManipulation),
        // RUBY-SEC-050: Brakeman CheckUnsafeReflection — Unsafe reflection with user input
        Box::new(BrakemanUnsafeReflection),
        // New Security Rules RUBY-SEC-051 to RUBY-SEC-065
        // RUBY-SEC-051: CSRF Missing protect_from_forgery
        Box::new(RubyCsrfProtectFromForgery),
        // RUBY-SEC-052: Default Routes
        Box::new(RubyDefaultRoutes),
        // RUBY-SEC-053: Session Access via User Input
        Box::new(RubySessionAccess),
        // RUBY-SEC-054: Session Cookie HttpOnly Missing
        Box::new(RubySessionCookieHttpOnly),
        // RUBY-SEC-055: Format Validation with Invalid Regex Anchors
        Box::new(RubyFormatValidationAnchor),
        // RUBY-SEC-056: Dynamic Render Path
        Box::new(RubyDynamicRenderPath),
        // RUBY-SEC-057: Regex DoS (ReDoS) — catastrophic backtracking patterns
        Box::new(RubyRegexDosAdvanced),
        // RUBY-SEC-058: Symbol DoS
        Box::new(RubySymbolDos),
        // RUBY-SEC-059: Dangerous Send / Public Send
        Box::new(RubyDangerousSend),
        // RUBY-SEC-060: Mail Header Injection
        Box::new(RubyMailHeaderInjection),
        // RUBY-SEC-061: Marshal.load / Marshal.restore
        Box::new(RubyMarshalLoad),
        // RUBY-SEC-062: Open3 Command Injection
        Box::new(RubyOpen3CommandInjection),
        // RUBY-SEC-063: Raw Output / Unsafe HTML
        Box::new(RubyRawOutputXss),
        // RUBY-SEC-064: Mass Assignment without Whitelist
        Box::new(RubyMassAssignmentUnsafe),
        // RUBY-SEC-065: IO.read Pipe / Backtick Command Injection
        Box::new(RubyIoReadPipe),
    ]
}
