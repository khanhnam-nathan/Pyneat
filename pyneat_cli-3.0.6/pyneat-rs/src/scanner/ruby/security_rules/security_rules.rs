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
                        });
                    }
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
    ]
}
