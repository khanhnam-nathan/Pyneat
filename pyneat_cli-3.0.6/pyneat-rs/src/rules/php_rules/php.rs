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

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

// PHP-SEC-001: PHP SQL Injection
pub struct PhpSqlInjectionRule;
impl Rule for PhpSqlInjectionRule {
    fn id(&self) -> &str { "PHP-SEC-001" }
    fn name(&self) -> &str { "PHP SQL Injection" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"mysqli_query\s*\([^,]+,\s*['"][^'"]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "mysqli_query() with string concatenation and user input"),
            (r##"mysql_query\s*\(\s*['"][^'"]*(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "mysql_query() (deprecated) with user input"),
            (r##"\$pdo\s*->\s*query\s*\(\s*['"][^'"]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "$pdo->query() with string concatenation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-001".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-89".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("SQL Injection via string concatenation: {}", desc),
                        fix_hint: "Use PDO prepared statements or mysqli with prepare() and bind_param().".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-002: PHP XSS
pub struct PhpXssRule;
impl Rule for PhpXssRule {
    fn id(&self) -> &str { "PHP-SEC-002" }
    fn name(&self) -> &str { "PHP Cross-Site Scripting (XSS)" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"echo\s+(?:GET|POST|REQUEST|COOKIE|SESSION)\s*[\['"][^\['"]+[\]['"]"##, "echo with unsanitized superglobal"),
            (r##"print\s+(?:GET|POST|REQUEST|COOKIE|SESSION)\s*[\['"][^\['"]+[\]['"]"##, "print with unsanitized superglobal"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-002".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("XSS vulnerability: {} without escaping.", desc),
                        fix_hint: "Always escape output with htmlspecialchars().".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-003: PHP Insecure File Upload
pub struct PhpInsecureFileUploadRule;
impl Rule for PhpInsecureFileUploadRule {
    fn id(&self) -> &str { "PHP-SEC-003" }
    fn name(&self) -> &str { "PHP Insecure File Upload" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"move_uploaded_file\s*\([^,]+,\s*['"][^'"]*"##, "move_uploaded_file() without extension validation"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-003".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-434".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Insecure file upload: {}", desc),
                        fix_hint: "Validate file extension with whitelist. Check MIME type with finfo_file().".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-004: PHP Loose Comparison
pub struct PhpLooseComparisonRule;
impl Rule for PhpLooseComparisonRule {
    fn id(&self) -> &str { "PHP-SEC-004" }
    fn name(&self) -> &str { "PHP Loose Comparison (Type Juggling)" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"(?:GET|POST|REQUEST|COOKIE)\s*[\['"][^\['"]+[\]['"]\s*=="##, "Loose comparison with GET/POST/REQUEST/COOKIE"),
            (r##"(?:GET|POST|REQUEST|COOKIE)\s*[\['"][^\['"]+[\]['"]\s*!="# ##"##, "Loose non-equality with GET/POST/REQUEST/COOKIE"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-004".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-20".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Type juggling vulnerability: {} using loose comparison.", desc),
                        fix_hint: "Use strict comparison (=== or !==).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-005: PHP eval/assert
pub struct PhpEvalAssertRule;
impl Rule for PhpEvalAssertRule {
    fn id(&self) -> &str { "PHP-SEC-005" }
    fn name(&self) -> &str { "PHP eval() and assert() Usage" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"eval\s*\("##, "eval() usage - direct code execution"),
            (r##"assert\s*\("##, "assert() usage"),
            (r##"create_function\s*\("##, "create_function() - deprecated"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-005".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-95".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Code injection risk: {}", desc),
                        fix_hint: "Replace eval() with safer alternatives.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-006: PHP unserialize
pub struct PhpUnserializeRule;
impl Rule for PhpUnserializeRule {
    fn id(&self) -> &str { "PHP-SEC-006" }
    fn name(&self) -> &str { "PHP unserialize() Vulnerability" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"unserialize\s*\(\s*(?:GET|POST|REQUEST|COOKIE|SESSION)"##, "unserialize() with user-supplied data"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-006".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-502".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A08:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("PHP Object Injection: {}", desc),
                        fix_hint: "Use json_decode() instead of unserialize(). If required, use allowed_classes parameter.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-007: PHP Path Traversal / File Inclusion
pub struct PhpIncludeTraversalRule;
impl Rule for PhpIncludeTraversalRule {
    fn id(&self) -> &str { "PHP-SEC-007" }
    fn name(&self) -> &str { "PHP Local/Remote File Inclusion" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"include\s*\(\s*(?:GET|POST|REQUEST|COOKIE)"##, "include() with user-supplied path"),
            (r##"require\s*\(\s*(?:GET|POST|REQUEST|COOKIE)"##, "require() with user-supplied path"),
            (r##"file_get_contents\s*\(\s*(?:GET|POST|REQUEST|COOKIE)"##, "file_get_contents() with user-supplied path"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-007".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-22".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Path traversal / File inclusion: {}", desc),
                        fix_hint: "Never use user input directly in include/require. Use an allowlist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-008: PHP Hardcoded Secrets
pub struct PhpHardcodedSecretsRule;
impl Rule for PhpHardcodedSecretsRule {
    fn id(&self) -> &str { "PHP-SEC-008" }
    fn name(&self) -> &str { "PHP Hardcoded Database Credentials" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"mysqli_connect\s*\(\s*['"][^'"]+['"]\s*,\s*['"][^'"]+['"]\s*,\s*['"][^'"]+['"]"##, "mysqli_connect() with hardcoded credentials"),
            (r##"new\s+PDO\s*\(\s*['"]mysql:host=[^'"]+;dbname=[^'"]+['"]\s*,\s*['"][^'"]+['"]\s*,\s*['"][^'"]+['"]"##, "PDO with hardcoded credentials in DSN"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-008".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-798".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Hardcoded credentials: {}", desc),
                        fix_hint: "Store credentials in environment variables.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-009: PHP Command Injection
pub struct PhpCommandInjectionRule;
impl Rule for PhpCommandInjectionRule {
    fn id(&self) -> &str { "PHP-SEC-009" }
    fn name(&self) -> &str { "PHP OS Command Injection" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"exec\s*\(\s*['"][^'"]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "exec() with string concatenation and user input"),
            (r##"shell_exec\s*\(\s*['"][^'"]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "shell_exec() with string concatenation and user input"),
            (r##"system\s*\(\s*['"][^'"]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "system() with string concatenation and user input"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-009".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-78".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("OS Command Injection: {}", desc),
                        fix_hint: "Never pass user input directly to shell commands. Use escapeshellarg().".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-010: PHP SSRF
pub struct PhpSsrfRule;
impl Rule for PhpSsrfRule {
    fn id(&self) -> &str { "PHP-SEC-010" }
    fn name(&self) -> &str { "PHP Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"file_get_contents\s*\(\s*(?:GET|POST|REQUEST|COOKIE)"##, "file_get_contents() with user-controlled URL"),
            (r##"curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*(?:GET|POST|REQUEST|COOKIE)"##, "cURL with user-controlled URL"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-010".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("SSRF vulnerability: {}", desc),
                        fix_hint: "Validate URLs against an allowlist of permitted domains.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-011: PHP Debug Mode
pub struct PhpDebugModeRule;
impl Rule for PhpDebugModeRule {
    fn id(&self) -> &str { "PHP-SEC-011" }
    fn name(&self) -> &str { "PHP Debug Mode and Error Display" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]1['"]"##, "ini_set('display_errors', '1') - exposes errors"),
            (r##"var_dump\s*\(\s*(?:GET|POST|REQUEST|COOKIE)"##, "var_dump() of superglobals - debug output"),
            (r##"phpinfo\s*\("##, "phpinfo() call - exposes PHP configuration"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-011".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-11".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Debug mode / Information disclosure: {}", desc),
                        fix_hint: "Disable display_errors in production.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-012: PHP Session
pub struct PhpSessionRule;
impl Rule for PhpSessionRule {
    fn id(&self) -> &str { "PHP-SEC-012" }
    fn name(&self) -> &str { "PHP Weak Session Management" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"ini_set\s*\(\s*['"]session\.cookie_httponly['"]\s*,\s*['"]0['"]"##, "session.cookie_httponly disabled - XSS can steal session"),
            (r##"ini_set\s*\(\s*['"]session\.cookie_secure['"]\s*,\s*['"]0['"]"##, "session.cookie_secure disabled on HTTPS"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-012".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-384".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Weak session management: {}", desc),
                        fix_hint: "Set secure session options: session.cookie_httponly=1, session.cookie_secure=1.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-013: PHP CSRF
pub struct PhpCsrfRule;
impl Rule for PhpCsrfRule {
    fn id(&self) -> &str { "PHP-SEC-013" }
    fn name(&self) -> &str { "PHP Missing CSRF Protection" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"if\s*\(\s*\$_SERVER\s*[\['"][']REQUEST_METHOD[METHOD]['\"]\s*]\s*==\s*['"]POST['"]\s*\)\s*\{"##, "POST form handler without CSRF check"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-013".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-352".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Missing CSRF protection: {}", desc),
                        fix_hint: "Generate and validate CSRF tokens.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-014: PHP XXE
pub struct PhpXxeRule;
impl Rule for PhpXxeRule {
    fn id(&self) -> &str { "PHP-SEC-014" }
    fn name(&self) -> &str { "PHP XML External Entity (XXE)" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"simplexml_load_string\s*\(\s*(?:GET|POST|REQUEST|COOKIE|file_get_contents)"##, "simplexml_load_string() with untrusted XML"),
            (r##"new\s+SimpleXMLElement\s*\(\s*(?:GET|POST|REQUEST|COOKIE|file_get_contents)"##, "SimpleXMLElement constructor with untrusted XML"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-014".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-611".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("XXE vulnerability: {} without safe XML configuration.", desc),
                        fix_hint: "Disable external entities: libxml_disable_entity_loader(true).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-015: PHP Open Redirect
pub struct PhpOpenRedirectRule;
impl Rule for PhpOpenRedirectRule {
    fn id(&self) -> &str { "PHP-SEC-015" }
    fn name(&self) -> &str { "PHP Open Redirect" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"header\s*\(\s*['"]Location:\s*['"]\s*\.\s*(?:GET|POST|REQUEST|COOKIE)"##, "header('Location:') with user input"),
            (r##"header\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)"##, "header('Location:') with superglobal"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-015".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-601".to_string()),
                        cvss_score: Some(6.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Open redirect: {} without validation.", desc),
                        fix_hint: "Validate redirect URLs against an allowlist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-016: PHP LDAP Injection
pub struct PhpLdapInjectionRule;
impl Rule for PhpLdapInjectionRule {
    fn id(&self) -> &str { "PHP-SEC-016" }
    fn name(&self) -> &str { "PHP LDAP Injection" }
    fn severity(&self) -> Severity { Severity::High }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"ldap_search\s*\([^)]*\.(?:\s*\.\s*)?(?:GET|POST|REQUEST|COOKIE)"##, "ldap_search() with user input in DN or filter"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-016".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-90".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("LDAP Injection: {} without escaping.", desc),
                        fix_hint: "Escape LDAP special characters or validate input against allowlist.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-017: PHP Mass Assignment
pub struct PhpMassAssignmentRule;
impl Rule for PhpMassAssignmentRule {
    fn id(&self) -> &str { "PHP-SEC-017" }
    fn name(&self) -> &str { "PHP Mass Assignment" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"->fill\s*\(\s*\$_"##, "Model->fill() with request data"),
            (r##"->update\s*\(\s*\$_POST\s*\)"##, "Model->update() with $_POST directly"),
            (r##"->update\s*\(\s*\$_REQUEST\s*\)"##, "Model->update() with $_REQUEST directly"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-017".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-915".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Mass assignment vulnerability: {}", desc),
                        fix_hint: "Use fillable/guarded properties in models.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}

// PHP-SEC-018: PHP Information Disclosure
pub struct PhpInfoDisclosureRule;
impl Rule for PhpInfoDisclosureRule {
    fn id(&self) -> &str { "PHP-SEC-018" }
    fn name(&self) -> &str { "PHP Information Disclosure" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r##"phpinfo\s*\("##, "phpinfo() call - exposes PHP configuration"),
            (r##"echo\s+\$\w+_ENV"##, "echo of environment variables"),
        ];
        for (pattern, desc) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "PHP-SEC-018".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: format!("Information disclosure: {}", desc),
                        fix_hint: "Never output environment variables, server info, or configuration values.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
}
