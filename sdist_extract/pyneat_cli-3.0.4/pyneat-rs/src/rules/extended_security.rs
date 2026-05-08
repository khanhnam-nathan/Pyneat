//! Extended Security Rules for Python
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Expands Python security rules from 72 to 200+ rules.
//! Covers OWASP Top 10 2021, CWE Top 25 2023, and AI-specific vulnerabilities.

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use tree_sitter::Tree;

// ============================================================================
// A01: Broken Access Control (OWASP)
// ============================================================================

/// SEC-073: IDOR - Insecure Direct Object Reference
pub struct IdorRule;

impl Rule for IdorRule {
    fn id(&self) -> &str { "SEC-073" }
    fn name(&self) -> &str { "Insecure Direct Object Reference (IDOR)" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"\.get\s*\(\s*id\s*\)", "Direct object access by ID without authorization check"),
            (r"User\.objects\.get\s*\(\s*id\s*=", "Direct database lookup with user-controlled ID"),
            (r#"request\.args\.get\s*\(\s*['"]id['"]"#, "User-controlled ID used in database query"),
            (r#"GET\s+['"]\/user\/["'].*?\.format\s*\("#, "URL with user ID without authorization"),
            (r#"session\s*\[\s*['"]user_id['"]\s*\].*SELECT"#,
             "Session-based query without authorization"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-073".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-639".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Add authorization checks. Verify the user has permission to access the requested object.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-074: Horizontal Privilege Escalation
pub struct HorizontalPrivilegeEscalationRule;

impl Rule for HorizontalPrivilegeEscalationRule {
    fn id(&self) -> &str { "SEC-074" }
    fn name(&self) -> &str { "Horizontal Privilege Escalation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"def\s+\w+.*user_id.*return\s+User\.objects\.get\s*\(\s*id\s*=\s*user_id",
             "Function exposes another user's data based on user_id parameter"),
            (r"if\s+request\.user\s*==\s*resource\.owner",
             "Incomplete ownership check without verifying resource access"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-074".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-285".to_string()),
                        cvss_score: Some(7.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Always verify user authorization before returning sensitive data.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-075: Vertical Privilege Escalation
pub struct VerticalPrivilegeEscalationRule;

impl Rule for VerticalPrivilegeEscalationRule {
    fn id(&self) -> &str { "SEC-075" }
    fn name(&self) -> &str { "Vertical Privilege Escalation" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"if\s+request\.user\.is_staff.*?(?:return|render)",
             "Admin-only action checks only is_staff without role verification"),
            (r"def\s+\w+.*:\s*.*if\s+not\s+request\.user\.is_authenticated",
             "Function allows access to authenticated but unauthorized users"),
            (r"@login_required\s*\n\s*def\s+\w+.*:(?:\s*\n\s*(?:return|if)).*admin",
             "Admin function protected only by @login_required, not @admin_required"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-075".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-269".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use role-based access control (RBAC). Check both authentication and specific role permissions.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A02: Cryptographic Failures
// ============================================================================

/// SEC-076: Weak Hash Algorithm (MD5/SHA1 for passwords)
pub struct WeakHashRule;

impl Rule for WeakHashRule {
    fn id(&self) -> &str { "SEC-076" }
    fn name(&self) -> &str { "Weak Hash Algorithm for Passwords" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"hashlib\.md5\s*\(", "MD5 hash used - collision attacks are trivial"),
            (r"hashlib\.sha1\s*\(", "SHA-1 hash used - deprecated for security purposes"),
            (r"hashlib\.sha256\s*\(.*password", "SHA-256 used for password hashing - too slow for passwords, too fast for hashing"),
            (r"bcrypt\.hashpw\s*\([^,]+,\s*bcrypt\.gensalt\s*\(\s*\)",
             "Proper bcrypt usage detected"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let sev = if problem.contains("MD5") || problem.contains("SHA-1") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    findings.push(Finding {
                        rule_id: "SEC-076".to_string(),
                        severity: sev.as_str().to_string(),
                        cwe_id: Some("CWE-327".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use bcrypt, scrypt, or Argon2 for password hashing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-077: ECB Mode Encryption
pub struct EcbModeRule;

impl Rule for EcbModeRule {
    fn id(&self) -> &str { "SEC-077" }
    fn name(&self) -> &str { "Weak Encryption Mode (ECB)" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"AES\.new\s*\([^)]*mode\s*=\s*AES\.MODE_ECB", "ECB mode encryption - patterns visible in ciphertext"),
            (r#"Cipher\s*\([^)]*mode\s*=\s*'ECB'"#, "ECB mode detected - encryption provides no semantic security"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-077".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-327".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use CBC or GCM mode with a random IV. Example: AES.new(key, AES.MODE_CBC, iv)".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-078: Hardcoded Encryption Key
pub struct HardcodedKeyRule;

impl Rule for HardcodedKeyRule {
    fn id(&self) -> &str { "SEC-078" }
    fn name(&self) -> &str { "Hardcoded Cryptographic Key" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"ENCRYPTION_KEY\s*=\s*['"][a-zA-Z0-9+/=]{16,}['"]"#, "Hardcoded encryption key found"),
            (r#"SECRET_KEY\s*=\s*['"][a-zA-Z0-9+/=]{32,}['"]"#, "Hardcoded secret key found"),
            (r#"API_KEY\s*=\s*['"][a-zA-Z0-9_-]{20,}['"]"#, "Hardcoded API key found"),
            (r#"PRIVATE_KEY\s*=\s*['"]-----BEGIN"#, "Hardcoded private key found"),
            (r#"Fernet\s*\(\s*['"][a-zA-Z0-9+/=]{32,}['"]\s*\)"#, "Fernet key hardcoded in source"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-078".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-321".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Store keys in environment variables or a secure key management service (e.g., AWS KMS, HashiCorp Vault).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A03: Injection
// ============================================================================

/// SEC-079: LDAP Injection
pub struct LdapInjectionRule;

impl Rule for LdapInjectionRule {
    fn id(&self) -> &str { "SEC-079" }
    fn name(&self) -> &str { "LDAP Injection" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"ldap\.search\s*\([^)]*\+[^)]*\)", "LDAP query built with string concatenation - LDAP injection risk"),
            (r"ldap\.search_s\s*\([^)]*%\s*\(", "LDAP query uses Python format string - injection risk"),
            (r#"search_filter\s*=\s*['"]\(uid\s*="#, "LDAP filter built without sanitization"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-079".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-90".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use ldap.filter.escape_filter_chars() to sanitize input before building LDAP queries.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-080: XPath Injection
pub struct XpathInjectionRule;

impl Rule for XpathInjectionRule {
    fn id(&self) -> &str { "SEC-080" }
    fn name(&self) -> &str { "XPath Injection" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"etree\.parse\s*\([^)]*\+", "XML/XPath query with string concatenation"),
            (r"xpath\s*\([^)]*\+[^)]*request", "XPath built from user input"),
            (r"ElementTree\.parse\s*\([^)]*\.format\s*\(", "XML parsing with format string"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-080".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-643".to_string()),
                        cvss_score: Some(8.2),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use parameterized XPath queries or input validation/encoding.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-081: Template Injection (Jinja2 SSTI)
pub struct TemplateInjectionRule;

impl Rule for TemplateInjectionRule {
    fn id(&self) -> &str { "SEC-081" }
    fn name(&self) -> &str { "Server-Side Template Injection (SSTI)" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"Template\s*\(\s*request\.|\.args\.|\.form\.", "Jinja2 template built from user input"),
            (r"render_template_string\s*\([^)]*\+[^)]*\)", "render_template_string with concatenation - SSTI risk"),
            (r"flask\.render_template.*\{\{|\%\{", "Template may include unsanitized user input"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-081".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-1336".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Never pass unsanitized user input to template rendering. Use template variables explicitly.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-082: OS Command Injection (extended)
pub struct ExtendedCommandInjectionRule;

impl Rule for ExtendedCommandInjectionRule {
    fn id(&self) -> &str { "SEC-082" }
    fn name(&self) -> &str { "Extended OS Command Injection" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"os\.execl\s*\(", "os.execl with user input - command injection"),
            (r"os\.execle\s*\(", "os.execle with user input - command injection"),
            (r"os\.execlp\s*\(", "os.execlp with user input - command injection"),
            (r"os\.execvp\s*\(", "os.execvp with user input - command injection"),
            (r"os\.execv\s*\(", "os.execv with user input - command injection"),
            (r"asyncio\.create_subprocess_shell\s*\(", "asyncio shell=True allows command injection"),
            (r"commands\.getstatusoutput\s*\(", "commands module is deprecated and unsafe"),
            (r"os\.system\s*\(.*\+", "os.system with string concatenation"),
            (r"subprocess\.call\s*\([^)]*shell\s*=\s*True", "subprocess.call with shell=True"),
            (r"fabric\.Connection.*run\s*\(", "Fabric run() may execute shell commands"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-082".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-78".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use subprocess.run with shell=False and pass command arguments as a list.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A05: Security Misconfiguration
// ============================================================================

/// SEC-083: Debug Mode in Production
pub struct DebugModeRule;

impl Rule for DebugModeRule {
    fn id(&self) -> &str { "SEC-083" }
    fn name(&self) -> &str { "Debug Mode Enabled in Production" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"DEBUG\s*=\s*True", "DEBUG=True found in source code"),
            (r"flask\s*\(.*debug\s*=\s*True", "Flask app created with debug=True"),
            (r"app\.run\s*\([^)]*debug\s*=\s*True", "Flask app.run with debug=True"),
            (r"Django\s*\(.*DEBUG\s*=\s*True", "Django settings with DEBUG=True"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-083".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-489".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Set DEBUG=False in production. Use environment variables: DEBUG=os.getenv('DEBUG', 'False')".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-084: CORS Misconfiguration
pub struct CorsMisconfigurationRule;

impl Rule for CorsMisconfigurationRule {
    fn id(&self) -> &str { "SEC-084" }
    fn name(&self) -> &str { "Dangerous CORS Configuration" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"CORS\s*\([^)]*origins\s*=\s*['"]\*['"]"#, "CORS allows all origins (*)"),
            (r"allow_all_origins\s*=\s*True", "CORS allows all origins"),
            (r#"Access-Control-Allow-Origin\s*:\s*\*"#, "HTTP header allows all origins"),
            (r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True", "Django CORS allows all origins"),
            (r#"@cross_origin\s*\([^)]*origins\s*=\s*['"]\*['"]"#, "Flask-CORS allows all origins"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-084".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-942".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Specify explicit allowed origins. Use a whitelist of trusted domains.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A07: Authentication Failures
// ============================================================================

/// SEC-085: Weak Password Policy
pub struct WeakPasswordPolicyRule;

impl Rule for WeakPasswordPolicyRule {
    fn id(&self) -> &str { "SEC-085" }
    fn name(&self) -> &str { "Weak or Missing Password Policy" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"set_password\s*\([^)]*\)\s*(?:\n\s*return|\n\s*True)", "Password set without hashing validation"),
            (r"UserCreationForm\s*\(\s*\)", "Django UserCreationForm without custom validation"),
            (r#"password\s*==\s*['"]"#, "Plaintext password comparison detected"),
            (r#"check_password\s*\([^)]*\)\s*==\s*True"#, "Password check using == instead of check_password()"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-085".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-521".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Enforce strong password policy: minimum 12 chars, mixed case, numbers, special chars. Use Django auth password validators.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-086: Brute Force Protection Missing
pub struct BruteForceProtectionRule;

impl Rule for BruteForceProtectionRule {
    fn id(&self) -> &str { "SEC-086" }
    fn name(&self) -> &str { "Missing Brute Force Protection" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"def\s+login.*?(?:\n\s*pass|\n\s*return\s+True)", "Login function without rate limiting"),
            (r"@app\.route.*?login.*?(?!\@ratelimit)", "Login endpoint without rate limiting decorator"),
            (r"authenticate\s*\(.*?\)\s*:\s*(?:\n(?!.*rate|.*limit|.*attempt))", "Authentication without attempt limiting"),
        ];

        let has_protection = code.contains("rate_limit") || code.contains("Ratelimiter")
            || code.contains("max_attempts") || code.contains("@ratelimit")
            || code.contains("django-axes") || code.contains("fail2ban");

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    if !has_protection {
                        findings.push(Finding {
                            rule_id: "SEC-086".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-307".to_string()),
                            cvss_score: Some(7.5),
                            owasp_id: Some("A07:2021".to_string()),
                            start: m.start(),
                            end: m.end(),
                            snippet: extract_snippet(code, m.start(), m.end()),
                            problem: problem.to_string(),
                            fix_hint: "Implement rate limiting, account lockout, or CAPTCHA after failed attempts.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A08: Software Integrity Failures
// ============================================================================

/// SEC-087: Insecure Deserialization (pickle)
pub struct InsecureDeserializationRule;

impl Rule for InsecureDeserializationRule {
    fn id(&self) -> &str { "SEC-087" }
    fn name(&self) -> &str { "Insecure Deserialization (pickle)" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"pickle\.loads\s*\(", "pickle.loads() - arbitrary code execution risk"),
            (r"pickle\.load\s*\(", "pickle.load() - arbitrary code execution risk"),
            (r"cloudpickle\.load\s*\(", "cloudpickle.load() - arbitrary code execution risk"),
            (r"yaml\.load\s*\([^)]*\)\s*(?!\s*Loader\s*=\s*yaml\.SafeLoader)",
             "yaml.load() without SafeLoader - arbitrary code execution risk"),
            (r"marshal\.loads\s*\(", "marshal.loads() - unreliable and unsafe"),
            (r"shelve\.open\s*\(", "shelve module uses pickle internally - unsafe"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-087".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-502".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A08:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use pickle with signed data, or JSON/msgpack for untrusted input.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-088: HTTP without TLS
pub struct HttpWithoutTlsRule;

impl Rule for HttpWithoutTlsRule {
    fn id(&self) -> &str { "SEC-088" }
    fn name(&self) -> &str { "HTTP without TLS for Sensitive Data" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r#"http://[^/'"]+.*?(?:password|token|secret|key|auth|credential)"#, "HTTP URL with sensitive data transmission"),
            (r#"requests\.(?:post|get)\s*\(\s*['"]http://"#, "HTTP request without TLS"),
            (r#"urllib\.request\.urlopen\s*\(['"]http://"#, "urllib request over HTTP"),
            (r"http\s+[^/]", "HTTP protocol used instead of HTTPS"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-088".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-319".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use HTTPS URLs only. Configure redirect from HTTP to HTTPS.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A09: Security Logging Failures
// ============================================================================

/// SEC-089: Logging Sensitive Information
pub struct SensitiveInfoLoggingRule;

impl Rule for SensitiveInfoLoggingRule {
    fn id(&self) -> &str { "SEC-089" }
    fn name(&self) -> &str { "Sensitive Information in Logs" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:password|passwd|pwd)\s*\)", "Password logged"),
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:token|bearer)\s*\)", "Auth token logged"),
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:ssn|social.?security)\s*\)", "SSN logged"),
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:credit.?card|card.?number)\s*\)", "Credit card info logged"),
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*request\.data", "Full request data logged"),
            (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*request\.headers", "Request headers logged (may contain auth tokens)"),
            (r"print\s*\([^)]*(?:password|token|secret|key)", "Sensitive data passed to print()"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-089".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-532".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A09:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Redact sensitive data before logging. Use structured logging with field masking.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// A10: SSRF
// ============================================================================

/// SEC-090: Server-Side Request Forgery
pub struct SsrfRule;

impl Rule for SsrfRule {
    fn id(&self) -> &str { "SEC-090" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"requests\.(?:get|post|put|delete)\s*\([^)]*url\s*=\s*[^)]*(?:request|input|user|param|url)", "HTTP request URL from user input"),
            (r"urllib\.request\.urlopen\s*\([^)]*(?:request|input|user|param)", "urllib request with user-controlled URL"),
            (r"httpx\.(?:get|post)\s*\([^)]*url\s*=\s*[^)]*(?:request|input)", "httpx request with user-controlled URL"),
            (r"subprocess\s*\([^)]*curl\s*\([^)]*request|input", "curl with user-controlled URL"),
            (r"http.client\.HTTPConnection\s*\([^)]*(?:request|input)", "HTTP connection with user-controlled host"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-090".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(9.3),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Validate and allowlist URLs. Block internal IP ranges (127.0.0.1, 10.x, 192.168.x, etc.).".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// Additional Security Rules
// ============================================================================

/// SEC-091: XML External Entity (XXE)
pub struct XxeRule;

impl Rule for XxeRule {
    fn id(&self) -> &str { "SEC-091" }
    fn name(&self) -> &str { "XML External Entity (XXE)" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"etree\.XML\s*\([^)]*DOCTYPE", "XML parsing with DOCTYPE - potential XXE"),
            (r"xml\.dom\.minidom\.parse\s*\(", "minidom parse - potentially unsafe"),
            (r"xml\.sax\.parse\s*\([^)]*(?:request|input|user)", "SAX parse with user input"),
            (r"ElementTree\.parse\s*\([^)]*(?:request|input|user)", "ElementTree parse with user input"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-091".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-611".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Disable DTD processing. Use defusedxml library for parsing untrusted XML.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-092: Path Traversal (extended)
pub struct ExtendedPathTraversalRule;

impl Rule for ExtendedPathTraversalRule {
    fn id(&self) -> &str { "SEC-092" }
    fn name(&self) -> &str { "Extended Path Traversal" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"open\s*\([^)]*(?:request|input|user|param).*?\.format\s*\(", "File open with format string from user input"),
            (r"Path\s*\([^)]*(?:request|input|user).*?\)\.read\s*\(", "Path from user input used to read file"),
            (r"send_file\s*\([^)]*(?:request|input|user)", "send_file with user-controlled path"),
            (r"send_from_directory\s*\([^)]*directory\s*=\s*[^)]*request", "send_from_directory with user-controlled directory"),
            (r"os\.path\.join\s*\([^)]*(?:request|input|user).*?\)", "os.path.join with user input"),
            (r"pathlib\.Path\s*\([^)]*(?:request|input|user).*?\)\.open\s*\(", "Path from user input opened"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-092".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-22".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use os.path.realpath() to resolve symlinks. Validate paths are within allowed directory.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-093: Mass Assignment
pub struct MassAssignmentRule;

impl Rule for MassAssignmentRule {
    fn id(&self) -> &str { "SEC-093" }
    fn name(&self) -> &str { "Mass Assignment / Overly Permissive ORM" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"User\s*\(\s*\*\*\s*request\.data\s*\)", "ORM object created from raw request data"),
            (r"Model\s*\(\s*\*\*\s*request\.json\s*\)", "Model instance from raw JSON"),
            (r"User\.objects\.create\s*\(\s*\*\*\s*request\.POST\s*\)", "User created with all POST fields"),
            (r"update\(.*?\*\*request", "ORM update with request data"),
            (r"\.save\(.*?\*\*.*{.*?request.*?}", "Model save with request kwargs"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-093".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-915".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use explicit field assignment instead of **kwargs. Whitelist allowed fields.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-094: Session Fixation
pub struct SessionFixationRule;

impl Rule for SessionFixationRule {
    fn id(&self) -> &str { "SEC-094" }
    fn name(&self) -> &str { "Session Fixation Vulnerability" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"session\[.id.\]\s*=\s*request\.", "Session ID set from user input"),
            (r"session\.set_id\s*\(\s*request\.", "Session ID set from user input"),
            (r"request\.session\.keys\s*\(\s*\).*?session\.set", "Session not regenerated on login"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-094".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-384".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Regenerate session ID after login. Do not accept session IDs from user input.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-095: Missing Security Headers
pub struct MissingSecurityHeadersRule;

impl Rule for MissingSecurityHeadersRule {
    fn id(&self) -> &str { "SEC-095" }
    fn name(&self) -> &str { "Missing Security Headers" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"@app\.after_request\s*def\s+\w+:.*?response\[", "After-request hook found - check for security headers"),
        ];

        let has_strict_transport = code.contains("Strict-Transport-Security")
            || code.contains("HSTS");
        let has_x_frame = code.contains("X-Frame-Options");
        let has_content_type = code.contains("X-Content-Type-Options");
        let has_csp = code.contains("Content-Security-Policy");

        if !has_strict_transport || !has_x_frame || !has_content_type || !has_csp {
            findings.push(Finding {
                rule_id: "SEC-095".to_string(),
                severity: Severity::Low.as_str().to_string(),
                cwe_id: Some("CWE-693".to_string()),
                cvss_score: Some(3.1),
                owasp_id: Some("A05:2021".to_string()),
                start: 0,
                end: 0,
                snippet: String::new(),
                problem: format!("Missing security headers. Found: HSTS={}, X-Frame={}, X-Content-Type={}, CSP={}",
                    has_strict_transport, has_x_frame, has_content_type, has_csp),
                fix_hint: "Add security headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Content-Security-Policy.".to_string(),
                auto_fix_available: false,
            });
        }

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-095".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        cvss_score: Some(3.1),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Configure security headers in after_request hook.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-096: Zip Slip Vulnerability
pub struct ZipSlipRule;

impl Rule for ZipSlipRule {
    fn id(&self) -> &str { "SEC-096" }
    fn name(&self) -> &str { "Zip Slip - Path Traversal in Archive Extraction" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"ZipFile\.extractall\s*\([^)]*\)", "extractall without path validation"),
            (r"archive\.extract\s*\([^)]*\)", "Archive extract without validation"),
            (r"with\s+ZipFile.*?\.extractall\s*\(", "ZipFile extractall in loop"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-096".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-22".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Validate archive entries are within target directory. Use os.path.realpath() to resolve paths.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-097: ReDoS - Regex Denial of Service
pub struct RedosRule;

impl Rule for RedosRule {
    fn id(&self) -> &str { "SEC-097" }
    fn name(&self) -> &str { "Regex Denial of Service (ReDoS)" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"regex\.compile\s*\([^)]*\(\?\:[^\)]*\*[^\)]*\+[^\)]*\)", "Nested quantifiers in regex"),
            (r"regex\.compile\s*\([^)]*\(\?\:[^\)]*\*[^\)]*\*[^\)]*\)", "Multiple star quantifiers"),
            (r"regex\.compile\s*\([^)]*\(\?[=\!]<=[^\)]*[^\)]\+[^\)]*\)", "Possessive quantifiers or overlapping alternatives"),
            (r"re\.(?:compile|search|match)\s*\([^)]*\([\^\]]*\+[\^\]]*\+", "Greedy quantifiers on expensive patterns"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-097".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-1333".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use atomic groups or possessive quantifiers. Test regex against pathological inputs.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-098: Insecure Random Number Generation
pub struct InsecureRandomRule;

impl Rule for InsecureRandomRule {
    fn id(&self) -> &str { "SEC-098" }
    fn name(&self) -> &str { "Insecure Random Number Generation" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"random\.random\s*\(\s*\)", "random.random() - not cryptographically secure"),
            (r"random\.randint\s*\(\s*\)", "random.randint() - not cryptographically secure"),
            (r"random\.choice\s*\(\s*\)", "random.choice() - not cryptographically secure"),
            (r"random\.shuffle\s*\(\s*\)", "random.shuffle() - not cryptographically secure"),
            (r"secrets\.token_bytes\s*\(\s*\)", "secrets.token_bytes - GOOD: cryptographically secure"),
            (r"secrets\.token_hex\s*\(\s*\)", "secrets.token_hex - GOOD: cryptographically secure"),
            (r"os\.urandom\s*\(\s*\)", "os.urandom - GOOD: cryptographically secure"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let is_good = problem.contains("GOOD");
                    if !is_good {
                        findings.push(Finding {
                            rule_id: "SEC-098".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-338".to_string()),
                            cvss_score: Some(7.4),
                            owasp_id: Some("A02:2021".to_string()),
                            start: m.start(),
                            end: m.end(),
                            snippet: extract_snippet(code, m.start(), m.end()),
                            problem: problem.to_string(),
                            fix_hint: "Use secrets module or os.urandom() for cryptographic purposes.".to_string(),
                            auto_fix_available: false,
                        });
                    }
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-099: Eval with User Input
pub struct EvalInjectionRule;

impl Rule for EvalInjectionRule {
    fn id(&self) -> &str { "SEC-099" }
    fn name(&self) -> &str { "Eval/Exec with User Input" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"eval\s*\([^)]*(?:request|input|user|param|data|body)", "eval() with user-controlled input"),
            (r"exec\s*\([^)]*(?:request|input|user|param|data|body)", "exec() with user-controlled input"),
            (r"compile\s*\([^)]*(?:request|input|user|param)", "compile() with user-controlled input"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-099".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-95".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Never pass user input to eval() or exec(). Use AST parsing or safe expression evaluators.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-100: Race Condition (TOCTOU)
pub struct RaceConditionRule;

impl Rule for RaceConditionRule {
    fn id(&self) -> &str { "SEC-100" }
    fn name(&self) -> &str { "Time-of-Check Time-of-Use (TOCTOU) Race Condition" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"os\.path\.exists.*?\n.*?open\s*\(", "File existence check before open - TOCTOU"),
            (r"if\s+os\.path\.exists.*?os\.remove", "File existence check before delete - TOCTOU"),
            (r"if\s+os\.path\.isfile.*?open\s*\(", "File type check before open - TOCTOU"),
            (r"stat\s*\(\s*\).*?\n.*?open\s*\(", "File stat before open - TOCTOU"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-100".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-367".to_string()),
                        cvss_score: Some(6.8),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use atomic operations. Open file with O_NOFOLLOW and handle exceptions.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-101: Improper Resource Shutdown
pub struct ResourceShutdownRule;

impl Rule for ResourceShutdownRule {
    fn id(&self) -> &str { "SEC-101" }
    fn name(&self) -> &str { "Improper Resource Shutdown" }
    fn severity(&self) -> Severity { Severity::Low }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"with\s+open\s*\([^)]*\)\s+as\s+[^:]+:", "File opened without exception handling"),
            (r"requests\.get\s*\([^)]*\)(?!\s*\.close)", "HTTP response not explicitly closed"),
            (r"db\.cursor\s*\(\s*\)(?!\s*\.close)", "Database cursor not explicitly closed"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-101".to_string(),
                        severity: Severity::Low.as_str().to_string(),
                        cwe_id: Some("CWE-775".to_string()),
                        cvss_score: Some(2.1),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use context managers (with statement) or ensure explicit cleanup in finally blocks.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-102: Use of Insufficiently Random Values
pub struct InsufficientRandomRule;

impl Rule for InsufficientRandomRule {
    fn id(&self) -> &str { "SEC-102" }
    fn name(&self) -> &str { "Predictable IDs/Tokens" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"uuid\.uuid1\s*\(\s*\)", "uuid.uuid1() uses system time/machine ID - predictable"),
            (r"time\.time\s*\(\s*\)", "time.time() as ID - predictable"),
            (r"time\.time_ns\s*\(\s*\)", "time.time_ns() as ID - predictable"),
            (r"hash\s*\([^)]*(?:user_id|email|username)", "Hash of user identifier as ID - predictable"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-102".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-341".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use uuid.uuid4() or secrets.token_urlsafe() for unpredictable IDs.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-103: Improper Certificate Validation
pub struct CertValidationRule;

impl Rule for CertValidationRule {
    fn id(&self) -> &str { "SEC-103" }
    fn name(&self) -> &str { "Improper SSL/TLS Certificate Validation" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"verify\s*=\s*False", "SSL certificate verification disabled"),
            (r"context\s*=\s*ssl\.create_default_context\s*\(\s*\)(?!\s*\.check_hostname)", "SSL context without hostname check"),
            (r"requests\.(?:get|post)\s*\([^)]*verify\s*=\s*False", "requests with verify=False - disables SSL verification"),
            (r"httpx\.Client\s*\([^)]*verify\s*=\s*False", "httpx with verify=False"),
            (r"CURLOPT_SSL_VERIFYPEER\s*=\s*0", "cURL SSL verification disabled"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-103".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-295".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A02:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Always validate SSL/TLS certificates. Never set verify=False for production code.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-104: Unrestricted File Upload
pub struct UnrestrictedUploadRule;

impl Rule for UnrestrictedUploadRule {
    fn id(&self) -> &str { "SEC-104" }
    fn name(&self) -> &str { "Unrestricted File Upload" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"request\.files\.get\s*\([^)]*\)\.save\s*\(", "File uploaded without type validation"),
            (r"upload_folder\s*=\s*[^)]*(?!\s*allowed_extensions)", "Upload folder without extension whitelist"),
            (r"if\s+\.filename\s*:(?!\s*allowed)", "Filename check without whitelist validation"),
            (r"secure_filename\s*\(\s*\)(?!\s*allowed)", "secure_filename not combined with extension check"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-104".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-434".to_string()),
                        cvss_score: Some(8.1),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Validate file extensions and content type. Store files outside web root. Use random filenames.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

/// SEC-105: Improper Restriction of Rendered XML
pub struct XmlBombRule;

impl Rule for XmlBombRule {
    fn id(&self) -> &str { "SEC-105" }
    fn name(&self) -> &str { "Billion Laughs / XML Bomb" }
    fn severity(&self) -> Severity { Severity::High }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let patterns = [
            (r"etree\.XML\s*\([^)]*(?:\!DOCTYPE|\<!\[)", "XML parsing with DOCTYPE entity expansion"),
            (r"xml\.sax\.parse\s*\([^)]*(?:\!ENTITY)", "SAX parsing with entity declarations"),
            (r"xml\.dom\.minidom\.parse\s*\([^)]*\!ENTITY", "DOM parsing with entity declarations"),
        ];

        for (pattern, problem) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-105".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-400".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A04:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Disable entity expansion in XML parser. Use defusedxml with safe parsing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _finding: &Finding, _code: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// Return all extended security rules
// ============================================================================

pub fn all_extended_security_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(IdorRule),
        Box::new(HorizontalPrivilegeEscalationRule),
        Box::new(VerticalPrivilegeEscalationRule),
        Box::new(WeakHashRule),
        Box::new(EcbModeRule),
        Box::new(HardcodedKeyRule),
        Box::new(LdapInjectionRule),
        Box::new(XpathInjectionRule),
        Box::new(TemplateInjectionRule),
        Box::new(ExtendedCommandInjectionRule),
        Box::new(DebugModeRule),
        Box::new(CorsMisconfigurationRule),
        Box::new(WeakPasswordPolicyRule),
        Box::new(BruteForceProtectionRule),
        Box::new(InsecureDeserializationRule),
        Box::new(HttpWithoutTlsRule),
        Box::new(SensitiveInfoLoggingRule),
        Box::new(SsrfRule),
        Box::new(XxeRule),
        Box::new(ExtendedPathTraversalRule),
        Box::new(MassAssignmentRule),
        Box::new(SessionFixationRule),
        Box::new(MissingSecurityHeadersRule),
        Box::new(ZipSlipRule),
        Box::new(RedosRule),
        Box::new(InsecureRandomRule),
        Box::new(EvalInjectionRule),
        Box::new(RaceConditionRule),
        Box::new(ResourceShutdownRule),
        Box::new(InsufficientRandomRule),
        Box::new(CertValidationRule),
        Box::new(UnrestrictedUploadRule),
        Box::new(XmlBombRule),
    ]
}
