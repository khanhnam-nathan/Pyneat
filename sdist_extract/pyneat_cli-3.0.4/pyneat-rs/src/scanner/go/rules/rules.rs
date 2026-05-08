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
//! weak crypto, insecure random, unsafe XML, Cgo security, and AI-generated code issues.

use std::collections::HashSet;
use crate::scanner::ln_ast::LnAst;
use crate::scanner::base::{LangRule, LangFinding, LangFix};

fn get_line_from_byte(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

fn get_line_offsets(code: &str, line: usize) -> (usize, usize) {
    let mut current_line = 1;
    let mut line_start = 0;
    for (i, c) in code.char_indices() {
        if current_line == line {
            line_start = i;
            break;
        }
        if c == '\n' { current_line += 1; }
    }
    let mut line_end = line_start;
    for (i, c) in code[line_start..].char_indices() {
        if c == '\n' { line_end = line_start + i + 1; break; }
    }
    if line_end == line_start { line_end = code.len(); }
    (line_start, line_end)
}

fn add_finding(findings: &mut Vec<LangFinding>, rule_id: &str, severity: &str,
               pattern: &str, desc: &str, code: &str) {
    if let Ok(re) = regex::Regex::new(pattern) {
        for m in re.find_iter(code) {
            let line = get_line_from_byte(code, m.start());
            let (start, end) = get_line_offsets(code, line);
            findings.push(LangFinding {
                rule_id: rule_id.to_string(),
                severity: severity.to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: m.as_str().to_string(),
                problem: desc.to_string(),
                fix_hint: String::new(),
                auto_fix_available: false,
            });
        }
    }
}

// ─── GO-SEC-001: Command Injection ─────────────────────────────────────────

pub struct GoCommandInjection;

impl LangRule for GoCommandInjection {
    fn id(&self) -> &str { "GO-SEC-001" }
    fn name(&self) -> &str { "Command Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let dangerous: HashSet<&str> = ["os/exec.Command", "os/exec.LookPath"].into_iter().collect();
        let shell_arg_patterns: Vec<(&str, &str)> = vec![
            (r##"exec\.Command\s*\(\s*"[^\"]*sh[^\"]*"\s*,\s*"[^\"]*[-c]\s*"##, "exec.Command with shell -c flag"),
            (r##"exec\.Command\s*\(\s*"?-[c]"?\s*"##, "exec.Command with -c flag (shell)"),
            (r##"`[^`]*\$\([^)]+\)`"##, "Backtick command with $() subshell"),
            (r##"exec\.Command\s*\(\s*"sh"\s*,\s*"-c"\s*,\s*"##, "exec.Command(\"sh\", \"-c\", ...) pattern"),
        ];
        for (pat, desc) in &shell_arg_patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        for fun in &dangerous {
            if code.contains(fun) {
                let pat = &format!(r##"{}"##, regex::escape(fun));
                if let Ok(re) = regex::Regex::new(&pat) {
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
                            problem: format!("Command injection risk: {} - verify input is sanitized.", fun),
                            fix_hint: "Use exec.Command with separate args: exec.Command(\"ls\", \"-la\") instead of shell string.".to_string(),
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

// ─── GO-SEC-002: SQL Injection ───────────────────────────────────────────────

pub struct GoSqlInjection;

impl LangRule for GoSqlInjection {
    fn id(&self) -> &str { "GO-SEC-002" }
    fn name(&self) -> &str { "SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\.Query\s*\(\s*`[^`]*\+[^`]*`"##, "sql.Query with string concatenation"),
            (r##"\.Exec\s*\(\s*`[^`]*\+[^`]*`"##, "sql.Exec with string concatenation"),
            (r##"\.QueryRow\s*\(\s*`[^`]*fmt\.Sprintf"##, "sql.QueryRow with fmt.Sprintf"),
            (r##"fmt\.Sprintf\s*\(\s*`[^`]*SELECT[^`]*%s"##, "fmt.Sprintf with SELECT and %s placeholder"),
            (r##"db\.Query\s*\([^)]*\+["'""][^)]*)"##, "db.Query with string concatenation"),
            (r##"rawBytes\s*:=\s*row\.Scan"##, "Direct row.Scan to []byte without validation"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-003: Path Traversal ──────────────────────────────────────────────

pub struct GoPathTraversal;

impl LangRule for GoPathTraversal {
    fn id(&self) -> &str { "GO-SEC-003" }
    fn name(&self) -> &str { "Path Traversal" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"ioutil\.ReadFile\s*\(\s*fmt\.Sprintf"##, "ioutil.ReadFile with fmt.Sprintf"),
            (r##"ioutil\.ReadFile\s*\([^)]*\+["'""][^)]*)"##, "ioutil.ReadFile with concatenation"),
            (r##"os\.Open\s*\([^)]*\+["'""][^)]*)"##, "os.Open with string concatenation"),
            (r##"os\.Create\s*\([^)]*\+["'""][^)]*)"##, "os.Create with string concatenation"),
            (r##"os\.MkdirAll\s*\([^)]*\+["'""][^)]*)"##, "os.MkdirAll with concatenation"),
            (r##"filepath\.Join\s*\([^)]*\+\s*["'""][^)]*)"##, "filepath.Join with untrusted suffix"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-004: Hardcoded Secrets ────────────────────────────────────────────

pub struct GoHardcodedSecrets;

impl LangRule for GoHardcodedSecrets {
    fn id(&self) -> &str { "GO-SEC-004" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)password\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded password"),
            (r##"(?i)secret\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded secret"),
            (r##"(?i)api[_-]?key\s*[=:]\s*["'][^'"]{4,}["']"##, "Hardcoded API key"),
            (r##"(?i)token\s*[=:]\s*["'][A-Za-z0-9_\-]{10,}["']"##, "Hardcoded token"),
            (r##"AKIA[A-Z0-9]{16}"##, "AWS Access Key ID"),
            (r##"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"##, "Private key"),
            (r##"eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"##, "JWT token"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let mut replacement = line_text.to_string();

        let key_re = regex::Regex::new(r#"(?i)((?:api[_-]?)?(?:key|secret|password|token|pass(?:word)?))"#).ok()?;
        if let Some(caps) = key_re.captures(&finding.snippet) {
            let key_name = caps.get(1)?.as_str().to_uppercase().replace("-", "_");
            if replacement.contains("=\"") {
                replacement = regex::Regex::new(r##""[^"]*""##)
                    .ok()?
                    .replace(&replacement, &format!("os.Getenv(\"{}\") // FIXME: Set {} env var", key_name, key_name))
                    .to_string();
            }
            return Some(LangFix {
                rule_id: self.id().to_string(),
                original: line_text.to_string(),
                replacement,
                start_byte: 0,
                end_byte: 0,
                description: format!("Replace hardcoded {} with os.Getenv", key_name),
            });
        }
        None
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─── GO-SEC-005: YAML Unsafe Load ─────────────────────────────────────────────

pub struct GoYamlUnsafeLoad;

impl LangRule for GoYamlUnsafeLoad {
    fn id(&self) -> &str { "GO-SEC-005" }
    fn name(&self) -> &str { "YAML Unsafe Load" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"gopkg\.in\/yaml\.v[0-9]+\.Unmarshal\s*\([^,]+,\s*\[\]byte"##, "yaml.Unmarshal to []byte - may need strict: false"),
            (r##"yaml\.Unmarshal\s*\([^,)]+,\s*["'][^{]"##, "yaml.Unmarshal with no type restriction"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-006: Insecure TLS ─────────────────────────────────────────────────

pub struct GoInsecureTls;

impl LangRule for GoInsecureTls {
    fn id(&self) -> &str { "GO-SEC-006" }
    fn name(&self) -> &str { "Insecure TLS Configuration" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"InsecureSkipVerify\s*:\s*true"##, "InsecureSkipVerify = true (disables TLS verification)"),
            (r##"TLSClientConfig\s*:\s*\&tls\.Config\{[^}]*InsecureSkipVerify:\s*true"##, "TLS config with InsecureSkipVerify"),
            (r##"MinVersion\s*:\s*tls\.VersionTLS10"##, "TLS 1.0 (deprecated)"),
            (r##"MinVersion\s*:\s*tls\.VersionTLS11"##, "TLS 1.1 (deprecated)"),
            (r##"TLS\s*:\s*\&tls\.Config\{[^}]*\}".*(?i)"InsecureSkipVerify"##, "TLS config with InsecureSkipVerify"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-007: Dangerous Code Evaluation ────────────────────────────────────

pub struct GoEvalPattern;

impl LangRule for GoEvalPattern {
    fn id(&self) -> &str { "GO-SEC-007" }
    fn name(&self) -> &str { "Dangerous Code Evaluation" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"goja\.New\(\)\.Run\s*\("##, "goja (otto) JavaScript eval - dangerous"),
            (r##"otto\.Run\s*\("##, "otto JavaScript eval"),
            (r##"eval\s*\("##, "Direct eval usage"),
            (r##"seesaw\.Eval"##, "Seesaw eval"),
            (r##"gopherjs"##, "GopherJS dynamic code generation"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-008: Debug Mode Enabled ───────────────────────────────────────────

pub struct GoDebugMode;

impl LangRule for GoDebugMode {
    fn id(&self) -> &str { "GO-SEC-008" }
    fn name(&self) -> &str { "Debug Mode Enabled" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"(?i)debug\s*[=:]\s*true"##, "Debug flag set to true"),
            (r##"log\.Fatal[^;]*fmt\.Print"##, "Fatal with Print (error leakage)"),
            (r##"panic\s*\("##, "Panic used (exposes stack trace)"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-009: Server-Side Request Forgery (SSRF) ────────────────────────────

pub struct GoSsrf;

impl LangRule for GoSsrf {
    fn id(&self) -> &str { "GO-SEC-009" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"http\.Get\s*\(\s*["'][^"']*localhost"##, "http.Get with localhost URL"),
            (r##"http\.Get\s*\(\s*["'][^"']*127\.0\.0\.1"##, "http.Get with 127.0.0.1 URL"),
            (r##"http\.DefaultClient\.Do\s*\([^)]*url"##, "http.DefaultClient.Do with user-controlled URL"),
            (r##"http\.NewRequest\s*\([^)]*url"##, "http.NewRequest with user-controlled URL"),
            (r##"http\.Client\{[^}]*Transport\s*:\s*http\.DefaultTransport"##, "http.Client with default transport"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-010: Cross-Site Scripting (XSS) ────────────────────────────────────

pub struct GoXss;

impl LangRule for GoXss {
    fn id(&self) -> &str { "GO-SEC-010" }
    fn name(&self) -> &str { "Cross-Site Scripting (XSS)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"template\.HTML\s*\("##, "template.HTML with unsanitized content"),
            (r##"\.Write\s*\(\s*\[\]byte\s*\(\s*user"##, "Direct []byte write from user input"),
            (r##"\.WriteString\s*\([^)]*request\.FormValue"##, "WriteString with user FormValue"),
            (r##"\.WriteString\s*\([^)]*request\.PostFormValue"##, "WriteString with user PostFormValue"),
            (r##"html\.Template.*\.ParseFiles"##, "HTML template parse - verify .CSS and .JS escaping"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-011: Unsafe Reflection ────────────────────────────────────────────

pub struct GoUnsafeReflection;

impl LangRule for GoUnsafeReflection {
    fn id(&self) -> &str { "GO-SEC-011" }
    fn name(&self) -> &str { "Unsafe Reflection" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"reflect\.ValueOf\s*\(\s*user"##, "reflect.ValueOf with user input"),
            (r##"reflect\.Zero\s*\(\s*reflect\.TypeOf"##, "reflect.Zero without type validation"),
            (r##"\.Interface\s*\(\s*\)"##, "Interface() may bypass type safety"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-012: Weak Cryptography ────────────────────────────────────────────
pub struct GoWeakCrypto;

impl LangRule for GoWeakCrypto {
    fn id(&self) -> &str { "GO-SEC-012" }
    fn name(&self) -> &str { "Weak Cryptography" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"md5\.New\(\)"##, "MD5 hash - insecure for cryptographic use"),
            (r##"sha1\.New\(\)"##, "SHA1 hash - deprecated for security purposes"),
            (r##"des\.NewCipher\("##, "DES cipher - insecure (56-bit key)"),
            (r##"rc4\.NewCipher\("##, "RC4 cipher - deprecated and broken"),
            (r##"rsa\.GenerateKey\([^,]*512"##, "RSA with 512-bit key - trivially breakable"),
            (r##"crypto\/md5"##, "MD5 import - use SHA-256 instead"),
            (r##"crypto\/sha1"##, "SHA1 import - consider SHA-256"),
            (r##"math\/rand"##, "math/rand - use crypto/rand instead"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn fix(&self, finding: &LangFinding, code: &str) -> Option<LangFix> {
        let line_text = code.lines().nth(finding.line - 1)?;
        let mut replacement = line_text.to_string();
        let snippet = &finding.snippet;

        if snippet.contains("md5") {
            replacement = replacement.replace("md5.New()", "sha256.New()");
            replacement = replacement.replace("\"crypto/md5\"", "\"crypto/sha256\"");
        } else if snippet.contains("sha1") {
            replacement = replacement.replace("sha1.New()", "sha256.New()");
            replacement = replacement.replace("\"crypto/sha1\"", "\"crypto/sha256\"");
        } else if snippet.contains("rc4") {
            replacement = replacement.replace("rc4.NewCipher(", "// FIXME: Use AES-GCM instead of RC4");
        } else if snippet.contains("des.NewCipher") {
            replacement = replacement.replace("des.NewCipher(", "// FIXME: Use AES.NewCipher(");
        } else if snippet.contains("math/rand") {
            replacement = replacement.replace("math/rand", "crypto/rand");
        } else {
            return None;
        }

        Some(LangFix {
            rule_id: self.id().to_string(),
            original: line_text.to_string(),
            replacement,
            start_byte: 0,
            end_byte: 0,
            description: "Replace weak cryptographic algorithm with secure alternative".to_string(),
        })
    }

    fn supports_auto_fix(&self) -> bool { true }
}

// ─── GO-SEC-013: Insecure Random Number Generation ──────────────────────────────
pub struct GoInsecureRandom;

impl LangRule for GoInsecureRandom {
    fn id(&self) -> &str { "GO-SEC-013" }
    fn name(&self) -> &str { "Insecure Random Number Generation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"math\/rand\.New\s*\(\s*rand\.Source"##, "math/rand with default Source (predictable)"),
            (r##"math\/rand\.Intn\("##, "math/rand.Int - predictable for security-sensitive use"),
            (r##"math\/rand\.Int63n\("##, "math/rand.Int63n - predictable"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-014: Unsafe XML Parsing (XXE) ─────────────────────────────────────

pub struct GoUnsafeXml;

impl LangRule for GoUnsafeXml {
    fn id(&self) -> &str { "GO-SEC-014" }
    fn name(&self) -> &str { "Unsafe XML Parsing (XXE)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"xml\.Unmarshal\s*\("##, "xml.Unmarshal - verify DTD parsing is disabled"),
            (r##"xml\.NewDecoder\s*\([^)]*\)\.Decode"##, "xml.NewDecoder.Decode - check for DTD settings"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-015: Cgo Security Risk ────────────────────────────────────────────

pub struct GoCgoSecurity;

impl LangRule for GoCgoSecurity {
    fn id(&self) -> &str { "GO-SEC-015" }
    fn name(&self) -> &str { "Cgo Security Risk" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"#cgo\s+CFLAGS\s*:"##, "Cgo with custom CFLAGS - verify safety"),
            (r##"#cgo\s+LDFLAGS\s*:"##, "Cgo with custom LDFLAGS - verify linked libraries"),
            (r##"#include\s*<stdio\.h>"##, "Cgo including stdio - potential command injection"),
            (r##"#include\s*<stdlib\.h>"##, "Cgo including stdlib - potential memory issues"),
            (r##"#include\s*<unistd\.h>"##, "Cgo including unistd - system call exposure"),
            (r##"C\.String\s*\("##, "C.String - verify input is sanitized"),
            (r##"C\.GoString\s*\("##, "C.GoString - verify memory ownership"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-AI-001: Slopsquatting (AI-Hallucinated Dependencies) ─────────────────

pub struct GoSlopsquatting;

impl LangRule for GoSlopsquatting {
    fn id(&self) -> &str { "GO-AI-001" }
    fn name(&self) -> &str { "AI-Hallucinated Dependency (Slopsquatting)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let hallucinated: Vec<&str> = vec![
            "go-faker", "gonify", "gojson", "fauxauth", "mockhttp", "go-mocky",
            "gcp-utils-pro", "aws-sdk-go-fake", "k8s-fake-client", "db-fake-driver",
        ];
        for imp in &tree.imports {
            for fake in &hallucinated {
                if imp.module.contains(fake) {
                    let line = imp.start_line;
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: imp.module.clone(),
                        problem: format!(
                            "Slopsquatting Risk: The package '{}' appears to be a hallucinated name.", imp.module
                        ),
                        fix_hint: "Verify this package exists on pkg.go.dev before installing.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-AI-002: Verbose Error Exposure ────────────────────────────────────────

pub struct GoVerboseError;

impl LangRule for GoVerboseError {
    fn id(&self) -> &str { "GO-AI-002" }
    fn name(&self) -> &str { "Verbose Error Exposure" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"log\.Fatalf\s*\([^)]*\%v"##, "log.Fatalf exposing error details"),
            (r##"log\.Printf\s*\([^)]*err\.Error\(\)"##, "log.Printf exposing full error message"),
            (r##"fmt\.Printf\s*\([^)]*err\.Error\(\)"##, "fmt.Printf exposing full error"),
            (r##"w\.Write\s*\(\s*\[\]byte\s*\(\s*err\."##, "Direct error written to HTTP response"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-AI-003: Missing Input Validation ──────────────────────────────────────

pub struct GoMissingInputValidation;

impl LangRule for GoMissingInputValidation {
    fn id(&self) -> &str { "GO-AI-003" }
    fn name(&self) -> &str { "Missing Input Validation" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"request\.FormValue\s*\([^)]+\)\s*(?!.*regexp)(?!.*validate)"##, "FormValue without validation"),
            (r##"request\.Body\s*==\s*nil"##, "Direct nil check on request body"),
            (r##"json\.Unmarshal\s*\([^)]*nil"##, "json.Unmarshal into nil (ignores errors)"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-AI-004: AI-Generated Code Marker ──────────────────────────────────────

pub struct GoAiGenComment;

impl LangRule for GoAiGenComment {
    fn id(&self) -> &str { "GO-AI-004" }
    fn name(&self) -> &str { "AI-Generated Code Marker" }
    fn severity(&self) -> &'static str { "info" }

    fn detect(&self, tree: &LnAst, _code: &str) -> Vec<LangFinding> {
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
                        let line = comment.start_line;
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: 0,
                            end_byte: 0,
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

// ─── All Go Rules ─────────────────────────────────────────────────────────────

/// Get all Go language rules.
pub fn go_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(GoCommandInjection),
        Box::new(GoSqlInjection),
        Box::new(GoPathTraversal),
        Box::new(GoHardcodedSecrets),
        Box::new(GoYamlUnsafeLoad),
        Box::new(GoInsecureTls),
        Box::new(GoEvalPattern),
        Box::new(GoDebugMode),
        Box::new(GoSsrf),
        Box::new(GoXss),
        Box::new(GoUnsafeReflection),
        Box::new(GoWeakCrypto),
        Box::new(GoInsecureRandom),
        Box::new(GoUnsafeXml),
        Box::new(GoCgoSecurity),
        Box::new(GoSlopsquatting),
        Box::new(GoVerboseError),
        Box::new(GoMissingInputValidation),
        Box::new(GoAiGenComment),
    ]
}
