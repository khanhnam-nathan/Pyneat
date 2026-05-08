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
use regex::Regex;

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

fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines().nth(line.saturating_sub(1)).map(|l| l.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-SEC-034: Insecure Deserialization
// Severity: critical | CWE-502
// AI deserializes untrusted data with unsafe Go serialization formats
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoInsecureDeser;

impl LangRule for GoInsecureDeser {
    fn id(&self) -> &str { "GO-SEC-034" }
    fn name(&self) -> &str { "Insecure Deserialization" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_imports = ["encoding/gob", "github.com/ugorji/go/codec", "github.com/pelletier/go-toml"];

        let has_dangerous = tree.imports.iter().any(|imp| {
            dangerous_imports.iter().any(|d| imp.module.contains(d))
        });

        if !has_dangerous {
            return findings;
        }

        let user_input_patterns = ["request", "input", "r.FormValue", "r.Form", "r.PostForm", "io.ReadAll", "ioutil.ReadAll"];

        let dangerous_patterns: Vec<(&str, &str)> = vec![
            // gob deserialization
            (r#"gob\.NewDecoder\s*\([^)]*\)\.Decode\s*\(\s*&"#,
             "gob decode — insecure deserialization format"),
            (r#"gob\.Register\s*\(\s*\)"#, "gob.Register called — dynamic type registration"),

            // ugorji/go/codec
            (r#"codec\.NewDecoder\s*\([^)]*ioutil\.ReadAll|io\.ReadAll"#, "codec.NewDecoder with full reader — user input deserialization"),
            (r#"codec\.NewDecoder\s*\([^)]*r\."#, "codec.NewDecoder reading from request — user input deserialization"),

            // go-toml unsafe
            (r#"toml\.Load\s*\([^)]*request|input|FormValue|Body"#, "toml.Load with user input — potential deserialization risk"),
            (r#"toml\. Unmarshal\s*\([^)]*request|input|Body"#, "toml.Unmarshal with user input"),

            // generic unsafe deserialization patterns
            (r#"encoding\/json\.NewDecoder\s*\([^)]*io\.ReadAll\s*\([^)]*request"#, "JSON decoder reading request body directly"),
            (r#"json\.Decoder.*\.Decode\s*\(\s*&[A-Z]"#, "JSON decode into struct from unvalidated source"),
        ];

        let has_user_input = tree.calls.iter().any(|call| {
            user_input_patterns.iter().any(|p| call.callee.contains(p))
        });

        if !has_user_input {
            return findings;
        }

        for (pattern, desc) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
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
                            "Insecure deserialization: {}. CWE-502: Deserializing untrusted data \
                            can lead to remote code execution, type confusion, or denial of service.",
                            desc
                        ),
                        fix_hint: "Never deserialize untrusted data with gob encoding. Use JSON with \
                            explicit type constraints, or use a safe serialization format. For TOML, \
                            use toml.NewDecoder() with validation. Validate schema and bounds before \
                            deserializing into structs.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
                        replacement: String::new(),
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
                        replacement: String::new(),
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

// ─── GO-SEC-016: SQL Injection in GORM ─────────────────────────────────────────

pub struct GoGormSqlInjection;

impl LangRule for GoGormSqlInjection {
    fn id(&self) -> &str { "GO-SEC-016" }
    fn name(&self) -> &str { "SQL Injection in GORM" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"db\.Raw\s*\(\s*fmt\.Sprintf"##, "db.Raw with fmt.Sprintf - SQL injection risk"),
            (r##"db\.Exec\s*\(\s*fmt\.Sprintf"##, "db.Exec with fmt.Sprintf - SQL injection risk"),
            (r##"gorm\.Open\s*\([^)]*\)\s*\n[^)]*\.Raw\s*\(\s*fmt\.Sprintf"##, "GORM Raw with fmt.Sprintf"),
            (r##"db\.Query\s*\(\s*fmt\.Sprintf"##, "db.Query with fmt.Sprintf - SQL injection risk"),
            (r###".Scopes\s*\(\s*func\s*\([^)]*\)\s*\*gorm\.DB\s*\)".*(?i)"Raw""###, "GORM Scopes with Raw SQL"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-017: Race Condition ────────────────────────────────────────────────

pub struct GoRaceCondition;

impl LangRule for GoRaceCondition {
    fn id(&self) -> &str { "GO-SEC-017" }
    fn name(&self) -> &str { "Race Condition - Shared Map Access" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"map\[string\]\s+\w+\s*=\s*make\s*\(\s*map"##, "Shared map without mutex protection"),
            (r##"var\s+\w+\s+map\["##, "Global map accessed without sync"),
            (r##"sync\.Mutex"##, "Check mutex usage near map access"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }

        let map_access_re = Regex::new(r"(?m)^\s*(\w+)\[|^+\s*]=\s*").unwrap();
        let mutex_re = Regex::new(r"sync\.(Mutex|RWMutex)").unwrap();
        let has_mutex = mutex_re.is_match(code);

        if !has_mutex {
            for m in map_access_re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;
                let line_text = get_line_text(code, line).unwrap_or_default();
                if line_text.contains("map[") || line_text.contains("[") && line_text.contains("] =") {
                    findings.push(LangFinding {
                        rule_id: self.id().to_string(),
                        severity: self.severity().to_string(),
                        line,
                        column: 0,
                        start_byte: 0,
                        end_byte: 0,
                        snippet: line_text.trim().to_string(),
                        problem: "Map access detected without mutex protection. Concurrent map access causes race condition.".to_string(),
                        fix_hint: "Protect map access with sync.Mutex or sync.RWMutex. For high-concurrency code, consider sync.Map or a concurrent data structure.".to_string(),
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

// ─── GO-SEC-018: Missing Context Deadline ──────────────────────────────────────

pub struct GoMissingContextDeadline;

impl LangRule for GoMissingContextDeadline {
    fn id(&self) -> &str { "GO-SEC-018" }
    fn name(&self) -> &str { "Missing Context Deadline" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"http\.Get\s*\(\s*[^)]+\)\s*(?!\s*,)"##, "http.Get without timeout context"),
            (r##"http\.Post\s*\(\s*[^)]+\)\s*(?!\s*,)"##, "http.Post without timeout context"),
            (r##"http\.DefaultClient\.Do\s*\(\s*req\s*\)\s*(?!\s*,)"##, "http.DefaultClient.Do without timeout"),
            (r##"db\.Query\s*\(\s*[^)]+\)\s*(?!\s*,)"##, "DB Query without context"),
            (r##"db\.Exec\s*\(\s*[^)]+\)\s*(?!\s*,)"##, "DB Exec without context"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-019: Regex DoS (ReDoS) ─────────────────────────────────────────────

pub struct GoRegexDos;

impl LangRule for GoRegexDos {
    fn id(&self) -> &str { "GO-SEC-019" }
    fn name(&self) -> &str { "Regex Denial of Service (ReDoS)" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\*regexp\.Regexp|\bregexp\.(Must)?Compile"##, "Regexp compilation - check pattern for nested quantifiers"),
            (r##"\.\+\.\+|\(\.\+\)\+|a\+"##, "Nested quantifiers - potential catastrophic backtracking"),
            (r##"\.\*\.\*|\(\.\*\)\*|a\*"##, "Nested * quantifiers - catastrophic backtracking"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-020: Integer Overflow / Wraparound ────────────────────────────────

pub struct GoIntegerOverflow;

impl LangRule for GoIntegerOverflow {
    fn id(&self) -> &str { "GO-SEC-020" }
    fn name(&self) -> &str { "Integer Overflow Risk" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"\b\d+\s*[\+\-\*]\s*\d+"##, "Arithmetic operation without bounds check"),
            (r##"int\([^)]*\)\s*[\+\-\*]\s*\d+"##, "int conversion with arithmetic"),
            (r##"uint\([^)]*\)\s*[\+\-\*]\s*\d+"##, "uint conversion with arithmetic"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-021: SSRF - Internal Metadata ──────────────────────────────────────

pub struct GoSsrfInternal;

impl LangRule for GoSsrfInternal {
    fn id(&self) -> &str { "GO-SEC-021" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF) - Internal Metadata" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"169\.254\.169\.254"##, "AWS EC2 metadata endpoint"),
            (r##"metadata\.google\.internal"##, "GCP metadata endpoint"),
            (r##"metadata\.azure\.com"##, "Azure metadata endpoint"),
            (r##"kubernetes\.docker\.internal"##, "Kubernetes internal API"),
            (r##"host\.docker\.internal"##, "Docker host from container"),
            (r##"127\.0\.0\.1:\s*2375|2376"##, "Docker daemon port exposure"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-022: Command Injection - shell=True ──────────────────────────────

pub struct GoCommandInjectionShell;

impl LangRule for GoCommandInjectionShell {
    fn id(&self) -> &str { "GO-SEC-022" }
    fn name(&self) -> &str { "Command Injection via Shell Operators" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"exec\.Command\s*\(\s*"sh"\s*,\s*"-c"\s*,\s*"##, "exec.Command with shell -c and string arg"),
            (r##"exec\.Command\s*\(\s*"bash"\s*,\s*"-c"\s*,\s*"##, "exec.Command with bash -c and string arg"),
            (r##"`[^`]*\$\([^)]+\)`"##, "Backtick command with command substitution"),
            (r##"os/exec\.Command.*fmt\.Sprintf"##, "Command constructed via fmt.Sprintf"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-023: SSRF - Deep Check ────────────────────────────────────────────

pub struct GoSsrfDeep;

impl LangRule for GoSsrfDeep {
    fn id(&self) -> &str { "GO-SEC-023" }
    fn name(&self) -> &str { "Server-Side Request Forgery (SSRF) - Deep Check" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let http_calls_with_user_input: Vec<(&str, &str)> = vec![
            // http.Get with user input
            (r##"http\.Get\s*\([^)]*r\.URL\.Query\(\)"##, "http.Get with r.URL.Query() - potential SSRF"),
            (r##"http\.Get\s*\([^)]*r\.URL\.Path\(\)"##, "http.Get with r.URL.Path() - potential SSRF"),
            (r##"http\.Get\s*\([^)]*FormValue"##, "http.Get with FormValue - potential SSRF"),
            (r##"http\.Get\s*\([^)]*\.Query\s*\("##, "http.Get with query.Get() - potential SSRF"),
            (r##"http\.Get\s*\([^)]*RequestURI"##, "http.Get with RequestURI - SSRF vulnerability"),
            (r##"http\.Get\s*\([^)]*\.Host"##, "http.Get with r.Host - SSRF risk"),
            // http.Post with user input
            (r##"http\.Post\s*\([^)]*r\.URL\.Query\(\)"##, "http.Post with r.URL.Query() - potential SSRF"),
            (r##"http\.Post\s*\([^)]*r\.URL\.Path\(\)"##, "http.Post with r.URL.Path() - potential SSRF"),
            (r##"http\.Post\s*\([^)]*FormValue"##, "http.Post with FormValue - potential SSRF"),
            (r##"http\.Post\s*\([^)]*PostFormValue"##, "http.Post with PostFormValue - SSRF risk"),
            (r##"http\.Post\s*\([^)]*\.Form\["##, "http.Post with r.Form[] - SSRF risk"),
            // httpClient.Do with user input
            (r##"httpClient\.Do\s*\([^)]*r\.URL\.Query\(\)"##, "httpClient.Do with user-controlled URL"),
            (r##"httpClient\.Do\s*\([^)]*FormValue"##, "httpClient.Do with FormValue - SSRF risk"),
            // httpClient.Get with user input
            (r##"httpClient\.Get\s*\([^)]*r\.URL\.Query\(\)"##, "httpClient.Get with r.URL.Query() - SSRF"),
            (r##"httpClient\.Get\s*\([^)]*FormValue"##, "httpClient.Get with FormValue - SSRF"),
            // httpClient.Post with user input
            (r##"httpClient\.Post\s*\([^)]*r\.URL\.Path\(\)"##, "httpClient.Post with r.URL.Path() - SSRF"),
            (r##"httpClient\.Post\s*\([^)]*PostFormValue"##, "httpClient.Post with PostFormValue - SSRF"),
            // http.DefaultClient with user input
            (r##"http\.DefaultClient\.Get\s*\([^)]*FormValue"##, "http.DefaultClient.Get with FormValue - SSRF"),
            (r##"http\.DefaultClient\.Post\s*\([^)]*r\.Form\["##, "http.DefaultClient.Post with r.Form[] - SSRF"),
            // params["url"] pattern
            (r##"http\.Get\s*\([^)]*params\s*\[\s*["']url["']\s*\]"##, "http.Get with params[\"url\"] - SSRF"),
            (r##"http\.Post\s*\([^)]*params\s*\[\s*["']url["']\s*\]"##, "http.Post with params[\"url\"] - SSRF"),
        ];

        for (pat, desc) in &http_calls_with_user_input {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }

        // Internal IP detection in URL literals
        let internal_ip_patterns: Vec<(&str, &str)> = vec![
            // AWS metadata
            (r##"["'][^"']*169\.254\.169\.254[^"']*["']"##, "URL contains AWS metadata endpoint 169.254.169.254 - SSRF"),
            // Loopback
            (r##"["'][^"']*127\.0\.0\.1[^"']*["']"##, "URL contains localhost IP 127.0.0.1 - SSRF"),
            (r##"["'][^"']*localhost[^"']*["']"##, "URL contains localhost - SSRF"),
            // Private Class A (10.0.0.0/8)
            (r##"["'][^"']*10\.\d{1,3}\.\d{1,3}\.\d{1,3}[^"']*["']"##, "URL contains 10.x.x.x private IP range - SSRF"),
            // Private Class B (172.16.0.0/12)
            (r##"["'][^"']*172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}[^"']*["']"##, "URL contains 172.16-31.x.x private IP - SSRF"),
            // Private Class C (192.168.0.0/16)
            (r##"["'][^"']*192\.168\.\d{1,3}\.\d{1,3}[^"']*["']"##, "URL contains 192.168.x.x private IP - SSRF"),
        ];

        for (pat, desc) in &internal_ip_patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-SEC-024: Weak JWT Verification ────────────────────────────────────────

pub struct GoWeakJwt;

impl LangRule for GoWeakJwt {
    fn id(&self) -> &str { "GO-SEC-024" }
    fn name(&self) -> &str { "Weak JWT Verification" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r##"jwt\.Parse\s*\([^)]*,\s*nil"##, "jwt.Parse with nil key - no signature verification"),
            (r##"jwt\.Parse\s*\([^)]*,\s*\[\]byte\s*\(\s*""##, "jwt.Parse with empty byte slice as key"),
            (r##"jwt\.Parse\s*\([^)]*,\s*\[\]byte\s*\(\s*"secret"\s*\)"##, "jwt.Parse with weak 'secret' key"),
            (r##"jwt\.Parse\s*\([^)]*,\s*\[\]byte\s*\(\s*"password"\s*\)"##, "jwt.Parse with 'password' key"),
            (r##"jwt\.ParseWithClaims\s*\([^)]*,\s*nil"##, "jwt.ParseWithClaims with nil keyfunc"),
            (r##"jwt\.WithValidator\s*\([^)]*Keyfunc:\s*func"##, "jwt.WithValidator with keyfunc - verify it returns valid key"),
            (r##"SigningKey:\s*\[\]byte\s*\(\s*""##, "JWT signing with empty key"),
            (r##"SigningKey:\s*\[\]byte\s*\(\s*"secret"\s*\)"##, "JWT signing with weak 'secret' key"),
            (r##"SigningKey:\s*\[\]byte\s*\(\s*"password"\s*\)"##, "JWT signing with 'password' key"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─── GO-AI-005: Slopsquatting Typo Detection ──────────────────────────────────

pub struct GoSlopsquattingTypo;

impl LangRule for GoSlopsquattingTypo {
    fn id(&self) -> &str { "GO-AI-005" }
    fn name(&self) -> &str { "Typo-Squatted Go Package Import" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let typo_patterns: Vec<(&str, &str, &str)> = vec![
            // fmt typos
            (r##""fnt""##, "fmt", "Possible typo-squat of 'fmt' package"),
            (r##""fmpt""##, "fmt", "Possible typo-squat of 'fmt' package"),
            (r##""f\.mt""##, "fmt", "Possible typo-squat of 'fmt' package"),
            (r##""fmtm""##, "fmt", "Possible typo-squat of 'fmt' package"),
            // net/http typos
            (r##""net/htp""##, "net/http", "Possible typo-squat of 'net/http' package"),
            (r##""net/htpp""##, "net/http", "Possible typo-squat of 'net/http' package"),
            (r##""net/htp""##, "net/http", "Possible typo-squat of 'net/http' package"),
            // io/ioutil typos
            (r##""io/iutl""##, "io/ioutil", "Possible typo-squat of 'io/ioutil' package"),
            (r##""io/ioutl""##, "io/ioutil", "Possible typo-squat of 'io/ioutil' package"),
            (r##""io/iutil""##, "io/ioutil", "Possible typo-squat of 'io/ioutil' package"),
            // os/exec typos
            (r##""os/exc""##, "os/exec", "Possible typo-squat of 'os/exec' package"),
            (r##""os/exce""##, "os/exec", "Possible typo-squat of 'os/exec' package"),
            // database/sql typos
            (r##""databse/sql""##, "database/sql", "Possible typo-squat of 'database/sql' package"),
            (r##""database/sgl""##, "database/sql", "Possible typo-squat of 'database/sql' package"),
            // github.com typos
            (r##""githb\.com""##, "github.com", "Possible typo-squat of 'github.com' domain"),
            (r##""githu\.com""##, "github.com", "Possible typo-squat of 'github.com' domain"),
            (r##""github\.con""##, "github.com", "Possible typo-squat of 'github.com' domain"),
            (r##""guthub\.com""##, "github.com", "Possible typo-squat of 'github.com' domain"),
            (r##""gihub\.com""##, "github.com", "Possible typo-squat of 'github.com' domain"),
            // golang.org typos
            (r##""golang\.or""##, "golang.org", "Possible typo-squat of 'golang.org' domain"),
            (r##""golng\.org""##, "golang.org", "Possible typo-squat of 'golang.org' domain"),
            // uber.org/zap typos
            (r##""uber\.org/zpa""##, "uber.org/zap", "Possible typo-squat of 'uber.org/zap' package"),
            (r##""uber\.org/zqp""##, "uber.org/zap", "Possible typo-squat of 'uber.org/zap' package"),
        ];

        for (pattern, _canonical, desc) in &typo_patterns {
            if let Ok(re) = Regex::new(pattern) {
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
                        problem: format!("Slopsquatting Risk: {}", desc),
                        fix_hint: "Verify this package exists on pkg.go.dev before using.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Check for typosquatting keywords combined with known package patterns
        let keyword_patterns: Vec<(&str, &str)> = vec![
            (r##"github\.com/[^/]*/(typo|demo|test|lib|utils|helper)"##, "github.com with typosquatting keyword"),
            (r##"golang\.org/[^/]*/(typo|demo|test|lib|utils|helper)"##, "golang.org with typosquatting keyword"),
        ];

        for (pattern, desc) in &keyword_patterns {
            if let Ok(re) = Regex::new(pattern) {
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
                        problem: format!("Slopsquatting Risk: {} in import path", desc),
                        fix_hint: "Verify this package exists on pkg.go.dev before using.".to_string(),
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

// ─── GO-AI-006: Missing Nil Check After Marshal ──────────────────────────────

pub struct GoMissingNilCheckAfterMarshal;

impl LangRule for GoMissingNilCheckAfterMarshal {
    fn id(&self) -> &str { "GO-AI-006" }
    fn name(&self) -> &str { "Missing Nil Check After JSON Marshal/Unmarshal" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern 1: json.Unmarshal followed by direct field access without nil check
        let unmarshal_patterns: Vec<(&str, &str)> = vec![
            (r##"json\.Unmarshal\s*\([^)]*,\s*&\w+\s*\)"##, "json.Unmarshal call detected"),
            (r##"json\.NewDecoder\s*\([^)]*\)\.Decode\s*\(&"##, "json.NewDecoder.Decode call detected"),
        ];

        // Check for field access patterns that might be dangerous after Unmarshal
        let field_access_patterns = [
            (r##"\.\w+\s*=="##, "Field comparison after unmarshal"),
            (r##"\.\w+\s*!="##, "Field comparison after unmarshal"),
            (r##"if\s*\(\s*\w+\.\w+\s*\)"##, "Direct field check after unmarshal"),
        ];

        for (unmarshal_pattern, unmarshal_desc) in &unmarshal_patterns {
            if let Ok(re) = Regex::new(unmarshal_pattern) {
                for m in re.find_iter(code) {
                    let unmarshal_line = get_line_from_byte(code, m.start());
                    let unmarshal_context = &code[m.start()..];
                    let next_500 = &unmarshal_context[..unmarshal_context.len().min(500)];

                    // Check if there's a field access within the next few lines without an explicit nil/err check
                    let has_error_check = next_500.contains("if err != nil");
                    let has_nil_check = next_500.contains("== nil") || next_500.contains("!= nil");

                    if !has_error_check && !has_nil_check {
                        // Look for field access patterns
                        for (access_pattern, access_desc) in &field_access_patterns {
                            if let Ok(access_re) = Regex::new(access_pattern) {
                                if access_re.is_match(next_500) {
                                    let (start, end) = get_line_offsets(code, unmarshal_line);
                                    findings.push(LangFinding {
                                        rule_id: self.id().to_string(),
                                        severity: self.severity().to_string(),
                                        line: unmarshal_line,
                                        column: 0,
                                        start_byte: start,
                                        end_byte: end,
                                        snippet: m.as_str().to_string(),
                                        problem: format!("Missing nil/error check after JSON operations: {}", unmarshal_desc),
                                        fix_hint: "Always check the error return from json.Unmarshal before accessing fields. Example: if err := json.Unmarshal(data, &obj); err != nil { return err }. Verify obj is not nil before accessing fields.".to_string(),
                                        auto_fix_available: false,
                        replacement: String::new(),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Pattern 2: json.Marshal followed by use without error check
        let marshal_patterns: Vec<(&str, &str)> = vec![
            (r##"json\.Marshal\s*\([^)]+\s*\)\s*(?!\s*if)"##, "json.Marshal without immediate error check"),
            (r##"json\.MarshalIndent\s*\([^)]+\s*\)\s*(?!\s*if)"##, "json.MarshalIndent without immediate error check"),
        ];

        for (pattern, desc) in &marshal_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
                    let context = &code[m.start()..];
                    let next_300 = &context[..context.len().min(300)];

                    // Check if error is checked in the same statement
                    if !next_300.contains("err != nil") && !next_300.contains("_,") && !next_300.contains("_, err") {
                        let (start, end) = get_line_offsets(code, line);
                        findings.push(LangFinding {
                            rule_id: self.id().to_string(),
                            severity: self.severity().to_string(),
                            line,
                            column: 0,
                            start_byte: start,
                            end_byte: end,
                            snippet: m.as_str().to_string(),
                            problem: format!("Missing error check after JSON marshal: {}", desc),
                            fix_hint: "Always check the error return from json.Marshal. Example: data, err := json.Marshal(v); if err != nil { return err }".to_string(),
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

// ─── GO-AI-007: Off-by-one in Loop Bounds ───────────────────────────────────

pub struct GoOffByOneLoopBounds;

impl LangRule for GoOffByOneLoopBounds {
    fn id(&self) -> &str { "GO-AI-007" }
    fn name(&self) -> &str { "Off-by-one in Loop Bounds" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern 1: for i := 0; i <= len(arr); i++ (should be < not <=)
        let offbyone_patterns: Vec<(&str, &str)> = vec![
            (r##"for\s+\w+\s*:=\s*0\s*;\s*\w+\s*<=\s*len\("##, "Loop uses <= with len() (off-by-one: should be <)"),
            (r##"for\s+\w+\s*:=\s*0\s*;\s*\w+\s*<\s*len\([^)]+\)\s*\+\s*1"##, "Loop uses < len() + 1 (off-by-one)"),
            (r##"for\s+\w+\s*:=\s*0\s*;\s*\w+\s*<=\s*len\([^)]+\)\s*\+\s*1"##, "Loop uses <= len() + 1 (definite off-by-one)"),
            (r##"for\s+\w+\s*:=\s*0\s*;\s*\w+\s*<=\s*cap\("##, "Loop uses <= with cap() (off-by-one: should be <)"),
        ];

        // Pattern 2: range with len() in body that suggests off-by-one
        let range_patterns: Vec<(&str, &str)> = vec![
            (r##"for\s+\w+\s*:=\s*range\s+\w+\s*\{[^}]*\[len\("##, "Range loop accessing len() inside (possible off-by-one)"),
        ];

        for (pattern, desc) in &offbyone_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
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
                        problem: format!("Off-by-one in loop bounds: {}", desc),
                        fix_hint: "Use < (strict less than) instead of <= when iterating over array/slice indices. Arrays are 0-indexed, so valid indices are 0 to len-1.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        for (pattern, desc) in &range_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
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
                        problem: format!("Potential off-by-one: {}", desc),
                        fix_hint: "When using range, remember it returns index and value. Check that index access patterns are correct.".to_string(),
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
// GO-CRYPT-001: Insecure TLS Configuration in Go
// Severity: critical | CWE-295, CWE-327
// Detects insecure TLS configuration patterns in Go code
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoInsecureTlsConfig;

impl LangRule for GoInsecureTlsConfig {
    fn id(&self) -> &str { "GO-CRYPT-001" }
    fn name(&self) -> &str { "Insecure TLS Configuration" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let insecure_tls_patterns: Vec<(&str, &str)> = vec![
            // InsecureSkipVerify patterns
            (r##"InsecureSkipVerify\s*:\s*true"##, "InsecureSkipVerify: true - disables TLS certificate verification (MITM vulnerable)"),
            (r##"TLSClientConfig\s*:\s*\&tls\.Config\{[^}]*InsecureSkipVerify\s*:\s*true"##, "TLSClientConfig with InsecureSkipVerify: true"),
            (r##"tls\.Config\s*\{\s*InsecureSkipVerify\s*:\s*true"##, "tls.Config with InsecureSkipVerify: true"),
            (r##"\&tls\.Config\s*\{\s*InsecureSkipVerify\s*:\s*true"##, "&tls.Config with InsecureSkipVerify: true"),
            
            // Deprecated TLS versions
            (r##"MinVersion\s*:\s*tls\.VersionTLS10"##, "MinVersion: tls.VersionTLS10 - TLS 1.0 is deprecated (PCI DSS non-compliant)"),
            (r##"MinVersion\s*:\s*tls\.VersionTLS11"##, "MinVersion: tls.VersionTLS11 - TLS 1.1 is deprecated"),
            (r##"MinVersion\s*:\s*tls\.VersionSSL30"##, "MinVersion: tls.VersionSSL30 - SSL 3.0 is broken (POODLE)"),
            (r##"MaxVersion\s*:\s*tls\.VersionTLS10"##, "MaxVersion: tls.VersionTLS10 - restricts to TLS 1.0 (deprecated)"),
            (r##"MaxVersion\s*:\s*tls\.VersionTLS11"##, "MaxVersion: tls.VersionTLS11 - restricts to TLS 1.1 (deprecated)"),
            
            // Weak cipher suites
            (r##"CipherSuites\s*:\s*\[\]"##, "Empty CipherSuites - uses default weak ciphers"),
            (r##"CurvePreferences\s*:\s*\[\]"##, "Empty CurvePreferences - relies on default (potentially weak) curves"),
            
            // TLS version comparison patterns
            (r##"tlsVersionMinSuite\s*:\s*tls\.TLSVersionSSL30"##, "tlsVersionMinSuite: SSLv3 (POODLE vulnerable)"),
            (r##"tlsVersionMaxSuite\s*:\s*tls\.TLSVersionTLS10"##, "tlsVersionMaxSuite: TLS 1.0 (deprecated)"),
        ];

        for (pat, desc) in &insecure_tls_patterns {
            if let Ok(re) = regex::Regex::new(pat) {
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
                        problem: format!(
                            "Insecure TLS Configuration: {}. CWE-295/CWE-327: This configuration \
                            disables certificate verification or uses deprecated protocols, enabling \
                            man-in-the-middle attacks and exposing encrypted communications.",
                            desc
                        ),
                        fix_hint: "Never set InsecureSkipVerify: true in production. Use TLS 1.2 minimum \
                            (MinVersion: tls.VersionTLS12). Configure strong cipher suites. \
                            Example: &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: [...]}. \
                            For testing only: wrap in feature flag and never use in production.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }

        // Additional check for CurvePreferences missing (weak default curves)
        let has_tls_config = code.contains("tls.Config") || code.contains("tls.ClientConfig");
        let has_curve_preferences = code.contains("CurvePreferences");
        let has_insecure_skip = code.contains("InsecureSkipVerify");
        
        if has_tls_config && !has_curve_preferences && !has_insecure_skip {
            // This is informational - check if TLS is being configured
            let tls_config_pattern = regex::Regex::new(r##"tls\.Config\s*\{"##).unwrap();
            if tls_config_pattern.is_match(code) {
                // Only flag if it's not already flagged with insecure patterns
                let already_flagged = findings.iter().any(|f: &LangFinding| 
                    f.rule_id == "GO-CRYPT-001" && f.line <= 50
                );
                if !already_flagged {
                    // This is a subtle issue - TLS Config without CurvePreferences
                    // Don't add to findings to avoid noise, just log intent
                }
            }
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-SEC-035: GORM Raw Query / Order By Injection
// Severity: critical | CWE-89
// GORM raw methods with string interpolation allow SQL injection
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoGormRawInjection;

impl LangRule for GoGormRawInjection {
    fn id(&self) -> &str { "GO-SEC-035" }
    fn name(&self) -> &str { "SQL Injection (GORM Raw / Order By Injection)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let gorm_imports = ["gorm.io/gorm", "github.com/jinzhu/gorm"];
        let has_gorm = tree.imports.iter().any(|imp| {
            gorm_imports.iter().any(|g| imp.module.contains(g))
        });

        if !has_gorm && !code.contains("gorm") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"\.Raw\s*\([^)]*fmt\.Sprintf|fmt\.Errorf|fmt\.Print"#, "GORM Raw() with fmt.Sprintf — string interpolation SQL risk"),
            (r#"\.Exec\s*\([^)]*\+[^)]*(?:r\.Form|r\.URL|r\.Body|r\.Header|req\.)"#, "GORM Exec() with string concatenation of user input"),
            (r#"\.Order\s*\([^)]*\+[^)]*(?:r\.Form|r\.URL|r\.Body|req\.)"#, "GORM Order() with string concatenation — ORDER BY injection risk"),
            (r#"\.Select\s*\([^)]*\+[^)]*(?:r\.Form|r\.URL|req\.)"#, "GORM Select() with string concatenation — column injection risk"),
            (r#"\.Where\s*\([^)]*fmt\.Sprintf|fmt\.Sprintf[^)]*\+[^)]*\)"#, "GORM Where() with fmt.Sprintf — SQL injection risk"),
            (r#"\.Find\s*\([^)]*fmt\.Sprintf"#, "GORM Find() with fmt.Sprintf — SQL injection risk"),
            (r#"db\.Exec\s*\([^)]*fmt\.Sprintf|fmt\.Sprintf[^)]*\+[^)]*\)"#, "GORM db.Exec() with fmt.Sprintf SQL injection"),
            (r#"gorm\.Raw\s*\([^)]*\+[^)]*(?:r\.Form|r\.URL|req\.)"#, "gorm.Raw with concatenation of user input"),
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
                            "GORM SQL injection: {}. CWE-89: GORM raw query methods with string \
                            interpolation allow attackers to manipulate SQL queries, especially ORDER BY, \
                            GROUP BY, and column names which cannot be parameterized.",
                            desc
                        ),
                        fix_hint: "Never use string concatenation in GORM raw queries. Use parameterized queries: \
                            db.Raw(\"SELECT * FROM users WHERE id = ?\", userID). \
                            For ORDER BY with user input, whitelist: allowedFields := map[string]bool{\"name\":true}; \
                            if !allowedFields[sortField] { return error }; \
                            db.Order(sortField + \" \" + direction);".to_string(),
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
// GO-SEC-036: Insecure Direct Object Reference (IDOR)
// Severity: high | CWE-639
// Resource IDs from user input used directly without ownership verification
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoIdor;

impl LangRule for GoIdor {
    fn id(&self) -> &str { "GO-SEC-036" }
    fn name(&self) -> &str { "Insecure Direct Object Reference (IDOR)" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let web_imports = ["net/http", "github.com/gin-gonic", "github.com/labstack/echo", "github.com/gorilla/mux", "go-chi", "net/rpc"];
        let has_web = tree.imports.iter().any(|imp| {
            web_imports.iter().any(|w| imp.module.contains(w))
        });

        if !has_web && !code.contains("http.HandlerFunc") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"db\.(?:First|Where|Find|Delete|Update)\s*\(\s*&(?:User|Item|Resource|Account)[^)]*\)\s*(?:.*?)?(?:r\.FormValue|r\.URL|r\.Param|r\.Form)\s*\("#, "Database operation with user-provided ID without ownership check"),
            (r#"FirstOrInit|FirstOrCreate|Assign\s*\([^)]*(?:r\.Form|r\.URL|r\.Param)\s*\("#, "GORM FirstOrCreate/Assign with user input — IDOR risk"),
            (r#"ID\s*=\s*(?:r\.FormValue|r\.URL|r\.Param)\s*\([^)]*\).*?db\.(?:First|Update|Delete)\s*\("#, "ID from user input used in database operation without verification"),
            (r#"fmt\.Sprintf\s*\([^)]*%s[^)]*(?:r\.FormValue|r\.URL|r\.Param)"#, "Sprintf with user input in database query"),
            (r#"awsAccessKey\s*=\s*r\.FormValue|awsSecretKey\s*=\s*r\.FormValue"#, "AWS credentials from user input — IDOR can expose cloud resources"),
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
                            "Insecure Direct Object Reference (IDOR): {}. CWE-639: User-supplied object ID \
                            used directly in a database or resource operation without verifying the user \
                            owns or has permission to access that object.",
                            desc
                        ),
                        fix_hint: "Always verify the user has permission to access the requested object: \
                            resource, err := db.First(&obj, id); \
                            if resource.UserID != currentUser.ID { return error }; \
                            Use middleware or service-layer authorization checks.".to_string(),
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
// GO-SEC-037: Command Injection via exec.LookPath / exec.Command
// Severity: critical | CWE-78
// User input passed to command execution without proper validation
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoCommandInjectionLookPath;

impl LangRule for GoCommandInjectionLookPath {
    fn id(&self) -> &str { "GO-SEC-037" }
    fn name(&self) -> &str { "Command Injection (LookPath + exec.Command)" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"exec\.LookPath\s*\([^)]*(?:r\.Form|r\.URL|r\.Param|r\.Body|os\.Args|flag|flag\.Arg)"#, "exec.LookPath with user input — command injection via PATH manipulation"),
            (r#"exec\.Command\s*\([^)]*(?:r\.Form|r\.URL|r\.Param|r\.Body|os\.Args|flag)"#, "exec.Command with user input — command injection risk"),
            (r#"exec\.Command\s*\(\s*(?:r\.FormValue|r\.URL|r\.Param|r\.Body)"#, "exec.Command using user-supplied command name"),
            (r#"syscall\.Exec\s*\([^)]*(?:r\.Form|r\.URL|r\.Param)"#, "syscall.Exec with user input — direct command execution"),
            (r#"os/exec\.Command.*?(?:r\.FormValue|r\.URL\.Query|r\.Param)"#, "os/exec.Command from HTTP request — command injection"),
            (r#"\.Run\s*\(\s*\).*?(?:r\.Form|r\.URL|r\.Param)"#, "Command Run() with user input"),
            (r#"os\.StartProcess\s*\([^)]*(?:r\.Form|r\.URL|r\.Param|flag)"#, "os.StartProcess with user-controlled arguments"),
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
                            "Command injection: {}. CWE-78: User input passed to exec.Command or \
                            exec.LookPath allows attackers to execute arbitrary commands on the host.",
                            desc
                        ),
                        fix_hint: "Never pass user input directly to exec.Command. Use exec.CommandContext \
                            with validated, whitelisted values. Example: allowedCmds := map[string]bool{\"ls\":true}; \
                            if !allowedCmds[cmd] { return error }; \
                            exec.Command(cmd, args...).Run().".to_string(),
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
// GO-SEC-038: HTTP KeepAlive Disabled
// Severity: medium | CWE-910
// Transport.DisableKeepAlives = true causes connection overhead and potential DoS
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHttpKeepAliveDisabled;

impl LangRule for GoHttpKeepAliveDisabled {
    fn id(&self) -> &str { "GO-SEC-038" }
    fn name(&self) -> &str { "HTTP KeepAlive Disabled" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let patterns: Vec<(&str, &str)> = vec![
            (r#"DisableKeepAlives\s*:\s*true"#, "DisableKeepAlives: true — disables HTTP keep-alive (CWE-910)"),
            (r#"transport\s*=\s*&http\.Transport\s*\{[^}]*DisableKeepAlives\s*:\s*true"#, "HTTP Transport with DisableKeepAlives: true"),
            (r#"Client\s*\{\s*Transport\s*:\s*&http\.Transport\s*\{[^}]*DisableKeepAlives\s*:\s*true"#, "HTTP Client with DisableKeepAlives: true"),
        ];
        for (pat, desc) in &patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-SEC-039: HTTP No Timeout
// Severity: medium | CWE-910
// Transport with no timeout can cause resource exhaustion
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHttpNoTimeout;

impl LangRule for GoHttpNoTimeout {
    fn id(&self) -> &str { "GO-SEC-039" }
    fn name(&self) -> &str { "HTTP Request Without Timeout" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for HTTP client without Timeout set
        let no_timeout_patterns: Vec<(&str, &str)> = vec![
            (r#"http\.Client\s*\{\s*\}"#, "Empty http.Client{} — no Timeout configured"),
            (r#"http\.Client\s*\{\s*Transport\s*:"#, "http.Client with Transport but no Timeout"),
            (r#"TLSClientConfig\s*:\s*&tls\.Config\s*\{\s*\}"#, "TLSClientConfig without Timeout (CWE-910)"),
        ];

        for (pat, desc) in &no_timeout_patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }

        // Check for Timeout: 0 patterns
        let zero_timeout_patterns: Vec<(&str, &str)> = vec![
            (r#"Timeout\s*:\s*0\s*[,\}]"#, "Timeout: 0 — no timeout (infinite wait)"),
            (r#"client\.Timeout\s*=\s*0"#, "client.Timeout set to 0"),
        ];

        for (pat, desc) in &zero_timeout_patterns {
            add_finding(&mut findings, self.id(), self.severity(), pat, desc, code);
        }

        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// GO-SEC-040: Go Template Injection
// Severity: critical | CWE-1336
// User input passed to html/template.Parse can cause XSS
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoTemplateInjection;

impl LangRule for GoTemplateInjection {
    fn id(&self) -> &str { "GO-SEC-040" }
    fn name(&self) -> &str { "Go Template Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"template\.New\s*\([^)]*\)\s*\.Parse\s*\([^)]*(?:r\.Form|r\.URL|r\.Body|r\.PostForm|request\.)"#, "template.Parse with user input — template injection (CWE-1336)"),
            (r#"template\.Must\s*\([^)]*template\.New\s*\([^)]*\)\s*\.Parse\s*\([^)]*(?:r\.Form|r\.URL)"#, "template.Must with Parse from user input"),
            (r#"template\.ParseFiles?\s*\([^)]*(?:r\.Form|r\.URL|r\.Param)"#, "template.ParseFiles with user-controlled path"),
            (r#"template\.ParseGlob\s*\([^)]*(?:r\.Form|r\.URL|r\.Param)"#, "template.ParseGlob with user-controlled pattern"),
            (r#"\.Execute\s*\([^)]*,\s*(?:r\.Form|r\.URL|r\.Body)"#, "template.Execute with user data"),
            (r#"text\/template\.(?:New|Must|Parse|ParseFiles)\s*\([^)]*(?:r\.Form|r\.URL|os\.Args|flag)"#, "text/template with user input — potential command injection"),
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
                            "Template injection: {}. CWE-1336: User input passed to template parsing \
                            can lead to XSS or template injection attacks.",
                            desc
                        ),
                        fix_hint: "Never pass unsanitized user input to template.Parse(). Always validate \
                            template paths against a whitelist. For dynamic templates, use a sandboxed engine \
                            or pre-compile templates from trusted sources only.".to_string(),
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
// GO-SEC-041: Host of Death (Unbounded Response Read)
// Severity: high | CWE-400
// Reading full HTTP response without size limit can cause memory exhaustion
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHostOfDeath;

impl LangRule for GoHostOfDeath {
    fn id(&self) -> &str { "GO-SEC-041" }
    fn name(&self) -> &str { "Host of Death - Unbounded Response Read" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"io\.ReadAll\s*\(\s*resp\.Body\s*\)"#, "io.ReadAll on response body — no size limit (CWE-400)"),
            (r#"ioutil\.ReadAll\s*\(\s*resp\.Body\s*\)"#, "ioutil.ReadAll on response body — no size limit"),
            (r#"ioutil\.ReadAll\s*\([^)]*Response\)"#, "ioutil.ReadAll on HTTP response without limit"),
            (r#"io\.Copy\s*\([^,]+,\s*resp\.Body\s*\)"#, "io.Copy with response body — verify destination has limit"),
            (r#"\.Read\s*\(\s*resp\.Body\s*\)"#, "Read from response body — ensure bounded buffer"),
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
                            "Host of Death vulnerability: {}. CWE-400: Unbounded reading of HTTP response \
                            can cause memory exhaustion if server sends massive or infinite data.",
                            desc
                        ),
                        fix_hint: "Use io.LimitReader() to bound response reads: \
                            io.Copy(w, io.LimitReader(resp.Body, 10<<20)). \
                            Set a reasonable max response size (e.g., 10MB) and reject oversized responses.".to_string(),
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
// GO-SEC-042: Constant Math Overflow
// Severity: medium | CWE-682
// Arithmetic operations with all constant operands that could overflow
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoConstantMathOverflow;

impl LangRule for GoConstantMathOverflow {
    fn id(&self) -> &str { "GO-SEC-042" }
    fn name(&self) -> &str { "Constant Math Overflow Risk" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let constant_math_patterns = vec![
            (r#"\b0[xX][0-9a-fA-F]+\s*[\+\-\*]\s*0[xX][0-9a-fA-F]+"#, "Hex constant arithmetic — verify no overflow"),
            (r#"\b\d{10,}\s*[\+\-\*]"#, "Large decimal constant arithmetic — potential overflow"),
            (r#"\b[\+\-]?\d+\s*[\+\-]\s*[\+\-]?\d+\s*[\+\-]\s*[\+\-]?\d+\s*[\+\-]"#, "Chained constant additions — verify bounds"),
            (r#"(?<![\w])[12]\d{9}(?!\d)"#, "Unix timestamp literal — verify time range handling"),
            (r#"\b\d{4,}\s*\*\s*\d{4,}"#, "Large number multiplication — verify overflow check"),
            (r#"int64\s*\([^)]*[0-9]{19,}"#, "int64 cast of very large constant — possible overflow"),
            (r#"uint\s*\([^)]*-[0-9]+"#, "uint cast of negative constant — wraps around"),
        ];

        for (pattern, desc) in &constant_math_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let line = get_line_from_byte(code, m.start());
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
                            "Constant math overflow risk: {}. CWE-682: Operations with all constant operands \
                            may overflow at runtime without warning.",
                            desc
                        ),
                        fix_hint: "Use checked arithmetic or explicit overflow handling. Consider using \
                            big.Int for large numbers. Example: import \"math/big\"; n := new(big.Int).SetString(\"12345678901234567890\", 10)".to_string(),
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
// GO-SEC-043: Multipart Form Boundary Validation
// Severity: medium | CWE-68
// Custom MIME boundary without validation can be exploited
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoMultipartBoundary;

impl LangRule for GoMultipartBoundary {
    fn id(&self) -> &str { "GO-SEC-043" }
    fn name(&self) -> &str { "Multipart Form Boundary Validation Missing" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for multipart imports
        let has_multipart = tree.imports.iter().any(|imp| {
            imp.module.contains("mime/multipart") || imp.module.contains("net/http")
        });

        if !has_multipart && !code.contains("multipart") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"multipart\.NewWriter\s*\([^)]*\)\s*\n[^}]*\.WriteField\s*\("#, "Multipart writer without boundary validation"),
            (r#"r\.ParseMultipartForm\s*\([^)]*\)"#, "ParseMultipartForm — verify size limits"),
            (r#"r\.FormFile\s*\([^)]*\)"#, "FormFile — verify boundary handling"),
            (r#"boundary\s*=\s*["'][^"']{0,20}["']"#, "Short MIME boundary — easier to bypass"),
            (r#"boundary\s*=\s*r\.FormValue|r\.PostFormValue"#, "Boundary from user input — boundary injection (CWE-68)"),
            (r#"mime\.TypeByExtension\s*\([^)]*\)\s*\n[^}]*Content-Type"#, "Content-Type from file extension — verify type"),
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
                            "Multipart boundary issue: {}. CWE-68: Custom or user-controlled MIME boundaries \
                            can be exploited for request smuggling or content-type bypass.",
                            desc
                        ),
                        fix_hint: "Use cryptographically random boundaries (min 16 bytes). \
                            Validate Content-Type before processing. Set ParseMultipartForm max memory limit.".to_string(),
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
// GO-SEC-044: HTTP Request Smuggling
// Severity: high | CWE-444
// Ambiguous HTTP request parsing between proxy and server
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHttpRequestSmuggling;

impl LangRule for GoHttpRequestSmuggling {
    fn id(&self) -> &str { "GO-SEC-044" }
    fn name(&self) -> &str { "HTTP Request Smuggling Vulnerability" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"Transfer-Encoding[^;]*chunked"#, "Transfer-Encoding: chunked — verify proxy handling (CWE-444)"),
            (r#"transfer-encoding[^;]*chunked"#, "transfer-encoding: chunked — ambiguous parsing risk"),
            (r#"r\.Header\.Set\s*\([^)]*["']Transfer-Encoding["']"#, "Setting Transfer-Encoding header — smuggling risk"),
            (r#"r\.Header\.Add\s*\([^)]*["']Transfer-Encoding["']"#, "Adding Transfer-Encoding header"),
            (r#"Content-Length[^:]*:\s*0\s*[^}]*Transfer-Encoding"#, "Both Content-Length and Transfer-Encoding — smuggling"),
            (r#"(?i)Transfer-Encoding[^:]*:\s*gzip|deflate|compress"#, "Transfer-Encoding with unsupported values — proxy confusion"),
            (r#"\.Write\s*\(\s*\[\]byte\s*\(\s*r\.Body\s*\)\s*\)"#, "Forwarding raw body without Content-Length — smuggling"),
            (r#"http\.Write\s*\([^)]*r\s*\)"#, "http.Write with request — verify headers"),
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
                            "HTTP request smuggling: {}. CWE-444: Ambiguous Transfer-Encoding or \
                            Content-Length can cause desync between proxies and servers.",
                            desc
                        ),
                        fix_hint: "Ensure consistent header handling between proxy and server. \
                            Disable Transfer-Encoding when Content-Length is present. \
                            Validate and normalize all HTTP headers before forwarding.".to_string(),
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
// GO-SEC-045: HTTP CORS Misconfiguration
// Severity: medium | CWE-942
// Access-Control-Allow-Origin: * with credentials exposes data
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoCorsMisconfiguration;

impl LangRule for GoCorsMisconfiguration {
    fn id(&self) -> &str { "GO-SEC-045" }
    fn name(&self) -> &str { "CORS Misconfiguration" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"Access-Control-Allow-Origin\s*:\s*["']?\*["']?"#, "Access-Control-Allow-Origin: * — overly permissive (CWE-942)"),
            (r#"Allow\s*\(\s*["']\*["']\s*,.*Credentials"#, "Allowing * with credentials"),
            (r#"w\.Header\(\)\.Set\s*\([^)]*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']"#, "Setting CORS origin to *"),
            (r#"ACAO\s*[=:]\s*["']\*["']"#, "ACAO = * shorthand"),
            (r#"(?i)any\s*\|{2}\s*origin"#, "Allowing any origin dynamically"),
            (r#"\*\.example\.com"#, "Wildcard subdomain CORS — verify intent"),
            (r#"Access-Control-Allow-Credentials\s*:\s*true[^}]*Access-Control-Allow-Origin\s*:\s*\*"#, "Credentials true with origin * — dangerous combination"),
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
                            "CORS misconfiguration: {}. CWE-942: Setting Access-Control-Allow-Origin to * \
                            with credentials allows any website to read sensitive data.",
                            desc
                        ),
                        fix_hint: "Never use '*' with Access-Control-Allow-Credentials: true. \
                            Use specific origins: AllowOrigin: func(origin string) bool { return origin == \"https://trusted.com\" }. \
                            Consider Vary: Origin header for caching.".to_string(),
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
// GO-SEC-046: JWT None Algorithm
// Severity: critical | CWE-347
// JWT library using SigningMethodNone allows unsigned tokens
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoJwtNoneAlgorithm;

impl LangRule for GoJwtNoneAlgorithm {
    fn id(&self) -> &str { "GO-SEC-046" }
    fn name(&self) -> &str { "JWT 'none' Algorithm Vulnerability" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Check for JWT imports
        let jwt_imports = ["github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go", "github.com/pascaldekloe/jwt"];
        let has_jwt = tree.imports.iter().any(|imp| {
            jwt_imports.iter().any(|j| imp.module.contains(j))
        });

        if !has_jwt && !code.contains("jwt") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"SigningMethodNone"#, "SigningMethodNone — JWT with no signature (CWE-347)"),
            (r#"\.Method\s*=\s*jwt\.SigningMethodHS256[^}]*\.Valid\s*=\s*false"#, "Weak JWT validation"),
            (r#"jwt\.WithValidat(or|ion)\s*\([^)]*\)\s*\n[^}]*\.Parse\s*\([^)]*,\s*nil"#, "JWT parsed with nil keyfunc — no verification"),
            (r#"ParseWithClaims\s*\([^)]*,\s*nil\s*,"#, "ParseWithClaims with nil keyfunc"),
            (r#"Parse\s*\([^)]*,\s*nil\s*,"#, "JWT Parse with nil key — no signature check"),
            (r#"jwt\.NewWithClaims\s*\([^)]*\.SigningMethodHMAC"#, "HMAC JWT — verify key strength"),
            (r#"ECDSA256"#, "ECDSA256 — consider ECDSA384/512 or EdDSA"),
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
                            "JWT vulnerability: {}. CWE-347: JWT 'none' algorithm allows attackers \
                            to forge tokens by changing algorithm to 'none' and removing signature.",
                            desc
                        ),
                        fix_hint: "Always specify expected algorithm: parser := jwt.NewParser(jwt.WithValidMethods([]string{\"RS256\"})). \
                            Never accept 'none' algorithm. Validate algorithm matches expected type. \
                            Example: if token.Method.(*jwt.SigningMethodRSA).Algorithm != \"RS256\" { return error }".to_string(),
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
// GO-SEC-047: Basic Auth in URL
// Severity: high | CWE-598
// Credentials embedded in URL are logged and exposed
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoBasicAuthInUrl;

impl LangRule for GoBasicAuthInUrl {
    fn id(&self) -> &str { "GO-SEC-047" }
    fn name(&self) -> &str { "Basic Authentication in URL" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"http\.Get\s*\(\s*["'][^"']*:[^"']*@[^"']*["']"#, "HTTP URL with embedded credentials (CWE-598)"),
            (r#"http\.NewRequest\s*\([^)]*["'][^"']*:[^"']*@[^"']*["']"#, "HTTP request with credentials in URL"),
            (r#"url\.UserPassword"#, "url.UserPassword in URL — credentials exposed"),
            (r#"url\.User\s*\([^)]*\).*\.Password\s*\([^)]*\)"#, "URL with User and Password set"),
            (r#"Parse\s*\([^)]*["'][^"']*:[^"']*@[^"']*["']"#, "URL parsing with embedded credentials"),
            (r#"proxy\s*[=:]\s*["'][^"']*:[^"']*@[^"']*["']"#, "Proxy URL with credentials"),
            (r#"http\.BasicAuth\s*\([^)]*\)"#, "BasicAuth call — verify credentials not logged"),
            (r#"Authorization\s*:\s*Basic[^;]*url\."#, "Authorization header with URL credentials"),
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
                            "Basic auth in URL: {}. CWE-598: Embedding credentials in URLs exposes them \
                            in logs, browser history, and server access logs.",
                            desc
                        ),
                        fix_hint: "Use Authorization header or SetBasicAuth instead: \
                            req.SetBasicAuth(\"user\", \"pass\"). \
                            Use environment variables: os.Getenv(\"API_USER\"), os.Getenv(\"API_PASS\"). \
                            Never log URLs with credentials.".to_string(),
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
// GO-SEC-048: TLS Weak Cipher Suites
// Severity: high | CWE-327
// TLS configuration using weak or deprecated cipher suites
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoTlsWeakCipher;

impl LangRule for GoTlsWeakCipher {
    fn id(&self) -> &str { "GO-SEC-048" }
    fn name(&self) -> &str { "TLS Weak Cipher Suites" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let weak_cipher_patterns = vec![
            (r#"CipherSuites\s*:\s*\[\s*\]\s*uint16\s*\{"#, "Empty CipherSuites array — uses system defaults"),
            (r#"TLS_RSA_WITH_"#, "RSA cipher suites — lacks forward secrecy (CWE-327)"),
            (r#"TLS_3DES_"#, "3DES cipher — deprecated (Sweet32 attack)"),
            (r#"TLS_DHE_"#, "DHE cipher — consider ECDHE instead"),
            (r#"TLS_ECDHE_"#, "ECDHE — verify specific curve"),
            (r#"CipherSuites\s*:\s*\[\s* tls\.TLS_"#, "Check cipher suite selection"),
            (r#"TLS_AES_128_"#, "AES-128 — consider AES-256 for sensitive data"),
            (r#"RC4"#, "RC4 cipher — broken and deprecated"),
            (r#"CBC\s*mode"#, "CBC mode — BEAST attack vulnerable"),
        ];

        for (pattern, desc) in &weak_cipher_patterns {
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
                            "TLS weak cipher: {}. CWE-327: Weak cipher suites can be broken by attackers, \
                            compromising encrypted communications.",
                            desc
                        ),
                        fix_hint: "Use strong cipher suites with forward secrecy: \
                            CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ...}. \
                            Prefer AES-256-GCM. Disable 3DES, RC4, and RSA key exchange ciphers.".to_string(),
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
// GO-SEC-049: Weak Diffie-Hellman Group
// Severity: medium | CWE-326
// DH parameters less than 2048 bits are cryptographically weak
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoWeakDhGroup;

impl LangRule for GoWeakDhGroup {
    fn id(&self) -> &str { "GO-SEC-049" }
    fn name(&self) -> &str { "Weak Diffie-Hellman Parameters" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let weak_dh_patterns = vec![
            (r#"dh\.GenerateKey\s*\([^)]*1024"#, "DH with 1024-bit key — too weak (CWE-326)"),
            (r#"dh\.GenerateKey\s*\([^)]*512"#, "DH with 512-bit key — trivially breakable"),
            (r#"dh\.Params\s*:\s*&dh\.Parameters\s*\{[^}]*P:\s*"#, "DH Parameters — verify P is >= 2048 bits"),
            (r#"crypto\/dh"#, "DH usage — prefer ECDHE with P-256/P-384"),
            (r#"tls\.CurvePreferences\s*:\s*\[\s*\]"#, "Empty CurvePreferences — verify default curves"),
            (r#"CurvePreferences\s*:\s*\[\s*crypto\/tls\.(CurveP256|CurveP384)"#, "Verify curve selection — prefer P-384+"),
            (r#"tls\.CurveP256"#, "CurveP256 — consider P-384 for sensitive data"),
        ];

        for (pattern, desc) in &weak_dh_patterns {
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
                            "Weak DH group: {}. CWE-326: Diffie-Hellman parameters < 2048 bits \
                            can be broken by adversaries with sufficient resources.",
                            desc
                        ),
                        fix_hint: "Use DH parameters >= 2048 bits: dh.Parameters{P: bigInt, G: bigInt}. \
                            Prefer ECDHE with P-384 or X25519: CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384}. \
                            TLS 1.3 uses secure defaults.".to_string(),
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
// GO-SEC-050: HTTP Verb Tampering
// Severity: medium | CWE-638
// Route accepting any HTTP method without proper authorization
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoHttpVerbTampering;

impl LangRule for GoHttpVerbTampering {
    fn id(&self) -> &str { "GO-SEC-050" }
    fn name(&self) -> &str { "HTTP Verb Tampering" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let web_imports = ["net/http", "github.com/gin-gonic", "github.com/labstack/echo", "github.com/gorilla/mux"];
        let has_web = tree.imports.iter().any(|imp| {
            web_imports.iter().any(|w| imp.module.contains(w))
        });

        if !has_web && !code.contains("http.HandlerFunc") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"ANY\s*\(\s*["']\/"#, "ANY() handler accepting all HTTP methods (CWE-638)"),
            (r#"\.Match\s*\([^)]*r\.Method\s*=\s*["']\*{}"#, "Route matching all methods"),
            (r#"r\.Method\s*==\s*["']\*{}"#, "Method check allowing any"),
            (r#"http\.MethodGet\s*\|\s*http\.MethodPost"#, "Multiple methods — verify authorization"),
            (r#"\.HandleFunc\s*\([^)]*func\s*\([^)]*r\s+\*http\.Request"#, "Generic handler — verify method-specific logic"),
            (r#"switch\s+r\.Method\s*\{[^}]*case\s+"[^"]+":[^}]*\}"#, "Switch on method — verify all cases"),
            (r#"r\.RequestURI\s*=="#, "RequestURI comparison — verify path handling"),
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
                            "HTTP verb tampering: {}. CWE-638: Routes accepting any HTTP method may \
                            bypass method-specific authorization checks.",
                            desc
                        ),
                        fix_hint: "Use explicit method handlers: router.GET(), router.POST(), etc. \
                            Implement method-specific authorization. Never rely solely on path-based access control. \
                            Example: router.GET(\"/resource\", authMiddleware, handler).".to_string(),
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
// GO-SEC-051: SQLite SQL Injection
// Severity: critical | CWE-89
// SQLite exec/query with string concatenation
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoSqliteSqlInjection;

impl LangRule for GoSqliteSqlInjection {
    fn id(&self) -> &str { "GO-SEC-051" }
    fn name(&self) -> &str { "SQLite SQL Injection" }
    fn severity(&self) -> &'static str { "critical" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let sqlite_imports = ["modernc.org/sqlite", "github.com/mattn/go-sqlite3", "crawshaw.io/sqlite"];
        let has_sqlite = tree.imports.iter().any(|imp| {
            sqlite_imports.iter().any(|s| imp.module.contains(s))
        });

        if !has_sqlite && !code.contains("sqlite") {
            return findings;
        }

        let dangerous_patterns = vec![
            (r#"sqlite3\.Exec\s*\([^)]*\+[^)]*\)"#, "sqlite3.Exec with string concatenation (CWE-89)"),
            (r#"sqlite3\.Query\s*\([^)]*\+[^)]*\)"#, "sqlite3.Query with string concatenation"),
            (r#"sqlite3\.QueryRow\s*\([^)]*\+[^)]*\)"#, "sqlite3.QueryRow with string concatenation"),
            (r#"\.Exec\s*\(\s*fmt\.Sprintf\s*\([^)]*sqlite"#, "Exec with fmt.Sprintf on SQLite"),
            (r#"\.Query\s*\(\s*`[^`]*\+[^`]*`"#, "Query with backtick and concatenation"),
            (r#"\.Exec\s*\(\s*`[^`]*SELECT[^`]*\+[^`]*`"#, "Exec with SELECT concatenation"),
            (r#"db\.Exec\s*\([^)]*\+[^)]*r\.(Form|URL|Body|FormValue)"#, "DB Exec with user input concatenation"),
            (r#"db\.Query\s*\([^)]*\+[^)]*req\."#, "DB Query with request data concatenation"),
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
                            "SQLite SQL injection: {}. CWE-89: String concatenation in SQL queries \
                            allows attackers to inject malicious SQL code.",
                            desc
                        ),
                        fix_hint: "Always use parameterized queries: \
                            db.Exec(\"INSERT INTO users VALUES(?, ?)\", username, email). \
                            Never concatenate user input into SQL strings. \
                            For dynamic identifiers, use a whitelist of allowed values.".to_string(),
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
// GO-SEC-052: Insecure File Permissions
// Severity: medium | CWE-732
// os.Chmod with overly permissive modes
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoInsecureFilePermission;

impl LangRule for GoInsecureFilePermission {
    fn id(&self) -> &str { "GO-SEC-052" }
    fn name(&self) -> &str { "Insecure File Permission" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let dangerous_patterns = vec![
            (r#"os\.Chmod\s*\([^)]*0[0-7]{3}"#, "os.Chmod with 0777 or similar — world-readable (CWE-732)"),
            (r#"os\.Chmod\s*\([^)]*0[0-7]{2}[6-7]"#, "os.Chmod adding group/other write — insecure"),
            (r#"ioutil\.WriteFile\s*\([^)]*0[0-7]{3}"#, "WriteFile with 0777 mode"),
            (r#"os\.OpenFile\s*\([^)]*0[0-7]{3}"#, "OpenFile with 0777 mode"),
            (r#"os\.MkdirAll\s*\([^)]*0[0-7]{3}"#, "MkdirAll with 0777 mode"),
            (r#"os\.Mkdir\s*\([^)]*0[0-7]{3}"#, "Mkdir with 0777 mode"),
            (r#"0600"#, "0600 — verify this is for secrets, not config"),
            (r#"0644"#, "0644 — world-readable — verify intent for sensitive files"),
            (r#"Perm\s*:\s*0[0-7]{3}"#, "File mode with 0777 pattern"),
            (r#"FileMode\s*\(\s*0[0-7]{3}"#, "FileMode with permissive octal"),
            (r#"chmod\s*\+\s*rw"#, "chmod adding read/write to group/others"),
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
                            "Insecure file permission: {}. CWE-732: Files with overly permissive modes \
                            (0777, world-readable) can be accessed by unauthorized users.",
                            desc
                        ),
                        fix_hint: "Use least-privilege permissions: 0600 for secrets, 0640 for config, 0755 for executables. \
                            Example: os.Chmod(\"secret.key\", 0600). \
                            On POSIX: umask 027 or stricter. Never use 0777 in production.".to_string(),
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
        Box::new(GoGormSqlInjection),
        Box::new(GoRaceCondition),
        Box::new(GoMissingContextDeadline),
        Box::new(GoRegexDos),
        Box::new(GoIntegerOverflow),
        Box::new(GoSsrfInternal),
        Box::new(GoCommandInjectionShell),
        Box::new(GoSsrfDeep),
        Box::new(GoWeakJwt),
        Box::new(GoSlopsquattingTypo),
        Box::new(GoMissingNilCheckAfterMarshal),
        Box::new(GoOffByOneLoopBounds),
        // GO-CRYPT-001: Insecure TLS Configuration
        Box::new(GoInsecureTlsConfig),
        // GO-SEC-034: Insecure Deserialization
        Box::new(GoInsecureDeser),
        // GO-SEC-035 to GO-SEC-037: Vulnerable Sink Detection
        Box::new(GoGormRawInjection),
        Box::new(GoIdor),
        Box::new(GoCommandInjectionLookPath),
        // GO-SEC-038 to GO-SEC-052: Additional Security Rules
        Box::new(GoHttpKeepAliveDisabled),      // GO-SEC-038
        Box::new(GoHttpNoTimeout),               // GO-SEC-039
        Box::new(GoTemplateInjection),            // GO-SEC-040
        Box::new(GoHostOfDeath),                 // GO-SEC-041
        Box::new(GoConstantMathOverflow),        // GO-SEC-042
        Box::new(GoMultipartBoundary),            // GO-SEC-043
        Box::new(GoHttpRequestSmuggling),        // GO-SEC-044
        Box::new(GoCorsMisconfiguration),         // GO-SEC-045
        Box::new(GoJwtNoneAlgorithm),            // GO-SEC-046
        Box::new(GoBasicAuthInUrl),              // GO-SEC-047
        Box::new(GoTlsWeakCipher),               // GO-SEC-048
        Box::new(GoWeakDhGroup),                  // GO-SEC-049
        Box::new(GoHttpVerbTampering),           // GO-SEC-050
        Box::new(GoSqliteSqlInjection),          // GO-SEC-051
        Box::new(GoInsecureFilePermission),      // GO-SEC-052
    ]
}
