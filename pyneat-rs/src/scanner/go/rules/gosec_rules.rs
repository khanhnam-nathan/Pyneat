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
//!
//! gosec - Security Scanner for Go source code
//! This module implements rules that complement gosec's coverage.
//! Rule logic is independently derived from public gosec documentation.
//!
//! gosec categories covered:
//!   G1xx: General (buffer, hardcoded credentials)
//!   G2xx: Injection / Config (SQL, Command, File traversal, exec)
//!   G3xx: Filesystem (race, permissions, symlink)
//!   G4xx: Cryptography (weak crypto, bad configs)
//!   G5xx: Hardcoded credentials, crypto algos
//!   G6xx: Misc (reflection, deferred ctx cancel)
//!   G7xx: Integer overflows

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
    code.lines().nth(line.saturating_sub(1)).map(|s| s.to_string())
}

#[allow(dead_code)]
fn add_findings<F>(
    findings: &mut Vec<LangFinding>,
    rule_id: &str,
    severity: &str,
    problem: &str,
    fix_hint: &str,
    code: &str,
    matcher: F,
)
where
    F: Fn(&str) -> Vec<(usize, usize, String)>, // (start, end, line_text)
{
    for (start, end, line_text) in matcher(code) {
        let line = code[..start].matches('\n').count() + 1;
        findings.push(LangFinding {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            line,
            column: 0,
            start_byte: start,
            end_byte: end,
            snippet: line_text.trim().to_string(),
            problem: problem.to_string(),
            fix_hint: fix_hint.to_string(),
            auto_fix_available: false,
                        replacement: String::new(),
        });
    }
    findings.sort_by_key(|f| f.line);
}

// ─────────────────────────────────────────────────────────────────────────────
// G106: Use of os/exec Command With Potential For Command Injection
// Severity: critical | CWE-78
// exec.Command with user-controlled input — should use exec.CommandContext
// gosec rule: G106
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoExecCommandContext;

impl LangRule for GoExecCommandContext {
    fn id(&self) -> &str { "GO-SEC-038" }
    fn name(&self) -> &str { "G106: exec.Command without context" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let re = regex::Regex::new(r"exec\.Command\s*\(\s*[^)]+\)").unwrap();

        for m in re.find_iter(code) {
            let line = code[..m.start()].matches('\n').count() + 1;
            let (start, end) = get_line_offsets(code, line);
            let line_text = get_line_text(code, line).unwrap_or_default();

            // Skip exec.CommandContext — that's the safe version
            if line_text.contains("exec.CommandContext") {
                continue;
            }

            // Check if this is exec.Command with user input (simplified heuristic)
            let has_user_input = line_text.contains("request")
                || line_text.contains("input")
                || line_text.contains("user")
                || line_text.contains("FormValue")
                || line_text.contains("PostForm")
                || line_text.contains("Query")
                || line_text.contains("Body");

            findings.push(LangFinding {
                rule_id: self.id().to_string(),
                severity: self.severity().to_string(),
                line,
                column: 0,
                start_byte: start,
                end_byte: end,
                snippet: line_text.trim().to_string(),
                problem: format!(
                    "G106: exec.Command() called without context. {}. \
                    Without context, the subprocess cannot be cancelled or timed out.",
                    if has_user_input {
                        "User input detected — potential command injection"
                    } else {
                        "No context for cancellation/timeout"
                    }
                ),
                fix_hint: "Use exec.CommandContext with a timeout context: \
                    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second); \
                    defer cancel(); \
                    exec.CommandContext(ctx, \"cmd\", args...). \
                    This prevents indefinite subprocess hangs and enables proper cleanup.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// G204: Subprocess launched with user-controlled execution
// Severity: high | CWE-78
// exec.Command with shell=True equivalent in Go or user input in args
// gosec rule: G204
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoSubprocessUserControlled;

impl LangRule for GoSubprocessUserControlled {
    fn id(&self) -> &str { "GO-SEC-039" }
    fn name(&self) -> &str { "G204: Subprocess with user-controlled execution" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern: exec.Command("sh", "-c", ...) or exec.Command("/bin/sh", "-c", ...)
        // OR exec.Command with multiple args where any arg comes from user input
        let patterns = [
            (r##"exec\.Command\s*\(\s*["'](?:sh|bash|ksh|zsh|cmd|cmd\.exe|powershell|pwsh)["']\s*,\s*["'](?:-[c]|-c\s)"##,
             "Shell invocation via exec.Command — use exec.CommandContext with arg array instead"),
            (r##"exec\.Command\s*\(\s*["'](?:sh|bash|ksh|zsh|cmd|cmd\.exe|powershell|pwsh)["']\s*,\s*["']-c["']"##,
             "Shell invocation — sh -c allows command injection"),
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
                    problem: format!("G204: {}. If the shell command string contains user input, this enables command injection.", problem),
                    fix_hint: "Pass command arguments as separate strings instead of a shell string: \
                        exec.Command(\"ls\", \"-la\", dir) instead of exec.Command(\"sh\", \"-c\", \"ls -la $dir\"). \
                        Never pass user input through shell -c. If shell features are needed, validate and sanitize input strictly.".to_string(),
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
// G302: Expect Write permissions on file to be 0600 or more restrictive
// Severity: medium | CWE-276
// File created with world-readable permissions (0o777, 0o666, etc.)
// gosec rule: G302
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoWorldWritableFile;

impl LangRule for GoWorldWritableFile {
    fn id(&self) -> &str { "GO-SEC-040" }
    fn name(&self) -> &str { "G302: World-writable file" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect: os.OpenFile with 0o777, 0o666, 0o776, 0o766, etc.
        // Also: os.Chmod with 0o777 or 0o666
        let patterns = [
            r##"os\.OpenFile\s*\([^)]*,\s*0+[0-7]*(?:[67][67]|7[0-7])"##,
            r##"os\.Chmod\s*\([^)]*,\s*0+[0-7]*(?:[67][67]|7[0-7])"##,
            r##"ioutil\.WriteFile\s*\([^)]*,\s*0+[0-7]*(?:[67][67]|7[0-7])"##,
            r##"os\.Create\s*\([^)]*\)\s*(?:\.\s*)?Chmod\s*\(\s*0+[0-7]*(?:[67][67]|7[0-7])"##,
        ];

        for pat in &patterns {
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
                    problem: "G302: File opened with world-readable or group-writable permissions. \
                        Files should be created with 0600 or 0640 at most to prevent unauthorized access.".to_string(),
                    fix_hint: "Use restrictive file permissions: 0600 (owner read/write only) or 0640 (owner read, group read). \
                        Example: os.OpenFile(f, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600). \
                        For sensitive files, use 0600. For config files readable by group, use 0640.".to_string(),
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
// G304: File access path is user-controlled
// Severity: high | CWE-22
// os.Open/ioutil.ReadFile with path containing user input
// gosec rule: G304 (already partially covered by GO-SEC-004)
// This rule adds G304's specific pattern: path.Join with user input
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoPathTraversalUserControlled;

impl LangRule for GoPathTraversalUserControlled {
    fn id(&self) -> &str { "GO-SEC-041" }
    fn name(&self) -> &str { "G304: Path traversal via user input" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect: path.Join(base, userInput) or filepath.Join with user-controlled component
        // Pattern: filepath.Join/ioutil.ReadFile/os.Open with request/user input
        let patterns = [
            (r##"path\.Join\s*\([^)]*(?:request|input|user|query|param|FormValue|PostForm)"##,
             "path.Join with user-controlled component"),
            (r##"filepath\.Join\s*\([^)]*(?:request|input|user|query|param|FormValue|PostForm)"##,
             "filepath.Join with user-controlled component"),
            (r##"ioutil\.ReadFile\s*\([^)]*(?:request|input|user|query|param|FormValue)"##,
             "ioutil.ReadFile with user-controlled path"),
            (r##"ioutil\.ReadDir\s*\([^)]*(?:request|input|user|query|param|FormValue)"##,
             "ioutil.ReadDir with user-controlled path"),
            (r##"os\.Open\s*\([^)]*(?:request|input|user|query|param|FormValue)"##,
             "os.Open with user-controlled path"),
            (r##"os\.ReadFile\s*\([^)]*(?:request|input|user|query|param|FormValue)"##,
             "os.ReadFile with user-controlled path"),
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
                    problem: format!("G304: {}. \
                        User input in file paths can enable path traversal attacks (../), \
                        allowing access to sensitive files outside the intended directory.", problem),
                    fix_hint: "Validate and sanitize the path component: \
                        1) Use filepath.Clean() and check it starts with the allowed base directory. \
                        2) Use path.Clean() and reject paths containing '..'. \
                        3) Use filepath.Rel() to verify the path stays within bounds. \
                        4) Open files with O_NONBLOCK if possible. \
                        Example: base := \"/safe/dir/\"; \
                        clean := filepath.Clean(filepath.Join(base, userPath)); \
                        if !strings.HasPrefix(clean, base) { return error }".to_string(),
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
// G305: Incomplete path traversal in filepath.Join
// Severity: high | CWE-22
// filepath.Join does not handle null-byte injection or double-dot sequences
// gosec rule: G305
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoPathTraversalJoin;

impl LangRule for GoPathTraversalJoin {
    fn id(&self) -> &str { "GO-SEC-042" }
    fn name(&self) -> &str { "G305: filepath.Join path traversal" }
    fn severity(&self) -> &'static str { "high" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Detect: filepath.Join with path traversal patterns
        let patterns = [
            r##"filepath\.Join\s*\([^)]*\.\./"##,
            r##"path\.Join\s*\([^)]*\.\./"##,
            r##"filepath\.Join\s*\([^)]*%2e%2e"##,
            r##"path\.Join\s*\([^)]*%2e%2e"##,
            r##"filepath\.Join\s*\([^)]*\.\.%(?![/\\])"##,
            r##"path\.Join\s*\([^)]*\.\.%(?![/\\])"##,
        ];

        for pat in &patterns {
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
                    problem: "G305: filepath.Join/filepath.Clean with path traversal sequences (../ or encoded ../). \
                        Go's filepath.Join doesn't prevent path traversal — '..' components are resolved. \
                        This allows reading/writing files outside the intended directory.".to_string(),
                    fix_hint: "Always validate the joined path stays within the allowed base directory: \
                        base := filepath.Clean(\"/allowed/dir\"); \
                        target := filepath.Clean(filepath.Join(base, userInput)); \
                        if !strings.HasPrefix(target+string(filepath.Separator), base) { return err }. \
                        Alternatively use fs.ValidPath() from Go 1.16+.".to_string(),
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
// G307: Deferring a method which returns an error
// Severity: medium | CWE-754
// defer resp.Body.Close() where Close() returns an error that is ignored
// gosec rule: G307
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoDeferredCloseError;

impl LangRule for GoDeferredCloseError {
    fn id(&self) -> &str { "GO-SEC-043" }
    fn name(&self) -> &str { "G307: Deferred Close returning error is ignored" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // Pattern: defer ...Close() — error is not handled
        let close_patterns = [
            r##"defer\s+[^;]+\.Close\s*\(\s*\)"##,
            r##"defer\s+[^;]+\.Logout\s*\(\s*\)"##,
            r##"defer\s+[^;]+\.Cancel\s*\(\s*\)"##,
        ];

        // Skip common safe patterns (defer within same function that checks error)
        let skip_patterns = [
            r##"defer\s+func\s*\(\s*\)\s*\{[^}]*\.Close\([^)]*\)\s*\}[^;]*"##,
        ];

        for close_pat in &close_patterns {
            let close_re = match regex::Regex::new(close_pat) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for m in close_re.find_iter(code) {
                let line = code[..m.start()].matches('\n').count() + 1;

                // Check if this is wrapped in a closure that handles the error
                let is_safe = skip_patterns.iter().any(|skip_pat| {
                    regex::Regex::new(skip_pat)
                        .map(|r| r.is_match(code))
                        .unwrap_or(false)
                });

                if is_safe {
                    continue;
                }

                // Skip if it's defer with named return handling (e.g., defer func() { _ = f.Close() })
                let line_text = get_line_text(code, line).unwrap_or_default();
                if line_text.contains("_ =") || line_text.contains("err :=") {
                    continue;
                }

                let (start, end) = get_line_offsets(code, line);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line_text.trim().to_string(),
                    problem: "G307: defer Close() — error return value is discarded. \
                        .Close(), .Logout(), .Cancel() and similar cleanup methods return errors. \
                        Ignoring these errors can cause resource leaks or incomplete cleanup.".to_string(),
                    fix_hint: "Handle the error in a deferred closure: \
                        defer func() { _ = f.Close() }() or \
                        defer func() { _ = resp.Body.Close() }(). \
                        For critical resources, log the error: \
                        defer func() { _ = f.Close(); if err != nil { log.Error(err) } }(). \
                        From Go 1.20+, use errors.Join to collect multiple close errors.".to_string(),
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
// G501: Blacklisted import MD5 (crypto/md5)
// Severity: medium | CWE-327
// MD5 is cryptographically broken for security purposes
// gosec rule: G501
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoBlacklistedCryptoMd5;

impl LangRule for GoBlacklistedCryptoMd5 {
    fn id(&self) -> &str { "GO-SEC-044" }
    fn name(&self) -> &str { "G501: Blacklisted import crypto/md5" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_md5 = tree.imports.iter().any(|imp| {
            imp.module.contains("crypto/md5") || imp.module == "\"crypto/md5\""
        });

        if !has_md5 {
            return findings;
        }

        // Find the import line
        for (i, line) in code.lines().enumerate() {
            if line.contains("crypto/md5") {
                let line_num = i + 1;
                let (start, end) = get_line_offsets(code, line_num);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_num,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "G501: Import of crypto/md5 is blacklisted. \
                        MD5 is broken for cryptographic purposes (collision attacks). \
                        Do not use for security-sensitive operations like hashing passwords, \
                        signing, or generating secure tokens.".to_string(),
                    fix_hint: "Use SHA-256 (crypto/sha256) or SHA-3 for hashing. \
                        For password hashing, use bcrypt, scrypt, or argon2. \
                        Example: sha256.Sum256([]byte(data)). \
                        For HMAC, use hmac.New(sha256.New, key, data).".to_string(),
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
// G502: Blacklisted import DES (crypto/des)
// Severity: medium | CWE-327
// DES is cryptographically broken — 56-bit key is brute-forceable
// gosec rule: G502
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoBlacklistedCryptoDes;

impl LangRule for GoBlacklistedCryptoDes {
    fn id(&self) -> &str { "GO-SEC-045" }
    fn name(&self) -> &str { "G502: Blacklisted import crypto/des" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_des = tree.imports.iter().any(|imp| {
            imp.module.contains("crypto/des") || imp.module == "\"crypto/des\""
        });

        if !has_des {
            return findings;
        }

        for (i, line) in code.lines().enumerate() {
            if line.contains("crypto/des") {
                let line_num = i + 1;
                let (start, end) = get_line_offsets(code, line_num);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_num,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "G502: Import of crypto/des is blacklisted. \
                        DES uses only a 56-bit key and is easily brute-forced. \
                        It should not be used for any security-sensitive purpose.".to_string(),
                    fix_hint: "Use AES (crypto/aes) with a 128, 192, or 256-bit key. \
                        AES-256 is recommended for security-sensitive applications. \
                        Example: aes.NewCipher(key256).".to_string(),
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
// G503: Blacklisted import RC4 (crypto/rc4)
// Severity: medium | CWE-327
// RC4 has known biases and is deprecated for security use
// gosec rule: G503
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoBlacklistedCryptoRc4;

impl LangRule for GoBlacklistedCryptoRc4 {
    fn id(&self) -> &str { "GO-SEC-046" }
    fn name(&self) -> &str { "G503: Blacklisted import crypto/rc4" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_rc4 = tree.imports.iter().any(|imp| {
            imp.module.contains("crypto/rc4") || imp.module == "\"crypto/rc4\""
        });

        if !has_rc4 {
            return findings;
        }

        for (i, line) in code.lines().enumerate() {
            if line.contains("crypto/rc4") {
                let line_num = i + 1;
                let (start, end) = get_line_offsets(code, line_num);

                findings.push(LangFinding {
                    rule_id: self.id().to_string(),
                    severity: self.severity().to_string(),
                    line: line_num,
                    column: 0,
                    start_byte: start,
                    end_byte: end,
                    snippet: line.trim().to_string(),
                    problem: "G503: Import of crypto/rc4 is blacklisted. \
                        RC4 has severe cryptographic weaknesses (biases, related-key attacks). \
                        Deprecated by RFC 7465. Do not use for any security purpose.".to_string(),
                    fix_hint: "Use AES (crypto/aes) in GCM mode for authenticated encryption. \
                        Example: aesgcm.Newcipher(key). \
                        For TLS, use TLS 1.3 which mandates AES-GCM or ChaCha20-Poly1305.".to_string(),
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
// G504: Blacklisted import CGI/HTTP using query parameters
// Severity: medium | CWE-79
// net/http/cgi passes user input as command-line arguments — command injection risk
// gosec rule: G504
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoCgiQueryParams;

impl LangRule for GoCgiQueryParams {
    fn id(&self) -> &str { "GO-SEC-047" }
    fn name(&self) -> &str { "G504: CGI with query parameters" }
    fn severity(&self) -> &'static str { "medium" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let has_cgi = code.contains("net/http/cgi")
            || code.contains("github.com/yooking/gocgi")
            || code.contains("\"net/http/cgi\"");

        if !has_cgi {
            return findings;
        }

        let cgi_pattern = Regex::new(r"(?i)cgi\.(?:FieldStorage|RequestURI|QueryString|ReadRequest)").unwrap();

        for m in cgi_pattern.find_iter(code) {
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
                problem: "G504: CGI net/http/cgi passes query parameters as environment variables, \
                    but certain deployments pass them as command-line arguments, which can be logged \
                    and exposed. Prefer net/http mux for new applications.".to_string(),
                fix_hint: "Replace net/http/cgi with net/http ServeMux for new applications. \
                    If CGI is required, ensure the deployment does not pass query parameters \
                    as command-line arguments. Consider using net/http/fcgi (FastCGI) instead.".to_string(),
                auto_fix_available: false,
                        replacement: String::new(),
            });
        }

        findings.sort_by_key(|f| f.line);
        findings
    }

    fn supports_auto_fix(&self) -> bool { false }
}

// ─────────────────────────────────────────────────────────────────────────────
// G601: Model attribute is stored expanded (reflects entire struct)
// Severity: low | CWE-915
// reflect.ValueOf on a model struct can expose internal fields via MarshalJSON
// gosec rule: G601
// ─────────────────────────────────────────────────────────────────────────────
pub struct GoReflectModelExposure;

impl LangRule for GoReflectModelExposure {
    fn id(&self) -> &str { "GO-SEC-048" }
    fn name(&self) -> &str { "G601: Reflect model exposure" }
    fn severity(&self) -> &'static str { "low" }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        // detect: reflect.ValueOf(model).FieldByName(...) where model could have unexported fields
        // Also: json.Marshal on a model struct without json tags
        let patterns = [
            r##"reflect\.ValueOf\s*\(\s*[A-Z][a-zA-Z0-9]*\s*\)"##,
            r##"json\.Marshal\s*\(\s*[A-Z][a-zA-Z0-9]*\s*\)"##,
            r##"json\.Encode\s*\(\s*[A-Z][a-zA-Z0-9]*\s*\)"##,
        ];

        for pat in &patterns {
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
                    problem: "G601: Reflect.ValueOf on a model struct can expose unexported fields. \
                        Internal fields (passwords, tokens, IDs) might be serialized if the struct \
                        lacks proper json tags or has custom MarshalJSON that includes all fields.".to_string(),
                    fix_hint: "Always use explicit field selection with json tags: \
                        type User struct { Name string `json:\"name\"` Password string `json:\"-\"` }. \
                        Avoid json.Marshal on entire structs. Use DTOs (data transfer objects) \
                        that explicitly list only the fields to serialize.".to_string(),
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
// Get all gosec-complementary rules
// ─────────────────────────────────────────────────────────────────────────────

use regex::Regex;

pub fn gosec_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        // G106: exec.Command without context
        Box::new(GoExecCommandContext),
        // G204: Subprocess with user-controlled execution
        Box::new(GoSubprocessUserControlled),
        // G302: World-writable files
        Box::new(GoWorldWritableFile),
        // G304: Path traversal via user input
        Box::new(GoPathTraversalUserControlled),
        // G305: Incomplete path traversal in filepath.Join
        Box::new(GoPathTraversalJoin),
        // G307: Deferred Close returning error is ignored
        Box::new(GoDeferredCloseError),
        // G501: Blacklisted import MD5
        Box::new(GoBlacklistedCryptoMd5),
        // G502: Blacklisted import DES
        Box::new(GoBlacklistedCryptoDes),
        // G503: Blacklisted import RC4
        Box::new(GoBlacklistedCryptoRc4),
        // G504: CGI with query parameters
        Box::new(GoCgiQueryParams),
        // G601: Reflect model exposure
        Box::new(GoReflectModelExposure),
    ]
}
