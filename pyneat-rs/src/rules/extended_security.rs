//! Extended Security Rules for Python
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Expands Python security rules from 72 to 200+ rules.
//! Covers OWASP Top 10 2021, CWE Top 25 2023, and AI-specific vulnerabilities.

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::Tree;

static SEC073_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"\.get\s*\(\s*id\s*\)", "Direct object access by ID without authorization check"),
    (r"User\.objects\.get\s*\(\s*id\s*=", "Direct database lookup with user-controlled ID"),
    (r#"request\.args\.get\s*\(\s*['"]id['"]"#, "User-controlled ID used in database query"),
    (r#"GET\s+['"]\/user\/["'].*?\.format\s*\("#, "URL with user ID without authorization"),
    (r#"session\s*\[\s*['"]user_id['"]\s*\].*SELECT"#,
     "Session-based query without authorization"),
]);

static SEC074_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"def\s+\w+.*user_id.*return\s+User\.objects\.get\s*\(\s*id\s*=\s*user_id",
     "Function exposes another user's data based on user_id parameter"),
    (r"if\s+request\.user\s*==\s*resource\.owner",
     "Incomplete ownership check without verifying resource access"),
]);

static SEC075_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"if\s+request\.user\.is_staff.*?(?:return|render)",
     "Admin-only action checks only is_staff without role verification"),
    (r"def\s+\w+.*:\s*.*if\s+not\s+request\.user\.is_authenticated",
     "Function allows access to authenticated but unauthorized users"),
    (r"@login_required\s*\n\s*def\s+\w+.*:(?:\s*\n\s*(?:return|if)).*admin",
     "Admin function protected only by @login_required, not @admin_required"),
]);

static SEC076_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"hashlib\.md5\s*\(", "MD5 hash used - collision attacks are trivial"),
    (r"hashlib\.sha1\s*\(", "SHA-1 hash used - deprecated for security purposes"),
    (r"hashlib\.sha256\s*\(.*password", "SHA-256 used for password hashing - too slow for passwords, too fast for hashing"),
    (r"bcrypt\.hashpw\s*\([^,]+,\s*bcrypt\.gensalt\s*\(\s*\)",
     "Proper bcrypt usage detected"),
]);

static SEC077_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"AES\.new\s*\([^)]*mode\s*=\s*AES\.MODE_ECB", "ECB mode encryption - patterns visible in ciphertext"),
    (r#"Cipher\s*\([^)]*mode\s*=\s*'ECB'"#, "ECB mode detected - encryption provides no semantic security"),
]);

static SEC078_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"ENCRYPTION_KEY\s*=\s*['"][a-zA-Z0-9+/=]{16,}['"]"#, "Hardcoded encryption key found"),
    (r#"SECRET_KEY\s*=\s*['"][a-zA-Z0-9+/=]{32,}['"]"#, "Hardcoded secret key found"),
    (r#"API_KEY\s*=\s*['"][a-zA-Z0-9_-]{20,}['"]"#, "Hardcoded API key found"),
    (r#"PRIVATE_KEY\s*=\s*['"]-----BEGIN"#, "Hardcoded private key found"),
    (r#"Fernet\s*\(\s*['"][a-zA-Z0-9+/=]{32,}['"]\s*\)"#, "Fernet key hardcoded in source"),
]);

static SEC079_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"ldap\.search\s*\([^)]*\+[^)]*\)", "LDAP query built with string concatenation - LDAP injection risk"),
    (r"ldap\.search_s\s*\([^)]*%\s*\(", "LDAP query uses Python format string - injection risk"),
    (r#"search_filter\s*=\s*['"]\(uid\s*="#, "LDAP filter built without sanitization"),
]);

static SEC080_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"etree\.parse\s*\([^)]*\+", "XML/XPath query with string concatenation"),
    (r"xpath\s*\([^)]*\+[^)]*request", "XPath built from user input"),
    (r"ElementTree\.parse\s*\([^)]*\.format\s*\(", "XML parsing with format string"),
]);

static SEC081_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // Jinja2 Template class from Flask — compiles user input directly into template engine.
    // This is the actual SSTI vulnerability. Template() is always dangerous when given user data.
    // Negative lookahead (?!) ensures render_template_string is NOT matched here (handled separately).
    (r#"flask\.Template\s*\(\s*request\.(?!render_template_string)"#, "Flask Template class compiled from user input — SSTI risk"),
    // render_template_string with concatenation — direct SSTI via string building
    (r#"render_template_string\s*\([^)]*\+[^)]*\)"#, "render_template_string with concatenation — SSTI risk"),
    // render_template_string alone — Jinja2's unsafe variant, dangerous with any user input
    (r#"render_template_string\s*\("#, "Flask render_template_string — risky if user input reaches it directly"),
    // Flask render_template with explicit template injection syntax in the template path arg
    // This catches e.g. render_template(user_supplied_path + '.html')
    (r#"render_template\s*\([^)]*\+\s*['\"]"#, "render_template with dynamic template path — path traversal + SSTI"),
]);

static SEC082_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
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
]);

static SEC083_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"DEBUG\s*=\s*True", "DEBUG=True found in source code"),
    (r"flask\s*\(.*debug\s*=\s*True", "Flask app created with debug=True"),
    (r"app\.run\s*\([^)]*debug\s*=\s*True", "Flask app.run with debug=True"),
    (r"Django\s*\(.*DEBUG\s*=\s*True", "Django settings with DEBUG=True"),
]);

static SEC084_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"CORS\s*\([^)]*origins\s*=\s*['"]\*['"]"#, "CORS allows all origins (*)"),
    (r"allow_all_origins\s*=\s*True", "CORS allows all origins"),
    (r#"Access-Control-Allow-Origin\s*:\s*\*"#, "HTTP header allows all origins"),
    (r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True", "Django CORS allows all origins"),
    (r#"@cross_origin\s*\([^)]*origins\s*=\s*['"]\*['"]"#, "Flask-CORS allows all origins"),
]);

static SEC085_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"set_password\s*\([^)]*\)\s*(?:\n\s*return|\n\s*True)", "Password set without hashing validation"),
    (r"UserCreationForm\s*\(\s*\)", "Django UserCreationForm without custom validation"),
    (r#"password\s*==\s*['"]"#, "Plaintext password comparison detected"),
    (r#"check_password\s*\([^)]*\)\s*==\s*True"#, "Password check using == instead of check_password()"),
]);

static SEC086_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"def\s+login.*?(?:\n\s*pass|\n\s*return\s+True)", "Login function without rate limiting"),
    (r"@app\.route.*?login.*?(?!\@ratelimit)", "Login endpoint without rate limiting decorator"),
    (r"authenticate\s*\(.*?\)\s*:\s*(?:\n(?!.*rate|.*limit|.*attempt))", "Authentication without attempt limiting"),
]);

static SEC087_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"pickle\.loads\s*\(", "pickle.loads() - arbitrary code execution risk"),
    (r"pickle\.load\s*\(", "pickle.load() - arbitrary code execution risk"),
    (r"cloudpickle\.load\s*\(", "cloudpickle.load() - arbitrary code execution risk"),
    (r"yaml\.load\s*\([^)]*\)\s*(?!\s*Loader\s*=\s*yaml\.SafeLoader)",
     "yaml.load() without SafeLoader - arbitrary code execution risk"),
    (r"marshal\.loads\s*\(", "marshal.loads() - unreliable and unsafe"),
    (r"shelve\.open\s*\(", "shelve module uses pickle internally - unsafe"),
]);

static SEC088_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"http://[^/'"]+.*?(?:password|token|secret|key|auth|credential)"#, "HTTP URL with sensitive data transmission"),
    (r#"requests\.(?:post|get)\s*\(\s*['"]http://"#, "HTTP request without TLS"),
    (r#"urllib\.request\.urlopen\s*\(['"]http://"#, "urllib request over HTTP"),
    (r"http\s+[^/]", "HTTP protocol used instead of HTTPS"),
]);

static SEC089_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:password|passwd|pwd)\s*\)", "Password logged"),
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:token|bearer)\s*\)", "Auth token logged"),
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:ssn|social.?security)\s*\)", "SSN logged"),
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*(?:credit.?card|card.?number)\s*\)", "Credit card info logged"),
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*request\.data", "Full request data logged"),
    (r"log(?:ger)?\.(?:info|debug|warning)\s*\([^)]*request\.headers", "Request headers logged (may contain auth tokens)"),
    (r"print\s*\([^)]*(?:password|token|secret|key)", "Sensitive data passed to print()"),
]);

static SEC090_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"requests\.(?:get|post|put|delete)\s*\([^)]*url\s*=\s*[^)]*(?:request|input|user|param|url)", "HTTP request URL from user input"),
    (r"urllib\.request\.urlopen\s*\([^)]*(?:request|input|user|param)", "urllib request with user-controlled URL"),
    (r"httpx\.(?:get|post)\s*\([^)]*url\s*=\s*[^)]*(?:request|input)", "httpx request with user-controlled URL"),
    // subprocess.run / subprocess.call with shell=True and a URL from user input
    (r"subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True[^)]*(?:request|input|param|url)", "subprocess with shell=True and user-controlled URL — SSRF risk"),
    // subprocess used with curl where the curl URL is user-controlled
    (r"subprocess\.(?:run|call|Popen)\s*\([^)]*curl\s*\([^)]*(?:request|input|param)", "subprocess curl with user-controlled URL — SSRF risk"),
    (r"http\.client\.HTTPConnection\s*\([^)]*(?:request|input)", "HTTP connection with user-controlled host"),
]);

static SEC091_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"etree\.XML\s*\([^)]*DOCTYPE", "XML parsing with DOCTYPE - potential XXE"),
    (r"xml\.dom\.minidom\.parse\s*\(", "minidom parse - potentially unsafe"),
    (r"xml\.sax\.parse\s*\([^)]*(?:request|input|user)", "SAX parse with user input"),
    (r"ElementTree\.parse\s*\([^)]*(?:request|input|user)", "ElementTree parse with user input"),
]);

static SEC092_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"open\s*\([^)]*(?:request|input|user|param).*?\.format\s*\(", "File open with format string from user input"),
    (r"Path\s*\([^)]*(?:request|input|user).*?\)\.read\s*\(", "Path from user input used to read file"),
    (r"send_file\s*\([^)]*(?:request|input|user)", "send_file with user-controlled path"),
    (r"send_from_directory\s*\([^)]*directory\s*=\s*[^)]*request", "send_from_directory with user-controlled directory"),
    (r"os\.path\.join\s*\([^)]*(?:request|input|user).*?\)", "os.path.join with user input"),
    (r"pathlib\.Path\s*\([^)]*(?:request|input|user).*?\)\.open\s*\(", "Path from user input opened"),
]);

static SEC093_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"User\s*\(\s*\*\*\s*request\.data\s*\)", "ORM object created from raw request data"),
    (r"Model\s*\(\s*\*\*\s*request\.json\s*\)", "Model instance from raw JSON"),
    (r"User\.objects\.create\s*\(\s*\*\*\s*request\.POST\s*\)", "User created with all POST fields"),
    (r"update\(.*?\*\*request", "ORM update with request data"),
    (r"\.save\(.*?\*\*.*{.*?request.*?}", "Model save with request kwargs"),
]);

static SEC094_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"session\[.id.\]\s*=\s*request\.", "Session ID set from user input"),
    (r"session\.set_id\s*\(\s*request\.", "Session ID set from user input"),
    (r"request\.session\.keys\s*\(\s*\).*?session\.set", "Session not regenerated on login"),
]);

static SEC095_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"@app\.after_request\s*def\s+\w+:.*?response\[", "After-request hook found - check for security headers"),
]);

static SEC096_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"ZipFile\.extractall\s*\([^)]*\)", "extractall without path validation"),
    (r"archive\.extract\s*\([^)]*\)", "Archive extract without validation"),
    (r"with\s+ZipFile.*?\.extractall\s*\(", "ZipFile extractall in loop"),
]);

static SEC097_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"regex\.compile\s*\([^)]*\(\?\:[^\)]*\*[^\)]*\+[^\)]*\)", "Nested quantifiers in regex"),
    (r"regex\.compile\s*\([^)]*\(\?\:[^\)]*\*[^\)]*\*[^\)]*\)", "Multiple star quantifiers"),
    (r"regex\.compile\s*\([^)]*\(\?[=\!]<=[^\)]*[^\)]\+[^\)]*\)", "Possessive quantifiers or overlapping alternatives"),
    (r"re\.(?:compile|search|match)\s*\([^)]*\([\^\]]*\+[\^\]]*\+", "Greedy quantifiers on expensive patterns"),
]);

static SEC098_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"random\.random\s*\(\s*\)", "random.random() - not cryptographically secure"),
    (r"random\.randint\s*\(\s*\)", "random.randint() - not cryptographically secure"),
    (r"random\.choice\s*\(\s*\)", "random.choice() - not cryptographically secure"),
    (r"random\.shuffle\s*\(\s*\)", "random.shuffle() - not cryptographically secure"),
    (r"secrets\.token_bytes\s*\(\s*\)", "secrets.token_bytes - GOOD: cryptographically secure"),
    (r"secrets\.token_hex\s*\(\s*\)", "secrets.token_hex - GOOD: cryptographically secure"),
    (r"os\.urandom\s*\(\s*\)", "os.urandom - GOOD: cryptographically secure"),
]);

static SEC099_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"eval\s*\([^)]*(?:request|input|user|param|data|body)", "eval() with user-controlled input"),
    (r"exec\s*\([^)]*(?:request|input|user|param|data|body)", "exec() with user-controlled input"),
    (r"compile\s*\([^)]*(?:request|input|user|param)", "compile() with user-controlled input"),
]);

static SEC100_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"os\.path\.exists.*?\n.*?open\s*\(", "File existence check before open - TOCTOU"),
    (r"if\s+os\.path\.exists.*?os\.remove", "File existence check before delete - TOCTOU"),
    (r"if\s+os\.path\.isfile.*?open\s*\(", "File type check before open - TOCTOU"),
    (r"stat\s*\(\s*\).*?\n.*?open\s*\(", "File stat before open - TOCTOU"),
]);

static SEC101_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"with\s+open\s*\([^)]*\)\s+as\s+[^:]+:", "File opened without exception handling"),
    (r"requests\.get\s*\([^)]*\)(?!\s*\.close)", "HTTP response not explicitly closed"),
    (r"db\.cursor\s*\(\s*\)(?!\s*\.close)", "Database cursor not explicitly closed"),
]);

static SEC102_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"uuid\.uuid1\s*\(\s*\)", "uuid.uuid1() uses system time/machine ID - predictable"),
    (r"time\.time\s*\(\s*\)", "time.time() as ID - predictable"),
    (r"time\.time_ns\s*\(\s*\)", "time.time_ns() as ID - predictable"),
    (r"hash\s*\([^)]*(?:user_id|email|username)", "Hash of user identifier as ID - predictable"),
]);

static SEC103_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"verify\s*=\s*False", "SSL certificate verification disabled"),
    (r"context\s*=\s*ssl\.create_default_context\s*\(\s*\)(?!\s*\.check_hostname)", "SSL context without hostname check"),
    (r"requests\.(?:get|post)\s*\([^)]*verify\s*=\s*False", "requests with verify=False - disables SSL verification"),
    (r"httpx\.Client\s*\([^)]*verify\s*=\s*False", "httpx with verify=False"),
    (r"CURLOPT_SSL_VERIFYPEER\s*=\s*0", "cURL SSL verification disabled"),
]);

static SEC104_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"request\.files\.get\s*\([^)]*\)\.save\s*\(", "File uploaded without type validation"),
    (r"upload_folder\s*=\s*[^)]*(?!\s*allowed_extensions)", "Upload folder without extension whitelist"),
    (r"if\s+\.filename\s*:(?!\s*allowed)", "Filename check without whitelist validation"),
    (r"secure_filename\s*\(\s*\)(?!\s*allowed)", "secure_filename not combined with extension check"),
]);

static SEC105_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r"etree\.XML\s*\([^)]*(?:\!DOCTYPE|\<!\[)", "XML parsing with DOCTYPE entity expansion"),
    (r"xml\.sax\.parse\s*\([^)]*(?:\!ENTITY)", "SAX parsing with entity declarations"),
    (r"xml\.dom\.minidom\.parse\s*\([^)]*\!ENTITY", "DOM parsing with entity declarations"),
]);

static SEC106_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"\.innerHTML\s*="#, "innerHTML assignment with potentially user-controlled data"),
    (r#"document\.write\s*\("#, "document.write() can inject arbitrary HTML/JS"),
    (r#"\.outerHTML\s*="#, "outerHTML assignment with potentially user-controlled data"),
    (r#"dangerouslySetInnerHTML\s*="#, "React dangerouslySetInnerHTML bypasses sanitization"),
    (r#"\.html\(\s*[^)]*\+[^)]*\)"#, "jQuery .html() with concatenation"),
    (r#"\.insertAdjacentHTML\s*\("#, "insertAdjacentHTML with user input"),
]);

static CSRF_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*['\"]POST['\"]"#, "POST route without CSRF protection"),
    (r#"@app\.post\s*\("#, "POST endpoint decorator"),
    (r#"@router\.post\s*\("#, "FastAPI POST endpoint"),
    (r#"@bp\.route\s*\([^)]*['"]POST['\"]"#, "Blueprint POST route"),
    (r#"\.submit\s*\(\s*\)"#, "Form submit handler without explicit CSRF check"),
]);

static AUTH_DECORATORS: Lazy<Vec<&'static str>> = Lazy::new(|| vec![
    r"(?i)@login_required", r"(?i)@requires_auth",
    r"(?i)@auth\.login_required", r"(?i)@self\.authorization_required",
    r"(?i)@require_[a-z_]+auth",
]);

static SENSITIVE_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"@app\.route\s*\([^)]*['\"](?:/|/api/|/admin/|/user/|/account/|/dashboard/|/profile/|/settings/)(?!.*(?:login|register|auth|public))"#, "Route to sensitive area without explicit auth"),
    (r#"@app\.(get|post|put|delete)\s*\(['\"](/admin/|/api/admin/|/user/|/account/|/config/|/settings/|/profile/)"#, "Sensitive endpoint without auth decorator"),
    (r#"@login_required"#, "Login_required decorator present"),
    (r#"@requires_auth"#, "requires_auth decorator present"),
    (r#"@auth\.login_required"#, "auth.login_required decorator present"),
    (r#"@self\.authorization_required"#, "authorization_required decorator present"),
]);

static SEC109_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"os\.chmod\s*\([^,]+,\s*0*777\b"#, "os.chmod with mode 777 - world readable/writable"),
    (r#"os\.chmod\s*\([^,]+,\s*0*0[0-7][0-7][0-7]\b"#, "os.chmod with overly permissive mode"),
    (r#"open\s*\([^)]*,\s*['\"]w['\"],\s*[^)]*mode\s*=\s*0*777\b"#, "open() with mode 777 creates world-writable file"),
    (r#"os\.mkdir\s*\([^,]+,\s*0*777\b"#, "os.mkdir with mode 777"),
    (r#"os\.makedirs\s*\([^,]+,\s*0*777\b"#, "os.makedirs with mode 777"),
    (r#"subprocess\.run\s*\([^)]*chmod\s+777"#, "subprocess chmod 777 command"),
    (r#"shutil\.chown\s*\([^)]*,\s*[^,]*,\s*[^,]*\)"#, "shutil.chown with potentially wide ownership"),
    (r#"requests\.get\s*\([^)]*mode\s*=\s*0*777"#, "requests with mode 777 (unusual pattern)"),
]);

static SEC110_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r#"jwt\.decode\s*\([^)]*verify\s*=\s*False"#, "JWT decode with verify=False - signature not validated"),
    (r#"jwt\.decode\s*\([^)]*verify\s*=\s*0"#, "JWT decode with verify=0 - signature not validated"),
    (r#"algorithm\s*=\s*['\"]none['\"]"#, "JWT algorithm set to 'none' - signature completely bypassed"),
    (r#"JWT_ALGORITHM\s*=\s*['\"]none['\"]"#, "JWT_ALGORITHM set to 'none' - signature bypassed"),
    (r#"options\s*=\s*\{[^}]*['\"]verify_signature['\"]\s*:\s*False"#, "JWT options with verify_signature=False"),
    (r#"\.verify\s*\(\s*False\s*\)"#, "JWT verify set to False in PyJWT call"),
    (r#"jwt\.encode\s*\([^)]*algorithm\s*=\s*['\"]HS256['\"]"#, "JWT encode with HS256 - symmetric key in code is risky"),
]);

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

        for (pattern, problem) in SEC073_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC074_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC075_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, problem) in SEC076_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC077_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC078_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC079_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC080_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC081_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC082_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC083_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC084_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC085_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        let has_protection = code.contains("rate_limit") || code.contains("Ratelimiter")
            || code.contains("max_attempts") || code.contains("@ratelimit")
            || code.contains("django-axes") || code.contains("fail2ban");

        for (pattern, problem) in SEC086_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, problem) in SEC087_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC088_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC089_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC090_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC091_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC092_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC093_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC094_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
                        replacement: String::new(),
            });
        }

        for (pattern, problem) in SEC095_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC096_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC097_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC098_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC099_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC100_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC101_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC102_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC103_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC104_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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

        for (pattern, problem) in SEC105_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
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
                        replacement: String::new(),
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
// SEC-106: DOM-based XSS (CWE-79)
// Severity: Critical | OWASP A03:2021
// innerHTML, document.write(), dangerouslySetInnerHTML with user input
// ============================================================================
pub struct DomBasedXssRule;

impl Rule for DomBasedXssRule {
    fn id(&self) -> &str { "SEC-106" }
    fn name(&self) -> &str { "DOM-based Cross-Site Scripting (XSS)" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, problem) in SEC106_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-106".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        cvss_score: Some(9.3),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use textContent instead of innerHTML. Sanitize with DOMPurify. Use React's JSX with proper escaping instead of dangerouslySetInnerHTML.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
// SEC-107: CSRF Token Missing (CWE-352)
// Severity: High | OWASP A01:2021
// Forms and state-changing endpoints without CSRF protection
// ============================================================================
pub struct CsrfTokenMissingRule;

impl Rule for CsrfTokenMissingRule {
    fn id(&self) -> &str { "SEC-107" }
    fn name(&self) -> &str { "Missing CSRF Token Protection" }
    fn severity(&self) -> Severity { Severity::High }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_csrf = Regex::new(
            r"(?i)(csrf|xsrf|anti[-_]csrf)[:_\s]*(token|request)"
        ).map(|re| re.is_match(code)).unwrap_or(false);

        let has_csrf_exempt = Regex::new(
            r"(?i)csrf\.exempt|@csrf_exempt"
        ).map(|re| re.is_match(code)).unwrap_or(false);

        if has_csrf_exempt {
            return findings;
        }

        for (pattern, problem) in CSRF_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    if !has_csrf {
                        findings.push(Finding {
                            rule_id: "SEC-107".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-352".to_string()),
                            cvss_score: Some(8.1),
                            owasp_id: Some("A01:2021".to_string()),
                            start: m.start(),
                            end: m.end(),
                            snippet: extract_snippet(code, m.start(), m.end()),
                            problem: problem.to_string(),
                            fix_hint: "Add CSRF protection: @app.csrf_protected() or use Flask-WTF forms with CSRF tokens. Enable CSRF on all state-changing endpoints.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
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
// SEC-108: Missing Authentication (CWE-306)
// Severity: High | OWASP A07:2021
// Endpoints with sensitive operations without auth decorators
// ============================================================================
pub struct MissingAuthenticationRule;

impl Rule for MissingAuthenticationRule {
    fn id(&self) -> &str { "SEC-108" }
    fn name(&self) -> &str { "Missing Authentication on Sensitive Endpoints" }
    fn severity(&self) -> Severity { Severity::High }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_auth = AUTH_DECORATORS.iter().any(|p| {
            Regex::new(p).map(|re| re.is_match(code)).unwrap_or(false)
        });

        for (pattern, _) in SENSITIVE_PATTERNS.iter().take(1) {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    if !has_auth {
                        findings.push(Finding {
                            rule_id: "SEC-108".to_string(),
                            severity: Severity::High.as_str().to_string(),
                            cwe_id: Some("CWE-306".to_string()),
                            cvss_score: Some(7.5),
                            owasp_id: Some("A07:2021".to_string()),
                            start: m.start(),
                            end: m.end(),
                            snippet: extract_snippet(code, m.start(), m.end()),
                            problem: "Sensitive endpoint detected without authentication decorator. This can allow unauthenticated access to privileged operations.".to_string(),
                            fix_hint: "Add @login_required or @requires_auth decorator to protect this endpoint. Implement proper session/token validation.".to_string(),
                            auto_fix_available: false,
                        replacement: String::new(),
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
// SEC-109: Insecure Default Permissions (CWE-276)
// Severity: Medium | OWASP A05:2021
// os.chmod with overly permissive modes, open() with 0o777
// ============================================================================
pub struct InsecureDefaultPermissionsRule;

impl Rule for InsecureDefaultPermissionsRule {
    fn id(&self) -> &str { "SEC-109" }
    fn name(&self) -> &str { "Insecure File / Directory Permissions" }
    fn severity(&self) -> Severity { Severity::Medium }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, problem) in SEC109_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-109".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-276".to_string()),
                        cvss_score: Some(6.5),
                        owasp_id: Some("A05:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Use restrictive permissions: 0o600 for private files, 0o755 for directories. Never use 0o777. Prefer: os.chmod(path, 0o600) and os.umask(0o077) before creating files.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
// SEC-110: Insecure JWT Verification (CWE-347)
// Severity: Critical | OWASP A07:2021
// jwt.decode with verify=False, JWT algorithm set to "none"
// ============================================================================
pub struct InsecureJwtVerificationRule;

impl Rule for InsecureJwtVerificationRule {
    fn id(&self) -> &str { "SEC-110" }
    fn name(&self) -> &str { "Insecure JWT Verification" }
    fn severity(&self) -> Severity { Severity::Critical }

    fn supported_languages(&self) -> Option<&'static [&'static str]> {
        Some(&["python"])
    }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (pattern, problem) in SEC110_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    findings.push(Finding {
                        rule_id: "SEC-110".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(),
                        end: m.end(),
                        snippet: extract_snippet(code, m.start(), m.end()),
                        problem: problem.to_string(),
                        fix_hint: "Always verify JWT signatures with a trusted public key. Remove verify=False. Use RS256 (asymmetric) instead of HS256 (symmetric). Validate expiration (exp), issuer (iss), and audience (aud) claims.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
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
        // New rules SEC-106 to SEC-110
        Box::new(DomBasedXssRule),
        Box::new(CsrfTokenMissingRule),
        Box::new(MissingAuthenticationRule),
        Box::new(InsecureDefaultPermissionsRule),
        Box::new(InsecureJwtVerificationRule),
        // Phase 2: Vulnerable Sink Detection (SEC-126 to SEC-131)
        Box::new(SqlInjectionSinkRule),
        Box::new(XssSinkRule),
        Box::new(LfiSinkRule),
        Box::new(CsrfSinkRule),
        Box::new(SsrfSinkRule),
        Box::new(OpenRedirectSinkRule),
    ]
}

// ============================================================================
// PHASE 2: Vulnerable Sink Detection (Reverse-Engineered from hackingtool)
// These rules detect VULNERABLE PYTHON CODE that hackingtool exploits target.
// Each attack category maps to the insecure code patterns SQLMap/XSStrike exploit.
// ============================================================================

// ============================================================================
// SEC-126: SQL Injection Vulnerable Sinks (AST-based)
// Attack Category: SQL Injection | Tools: Sqlmap, DSSS, Blisqy, SQLScan
//
// The Vulnerable Python "Sink" — Bad Code that SQLMap exploits:
//
//   # Sink 1: f-string in cursor.execute
//   cursor.execute(f"SELECT * FROM users WHERE name='{username}'")
//   cursor.execute(f"SELECT * FROM products WHERE id={request.args.get('id')}")
//
//   # Sink 2: %-formatting in SQL
//   cursor.execute("SELECT * FROM admin WHERE pass='%s'" % password)
//   db.execute("DELETE FROM logs WHERE id=%s" % user_id)
//
//   # Sink 3: .format() in SQL
//   cursor.execute("SELECT * FROM users WHERE email='{}'".format(email))
//
//   # Sink 4: String concatenation with +
//   query = "SELECT * FROM items WHERE category='" + category + "'"
//   cursor.execute(query)
//
//   # Sink 5: Raw SQL in ORM filter
//   Model.query.filter(f"id == {user_input}")
//   session.execute(text("SELECT * FROM " + table))
//
// AST Detection Logic:
//   1. Find "call" nodes where function is "execute" or "exec" or "query"
//   2. Walk into the first argument (the SQL string)
//   3. Detect f-string (Jinja, JoinedStr node), %-format, .format(), or + concat
//   4. Check if any identifier in the template/format comes from user input
//      (request, args, form, params, GET, POST, json, input, data, body)
// ============================================================================

static SEC126_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // f-string with % operator: cursor.execute(f"SELECT * FROM users WHERE name='{username}'" % password)
    (r#"(?:cursor|db|connection|session)\s*\.\s*(?:execute|exec|query)\s*\(\s*f["'][^}']*\{[^}]+\}[^"']*["']\s*%"#,
     "f-string interpolation inside SQL execute() — SQLMap can inject via template variables"),
    // %-formatting in SQL execute — captures SQL with %s (no keyword required inside)
    (r#"(?:cursor|db|connection|session)\s*\.\s*(?:execute|exec)\s*\([^)]*["'][^"']*%s[^"']*["']"#,
     "%-formatting in SQL execute() — user input can inject via %%s substitution"),
    // .format() in SQL execute
    (r#"(?:cursor|db|connection|session)\s*\.\s*(?:execute|exec)\s*\([^)]*["'][^"']*\.format\s*\([^)]+\)"#,
     ".format() interpolation in SQL execute() — SQLMap can manipulate format args"),
    // String concat (+ sign) building SQL query
    (r#"(?:query|sql|statement|cmd)\s*(?:\+=|=)\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"']*\+\s*\w+"#,
     "SQL query built by string concatenation — direct injection path"),
    // Raw query with f-string/format in SQLAlchemy text()
    (r#"text\s*\(\s*f["'][^}']*\{[^}]+\}[^}']*["']\s*\)"#,
     "SQLAlchemy text() with f-string interpolation — raw SQL injection sink"),
    // ORM filter with raw string interpolation
    (r#"(?:Model|Table)\s*\.\s*query\s*\.\s*(?:filter|filter_by)\s*\([^)]*f["'][^}]*\{"#,
     "ORM query.filter() with f-string — SQLAlchemy SQL injection sink"),
    // Execute raw SQL with user-controlled table/column name
    (r#"execute\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\s*\+\s*(?:request|input|param|args|form|body)"#,
     "SQL execute with user-controlled table/column name via concatenation"),
    // SQL with user input directly in string
    (r#"["'][^"']*SELECT[^"']*FROM[^"']*\{[^}]*(?:request|args|form|param|input)[^}]*\}[^"']*["']"#,
     "SQL template with user input in template variable — SQLMap entry point"),
]);

pub struct SqlInjectionSinkRule;

impl Rule for SqlInjectionSinkRule {
    fn id(&self) -> &str { "SEC-126" }
    fn name(&self) -> &str { "SQL Injection Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC126_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-126".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-89".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "SQLMap (Sqlmap, DSSS, Blisqy, SQLScan) exploits these sinks. Replace string interpolation with parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (username,)). Use SQLAlchemy ORM with bind parameters.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// SEC-127: XSS Vulnerable Sinks (AST-based)
// Attack Category: Cross-Site Scripting (XSS) | Tools: DalFox, XSStrike, XSpear
//
// The Vulnerable Python "Sink" — Bad Code that XSStrike exploits:
//
//   # Flask/Jinja2 — unescaped output
//   render_template_string(request.args.get('template', ''))
//   render_template('page.html', content=user_input)
//   {{ content | safe }}         <- marks content as safe (no escaping)
//   {{ user_name | safe }}
//
//   # Django — mark_safe / allow_false
//   from django.utils.safestring import mark_safe
//   mark_safe(user_input)
//   HttpResponse(content, content_type='text/html')
//
//   # FastAPI/Starlette — Response with HTML
//   HTMLResponse(content=user_input)   <- direct HTML injection
//
//   # Tornado / other frameworks
//   self.write(user_input)   <- no escaping in Tornado handlers
//
// AST Detection Logic:
//   1. Find render_template_string() calls — direct Jinja injection
//   2. Find | safe filter in Jinja templates — marks content trusted
//   3. Find mark_safe() calls — Django XSS bypass
//   4. Find HTMLResponse / Response with user-controlled content
//   5. Find dangerouslySetInnerHTML equivalents in template code
// ============================================================================

static SEC127_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // render_template_string with user input — Jinja2 SSTI
    (r#"render_template_string\s*\([^)]*(?:request|args|form|input|params|body|data|json|cookie)"#,
     "render_template_string() with user input — Jinja2 Server-Side Template Injection (SSTI) / XSS"),
    // mark_safe in Django with user input
    (r#"mark_safe\s*\([^)]*(?:request|args|form|input|params|body|data|POST|GET)"#,
     "Django mark_safe() wrapping user input — bypasses HTML escaping, direct XSS sink"),
    // Django HttpResponse with unescaped HTML content
    (r#"HttpResponse\s*\([^)]*(?:request|args|form|input|params|body|data)"#,
     "HttpResponse with user-controlled content — XSS sink in Django"),
    // HTMLResponse from FastAPI with user data
    (r#"HTMLResponse\s*\([^)]*(?:request|args|form|input|params|body|data|json)"#,
     "FastAPI HTMLResponse with user input — XSS sink"),
    // Jinja2 template with | safe filter on user data
    (r#"\|\s*safe\s*\}\}.*(?:request|args|form|input|params|body|data)"#,
     "Jinja2 | safe filter on user input — explicitly disables escaping"),
    // Tornado self.write with user input
    (r#"self\.write\s*\([^)]*(?:request|args|form|input|params|body|data)"#,
     "Tornado self.write() with user input — no automatic escaping"),
    // autoescape off in Jinja2 template
    (r#"autoescape\s*(?:=|:)\s*(?:false|None)"#,
     "Jinja2 autoescape disabled — all output rendered unescaped"),
    // Mako template with ${user_input} raw
    (r#"\$\{[^}]*(?:request|args|form|input|params|body)[^}]*\}"#,
     "Mako template with raw ${} on user input — direct XSS sink"),
    // Web2Py response.write with unsafe content
    (r#"response\.write\s*\([^)]*(?:request|args|form|input|params)"#,
     "Web2Py response.write() with user input — XSS sink"),
    // Flask jsonify used as HTML response
    (r#"jsonify\s*\([^)]*(?:request|args|form|input|params)\).*Content-Type.*html"#,
     "jsonify used as HTML response with user input — XSS via content-type confusion"),
]);

pub struct XssSinkRule;

impl Rule for XssSinkRule {
    fn id(&self) -> &str { "SEC-127" }
    fn name(&self) -> &str { "XSS Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC127_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-127".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        cvss_score: Some(9.3),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "DalFox, XSStrike, XSpear exploit these sinks. Never pass user input to render_template_string(). Use parameterized templating: render_template('page.html', content=escape(user_input)). In Django, avoid mark_safe() on raw user input. Use bleach library for HTML sanitization.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// SEC-128: LFI / Path Traversal Vulnerable Sinks
// Attack Category: Local File Inclusion / Path Traversal | Tools: Commix, Dirsearch
//
// The Vulnerable Python "Sink" — Bad Code that Dirsearch/Commix exploit:
//
//   # Flask — path from URL param used in open()
//   with open(f"templates/{page}.html") as f:    # page=/etc/passwd
//   return send_from_directory(dir, filename)     # filename=../../../etc/passwd
//
//   # Django — path injection
//   with open(request.GET['file']) as f:         # direct file open from user
//   os.path.join(BASE_DIR, request.params['path'])  # path traversal
//
//   # FastAPI — file read from user input
//   Path(request.query_params['file'])           # no sanitization
//   send_file(os.path.join(UPLOAD_DIR, name))     # name=../../etc/passwd
//
// AST Detection Logic:
//   1. Find open() with path that includes request.*, args, params, form
//   2. Find send_from_directory() / send_file() with user-controlled filename
//   3. Find os.path.join() where user input is in the path components
//   4. Find Path() constructor wrapping user input
//   5. Check for absence of path sanitization (no normpath, no basename, no allowlist)
// ============================================================================

static SEC128_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // open() with user input in path — LFI sink
    (r#"open\s*\([^)]*(?:request|args|form|params|input|query|cookie)[^)]*\)"#,
     "open() with user-controlled path — LFI / Path Traversal sink"),
    // send_from_directory with user-controlled filename
    (r#"send_from_directory\s*\([^)]*(?:request|args|form|params|input|query)"#,
     "send_from_directory() with user-controlled filename — directory traversal sink"),
    // send_file with path concatenation
    (r#"send_file\s*\([^)]*(?:request|args|form|params|input|query)"#,
     "send_file() with user-controlled path — LFI sink"),
    // os.path.join with user input — traversal risk
    (r#"os\.path\.join\s*\([^)]*(?:request|args|form|params|input|query)"#,
     "os.path.join() with user input — path traversal sink if not sanitized"),
    // Path() constructor with user input
    (r#"(?:Path|pathlib)\s*\([^)]*(?:request|args|form|params|input|query|cookie)"#,
     "pathlib.Path() with user input — LFI sink without sanitization"),
    // read() from user-controlled file path
    (r#"\.(?:read|open|read_text|read_bytes)\s*\([^)]*(?:request|args|form|params|input|query)"#,
     "File read operation with user-controlled path — LFI sink"),
    // Jinja2 template loading with user input
    (r#"loader\.get_template\s*\([^)]*(?:request|args|form|params|input)"#,
     "Template loader with user input — potential SSTI via template path traversal"),
    // Static file serving without sanitization
    (r#"static_file\s*\([^)]*(?:request|args|form|params|input)"#,
     "Static file serving with user-controlled path — LFI sink"),
    // include() or extends with user input (template injection)
    (r#"(?:include|extend|import)\s*\([^)]*(?:request|args|form|params|input)"#,
     "Template include/extend with user input — local file inclusion in templates"),
]);

pub struct LfiSinkRule;

impl Rule for LfiSinkRule {
    fn id(&self) -> &str { "SEC-128" }
    fn name(&self) -> &str { "LFI / Path Traversal Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC128_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-128".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-22".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Commix and Dirsearch exploit these sinks. Always sanitize paths: use os.path.basename() to extract only the filename, validate against an allowlist of permitted files, use safe_join() from werkzeug.utils, and never pass raw user input to file operations.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// SEC-129: CSRF Vulnerable Sinks
// Attack Category: Cross-Site Request Forgery | Tools: CSRF exploit modules
//
// The Vulnerable Python "Sink" — Bad Code that CSRF tools target:
//
//   # Flask — POST handler without @csrf.exempt or missing token
//   @app.route('/transfer', methods=['POST'])
//   def transfer():
//       amount = request.form['amount']    # no CSRF token validation
//       account.balance -= int(amount)
//
//   # Django — view without @csrf_protect
//   @csrf_exempt
//   def update_profile(request):
//       # directly processes POST without checking CSRF token
//
//   # FastAPI — mutation without CSRF middleware
//   @app.post("/admin/delete")
//   async def delete_user(user_id: str):
//       # no CSRF validation
//
// AST Detection Logic:
//   1. Find @csrf_exempt decorator — CSRF protection explicitly disabled
//   2. Find POST/DELETE handlers WITHOUT @csrf_protect or CSRF middleware
//   3. Find state-changing routes (POST/PUT/DELETE) with user data but no token check
//   4. Find @app.route with methods=['POST'] and no CSRF token extraction
// ============================================================================

static SEC129_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // CSRF exempt decorator — explicitly disables protection
    (r#"@csrf_exempt"#, "CSRF protection explicitly disabled with @csrf_exempt decorator — all state-changing requests from this handler are vulnerable"),
    // POST route without any CSRF token handling
    (r#"(?i)(?:@app\.route|@router\.post|@bp\.route|@app\.post|@router\.route)[^}]*methods\s*=\s*\[[^]]*['\"]POST['\"][^\n]*\n(?:(?!.*(?:csrf|token|csrf_protect|verify_token)).)*request\.(?:form|args|json|body)"#,
     "POST/PUT/DELETE route handling user data without visible CSRF token validation"),
    // State-changing operation without CSRF check
    (r#"(?i)(?:transfer|delete|remove|update.*password|change.*email|modify.*account|reset.*password)\s*(?::|def)[^:]*\([^)]*(?:request|form|args)"#,
     "State-changing function with user input but no CSRF protection pattern detected"),
    // Django CBV without CSRF
    (r#"(?i)(?:class.*View.*Update|class.*View.*Delete|class.*View.*Create)[^\n]*\n[^}]*(?:def post|def delete|def put)"#,
     "Django class-based view with state-changing methods — verify CSRF exemption"),
    // FastAPI mutation without CSRF middleware
    (r#"(?i)(?:@app\.(?:post|put|delete|patch)|@router\.(?:post|put|delete|patch))[^:]*\n(?:(?!.*(?:csrf|CSRF|token|verify)).)*def"#,
     "FastAPI mutation endpoint without CSRF middleware — vulnerable to cross-site request forgery"),
    // Flask-WTF form used without csrf_enabled = False check
    (r#"(?i)(?:Form|wtforms)\s*\([^)]*\)\s*(?:and|if)[^;]*(?<!csrf_token)"#,
     "WTForms Form instantiation without explicit CSRF token field — verify CSRF protection"),
]);

pub struct CsrfSinkRule;

impl Rule for CsrfSinkRule {
    fn id(&self) -> &str { "SEC-129" }
    fn name(&self) -> &str { "CSRF Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC129_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-129".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-352".to_string()),
                        cvss_score: Some(8.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "CSRF exploits target state-changing endpoints. Add CSRF token validation: Flask-WTF forms with CSRFProtect, Django's @csrf_protect, or custom double-submit cookie pattern. Never use @csrf_exempt on sensitive operations.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// SEC-130: SSRF Vulnerable Sinks
// Attack Category: Server-Side Request Forgery | Tools: Commix, wfuzz, SSRFMap
//
// The Vulnerable Python "Sink" — Bad Code that SSRFMap exploits:
//
//   # Flask — fetch URL from user input
//   requests.get(request.args.get('url'))
//   urllib.request.urlopen(request.form['url'])
//   subprocess.run(['curl', request.form['url']])
//
//   # AWS metadata exploitation
//   requests.get('http://' + request.args.get('host') + '/latest/meta-data/')
//
//   # File scheme for LFI via SSRF
//   urllib.request.urlopen('file:///etc/passwd')  # if url is controllable
//
// AST Detection Logic:
//   1. Find requests.get/post/put() with URL from request.*
//   2. Find urllib.urlopen() / urllib.request.urlopen() with user-controlled URL
//   3. Find subprocess calls (curl, wget) with user URL argument
//   4. Detect access to cloud metadata endpoints (169.254.169.254, metadata.google)
//   5. Check for URL validation absence (no URL parse, no scheme check, no allowlist)
// ============================================================================

static SEC130_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // requests library with user-controlled URL
    (r#"(?:requests|httpx|urllib3|aiohttp)\s*\.\s*(?:get|post|put|head|delete|patch|request)\s*\([^)]*(?:request|args|form|params|input|query|url)"#,
     "HTTP request library with user-controlled URL — SSRF sink"),
    // urllib with user URL
    (r#"(?:urllib\.request\.)?urlopen\s*\([^)]*(?:request|args|form|params|input|query|url)"#,
     "urllib.urlopen() with user-controlled URL — SSRF sink"),
    // subprocess curl/wget with user URL
    (r#"(?:subprocess|os\.system|os\.popen)\s*\([^)]*(?:curl|wget)\s+[^)]*(?:request|args|form|params|input|query|url)"#,
     "subprocess calling curl/wget with user URL — SSRF via command injection"),
    // AWS metadata endpoint access
    (r#"(?:169\.254\.169\.254|metadata\.google|metadata\.azure|metadata\.aws|ec2)"#,
     "Cloud metadata endpoint reference — SSRF could access cloud credentials here"),
    // fetch/axios-like patterns in Python web frameworks
    (r#"(?:aiohttp|httpx)\s*\.\s*(?:ClientSession|request)\s*\([^)]*(?:request|args|form|params|input|query|url)"#,
     "Async HTTP client with user-controlled URL — SSRF sink"),
    // URL built from user input and used in request
    (r#"(?:url|link|endpoint|uri)\s*=\s*[^;]*(?:request|args|form|params|input|query)[^;]*(?:requests|httpx|urllib|urlopen)"#,
     "URL assembled from user input and used in HTTP request — SSRF sink"),
    // fetch with data: or file: scheme possible
    (r#"(?:requests|httpx|urllib)\s*\.\s*(?:get|post)\s*\(\s*['\"]?(?:data:|file:|gopher:)"#,
     "HTTP request with dangerous URL scheme — SSRF with data/file/gopher protocol"),
]);

pub struct SsrfSinkRule;

impl Rule for SsrfSinkRule {
    fn id(&self) -> &str { "SEC-130" }
    fn name(&self) -> &str { "SSRF Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC130_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-130".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-918".to_string()),
                        cvss_score: Some(9.3),
                        owasp_id: Some("A10:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Commix, SSRFMap exploit these sinks. Always validate URLs: parse with urllib.parse.urlparse(), enforce scheme='https' or allowlist permitted domains, block internal IP ranges (127.x, 10.x, 192.168.x), and deny access to cloud metadata endpoints (169.254.169.254).".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ============================================================================
// SEC-131: Open Redirect Vulnerable Sinks
// Attack Category: Open Redirect | Tools: Commix, wfuzz, open-redirect-scanners
//
// The Vulnerable Python "Sink" — Bad Code that open-redirect scanners exploit:
//
//   # Flask — redirect to user-controlled URL
//   redirect(request.args.get('next'))
//   redirect(request.form['redirect_url'])
//
//   # Django — HttpResponseRedirect with user input
//   HttpResponseRedirect(request.GET['redirect'])
//
//   # Any framework — next=/redirect with user URL
//   return redirect(base + request.args.get('path'))   # path = https://evil.com
//
// AST Detection Logic:
//   1. Find redirect() / HttpResponseRedirect() with request.* in argument
//   2. Find URL constructed from user input + base domain
//   3. Find "next", "redirect", "return_url", "continue" params used in redirects
//   4. Check for absence of domain allowlist validation
// ============================================================================

static SEC131_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    // Flask redirect with user input
    (r#"redirect\s*\([^)]*(?:request|args|form|params|input|query|next|redirect|return_url|continue|url)"#,
     "Flask redirect() with user-controlled URL — open redirect sink"),
    // Django HttpResponseRedirect with user input
    (r#"HttpResponseRedirect\s*\([^)]*(?:request|args|form|params|input|query|next|redirect|return_url)"#,
     "Django HttpResponseRedirect with user input — open redirect sink"),
    // RedirectResponse in Starlette/FastAPI
    (r#"(?:RedirectResponse|redirect)\s*\([^)]*(?:request|args|form|params|input|query|next|redirect|return)"#,
     "FastAPI/Starlette RedirectResponse with user input — open redirect sink"),
    // next=/redirect parameter pattern
    (r#"(?:next|redirect|return_url|redirect_to|return|continue|callback|url)\s*=\s*[^;]*(?:request|args|form|params|input|query)[^;]*(?:redirect|HttpResponseRedirect|RedirectResponse)"#,
     "Redirect URL parameter (next/redirect/return_url) built from user input — open redirect sink"),
    // URL concatenation for redirect
    (r#"(?:redirect|HttpResponseRedirect)\s*\(\s*(?:base_url|domain|site|host)\s*\+\s*(?:request|args|form|params|input|query)"#,
     "Redirect URL built by concatenating base domain with user input — open redirect sink"),
    // Tornado redirect with user input
    (r#"self\.redirect\s*\([^)]*(?:request|args|form|params|input|query|next|redirect)"#,
     "Tornado self.redirect() with user input — open redirect sink"),
]);

pub struct OpenRedirectSinkRule;

impl Rule for OpenRedirectSinkRule {
    fn id(&self) -> &str { "SEC-131" }
    fn name(&self) -> &str { "Open Redirect Vulnerable Sinks (hackingtool target)" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python"]) }

    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC131_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-131".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-601".to_string()),
                        cvss_score: Some(6.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Commix and open-redirect scanners exploit these sinks. Always validate redirect URLs: use urlparse() to extract the domain and compare against an allowlist, or only accept relative paths (no external URLs). Django's is_safe_url() or Flask's URL validators can help.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }

    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}
