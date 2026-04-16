"""Central registry for all 50+ security rules.

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

This registry contains metadata for every security rule, including:
- Severity classification (critical/high/medium/low/info)
- CWE and OWASP mappings
- CVSS scores and vectors
- Fix guidance (constraints, do_not, verify, resources)
- Auto-fix availability

Registry lookup by rule_id returns a frozen dataclass that can be serialized
to JSON for CLI output and CI/CD integration.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional


@dataclass(frozen=True)
class SecurityRuleMetadata:
    """Immutable metadata for a single security rule."""
    id: str                    # SEC-001, SEC-010, ...
    name: str                 # Human-readable name
    description: str          # What the rule detects
    severity: str             # SecuritySeverity level
    cwe_id: str              # CWE-78, CWE-89, ...
    cwe_name: str            # OS Command Injection
    owasp_id: str            # A01, A02, ... (empty string if not mapped)
    owasp_name: str          # Broken Access Control
    cvss_base: float         # CVSS 3.1 base score 0.0-10.0
    cvss_vector: str         # Full CVSS vector string
    can_auto_fix: bool       # Is auto-fix conceptually possible?
    auto_fix_available: bool # Is auto-fix implemented?
    fix_constraints: Tuple[str, ...]    # What you MUST do
    do_not: Tuple[str, ...]             # Common mistakes to avoid
    verify: Tuple[str, ...]              # How to verify the fix
    resources: Tuple[str, ...]            # Links to documentation
    examples: Tuple[str, ...]             # Code examples
    example_snippet: str                 # Detected snippet template


# --------------------------------------------------------------------------
# Registry data — all 50+ rules
# --------------------------------------------------------------------------

SECURITY_RULES_REGISTRY: Dict[str, SecurityRuleMetadata] = {

    # ========================================================================
    # CRITICAL (5 rules) — Must fix immediately
    # ========================================================================

    "SEC-001": SecurityRuleMetadata(
        id="SEC-001",
        name="Command Injection",
        description="Detects command injection via os.system(), subprocess.run(..., shell=True), os.popen()",
        severity="critical",
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        owasp_id="A03",
        owasp_name="Injection",
        cvss_base=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use subprocess.run() with list arguments and shell=False",
            "Validate and escape all user input before passing to shell commands",
            "Use shlex.quote() for shell argument escaping",
        ),
        do_not=(
            "Do NOT add only strip() or basic sanitization",
            "Do NOT wrap in try/except without fixing the root cause",
            "Do NOT assume input is safe because it comes from 'trusted' source",
        ),
        verify=(
            "Test with payloads: '; rm -rf /', '$(whoami)', '`id`'",
            "Ensure no shell metacharacters: $ ` ; | & < > ( ) [ ] { } ! #",
            "Use parameterized approach: subprocess.run(['git', 'commit', '-m', msg])",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://docs.python.org/3/library/subprocess.html#security-considerations",
        ),
        examples=(
            "os.system(user_input)",
            "subprocess.run(cmd, shell=True)",
            "os.popen(f'ls {user_path}')",
        ),
        example_snippet='os.system(f"git commit -m \\"{user_msg}\\"")',
    ),

    "SEC-002": SecurityRuleMetadata(
        id="SEC-002",
        name="SQL Injection",
        description="Detects SQL injection via string concatenation in SQL queries",
        severity="critical",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_id="A03",
        owasp_name="Injection",
        cvss_base=9.9,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use parameterized queries (placeholders) exclusively",
            "Never concatenate user input into SQL strings",
            "Use an ORM (SQLAlchemy, Django ORM) when possible",
        ),
        do_not=(
            "Do NOT use string formatting (f-strings, .format()) for SQL",
            "Do NOT rely on input validation alone",
            "Do NOT use escaping as a substitute for parameterized queries",
        ),
        verify=(
            "Test with: ' OR '1'='1', '; DROP TABLE users; --",
            "Use SQLi detection tools (sqlmap) against your own code",
            "Ensure all database queries use parameterized approach",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ),
        examples=(
            "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            "cursor.execute('SELECT * FROM users WHERE name=' + username)",
        ),
        example_snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
    ),

    "SEC-003": SecurityRuleMetadata(
        id="SEC-003",
        name="Eval/Exec Usage",
        description="Detects dangerous use of eval() and exec() with dynamic code execution",
        severity="critical",
        cwe_id="CWE-95",
        cwe_name="Eval Injection",
        owasp_id="A03",
        owasp_name="Injection",
        cvss_base=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Replace eval()/exec() with safer alternatives",
            "Use AST parsing for safe expression evaluation",
            "Use restricted environments (sandboxing) only if absolutely necessary",
        ),
        do_not=(
            "Do NOT use eval() with any user input",
            "Do NOT assume the input is 'safe' because it is 'validated'",
            "Do NOT use eval() for performance optimization",
        ),
        verify=(
            "Audit all eval/exec calls and document why they are necessary",
            "Test with: __import__('os').system('ls')",
            "Replace with: ast.literal_eval() for JSON-like data, or custom parsers",
        ),
        resources=(
            "https://docs.python.org/3/library/functions.html#eval",
            "https://nedbatchelder.com/blog/201206/eval_really_dangerous.html",
        ),
        examples=(
            "eval(user_expression)",
            "exec(user_code)",
            "eval(f'os.{user_func}()')",
        ),
        example_snippet="eval(user_expression)",
    ),

    "SEC-004": SecurityRuleMetadata(
        id="SEC-004",
        name="Deserialization RCE",
        description="Detects pickle.loads() and yaml.unsafe_load() that can lead to RCE",
        severity="critical",
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        owasp_id="A08",
        owasp_name="Software and Data Integrity Failures",
        cvss_base=9.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use json.loads() instead of pickle for data exchange",
            "Use yaml.safe_load() exclusively for YAML",
            "Implement digital signatures for pickled data if pickle is required",
            "Use restricted unpickler with custom Unpickler subclass",
        ),
        do_not=(
            "Do NOT unpickle data from untrusted sources",
            "Do NOT use yaml.load() without Loader parameter",
            "Do NOT assume pickle is safe because data is 'compressed' or 'encoded'",
        ),
        verify=(
            "Test pickle with: __import__('os').system('ls')",
            "Replace with: json.loads() or MessagePack",
            "For YAML: always use yaml.safe_load() or yaml.unsafe_load() with SafeLoader",
        ),
        resources=(
            "https://docs.python.org/3/library/pickle.html",
            "https://github.com/sickcodes/security/blob/master/pocs/pickle_cve_2011_2522.py",
            "https://pyyaml.readthedocs.io/en/latest/library/yaml.html#yaml.safe_load",
        ),
        examples=(
            "pickle.loads(untrusted_data)",
            "yaml.load(user_yaml)",
            "marshal.loads(data)",
        ),
        example_snippet="pickle.loads(user_data)",
    ),

    "SEC-005": SecurityRuleMetadata(
        id="SEC-005",
        name="Path Traversal",
        description="Detects unsanitized file path operations that may allow path traversal attacks",
        severity="critical",
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        owasp_id="A01",
        owasp_name="Broken Access Control",
        cvss_base=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Validate and sanitize all user-supplied file paths",
            "Use os.path.realpath() to resolve symlinks and normalize paths",
            "Use a whitelist of allowed directories",
            "Never concatenate user input directly into file paths",
        ),
        do_not=(
            "Do NOT rely on string replacement (strip('../')) alone",
            "Do NOT check for '..' only at the start of the path",
            "Do NOT assume the path is safe because it has a known prefix",
        ),
        verify=(
            "Test with: ../../../etc/passwd, ..%2F..%2F..%2Fetc%2Fpasswd",
            "Ensure realpath stays within allowed directory",
            "Use: pathlib.Path(base).resolve() and check .is_relative_to()",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.miter.org/data/definitions/22.html",
        ),
        examples=(
            "open(user_filename)",
            "os.path.join(base, user_input)",
            "Path(user_path) / filename",
        ),
        example_snippet='open(f"uploads/{user_filename}")',
    ),

    # ========================================================================
    # HIGH (10 rules)
    # ========================================================================

    "SEC-010": SecurityRuleMetadata(
        id="SEC-010",
        name="Hardcoded Secrets",
        description="Detects hardcoded API keys, passwords, tokens, and credentials in source code",
        severity="high",
        cwe_id="CWE-798",
        cwe_name="Use of Hard-coded Credentials",
        owasp_id="A07",
        owasp_name="Identification and Authentication Failures",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Move all secrets to environment variables",
            "Use python-dotenv (.env files) for local development",
            "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) in production",
            "Never commit .env files to version control",
        ),
        do_not=(
            "Do NOT hardcode any secret value in source code",
            "Do NOT commit .env files or credentials to git",
            "Do NOT use placeholder values (e.g., 'changeme') in production",
        ),
        verify=(
            "Run: git log --all --full-history -S 'password='",
            "Use: gitleaks, trufflehog, or git-secrets to scan repos",
            "Ensure .gitignore excludes .env files",
        ),
        resources=(
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://12factor.net/config",
        ),
        examples=(
            "api_key = 'sk-abc123...'",
            "password = 'hunter2'",
            "SECRET_KEY = 'dev-secret-key'",
        ),
        example_snippet="api_key = 'sk-live-abc123DEF456'",
    ),

    "SEC-011": SecurityRuleMetadata(
        id="SEC-011",
        name="Weak Cryptography",
        description="Detects weak hashing (MD5, SHA1) and weak encryption algorithms",
        severity="high",
        cwe_id="CWE-327",
        cwe_name="Use of Weak Cryptographic Algorithm",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use hashlib.sha256() or hashlib.sha3_256() for integrity checks",
            "Use hashlib.pbkdf2_hmac() or argon2-cffi for password hashing",
            "Use secrets.token_hex() for token generation",
            "Use TLS 1.2+ for network encryption",
        ),
        do_not=(
            "Do NOT use MD5 or SHA1 for password hashing or security purposes",
            "Do NOT use DES or 3DES for encryption",
            "Do NOT use random module for cryptographic randomness",
        ),
        verify=(
            "Replace MD5/SHA1 with SHA-256 or SHA-3 for integrity",
            "Use bcrypt, argon2, or scrypt for password hashing",
            "Check: hashlib.algorithms_guaranteed contains the algorithm",
        ),
        resources=(
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://docs.python.org/3/library/hashlib.html",
            "https://docs.python.org/3/library/secrets.html",
        ),
        examples=(
            "hashlib.md5(data)",
            "hashlib.sha1(data)",
            "ssl._create_unverified_context()",
        ),
        example_snippet="hashlib.md5(password.encode()).hexdigest()",
    ),

    "SEC-012": SecurityRuleMetadata(
        id="SEC-012",
        name="Insecure SSL/TLS",
        description="Detects insecure SSL context creation that disables certificate verification",
        severity="high",
        cwe_id="CWE-295",
        cwe_name="Improper Certificate Validation",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Always verify SSL certificates in production",
            "Use the default SSL context with proper verification",
            "Configure CA certificates properly for corporate proxies",
        ),
        do_not=(
            "Do NOT use ssl._create_unverified_context() in production",
            "Do NOT disable cert verification for 'testing' without reverting",
            "Do NOT ignore SSL warnings",
        ),
        verify=(
            "Check SSL certificate chain: ssl.create_default_context()",
            "Test with: requests.get(url, verify=True)",
            "Use: urllib3.util.ssl_.create_urllib3_context()",
        ),
        resources=(
            "https://docs.python.org/3/library/ssl.html#ssl.SSLContext",
            "https://urllib3.readthedocs.io/en/latest/user-guide.html#certificate-verification",
        ),
        examples=(
            "ssl._create_unverified_context()",
            "requests.get(url, verify=False)",
            "urllib3.disable_warnings()",
        ),
        example_snippet="ssl._create_unverified_context()",
    ),

    "SEC-013": SecurityRuleMetadata(
        id="SEC-013",
        name="XML External Entity (XXE)",
        description="Detects XML parsing without safe settings that allows XXE attacks",
        severity="high",
        cwe_id="CWE-611",
        cwe_name="XML External Entity (XXE) Reference",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Disable DTD processing in XML parsers",
            "Use defusedxml library for untrusted XML",
            "Configure XML parsers with safe defaults",
        ),
        do_not=(
            "Do NOT parse XML from untrusted sources without safe settings",
            "Do NOT use xml.etree.ElementTree.parse() with default settings",
            "Do NOT load DTDs from untrusted sources",
        ),
        verify=(
            "Test XXE with: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "Use: defusedxml.cElementTree instead of xml.etree",
            "Disable: resolve_entities=False, no_network=True",
        ),
        resources=(
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://github.com/tiran/defusedxml",
        ),
        examples=(
            "xml.etree.ElementTree.parse(user_xml)",
            "xml.dom.minidom.parseString(user_xml)",
            "lxml.etree.parse(user_xml)",
        ),
        example_snippet="ET.parse(user_xml_file)",
    ),

    "SEC-014": SecurityRuleMetadata(
        id="SEC-014",
        name="YAML Unsafe Load",
        description="Detects yaml.load() without SafeLoader that can execute arbitrary code",
        severity="high",
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        owasp_id="A08",
        owasp_name="Software and Data Integrity Failures",
        cvss_base=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=True,
        auto_fix_available=True,
        fix_constraints=(
            "Always use yaml.safe_load() instead of yaml.load()",
            "If unsafe loading is needed, use yaml.unsafe_load() with documented justification",
        ),
        do_not=(
            "Do NOT use yaml.load() without specifying Loader=",
            "Do NOT load YAML from untrusted sources without safe loading",
        ),
        verify=(
            "Replace: yaml.load(data) -> yaml.load(data, Loader=yaml.SafeLoader)",
            "Test with Python payload in YAML",
        ),
        resources=(
            "https://pyyaml.readthedocs.io/en/latest/library/yaml.html#yaml.safe_load",
            "https://RuThinkAboutIt.com/exploring-code-execution-in-yaml/",
        ),
        examples=(
            "yaml.load(user_yaml)",
            "yaml.load(data)",
            "yaml.unsafe_load(user_yaml)",
        ),
        example_snippet="yaml.load(user_yaml)",
    ),

    "SEC-015": SecurityRuleMetadata(
        id="SEC-015",
        name="Assert in Production",
        description="Detects assert statements that may be disabled in production Python",
        severity="high",
        cwe_id="CWE-573",
        cwe_name="Improper Following of Specification",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Replace assert with explicit if-raise for security-critical checks",
            "Move security checks outside of assert statements",
            "Use proper validation functions",
        ),
        do_not=(
            "Do NOT use assert for input validation in production code",
            "Do NOT rely on assertions for security-critical logic",
            "Python's -O flag disables all assertions",
        ),
        verify=(
            "Search for: assert statements that check permissions, auth, or security",
            "Replace with: if not condition: raise PermissionError(...)",
        ),
        resources=(
            "https://docs.python.org/3/using/cmdline.html#cmdoption-O",
            "https://stackoverflow.com/questions/1271154",
        ),
        examples=(
            "assert is_admin, 'Not admin'",
            "assert has_permission, 'No access'",
            "assert user_authenticated",
        ),
        example_snippet="assert is_admin, 'Not authorized'",
    ),

    "SEC-016": SecurityRuleMetadata(
        id="SEC-016",
        name="Debug Mode Enabled",
        description="Detects DEBUG=True or debug mode in web frameworks that expose internals",
        severity="high",
        cwe_id="CWE-11",
        cwe_name="Incorrect Permission Assignment",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Set DEBUG=False in production",
            "Use environment variables for debug configuration",
            "Never deploy with debug mode enabled in production",
        ),
        do_not=(
            "Do NOT commit DEBUG=True to production code",
            "Do NOT use debug mode as a 'feature'",
            "Do NOT assume DEBUG is safe because the app 'needs' it",
        ),
        verify=(
            "Check: app.config['DEBUG'] is False in production config",
            "Use: environment variables (DEBUG=false) for configuration",
            "Verify: no debug endpoints or stack traces in production",
        ),
        resources=(
            "https://flask.palletsprojects.com/en/latest/config/",
            "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
        ),
        examples=(
            "DEBUG=True",
            "app.config['DEBUG'] = True",
            "app.run(debug=True)",
        ),
        example_snippet="DEBUG = True",
    ),

    "SEC-017": SecurityRuleMetadata(
        id="SEC-017",
        name="CORS Wildcard",
        description="Detects CORS configurations that allow all origins, exposing APIs",
        severity="high",
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-Domain Policy",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Specify explicit allowed origins instead of '*'",
            "Use environment-based CORS configuration",
            "Validate Origin header against whitelist",
        ),
        do_not=(
            "Do NOT use CORS(allow_all='*') in production",
            "Do NOT allow credentials with wildcard origins",
            "Do NOT expose sensitive APIs without proper CORS restrictions",
        ),
        verify=(
            "Check: cors_allowed_origins is not ['*'] in production",
            "Use: specific domains in allowlist",
        ),
        resources=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Cross_Site_Request_Forgery",
        ),
        examples=(
            "CORS(app, resources={'/api/*': {'origins': '*'}}",
            "Access-Control-Allow-Origin: *",
            "@app.route('/api') @cross_origin(origins='*')",
        ),
        example_snippet="Access-Control-Allow-Origin: *",
    ),

    "SEC-018": SecurityRuleMetadata(
        id="SEC-018",
        name="JWT None Algorithm",
        description="Detects JWT token verification with 'none' algorithm vulnerability",
        severity="high",
        cwe_id="CWE-347",
        cwe_name="Improper Verification of Cryptographic Signature",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=9.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Always specify and verify the expected algorithm",
            "Reject tokens with 'none' algorithm",
            "Use a library that prevents algorithm confusion attacks",
        ),
        do_not=(
            "Do NOT accept tokens without verifying signature",
            "Do NOT rely solely on client-specified algorithm",
            "Do NOT use asymmetric algorithms when symmetric is expected",
        ),
        verify=(
            "Test JWT with: header {'alg': 'none', 'typ': 'JWT'}",
            "Ensure algorithm is validated server-side",
            "Use: PyJWT with algorithm='HS256' explicitly set",
        ),
        resources=(
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://pyjwt.readthedocs.io/en/latest/algorithms.html",
        ),
        examples=(
            "jwt.decode(token, options={'verify_signature': False})",
            "jwt.decode(token, algorithms=['none'])",
            "PyJWT().decode(token, options={'verify_signature': False})",
        ),
        example_snippet="jwt.decode(token, verify=False)",
    ),

    "SEC-019": SecurityRuleMetadata(
        id="SEC-019",
        name="Weak Random Number Generator",
        description="Detects use of random module for security-sensitive operations",
        severity="high",
        cwe_id="CWE-338",
        cwe_name="Use of Cryptographically Weak PRNG",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use secrets module for security-sensitive randomness",
            "Use secrets.token_hex() for tokens",
            "Use secrets.choice() for secure selection",
        ),
        do_not=(
            "Do NOT use random.random() for security tokens or passwords",
            "Do NOT use random.randint() for session IDs or API keys",
            "Do NOT use random.choice() for security-sensitive selections",
        ),
        verify=(
            "Replace: random.choice() -> secrets.choice()",
            "Replace: random.randint() for tokens -> secrets.randbelow()",
            "Use: secrets.token_hex(32) for API keys",
        ),
        resources=(
            "https://docs.python.org/3/library/secrets.html",
            "https://owasp.org/www-community/Insecure_Randomness",
        ),
        examples=(
            "random.choice(alphabet)",
            "random.randint(0, 100)",
            "''.join(random.choices(charset, k=length))",
        ),
        example_snippet="token = ''.join(random.choices(charset, k=32))",
    ),

    # ========================================================================
    # MEDIUM (15 rules)
    # ========================================================================

    "SEC-020": SecurityRuleMetadata(
        id="SEC-020",
        name="LDAP Injection",
        description="Detects LDAP query construction that may allow LDAP injection",
        severity="medium",
        cwe_id="CWE-90",
        cwe_name="LDAP Injection",
        owasp_id="A03",
        owasp_name="Injection",
        cvss_base=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Escape special LDAP characters in user input",
            "Use parameterized LDAP queries when available",
            "Validate input against a strict allowlist",
        ),
        do_not=(
            "Do NOT concatenate user input into LDAP DN or filter strings",
            "Do NOT trust LDAP responses without validation",
        ),
        verify=(
            "Test with: * ( ) \\ NUL character",
            "Use ldap.filter.escape_filter_chars() for filtering",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/LDAP_Injection",
        ),
        examples=(
            'ldap.search_s(f"dc={user_input},dc=com")',
            'ldapConn.search_s(f"uid={username},ou=people,dc=x")',
        ),
        example_snippet='ldap.search_s(f"dc={user_input},dc=com")',
    ),

    "SEC-021": SecurityRuleMetadata(
        id="SEC-021",
        name="Cross-Site Scripting (XSS)",
        description="Detects potential XSS vulnerabilities in template rendering",
        severity="medium",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        owasp_id="A03",
        owasp_name="Injection",
        cvss_base=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Always escape user input in HTML templates",
            "Use auto-escaping template engines (Jinja2 default)",
            "Implement Content Security Policy (CSP) headers",
        ),
        do_not=(
            "Do NOT mark user input as safe without thorough sanitization",
            "Do NOT use |safe in Jinja2 unless absolutely necessary",
            "Do NOT insert raw HTML from user input",
        ),
        verify=(
            "Test with: <script>alert('XSS')</script>",
            "Use: |escape filter or autoescape in templates",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/xss/",
            "https://jinja.palletsprojects.com/en/latest/templates/#html",
        ),
        examples=(
            'render_template_string(user_html)',
            '{{ user_input | safe }}',
            'MarkSafe(user_input)',
        ),
        example_snippet='render_template_string(user_html)',
    ),

    "SEC-022": SecurityRuleMetadata(
        id="SEC-022",
        name="Server-Side Request Forgery (SSRF)",
        description="Detects URL fetching with user-controlled URLs that may cause SSRF",
        severity="medium",
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
        owasp_id="A10",
        owasp_name="Server-Side Request Forgery",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Validate and sanitize all user-supplied URLs",
            "Use allowlist for permitted domains and protocols",
            "Block internal IP ranges (10.x, 192.168.x, 127.0.0.1, etc.)",
            "Disable unused URL schemes (file://, dict://, etc.)",
        ),
        do_not=(
            "Do NOT fetch URLs without validating against allowlist",
            "Do NOT allow file:// scheme for fetched URLs",
            "Do NOT assume localhost is safe",
        ),
        verify=(
            "Test with: http://169.254.169.254/ (AWS metadata)",
            "Test with: http://localhost/admin",
            "Use: urllib.parse.urlparse() to validate URL components",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://portswigger.net/web-security/ssrf",
        ),
        examples=(
            "requests.get(user_url)",
            "urllib.request.urlopen(user_provided_url)",
            "httpx.get(url=from_user)",
        ),
        example_snippet="requests.get(user_url)",
    ),

    "SEC-023": SecurityRuleMetadata(
        id="SEC-023",
        name="Open Redirect",
        description="Detects URL redirects that can be manipulated for phishing attacks",
        severity="medium",
        cwe_id="CWE-601",
        cwe_name="URL Redirect to Untrusted Site",
        owasp_id="A01",
        owasp_name="Broken Access Control",
        cvss_base=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Validate redirect URLs against an allowlist",
            "Never use user input directly in redirect destinations",
            "Use relative URLs when possible",
        ),
        do_not=(
            "Do NOT redirect based on user-supplied query parameters",
            "Do NOT use raw URLs from user input for redirects",
        ),
        verify=(
            "Test with: https://trusted.com@evil.com",
            "Validate against allowlist of safe domains",
        ),
        resources=(
            "https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards",
        ),
        examples=(
            'redirect(request.args.get("next"))',
            'return redirect(user_url)',
            'return redirect(f"/redirect?url={target}")',
        ),
        example_snippet='redirect(request.args.get("next"))',
    ),

    "SEC-024": SecurityRuleMetadata(
        id="SEC-024",
        name="Mass Assignment",
        description="Detects object attribute assignment that may allow mass assignment attacks",
        severity="medium",
        cwe_id="CWE-915",
        cwe_name="Improperly Controlled Modification of Dynamic Object Attributes",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use explicit field assignment instead of dict-to-object mapping",
            "Define explicit allowed and forbidden fields",
            "Use serializers with field allowlists",
        ),
        do_not=(
            "Do NOT blindly assign request data to model objects",
            "Do NOT use update() or setattr() with unfiltered input",
        ),
        verify=(
            "Audit ORM/model update patterns",
            "Use Pydantic or Marshmallow schemas for input validation",
        ),
        resources=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Granting_Account",
        ),
        examples=(
            "User(**request.form)",
            "obj.__dict__.update(request.json)",
            "for key, val in data.items(): setattr(obj, key, val)",
        ),
        example_snippet="User(**request.form)",
    ),

    "SEC-025": SecurityRuleMetadata(
        id="SEC-025",
        name="Race Condition (TOCTOU)",
        description="Detects time-of-check-time-of-use race conditions in file operations",
        severity="medium",
        cwe_id="CWE-362",
        cwe_name="Race Condition",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=6.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use atomic file operations where possible",
            "Use file locking (fcntl.flock, fasteners) for check-then-act patterns",
            "Use os.rename() instead of check-then-rename for atomic moves",
        ),
        do_not=(
            "Do NOT check file existence then open/create without locking",
            "Do NOT use temporary files without proper synchronization",
        ),
        verify=(
            "Use: tempfile.NamedTemporaryFile with delete=False + os.replace()",
            "Use: fasteners interprocess locks",
        ),
        resources=(
            "https://cwe.mitre.org/data/definitions/362.html",
            "https://docs.python.org/3/library/tempfile.html",
        ),
        examples=(
            "if not os.path.exists(path): open(path, 'w')",
            "os.access(f'/tmp/{user}', os.W_OK)",
            "if os.path.isfile(f): os.remove(f)",
        ),
        example_snippet="if not os.path.exists(path): open(path, 'w')",
    ),

    "SEC-026": SecurityRuleMetadata(
        id="SEC-026",
        name="Insecure Temporary Files",
        description="Detects use of insecure temporary file creation patterns",
        severity="medium",
        cwe_id="CWE-377",
        cwe_name="Insecure Temporary File",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.2,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use tempfile.mkstemp() or tempfile.TemporaryFile()",
            "Use tempfile.NamedTemporaryFile with delete=True",
            "Set restrictive file permissions (0o600) on temp files",
        ),
        do_not=(
            "Do NOT use mktemp() for generating temporary file names",
            "Do NOT create temp files in world-writable directories",
        ),
        verify=(
            "Replace: mktemp() with tempfile.mkstemp()",
            "Ensure temp file permissions are 0600",
        ),
        resources=(
            "https://docs.python.org/3/library/tempfile.html",
        ),
        examples=(
            "tempfile.mktemp()",
            "open('/tmp/tmpfile', 'w')",
            "NamedTemporaryFile(dir='/tmp/')",
        ),
        example_snippet="tempfile.mktemp()",
    ),

    "SEC-027": SecurityRuleMetadata(
        id="SEC-027",
        name="Predictable Random for Non-Security",
        description="Detects use of Mersenne Twister random for non-security but sensitive operations",
        severity="medium",
        cwe_id="CWE-338",
        cwe_name="Use of Cryptographically Weak PRNG",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:U",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use secrets module for any operation that could affect security",
            "Use random module only for non-security purposes (games, UI, etc.)",
        ),
        do_not=(
            "Do NOT use random for shuffling sensitive data",
            "Do NOT use random for any operation where predictability is a concern",
        ),
        verify=(
            "Audit all random module usage for security implications",
            "Use secrets.choice() for secure selection",
        ),
        resources=(
            "https://docs.python.org/3/library/secrets.html",
        ),
        examples=(
            "random.shuffle(questions)",
            "random.sample(population, k)",
            "random.choice(items)",
        ),
        example_snippet="random.shuffle(questions)",
    ),

    "SEC-028": SecurityRuleMetadata(
        id="SEC-028",
        name="Password in URL",
        description="Detects passwords or credentials passed in URL query strings",
        severity="medium",
        cwe_id="CWE-598",
        cwe_name="Information Leak Through Query String",
        owasp_id="A01",
        owasp_name="Broken Access Control",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Never include credentials in URL query parameters",
            "Use request headers or POST body for sensitive data",
            "Use proper authentication mechanisms (Bearer tokens, OAuth)",
        ),
        do_not=(
            "Do NOT pass passwords: https://api.example.com?key=secret",
            "Do NOT log URLs that may contain credentials",
        ),
        verify=(
            "Check: URLs do not contain passwords or API keys",
            "Use: Authorization header or request body",
        ),
        resources=(
            "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
        ),
        examples=(
            "requests.get('https://api.com?api_key=secret')",
            "http://user:pass@example.com/",
            "url = f'https://key={api_key}@api.com'",
        ),
        example_snippet="requests.get('https://api.com?api_key=secret')",
    ),

    "SEC-029": SecurityRuleMetadata(
        id="SEC-029",
        name="Missing Rate Limiting",
        description="Detects API endpoints without rate limiting that may be abused",
        severity="medium",
        cwe_id="CWE-307",
        cwe_name="Improper Restriction of Excessive Authentication Attempts",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:U",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Implement rate limiting on all public endpoints",
            "Use per-IP and per-user rate limits",
            "Use a rate limiting library or service (redis-based, etc.)",
        ),
        do_not=(
            "Do NOT expose authentication endpoints without rate limiting",
            "Do NOT assume DDoS protection is handled by infrastructure alone",
        ),
        verify=(
            "Check: all /auth, /api, /login endpoints have rate limits",
            "Use: @limiter.limit decorator or middleware",
        ),
        resources=(
            "https://owasp.org/www-project-rate-limiting-cheat-sheet/",
        ),
        examples=(
            "@app.route('/login')  # no rate limit",
            "@app.route('/api/search')  # no rate limit",
            "@app.route('/reset-password')  # no rate limit",
        ),
        example_snippet="@app.route('/login')",
    ),

    "SEC-030": SecurityRuleMetadata(
        id="SEC-030",
        name="Insufficient Session Timeout",
        description="Detects session configurations with excessive or missing timeout",
        severity="medium",
        cwe_id="CWE-613",
        cwe_name="Insufficient Session Expiration",
        owasp_id="A07",
        owasp_name="Identification and Authentication Failures",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Set reasonable session timeout (15-30 minutes for active sessions)",
            "Implement absolute session timeout (24 hours maximum)",
            "Invalidate sessions on logout and password change",
        ),
        do_not=(
            "Do NOT set session timeout to infinite or very long periods",
            "Do NOT keep sessions alive indefinitely",
        ),
        verify=(
            "Check: session.max_age is set to reasonable value",
            "Verify: sessions expire after inactivity",
        ),
        resources=(
            "https://owasp.org/www-community/Sessions/Session_expiration",
        ),
        examples=(
            "SESSION_COOKIE_AGE = 8640000  # 100 days",
            "session.permanent = True  # no timeout",
            "app.config['PERMANENT_SESSION_LIFETIME'] = 3600 * 24 * 365",
        ),
        example_snippet="SESSION_COOKIE_AGE = 8640000",
    ),

    "SEC-031": SecurityRuleMetadata(
        id="SEC-031",
        name="Trust Boundary Violation",
        description="Detects mixing of trusted and untrusted data without proper separation",
        severity="medium",
        cwe_id="CWE-501",
        cwe_name="Trust Boundary Violation",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:U",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Clearly separate trusted server-side data from untrusted client input",
            "Use different data structures for internal vs. external data",
            "Validate and sanitize at trust boundaries",
        ),
        do_not=(
            "Do NOT assign client request data directly to server-side objects",
            "Do NOT mix internal state with user-controlled data",
        ),
        verify=(
            "Audit data flow from request to storage",
            "Use serializers that separate internal and external fields",
        ),
        resources=(
            "https://owasp.org/www-community/vulnerabilities/Trust_Boundary_Violation",
        ),
        examples=(
            "config.update(request.json)",
            "settings.__dict__.update(user_data)",
            "class Config: pass; config = Config(**user_input)",
        ),
        example_snippet="config.update(request.json)",
    ),

    "SEC-032": SecurityRuleMetadata(
        id="SEC-032",
        name="Cookie Missing Security Flags",
        description="Detects cookies set without HttpOnly, Secure, or SameSite flags",
        severity="medium",
        cwe_id="CWE-1004",
        cwe_name="Sensitive Cookie Without HttpOnly Flag",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Set HttpOnly=True on all session cookies",
            "Set Secure=True on all cookies in production",
            "Set SameSite='Lax' or 'Strict' on cookies",
        ),
        do_not=(
            "Do NOT set cookies without HttpOnly for session tokens",
            "Do NOT use Secure=False in production",
        ),
        verify=(
            "Check: Set-Cookie header has HttpOnly, Secure, SameSite",
            "Use: Flask: app.config['SESSION_COOKIE_SECURE'] = True",
        ),
        resources=(
            "https://owasp.org/www-community/SameSite",
        ),
        examples=(
            "response.set_cookie('token', value)",
            "response.set_cookie(key, val, httponly=False)",
            "session['user'] = username  # default cookie settings",
        ),
        example_snippet="response.set_cookie('token', value)",
    ),

    "SEC-033": SecurityRuleMetadata(
        id="SEC-033",
        name="Missing Content Security Policy",
        description="Detects web apps missing Content-Security-Policy headers",
        severity="low",
        cwe_id="CWE-1021",
        cwe_name="Improper Restriction of Rendered UI Layer",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:U",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add Content-Security-Policy header to all responses",
            "Start with restrictive CSP and relax as needed",
        ),
        do_not=(
            "Do NOT use CSP: default-src * (too permissive)",
            "Do NOT skip CSP on pages handling sensitive data",
        ),
        verify=(
            "Check: all HTML responses have CSP header",
            "Use: @app.after_request to add security headers",
        ),
        resources=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        ),
        examples=(
            "# No CSP header set",
            "response.headers['Content-Security-Policy'] = 'default-src self'",
        ),
        example_snippet="# No CSP header",
    ),

    "SEC-034": SecurityRuleMetadata(
        id="SEC-034",
        name="XML External Entity Partial",
        description="Detects XML parsing configurations that partially allow DTD processing",
        severity="medium",
        cwe_id="CWE-611",
        cwe_name="XML External Entity (XXE) Reference",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Disable DTD processing entirely in XML parsers",
            "Use defusedxml as a safe alternative",
        ),
        do_not=(
            "Do NOT allow DTD processing on untrusted XML",
            "Do NOT use lxml.etree with default settings on untrusted input",
        ),
        verify=(
            "Test XXE payloads against your XML parsers",
            "Use: from defusedxml import ElementTree",
        ),
        resources=(
            "https://github.com/tiran/defusedxml",
        ),
        examples=(
            "lxml.etree.parse(user_xml)",
            "xml.dom.pulldom.parse(user_xml)",
            "xml.sax.parseString(user_xml)",
        ),
        example_snippet="lxml.etree.parse(user_xml)",
    ),

    # ========================================================================
    # LOW (10 rules)
    # ========================================================================

    "SEC-040": SecurityRuleMetadata(
        id="SEC-040",
        name="Sensitive Information in Comments",
        description="Detects TODO/HACK/FIXME comments containing sensitive information patterns",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="",
        owasp_name="",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Remove or sanitize comments containing sensitive patterns",
            "Use generic placeholders instead of real values",
        ),
        do_not=(
            "Do NOT include real passwords, API keys, or credentials in comments",
            "Do NOT leave production credentials in code comments",
        ),
        verify=(
            "Search for: TODO.*password, HACK.*secret, FIXME.*key",
            "Review all TODO/HACK comments for sensitive data",
        ),
        resources=(
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        ),
        examples=(
            "# TODO: password = 'hunter2'  # remove before prod",
            "# HACK: API key = 'sk-xxx' for testing",
            "# FIXME: secret = 'dev-token-123'",
        ),
        example_snippet="# TODO: password = 'hunter2'",
    ),

    "SEC-041": SecurityRuleMetadata(
        id="SEC-041",
        name="Information Disclosure in Errors",
        description="Detects error handlers that expose stack traces or sensitive information",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A01",
        owasp_name="Security Misconfiguration",
        cvss_base=4.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use generic error messages in production",
            "Log detailed errors server-side, return generic messages to users",
            "Configure web framework to not show stack traces",
        ),
        do_not=(
            "Do NOT show stack traces to end users",
            "Do NOT expose file paths or internal system details in errors",
        ),
        verify=(
            "Test: trigger errors and verify no stack traces in response",
            "Check: debug mode is disabled in production",
        ),
        resources=(
            "https://owasp.org/www-community/Improper_Error_Handling",
        ),
        examples=(
            "raise Exception(detailed_error)",
            "return jsonify(error=str(e))",
            "print(stack_trace)",
        ),
        example_snippet="return jsonify(error=str(e))",
    ),

    "SEC-042": SecurityRuleMetadata(
        id="SEC-042",
        name="Sensitive Data in Logs",
        description="Detects logging of sensitive data that should not be persisted",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A09",
        owasp_name="Security Logging Failures",
        cvss_base=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Never log passwords, tokens, API keys, or PII",
            "Use structured logging with field allowlists",
            "Implement log redaction for sensitive patterns",
        ),
        do_not=(
            "Do NOT log: request.body with form data",
            "Do NOT log: authorization headers, cookies",
        ),
        verify=(
            "Audit logging calls for sensitive data patterns",
            "Use: logging.setLogRecordFactory() to redact sensitive fields",
        ),
        resources=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces",
        ),
        examples=(
            "logging.info(f'User {user} logged in with password {pwd}')",
            "logger.debug(request.headers)",
            "print(f'API key: {api_key}')",
        ),
        example_snippet="logging.info(f'password: {password}')",
    ),

    "SEC-043": SecurityRuleMetadata(
        id="SEC-043",
        name="Missing Security Headers",
        description="Detects missing recommended security headers in HTTP responses",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add recommended security headers: X-Frame-Options, X-Content-Type-Options, etc.",
            "Use a security headers middleware",
        ),
        do_not=(
            "Do NOT skip security headers on admin/internal pages",
        ),
        verify=(
            "Check: securityheaders.com scanner",
            "Use: Flask-Talisman or similar library",
        ),
        resources=(
            "https://securityheaders.com/",
            "https://owasp.org/www-project-secure-headers/",
        ),
        examples=(
            "# No security headers configured",
            "response.headers['X-Frame-Options'] = 'DENY'",
        ),
        example_snippet="# No security headers",
    ),

    "SEC-044": SecurityRuleMetadata(
        id="SEC-044",
        name="EXIF Data in Uploads",
        description="Detects image upload handling that may preserve EXIF metadata with sensitive info",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Strip EXIF metadata from uploaded images",
            "Use PIL/Pillow to re-save images (removes EXIF)",
        ),
        do_not=(
            "Do NOT serve uploaded images without stripping metadata",
        ),
        verify=(
            "Check: uploaded images do not contain GPS, camera info",
            "Use: Image.save(buffer, format='JPEG') to strip EXIF",
        ),
        resources=(
            "https://pillow.readthedocs.io/en/latest/handbook/image-file-formats.html#jpeg",
        ),
        examples=(
            "# Serve uploaded image without processing",
            "send_file(user_uploaded_image)",
        ),
        example_snippet="# Serve uploaded image without processing",
    ),

    "SEC-045": SecurityRuleMetadata(
        id="SEC-045",
        name="Missing Referrer Policy",
        description="Detects missing Referrer-Policy header that controls referrer leakage",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=2.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add Referrer-Policy header: 'strict-origin-when-cross-origin'",
            "Use appropriate policy for your use case",
        ),
        do_not=(
            "Do NOT use 'no-referrer-when-downgrade' on sensitive pages",
        ),
        verify=(
            "Check: responses include Referrer-Policy header",
        ),
        resources=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ),
        examples=(
            "# No Referrer-Policy header",
            "response.headers['Referrer-Policy'] = 'strict-origin'",
        ),
        example_snippet="# No Referrer-Policy header",
    ),

    "SEC-046": SecurityRuleMetadata(
        id="SEC-046",
        name="Security Feature Disabled",
        description="Detects explicit disabling of security features (e.g., CSP disabled, auth bypassed)",
        severity="medium",
        cwe_id="",
        cwe_name="",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Re-enable disabled security features",
            "Document and approve any security bypass with risk assessment",
        ),
        do_not=(
            "Do NOT disable auth for 'development' and forget to re-enable",
            "Do NOT leave debug security overrides in production code",
        ),
        verify=(
            "Audit all @skip_auth, @auth_public, bypass patterns",
        ),
        resources=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/",
        ),
        examples=(
            "# Disable auth for testing",
            "@app.route('/admin') @login_required(auth=False)",
            "ENABLE_AUTH = False  # DANGEROUS",
        ),
        example_snippet="# Disable auth for testing",
    ),

    "SEC-047": SecurityRuleMetadata(
        id="SEC-047",
        name="Insufficient Anti-Automation",
        description="Detects missing or weak anti-automation controls (CAPTCHA, bot detection)",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add CAPTCHA or bot detection to public forms",
            "Implement rate limiting per IP and per account",
        ),
        do_not=(
            "Do NOT expose sensitive operations without anti-automation",
        ),
        verify=(
            "Check: registration, login, password reset have bot protection",
        ),
        resources=(
            "https://owasp.org/www-community/controls/Botnet",
        ),
        examples=(
            "# Registration form without CAPTCHA",
            "# Contact form without rate limiting",
        ),
        example_snippet="# Registration form without CAPTCHA",
    ),

    "SEC-048": SecurityRuleMetadata(
        id="SEC-048",
        name="Privacy Violation - PII in Logs",
        description="Detects logging or storage of Personally Identifiable Information without consent",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A09",
        owasp_name="Security Logging Failures",
        cvss_base=4.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Never log PII: email, phone, SSN, credit card",
            "Use UUID or hash for user identification in logs",
            "Comply with GDPR/CCPA data minimization principles",
        ),
        do_not=(
            "Do NOT log email addresses, names, or IDs without anonymization",
        ),
        verify=(
            "Audit logging statements for PII patterns",
            "Use: log scrubbing tools or redaction middleware",
        ),
        resources=(
            "https://gdpr.eu/",
        ),
        examples=(
            "logging.info(f'User {user.email} created')",
            "logger.info({'user': user.email, 'ip': request.ip})",
        ),
        example_snippet="logging.info(f'User {user.email} created')",
    ),

    "SEC-049": SecurityRuleMetadata(
        id="SEC-049",
        name="Weak Password Policy",
        description="Detects password validation that allows weak passwords",
        severity="low",
        cwe_id="",
        cwe_name="",
        owasp_id="A07",
        owasp_name="Identification and Authentication Failures",
        cvss_base=4.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Enforce minimum 8 characters with mix of types",
            "Check against known weak passwords list",
            "Use zxcvbn or similar strength meter",
        ),
        do_not=(
            "Do NOT allow: 'password', '123456', 'qwerty'",
            "Do NOT skip password strength validation",
        ),
        verify=(
            "Check: password validation enforces strength requirements",
        ),
        resources=(
            "https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret",
        ),
        examples=(
            "# No password validation",
            "if len(password) > 0: register()",
        ),
        example_snippet="if len(password) > 0: register()",
    ),

    # ========================================================================
    # INFO (10 rules)
    # ========================================================================

    "SEC-050": SecurityRuleMetadata(
        id="SEC-050",
        name="Deprecated Security Function",
        description="Detects use of deprecated security-related Python functions",
        severity="info",
        cwe_id="",
        cwe_name="",
        owasp_id="",
        owasp_name="",
        cvss_base=1.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Migrate to modern, non-deprecated alternatives",
        ),
        do_not=(
            "Do NOT continue using deprecated crypto functions",
        ),
        verify=(
            "Check Python docs for deprecation warnings",
        ),
        resources=(
            "https://docs.python.org/3/whatsnew/3.10.html#deprecated",
        ),
        examples=(
            "ssl.wrap_socket()  # deprecated",
            "hashlib.new('md5')  # weak",
        ),
        example_snippet="ssl.wrap_socket(conn)",
    ),

    "SEC-051": SecurityRuleMetadata(
        id="SEC-051",
        name="Missing Function-Level Access Control",
        description="Detects sensitive functions or endpoints without explicit authorization checks",
        severity="info",
        cwe_id="",
        cwe_name="",
        owasp_id="A01",
        owasp_name="Broken Access Control",
        cvss_base=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add authorization checks to all sensitive functions",
            "Use decorator-based authorization for consistency",
        ),
        do_not=(
            "Do NOT assume internal functions are not reachable from outside",
        ),
        verify=(
            "Audit all @app.route and sensitive function decorators",
        ),
        resources=(
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
        ),
        examples=(
            "@app.route('/admin/delete_user')",
            "def delete_all_data():  # no decorator",
        ),
        example_snippet="@app.route('/admin/delete_user')",
    ),

    "SEC-052": SecurityRuleMetadata(
        id="SEC-052",
        name="Improper Error Handling",
        description="Detects error handling that may leak information or cause unexpected behavior",
        severity="info",
        cwe_id="",
        cwe_name="",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use structured error handling with proper logging",
            "Return generic error messages to users",
        ),
        do_not=(
            "Do NOT catch bare Exception without re-raising",
            "Do NOT suppress errors silently",
        ),
        verify=(
            "Audit exception handling patterns",
        ),
        resources=(
            "https://owasp.org/www-community/Improper_Error_Handling",
        ),
        examples=(
            "try: dangerous() except: pass",
            "except: raise  # bare except",
        ),
        example_snippet="try: dangerous() except: pass",
    ),

    "SEC-053": SecurityRuleMetadata(
        id="SEC-053",
        name="Integer Overflow",
        description="Detects potential integer overflow conditions in numeric operations",
        severity="info",
        cwe_id="CWE-190",
        cwe_name="Integer Overflow or Wraparound",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use try/except around arithmetic that could overflow",
            "Use Python 3's arbitrary-precision integers (less risk)",
        ),
        do_not=(
            "Do NOT assume integers are unlimited in all contexts",
        ),
        verify=(
            "Audit: array indexing, buffer allocation, loop counters",
        ),
        resources=(
            "https://cwe.mitre.org/data/definitions/190.html",
        ),
        examples=(
            "data = [0] * (user_size * user_size)",
            "offset = base + (user_val * 8)",
        ),
        example_snippet="data = [0] * (user_size * user_size)",
    ),

    "SEC-054": SecurityRuleMetadata(
        id="SEC-054",
        name="TOCTOU Race Condition",
        description="Detects time-of-check-time-of-use patterns that could be exploited",
        severity="info",
        cwe_id="CWE-362",
        cwe_name="Race Condition",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Use atomic operations where possible",
            "Implement proper file locking for check-then-act patterns",
        ),
        do_not=(
            "Do NOT assume file checks and file operations are atomic",
        ),
        verify=(
            "Use: fcntl.flock() for file locking",
        ),
        resources=(
            "https://cwe.mitre.org/data/definitions/367.html",
        ),
        examples=(
            "if os.access(path, os.W_OK): os.remove(path)",
            "if os.path.exists(f): f.open()",
        ),
        example_snippet="if os.access(path, os.W_OK): os.remove(path)",
    ),

    "SEC-055": SecurityRuleMetadata(
        id="SEC-055",
        name="Improper Certificate Validation",
        description="Detects incomplete SSL/TLS certificate validation patterns",
        severity="info",
        cwe_id="CWE-295",
        cwe_name="Improper Certificate Validation",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Always use proper certificate validation",
            "Verify certificate chain, hostname, and expiry",
        ),
        do_not=(
            "Do NOT disable hostname verification",
        ),
        verify=(
            "Check: ssl.SSLContext.check_hostname = True",
        ),
        resources=(
            "https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname",
        ),
        examples=(
            "ctx.verify_mode = ssl.CERT_NONE",
            "ctx.check_hostname = False",
        ),
        example_snippet="ctx.verify_mode = ssl.CERT_NONE",
    ),

    "SEC-056": SecurityRuleMetadata(
        id="SEC-056",
        name="Missing Encryption for Sensitive Data",
        description="Detects storage or transmission of sensitive data without encryption",
        severity="info",
        cwe_id="CWE-311",
        cwe_name="Missing Encryption of Sensitive Data",
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        cvss_base=4.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Encrypt sensitive data at rest and in transit",
            "Use TLS for network communication",
            "Use Fernet (cryptography library) for at-rest encryption",
        ),
        do_not=(
            "Do NOT store sensitive data in plain text",
            "Do NOT send sensitive data over plain HTTP",
        ),
        verify=(
            "Audit: database columns, file storage, API calls",
        ),
        resources=(
            "https://cryptography.io/en/latest/fernet/",
        ),
        examples=(
            "# Store password in plain text",
            "# Send credit card over HTTP",
        ),
        example_snippet="# Store password in plain text",
    ),

    "SEC-057": SecurityRuleMetadata(
        id="SEC-057",
        name="Improper Restriction of Rendered UI Layer",
        description="Detects UI rendering that may allow clickjacking or UI redress attacks",
        severity="info",
        cwe_id="CWE-1021",
        cwe_name="Improper Restriction of Rendered UI Layer",
        owasp_id="A05",
        owasp_name="Security Misconfiguration",
        cvss_base=3.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header",
        ),
        do_not=(
            "Do NOT allow sensitive pages to be embedded in iframes",
        ),
        verify=(
            "Check: X-Frame-Options header on all pages",
        ),
        resources=(
            "https://owasp.org/www-community/attacks/Clickjacking",
        ),
        examples=(
            "# No X-Frame-Options header",
        ),
        example_snippet="# No X-Frame-Options header",
    ),

    "SEC-058": SecurityRuleMetadata(
        id="SEC-058",
        name="Server-Side Request Forgery (Cloud)",
        description="Detects potential SSRF targeting cloud metadata services",
        severity="medium",
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery",
        owasp_id="A10",
        owasp_name="Server-Side Request Forgery",
        cvss_base=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Block access to cloud metadata IP ranges (169.254.169.254)",
            "Use URL allowlists for external fetching",
            "Disable metadata endpoints in production",
        ),
        do_not=(
            "Do NOT allow user-controlled URLs to access metadata services",
        ),
        verify=(
            "Test: curl http://169.254.169.254/latest/meta-data/",
            "Block: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16",
        ),
        resources=(
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
        ),
        examples=(
            "requests.get(metadata_url)",
            "fetch(user_controlled_url)",
        ),
        example_snippet="requests.get(metadata_url)",
    ),

    "SEC-059": SecurityRuleMetadata(
        id="SEC-059",
        name="Business Logic Vulnerability",
        description="Detects patterns that may indicate business logic flaws (price manipulation, etc.)",
        severity="info",
        cwe_id="",
        cwe_name="",
        owasp_id="A04",
        owasp_name="Insecure Design",
        cvss_base=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=False,
        fix_constraints=(
            "Implement server-side validation of all business rules",
            "Do not trust client-supplied values for calculations",
        ),
        do_not=(
            "Do NOT trust client-side totals, quantities, or prices",
        ),
        verify=(
            "Audit: pricing, discounts, quantity calculations",
        ),
        resources=(
            "https://owasp.org/www-project-top-ten/2017/A4_2017-Insecure_Design",
        ),
        examples=(
            "total = client_supplied_total",
            "discount = request.form['discount_percent']",
        ),
        example_snippet="total = client_supplied_total",
    ),

    # ========================================================================
    # DEPENDENCY RULES
    # ========================================================================

    "SEC-DEP-001": SecurityRuleMetadata(
        id="SEC-DEP-001",
        name="Vulnerable Dependency",
        description="Detects dependencies with known CVE vulnerabilities",
        severity="high",
        cwe_id="CWE-1104",
        cwe_name="Use of Unmaintained Third-Party Components",
        owasp_id="A06",
        owasp_name="Vulnerable and Outdated Components",
        cvss_base=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        can_auto_fix=False,
        auto_fix_available=True,
        fix_constraints=(
            "Update the dependency to the fixed version",
            "Remove the dependency if not essential",
            "Consider alternative libraries without known vulnerabilities",
        ),
        do_not=(
            "Do NOT ignore known CVEs without risk assessment",
        ),
        verify=(
            "Use: pip-audit, safety, or pip list --outdated",
        ),
        resources=(
            "https://pypi.org/project/pip-audit/",
        ),
        examples=(
            "requests==2.24.0  # CVE-2021-1234",
            "flask==1.0.0  # known vulnerabilities",
        ),
        example_snippet="requests==2.24.0",
    ),
}


# --------------------------------------------------------------------------
# Helper functions for registry lookup
# --------------------------------------------------------------------------

def get_security_rule(rule_id: str) -> Optional[SecurityRuleMetadata]:
    """Get security rule metadata by rule_id."""
    return SECURITY_RULES_REGISTRY.get(rule_id)


def get_rules_by_severity(severity: str) -> List[SecurityRuleMetadata]:
    """Get all rules matching a severity level."""
    return [r for r in SECURITY_RULES_REGISTRY.values() if r.severity == severity]


def get_all_rule_ids() -> List[str]:
    """Get all registered rule IDs."""
    return list(SECURITY_RULES_REGISTRY.keys())


def get_all_rule_ids_by_severity() -> Dict[str, List[str]]:
    """Get rule IDs grouped by severity."""
    from pyneat.core.types import SecuritySeverity
    return {
        SecuritySeverity.CRITICAL: [r.id for r in get_rules_by_severity(SecuritySeverity.CRITICAL)],
        SecuritySeverity.HIGH: [r.id for r in get_rules_by_severity(SecuritySeverity.HIGH)],
        SecuritySeverity.MEDIUM: [r.id for r in get_rules_by_severity(SecuritySeverity.MEDIUM)],
        SecuritySeverity.LOW: [r.id for r in get_rules_by_severity(SecuritySeverity.LOW)],
        SecuritySeverity.INFO: [r.id for r in get_rules_by_severity(SecuritySeverity.INFO)],
    }
