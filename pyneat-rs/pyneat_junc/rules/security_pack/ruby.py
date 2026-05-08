"""Ruby-specific security rules (RUBY-SEC-001 to RUBY-SEC-050) including Brakeman Rails rules.

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

This module contains Ruby-specific security rules that complement the
language-agnostic security_pack rules.
"""

from pyneat.core.types import SecuritySeverity

__all__ = ["RUBY_SECURITY_RULES", "get_ruby_rules_by_severity"]


# Ruby Critical Security Rules
RUBY_CRITICAL_RULES = [
    {
        "rule_id": "RUBY-SEC-001",
        "name": "SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "SQL Injection via ActiveRecord .find_by_sql(), .execute() with string interpolation",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-002",
        "name": "OS Command Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "OS Command Injection via system(), backticks, exec() with user input",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-005",
        "name": "Dangerous Eval Usage",
        "severity": SecuritySeverity.CRITICAL,
        "description": "eval(), instance_eval(), class_eval() with dynamic code execution",
        "cwe": "CWE-95",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-015",
        "name": "AI-Hallucinated Dependency (Slopsquatting)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Gem names that appear to be hallucinated AI package names",
        "cwe": "CWE-1595",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-022",
        "name": "SQL Injection (Sequel ORM / String Interpolation)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "SQL injection via Sequel ORM or ActiveRecord with string interpolation",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-023",
        "name": "Command Injection (system/backticks/exec)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Shell commands with user input via system(), backticks, or exec()",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-028",
        "name": "SQL Injection in ActiveRecord - where/find_by_sql",
        "severity": SecuritySeverity.CRITICAL,
        "description": ".where(), .find_by_sql() with string interpolation - ORDER BY injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-029",
        "name": "Command Injection - Shell Metacharacters",
        "severity": SecuritySeverity.CRITICAL,
        "description": "system(), backticks, exec() with shell metacharacters in user input",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
]


# Ruby High Security Rules
RUBY_HIGH_RULES = [
    {
        "rule_id": "RUBY-SEC-003",
        "name": "YAML Unsafe Load",
        "severity": SecuritySeverity.HIGH,
        "description": "YAML.load() without SafeLoader - can deserialize arbitrary Ruby objects",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "RUBY-SEC-004",
        "name": "Hardcoded Secrets",
        "severity": SecuritySeverity.HIGH,
        "description": "Hardcoded passwords, API keys, tokens, AWS credentials in code",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "RUBY-SEC-006",
        "name": "Weak Cryptography",
        "severity": SecuritySeverity.HIGH,
        "description": "RC4, MD5, SHA1, DES cipher usage - deprecated cryptographic algorithms",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "RUBY-SEC-008",
        "name": "LDAP Injection",
        "severity": SecuritySeverity.HIGH,
        "description": "LDAP queries with user-controlled filter/dn parameters",
        "cwe": "CWE-90",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-020",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": SecuritySeverity.HIGH,
        "description": "HTTP requests with user-controlled URLs or internal IP access (169.254.169.254)",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    {
        "rule_id": "RUBY-SEC-021",
        "name": "Weak JWT Verification",
        "severity": SecuritySeverity.CRITICAL,
        "description": "JWT.decode with nil/false key - no signature verification",
        "cwe": "CWE-345",
        "owasp": "A02:2021",
    },
    {
        "rule_id": "RUBY-SEC-030",
        "name": "YAML Unsafe Load - Extended Detection",
        "severity": SecuritySeverity.HIGH,
        "description": "YAML.load(), Psych.load(), YAML.unsafe_load() - deserialization RCE",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "rule_id": "RUBY-SEC-032",
        "name": "Security/JSONLoad (RuboCop)",
        "severity": SecuritySeverity.HIGH,
        "description": "JSON.load() / JSON.restore() without create_additions: false — arbitrary Ruby object deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
]


# Ruby Medium Security Rules
RUBY_MEDIUM_RULES = [
    {
        "rule_id": "RUBY-SEC-007",
        "name": "Mass Assignment",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Model.new(params) without strong parameters - allowlist bypass",
        "cwe": "CWE-915",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "RUBY-SEC-009",
        "name": "Weak Session Management",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Session cookies without secure/httponly flags",
        "cwe": "CWE-384",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-010",
        "name": "Open Redirect",
        "severity": SecuritySeverity.MEDIUM,
        "description": "redirect_to with user-controlled parameters or request referer",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-012",
        "name": "Missing CSRF Protection",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Rails controller actions without protect_from_forgery",
        "cwe": "CWE-352",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-013",
        "name": "Unsafe File Access (Path Traversal)",
        "severity": SecuritySeverity.MEDIUM,
        "description": "File.read/open with user input concatenation - path traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-014",
        "name": "Regex DoS (ReDoS)",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Nested quantifiers and catastrophic backtracking in regex",
        "cwe": "CWE-1333",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "RUBY-SEC-016",
        "name": "Format String Vulnerability",
        "severity": SecuritySeverity.HIGH,
        "description": "sprintf, % with user input - can leak memory addresses",
        "cwe": "CWE-134",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-019",
        "name": "Race Condition in Transactions",
        "severity": SecuritySeverity.MEDIUM,
        "description": "ActiveRecord transactions without row-level locking",
        "cwe": "CWE-362",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "RUBY-SEC-031",
        "name": "Insecure Cookie Configuration",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Cookies without secure, httponly, or samesite flags",
        "cwe": "CWE-614",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-033",
        "name": "Security/IoMethods (RuboCop)",
        "severity": SecuritySeverity.MEDIUM,
        "description": "IO.read/write/foreach with pipe prefix — subprocess invocation enabling command injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-034",
        "name": "Security/CompoundHash (RuboCop)",
        "severity": SecuritySeverity.MEDIUM,
        "description": "Custom hash() method using unsafe combinators instead of delegating to Array#hash — collision-prone",
        "cwe": "CWE-385",
        "owasp": "A04:2021",
    },
]


# Ruby Low/Info Security Rules
RUBY_LOW_RULES = [
    {
        "rule_id": "RUBY-SEC-011",
        "name": "Information Disclosure",
        "severity": SecuritySeverity.LOW,
        "description": "puts ENV, logging params, debuggers (byebug, binding.pry) in code",
        "cwe": "CWE-200",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-017",
        "name": "XSS in Rails Views",
        "severity": SecuritySeverity.HIGH,
        "description": "raw(), .html_safe without sanitization - HTML escaping bypass",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-018",
        "name": "Insecure Deserialization (Marshal / YAML)",
        "severity": SecuritySeverity.CRITICAL,
        "description": "Marshal.load/YAML.load on user input - arbitrary code execution",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
]


# Brakeman Rails Security Rules
BRAKEMAN_CRITICAL_RULES = [
    {
        "rule_id": "RUBY-SEC-035",
        "name": "Brakeman: SQL Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "SQL injection via ActiveRecord with string interpolation in .where(), .find_by_sql()",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-037",
        "name": "Brakeman: Command Injection",
        "severity": SecuritySeverity.CRITICAL,
        "description": "system(), exec(), backticks, Open3 with string interpolation of user input",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
]

BRAKEMAN_HIGH_RULES = [
    {
        "rule_id": "RUBY-SEC-036",
        "name": "Brakeman: XSS Inline Template",
        "severity": SecuritySeverity.HIGH,
        "description": "render :inline with params or raw()/html_safe with user input - XSS",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-038",
        "name": "Brakeman: Mass Assignment",
        "severity": SecuritySeverity.HIGH,
        "description": "Model.new(params) without strong params - allows modifying protected attributes",
        "cwe": "CWE-915",
        "owasp": "A04:2021",
    },
    {
        "rule_id": "RUBY-SEC-040",
        "name": "Brakeman: SQL LIKE Injection",
        "severity": SecuritySeverity.HIGH,
        "description": "LIKE queries with unsanitized user input - LIKE wildcard manipulation",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-041",
        "name": "Brakeman: send_file Path Traversal",
        "severity": SecuritySeverity.HIGH,
        "description": "send_file with user-controlled filename - path traversal vulnerability",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-042",
        "name": "Brakeman: XML XXE Injection",
        "severity": SecuritySeverity.HIGH,
        "description": "REXML/Nokogiri parsing without XXE protection - file disclosure/SSRF",
        "cwe": "CWE-611",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-044",
        "name": "Brakeman: XSS via content_tag",
        "severity": SecuritySeverity.HIGH,
        "description": "content_tag with raw()/.html_safe - XSS bypass of HTML escaping",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-046",
        "name": "Brakeman: render Path Traversal",
        "severity": SecuritySeverity.HIGH,
        "description": "render partial: with dynamic path - path traversal/template injection",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-047",
        "name": "Brakeman: SQL via Table/Column Name",
        "severity": SecuritySeverity.HIGH,
        "description": ".order/.pluck with column name interpolation without quoting",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
]

BRAKEMAN_MEDIUM_RULES = [
    {
        "rule_id": "RUBY-SEC-039",
        "name": "Brakeman: Open Redirect",
        "severity": SecuritySeverity.MEDIUM,
        "description": "redirect_to with params/referer without validation - open redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
    },
    {
        "rule_id": "RUBY-SEC-043",
        "name": "Brakeman: Detailed Exceptions",
        "severity": SecuritySeverity.MEDIUM,
        "description": "consider_all_requests_local=true in production - stack trace disclosure",
        "cwe": "CWE-209",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-045",
        "name": "Brakeman: XSS in select_tag",
        "severity": SecuritySeverity.MEDIUM,
        "description": "select_tag/options_for_select with user input - XSS in dropdown options",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    {
        "rule_id": "RUBY-SEC-048",
        "name": "Brakeman: Model Attributes Exposed",
        "severity": SecuritySeverity.MEDIUM,
        "description": "render json: @user without as_json exclusions - sensitive attrs exposed",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-049",
        "name": "Brakeman: Session Manipulation",
        "severity": SecuritySeverity.MEDIUM,
        "description": "session[key] = params[key] or auth via session value - privilege escalation",
        "cwe": "CWE-20",
        "owasp": "A05:2021",
    },
    {
        "rule_id": "RUBY-SEC-050",
        "name": "Brakeman: Unsafe Reflection",
        "severity": SecuritySeverity.MEDIUM,
        "description": "constantize/send/public_send with user input - arbitrary code execution",
        "cwe": "CWE-470",
        "owasp": "A03:2021",
    },
]


# Combined Ruby rules for convenience
RUBY_SECURITY_RULES = (
    RUBY_CRITICAL_RULES
    + RUBY_HIGH_RULES
    + RUBY_MEDIUM_RULES
    + RUBY_LOW_RULES
    + BRAKEMAN_CRITICAL_RULES
    + BRAKEMAN_HIGH_RULES
    + BRAKEMAN_MEDIUM_RULES
)


def get_ruby_rules_by_severity(severity: str) -> list:
    """Return Ruby security rules for a specific severity level."""
    mapping = {
        SecuritySeverity.CRITICAL: RUBY_CRITICAL_RULES,
        SecuritySeverity.HIGH: RUBY_HIGH_RULES,
        SecuritySeverity.MEDIUM: RUBY_MEDIUM_RULES,
        SecuritySeverity.LOW: RUBY_LOW_RULES,
    }
    return mapping.get(severity, [])
