# PyNEAT Rules Catalog

Complete documentation for all rules in PyNEAT 2.0.0.

## Table of Contents

- [Security Rules (SEC-001 ~ SEC-059)](#security-rules-sec-001--sec-059)
  - [Critical](#critical--5-rules)
  - [High](#high--10-rules)
  - [Medium](#medium--15-rules)
  - [Low](#low--10-rules)
  - [Info](#info--10-rules)
- [Code Quality Rules](#code-quality-rules)
- [Auto-fix Rules](#auto-fix-rules)

---

## Security Rules (SEC-001 ~ SEC-059)

### CRITICAL (5 rules)

Exit immediately — highest security risk.

#### SEC-001: Command Injection

**Description:** Detects command injection via `os.system()`, `subprocess.run(..., shell=True)`, `os.popen()`

**CWE:** CWE-78 (OS Command Injection)

**CVSS:** 9.8 (Critical)

**Detection examples:**

```python
# Bad
os.system(f"git commit -m \"{user_msg}\"")
subprocess.run(cmd, shell=True)
os.popen(f'ls {user_path}')
```

**How to fix:**

```python
# Good - Use list arguments
subprocess.run(['git', 'commit', '-m', msg], shell=False)

# Or use shlex.quote
import shlex
os.system(shlex.quote(cmd))
```

**Flag:** `--enable-security`

---

#### SEC-002: SQL Injection

**Description:** Detects SQL injection via string concatenation in queries

**CWE:** CWE-89 (SQL Injection)

**CVSS:** 9.9 (Critical)

**Detection examples:**

```python
# Bad
cursor.execute(f'SELECT * FROM users WHERE id={user_id}')
cursor.execute('SELECT * FROM users WHERE name=' + username)
```

**How to fix:**

```python
# Good - Use parameterized queries
cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
```

**Flag:** `--enable-security`

---

#### SEC-003: Eval/Exec Usage

**Description:** Detects dangerous use of `eval()` and `exec()` with dynamic code execution

**CWE:** CWE-95 (Eval Injection)

**CVSS:** 9.8 (Critical)

**Detection examples:**

```python
# Bad
eval(user_expression)
exec(user_code)
eval(f'os.{user_func}()')
```

**How to fix:**

```python
# Good - Use ast.literal_eval for data
import ast
result = ast.literal_eval(user_expression)
```

**Flag:** `--enable-security`

---

#### SEC-004: Deserialization RCE

**Description:** Detects `pickle.loads()` and `yaml.unsafe_load()` that can lead to RCE

**CWE:** CWE-502 (Deserialization of Untrusted Data)

**CVSS:** 9.6 (Critical)

**Detection examples:**

```python
# Bad
pickle.loads(untrusted_data)
yaml.load(user_yaml)  # Without Loader
yaml.unsafe_load(user_yaml)
```

**How to fix:**

```python
# Good - Use json or safe_load
import json
result = json.loads(data)

# Or for YAML
yaml.safe_load(user_yaml)
```

**Auto-fix:** Yes (yaml.load → yaml.safe_load)

**Flag:** `--enable-security`

---

#### SEC-005: Path Traversal

**Description:** Detects unsanitized file path operations that may allow path traversal attacks

**CWE:** CWE-22 (Path Traversal)

**CVSS:** 8.6 (Critical)

**Detection examples:**

```python
# Bad
open(f"uploads/{user_filename}")
os.path.join(base, user_input)
Path(user_path) / filename
```

**How to fix:**

```python
# Good - Validate path
from pathlib import Path
base = Path("/safe/uploads")
user_path = Path(user_input).resolve()

if not user_path.is_relative_to(base):
    raise ValueError("Invalid path")
```

**Flag:** `--enable-security`

---

### HIGH (10 rules)

Fix soon — high security risk.

#### SEC-010: Hardcoded Secrets

**Description:** Detects hardcoded API keys, passwords, tokens in source code

**CWE:** CWE-798 (Use of Hard-coded Credentials)

**CVSS:** 7.5 (High)

**Detection examples:**

```python
# Bad
api_key = 'sk-abc123...'
password = 'hunter2'
SECRET_KEY = 'dev-secret-key'
```

**How to fix:**

```python
# Good - Use environment variables
import os
api_key = os.environ.get('API_KEY')
# Or use .env file with python-dotenv
```

**Flag:** `--enable-security`

---

#### SEC-011: Weak Cryptography

**Description:** Detects weak hashing (MD5, SHA1) and weak encryption

**CWE:** CWE-327 (Use of Weak Cryptographic Algorithm)

**CVSS:** 7.4 (High)

**Detection examples:**

```python
# Bad
hashlib.md5(password.encode()).hexdigest()
hashlib.sha1(data)
ssl._create_unverified_context()
```

**How to fix:**

```python
# Good
hashlib.sha256(password.encode()).hexdigest()  # Or use bcrypt
import secrets
token = secrets.token_hex(32)
```

**Flag:** `--enable-security`

---

#### SEC-012: Insecure SSL/TLS

**Description:** Detects insecure SSL context creation

**CWE:** CWE-295 (Improper Certificate Validation)

**CVSS:** 7.4 (High)

**Detection examples:**

```python
# Bad
ssl._create_unverified_context()
requests.get(url, verify=False)
urllib3.disable_warnings()
```

**How to fix:**

```python
# Good
import ssl
context = ssl.create_default_context()
# Or with requests
requests.get(url, verify=True)
```

**Flag:** `--enable-security`

---

#### SEC-013: XML External Entity (XXE)

**Description:** Detects XML parsing without safe settings

**CWE:** CWE-611 (XML External Entity (XXE) Reference)

**CVSS:** 7.5 (High)

**Detection examples:**

```python
# Bad
xml.etree.ElementTree.parse(user_xml)
lxml.etree.parse(user_xml)
```

**How to fix:**

```python
# Good - Use defusedxml
from defusedxml import ElementTree
data = ElementTree.parse(user_xml)
```

**Flag:** `--enable-security`

---

#### SEC-014: YAML Unsafe Load

**Description:** Detects `yaml.load()` without SafeLoader

**CWE:** CWE-502 (Deserialization of Untrusted Data)

**CVSS:** 9.1 (Critical)

**Detection examples:**

```python
# Bad
yaml.load(user_yaml)
yaml.load(data)
```

**How to fix:**

```python
# Good
yaml.safe_load(user_yaml)
```

**Auto-fix:** Yes (automatically adds SafeLoader)

**Flag:** `--enable-security`

---

#### SEC-015: Assert in Production

**Description:** Detects assert statements that may be disabled in production

**CWE:** CWE-573 (Improper Following of Specification)

**CVSS:** 6.5 (Medium)

**Detection examples:**

```python
# Bad
assert is_admin, 'Not admin'
assert has_permission, 'No access'
```

**How to fix:**

```python
# Good - Use explicit validation
def require_admin():
    if not is_admin:
        raise PermissionError('Admin access required')
```

**Flag:** `--enable-security`

---

#### SEC-016: Debug Mode Enabled

**Description:** Detects `DEBUG=True` or debug mode in web frameworks

**CWE:** CWE-11 (Incorrect Permission Assignment)

**CVSS:** 7.5 (High)

**Detection examples:**

```python
# Bad
DEBUG = True
app.config['DEBUG'] = True
app.run(debug=True)
```

**How to fix:**

```python
# Good - Use environment variables
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
app.run(debug=DEBUG)
```

**Flag:** `--enable-security`

---

#### SEC-017: CORS Wildcard

**Description:** Detects CORS configurations that allow all origins

**CWE:** CWE-942 (Permissive Cross-Domain Policy)

**CVSS:** 6.5 (Medium)

**Detection examples:**

```python
# Bad
CORS(app, resources={'/api/*': {'origins': '*'}})
Access-Control-Allow-Origin: *
```

**How to fix:**

```python
# Good - Specify specific origins
ALLOWED_ORIGINS = ['https://yourdomain.com']
CORS(app, resources={'/api/*': {'origins': ALLOWED_ORIGINS}})
```

**Flag:** `--enable-security`

---

#### SEC-018: JWT None Algorithm

**Description:** Detects JWT verification with 'none' algorithm vulnerability

**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

**CVSS:** 9.0 (Critical)

**Detection examples:**

```python
# Bad
jwt.decode(token, options={'verify_signature': False})
jwt.decode(token, algorithms=['none'])
```

**How to fix:**

```python
# Good - Always verify signature
import jwt
decoded = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=['HS256']
)
```

**Flag:** `--enable-security`

---

#### SEC-019: Weak Random Number Generator

**Description:** Detects use of `random` module for security-sensitive operations

**CWE:** CWE-338 (Use of Cryptographically Weak PRNG)

**CVSS:** 7.5 (High)

**Detection examples:**

```python
# Bad - For tokens, passwords
token = ''.join(random.choices(charset, k=32))
random.randint(0, 100)
```

**How to fix:**

```python
# Good - Use secrets module
import secrets
token = ''.join(secrets.choice(charset) for _ in range(32))
api_key = secrets.token_hex(32)
```

**Flag:** `--enable-security`

---

### MEDIUM (15 rules)

Should be fixed in the next sprint.

#### SEC-020: LDAP Injection

**Description:** Detects LDAP query construction that may allow LDAP injection

**Example:**

```python
# Bad
ldap.search_s(f"dc={user_input},dc=com")
```

**How to fix:**

```python
# Good
import ldap.filter
safe_input = ldap.filter.escape_filter_chars(user_input)
ldap.search_s(f"dc={safe_input},dc=com")
```

---

#### SEC-021: Cross-Site Scripting (XSS)

**Description:** Detects potential XSS vulnerabilities in template rendering

**Example:**

```python
# Bad
render_template_string(user_html)
{{ user_input | safe }}
```

**How to fix:**

```python
# Good - Jinja2 escapes by default
{{ user_input }}  # Auto-escaped
```

---

#### SEC-022: Server-Side Request Forgery (SSRF)

**Description:** Detects URL fetching with user-controlled URLs

**Example:**

```python
# Bad
requests.get(user_url)
urllib.request.urlopen(user_provided_url)
```

**How to fix:**

```python
# Good - Validate URL
from urllib.parse import urlparse
ALLOWED_DOMAINS = ['api.trusted.com']
parsed = urlparse(user_url)
if parsed.netloc not in ALLOWED_DOMAINS:
    raise ValueError("URL not allowed")
```

---

#### SEC-023: Open Redirect

**Description:** Detects URL redirects that can be manipulated for phishing

**Example:**

```python
# Bad
redirect(request.args.get("next"))
return redirect(user_url)
```

**How to fix:**

```python
# Good - Validate redirect URL
from urllib.parse import urlparse
ALLOWED_DOMAINS = ['yourdomain.com']
parsed = urlparse(redirect_url)
if parsed.netloc not in ALLOWED_DOMAINS:
    redirect_url = '/default'
```

---

#### SEC-024: Mass Assignment

**Description:** Detects object attribute assignment that may allow mass assignment attacks

**Example:**

```python
# Bad
User(**request.form)
obj.__dict__.update(request.json)
```

**How to fix:**

```python
# Good - Explicit field assignment
from pydantic import BaseModel

class UserCreate(BaseModel):
    name: str
    email: str
    # admin and role are excluded

user = User(**UserCreate(**request.json).dict())
```

---

#### SEC-025: Race Condition (TOCTOU)

**Description:** Detects time-of-check-time-of-use race conditions

**Example:**

```python
# Bad
if not os.path.exists(path):
    open(path, 'w')
```

**How to fix:**

```python
# Good - Atomic operations
import tempfile
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write(content)
    temp_path = f.name
os.rename(temp_path, target_path)
```

---

#### SEC-026: Insecure Temporary Files

**Description:** Detects use of insecure temporary file creation patterns

**Example:**

```python
# Bad
tempfile.mktemp()
open('/tmp/tmpfile', 'w')
```

**How to fix:**

```python
# Good
with tempfile.NamedTemporaryFile(mode='w', delete=True, dir='/safe/dir') as f:
    f.write(content)
```

---

#### SEC-027: Predictable Random for Non-Security

**Description:** Detects use of Mersenne Twister random for sensitive operations

**Example:**

```python
# Bad - For shuffle questions, sampling
random.shuffle(questions)
random.sample(population, k)
```

**How to fix:**

```python
# Good - Use secrets for security-sensitive
import secrets
secrets.choice(items)
```

---

#### SEC-028: Password in URL

**Description:** Detects passwords or credentials in URL query strings

**Example:**

```python
# Bad
requests.get('https://api.com?api_key=secret')
http://user:pass@example.com/
```

**How to fix:**

```python
# Good - Use headers
requests.get('https://api.com', headers={'Authorization': f'Bearer {token}'})
```

---

#### SEC-029: Missing Rate Limiting

**Description:** Detects API endpoints without rate limiting

**Example:**

```python
# Bad
@app.route('/login')  # No rate limit
```

**How to fix:**

```python
# Good - Add rate limiting
from flask_limiter import Limiter
limiter = Limiter(app)
limiter.limit("5 per minute")(protected_endpoints)
```

---

#### SEC-030: Insufficient Session Timeout

**Description:** Detects session configurations with excessive timeout

**Example:**

```python
# Bad
SESSION_COOKIE_AGE = 8640000  # 100 days
```

**How to fix:**

```python
# Good
SESSION_COOKIE_AGE = 1800  # 30 minutes
SESSION_PERMANENT_SESSION_LIFETIME = 3600  # 1 hour max
```

---

#### SEC-031: Trust Boundary Violation

**Description:** Detects mixing of trusted and untrusted data

**Example:**

```python
# Bad
config.update(request.json)
```

**How to fix:**

```python
# Good - Explicit validation
from pydantic import BaseModel
class ConfigUpdate(BaseModel):
    theme: str
    language: str
config.update(ConfigUpdate(**request.json).dict())
```

---

#### SEC-032: Cookie Missing Security Flags

**Description:** Detects cookies set without HttpOnly, Secure, or SameSite flags

**Example:**

```python
# Bad
response.set_cookie('token', value)
```

**How to fix:**

```python
# Good
response.set_cookie(
    'token',
    value,
    httponly=True,
    secure=True,
    samesite='Lax'
)
```

---

#### SEC-033: Missing Content Security Policy

**Description:** Detects web apps missing CSP headers

**Example:**

```python
# Bad - No CSP header
```

**How to fix:**

```python
# Good
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

#### SEC-034: XML External Entity Partial

**Description:** Detects XML parsing configurations that allow partial DTD processing

**Example:**

```python
# Bad
lxml.etree.parse(user_xml)
```

**How to fix:**

```python
# Good
from defusedxml import lxml
lxml.parse(user_xml)
```

---

### LOW (10 rules)

Can be fixed when time permits.

#### SEC-040: Sensitive Information in Comments

**Example:**

```python
# Bad
# TODO: password = 'hunter2'  # remove before prod
# HACK: API key = 'sk-xxx' for testing
```

#### SEC-041: Information Disclosure in Errors

**Example:**

```python
# Bad
return jsonify(error=str(e))  # Stack trace leak
```

#### SEC-042: Sensitive Data in Logs

**Example:**

```python
# Bad
logging.info(f'User {user} logged in with password {pwd}')
```

#### SEC-043: Missing Security Headers

**Example:**

```python
# Bad - No X-Frame-Options, X-Content-Type-Options
```

#### SEC-044: EXIF Data in Uploads

**Example:**

```python
# Bad - Serve uploaded image without stripping EXIF
send_file(user_uploaded_image)
```

#### SEC-045: Missing Referrer Policy

**Example:**

```python
# Bad - No Referrer-Policy header
```

#### SEC-046: Security Feature Disabled

**Example:**

```python
# Bad
ENABLE_AUTH = False  # For testing, forgot to re-enable
```

#### SEC-047: Insufficient Anti-Automation

**Example:**

```python
# Bad - Registration form without CAPTCHA
```

#### SEC-048: Privacy Violation - PII in Logs

**Example:**

```python
# Bad
logging.info(f'User {user.email} created')
```

#### SEC-049: Weak Password Policy

**Example:**

```python
# Bad
if len(password) > 0: register()  # No strength check
```

---

### INFO (10 rules)

Best practice hints.

#### SEC-050: Deprecated Security Function

```python
# Bad
ssl.wrap_socket()  # deprecated
```

#### SEC-051: Missing Function-Level Access Control

```python
# Bad
@app.route('/admin/delete_user')  # No auth check
```

#### SEC-052: Improper Error Handling

```python
# Bad
try: dangerous() except: pass
```

#### SEC-053: Integer Overflow

```python
# Bad
data = [0] * (user_size * user_size)
```

#### SEC-054: TOCTOU Race Condition

```python
# Bad
if os.access(path, os.W_OK): os.remove(path)
```

#### SEC-055: Improper Certificate Validation

```python
# Bad
ctx.verify_mode = ssl.CERT_NONE
```

#### SEC-056: Missing Encryption for Sensitive Data

```python
# Bad - Store password in plain text
```

#### SEC-057: Improper Restriction of Rendered UI Layer

```python
# Bad - No X-Frame-Options header
```

#### SEC-058: Server-Side Request Forgery (Cloud)

```python
# Bad - Don't block cloud metadata
requests.get(metadata_url)  # 169.254.169.254
```

#### SEC-059: Business Logic Vulnerability

```python
# Bad
total = client_supplied_total  # Can be manipulated
```

---

## Code Quality Rules

Non-security rules that improve code quality.

### Basic Rules (Always On)

| Rule | Description | Example |
|------|-------------|---------|
| `ImportCleaningRule` | Standardizes and deduplicates imports | Remove duplicate imports |
| `NamingConventionRule` | Enforces PEP8 naming conventions | `myFunction` → `my_function` |
| `RefactoringRule` | Refactors nested code (Arrow Anti-pattern) | Reduce deep nesting |
| `DebugCleaner` | Removes print/log/pdb artifacts | Delete `print()`, `pdb` |
| `CommentCleaner` | Removes empty TODO/AI comments | Delete `# TODO: ` |

### Optional Rules

| Flag | Rule | Description |
|------|------|-------------|
| `--enable-quality` | `CodeQualityRule` | Magic numbers, empty except blocks |
| `--enable-performance` | `PerformanceRule` | Inefficient loops, patterns |
| `--enable-unused` | `UnusedImportRule` | Removes unused imports via AST |
| `--enable-redundant` | `RedundantExpressionRule` | Simplifies `x == True` |
| `--enable-dead-code` | `DeadCodeRule` | Removes unused functions/classes |
| `--enable-fstring` | `FStringRule` | Converts `.format()` to f-strings |
| `--enable-range-len` | `RangeLenRule` | Fixes `range(len())` anti-pattern |
| `--enable-typing` | `TypingRule` | Suggests type annotations |
| `--enable-match-case` | `MatchCaseRule` | Suggests match-case for if-elif |
| `--enable-dataclass` | `DataclassSuggestionRule` | Suggests `@dataclass` |

---

## Auto-fix Rules

Rules that can automatically fix issues:

| Rule | Auto-fix | Description |
|------|----------|-------------|
| SEC-004 (Deserialization) | Yes | yaml.load → yaml.safe_load |
| SEC-014 (YAML Unsafe Load) | Yes | Add SafeLoader |
| Quality Rules | Yes | Varies by rule |

---

## Using Rules

### Enable Security Rules

```bash
pyneat check file.py --enable-security
```

### Enable Quality Rules

```bash
pyneat clean file.py --package conservative --enable-quality
```

### Custom Rules Configuration

```toml
# pyproject.toml
[tool.pyneat]
enable_security = true
enable_quality = true
enable_performance = true
enable_unused_imports = true
enable_redundant = true
```

### List All Rules

```bash
pyneat rules
```
