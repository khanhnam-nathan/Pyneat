# Security Rules Documentation (v2.2.5+)

## New Rules Added (SEC-060 to SEC-072)

### SEC-060: Autocomplete Enabled on Sensitive Fields
**Severity:** Medium | **CWE:** CWE-200

Detects when autocomplete attribute is enabled on sensitive form fields like passwords, credit card numbers, SSN, etc.

**Example:**
```html
<!-- VULNERABLE -->
<input type="password" name="pwd" autocomplete="on">

<!-- SAFE -->
<input type="password" name="pwd" autocomplete="off">
```

**Fix:** Add `autocomplete='off'` or `autocomplete='new-password'` to sensitive input fields.

---

### SEC-061: Missing Subresource Integrity (SRI)
**Severity:** Medium | **CWE:** CWE-345

Detects when external scripts/stylesheets are loaded from CDN without integrity check.

**Example:**
```html
<!-- VULNERABLE -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- SAFE -->
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-..."
        crossorigin="anonymous"></script>
```

**Fix:** Add `integrity` and `crossorigin` attributes to external scripts.

---

### SEC-062: Missing Content-Type Validation
**Severity:** High | **CWE:** CWE-434

Detects file uploads without proper Content-Type header validation.

**Example:**
```python
# VULNERABLE
file = request.files.get('upload')
file.save(os.path.join(UPLOAD_DIR, file.filename))

# SAFE
if file.content_type in ALLOWED_TYPES:
    file.save(os.path.join(UPLOAD_DIR, file.filename))
```

**Fix:** Always validate Content-Type header server-side using a whitelist approach.

---

### SEC-063: Missing Rate Limiting
**Severity:** Medium | **CWE:** CWE-307

Detects sensitive endpoints without rate limiting protection.

**Target endpoints:**
- Login/Authentication
- Registration
- Password reset
- OTP/2FA verification
- SMS/Email sending

**Example:**
```python
# VULNERABLE
@app.route('/login')
def login():
    # No rate limiting
    return authenticate()

# SAFE
@app.route('/login')
@rate_limit(limit=5, period=60)  # 5 attempts per minute
def login():
    return authenticate()
```

**Fix:** Add rate limiting using decorators like `@rate_limit` or middleware.

---

### SEC-064: Weak JWT Secret Key
**Severity:** Critical | **CWE:** CWE-344

Detects hardcoded weak secrets used for JWT signing.

**Example:**
```python
# VULNERABLE
JWT_SECRET = "secret_key"
token = jwt.encode(payload, "123456", algorithm="HS256")

# SAFE
JWT_SECRET = os.environ.get('JWT_SECRET')
# or use a secure secret manager
```

**Fix:** Use cryptographically strong secret (256+ bits) from environment variables.

---

### SEC-065: Incomplete Session Destruction on Logout
**Severity:** Medium | **CWE:** CWE-613

Detects when session is not properly destroyed on logout.

**Example:**
```python
# VULNERABLE
def logout():
    response.delete_cookie('session_id')  # Only client-side

# SAFE
def logout():
    session.flush()  # or session.delete() / session.invalidate()
    response.delete_cookie('session_id')
```

**Fix:** Properly destroy session server-side in addition to clearing cookies.

---

### SEC-066: Timing Attack Vulnerability
**Severity:** Medium | **CWE:** CWE-208

Detects string comparison that could be vulnerable to timing attacks.

**Example:**
```python
# VULNERABLE
if token == user_token:
    return True

# SAFE
import hmac
if hmac.compare_digest(token, user_token):
    return True
```

**Fix:** Use timing-safe comparison functions: `hmac.compare_digest()` or `secrets.compare_digest()`.

---

### SEC-067: Weak Server-side Validation
**Severity:** High | **CWE:** CWE-20

Detects input validation only done client-side without server verification.

**Example:**
```html
<!-- VULNERABLE - Client-side only -->
<form onsubmit="return validatePassword()">
    <input type="password" pattern=".{8,}" required>
</form>

<!-- SAFE - Client + Server validation -->
<form onsubmit="return validatePassword()">
    <input type="password" pattern=".{8,}" required>
</form>

# Server-side validation required!
if not validate_password_strength(password):
    return error("Password too weak")
```

**Fix:** Always validate input server-side. Client-side validation can be bypassed.

---

### SEC-068: Client-side Price Calculation
**Severity:** High | **CWE:** CWE-641

Detects when price calculations are done client-side and sent to server.

**Example:**
```javascript
// VULNERABLE - Client calculates total
total = parseFloat(price * quantity);
fetch('/api/checkout', {
    body: JSON.stringify({ total: total })
});

# SAFE - Server calculates
@app.route('/api/checkout')
def checkout():
    items = request.json['items']
    total = calculate_total_server_side(items)  # Always server-side
    return process_payment(total)
```

**Fix:** Calculate prices server-side only. Never trust client-submitted prices.

---

### SEC-069: Dangerous Dependencies
**Severity:** Medium | **CWE:** CWE-1104

Detects potentially dangerous or outdated dependencies.

**Detected issues:**
- Outdated web frameworks (Django < 3.x, Flask < 2.x)
- Outdated requests library
- Unmaintained packages (PyCrypto)
- Debug packages in production
- Insecure serialization (pickle)

**Fix:** Keep dependencies updated. Run `pip list --outdated` regularly.

---

### SEC-070: Missing Docker Image Vulnerability Scan
**Severity:** Medium | **CWE:** CWE-1104

Detects Docker configurations without vulnerability scanning.

**Example:**
```dockerfile
# VULNERABLE
FROM python:3.9-slim
RUN pip install -r requirements.txt

# SAFE
FROM python:3.9-slim
RUN pip install -r requirements.txt
# Run vulnerability scan before deploy
RUN trivy image python:3.9-slim
```

**Fix:** Add vulnerability scanning using Trivy, Grype, or similar tools in CI/CD.

---

### SEC-071: Sensitive Data in JWT Payload
**Severity:** High | **CWE:** CWE-315

Detects sensitive data stored in JWT payload.

**Example:**
```python
# VULNERABLE - Sensitive data in JWT
payload = {
    "user": "john",
    "password": "secret123",  # NEVER do this!
    "credit_card": "4111111111111111"
}
jwt.encode(payload, secret, algorithm="HS256")

# SAFE - Minimal claims only
payload = {
    "user_id": 12345,
    "exp": time.time() + 3600
}
jwt.encode(payload, secret, algorithm="HS256")
```

**Fix:** JWT is only Base64 encoded, not encrypted. Never store sensitive data in JWT.

---

### SEC-072: Missing CSP Nonce for Inline Scripts
**Severity:** Medium | **CWE:** CWE-1021

Detects Content-Security-Policy without nonce for inline scripts.

**Example:**
```html
<!-- VULNERABLE -->
<script nonce="abc123">
    // This is safe with nonce
</script>

<!-- But CSP without nonce checking -->
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">

# VULNERABLE - If nonce is used but not enforced in CSP
```

**Fix:** Add nonce to CSP: `Content-Security-Policy: script-src 'nonce-{RANDOM}'`

---

## Total Rules Coverage

| Category | Count | Severity Levels |
|----------|-------|----------------|
| Critical | 5 | Command Injection, SQL Injection, etc. |
| High | 10 | Hardcoded Secrets, Weak Crypto, JWT issues |
| Medium | 17 | XSS, SSRF, CORS, New Rules |
| Low | 11 | Info Disclosure, Sensitive Comments |
| Info | 9 | Deprecated Functions, Business Logic |
| **Total** | **52+** | All OWASP Top 10 covered |

## CWE Coverage

All rules map to CWE (Common Weakness Enumeration) IDs for easier integration with security tools and compliance frameworks.
