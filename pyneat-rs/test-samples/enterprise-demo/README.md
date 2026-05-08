# PyNEAT Enterprise Demo — Real-World Security Findings
# Source: OWASP WrongSecrets (https://github.com/OWASP/wrongsecrets)
# Source: swiss-cheese (https://github.com/austimkelly/swiss-cheese)

This directory contains real-world vulnerable code from open-source security training
projects. It is used to validate PyNEAT's detection capabilities.

## Scanning This Directory

```bash
# Scan all files
pyneat scan .

# Scan with JSON output
pyneat -f json scan .

# Scan with SARIF (for GitHub Security Lab)
pyneat -f sarif scan .

# Only show critical/high findings
pyneat --severity high scan .
```

## Expected Findings Summary

| File | Language | Expected Findings |
|------|----------|-------------------|
| Java files | Java | Hardcoded secrets, weak crypto, XXE, SQL injection |
| Python files | Python | Command injection, SQL injection, broken auth |
| JavaScript files | JavaScript | XSS, hardcoded secrets, prototype pollution |
| Go files | Go | Command injection, insecure TLS, hardcoded secrets |
| Config files | YAML/TOML | Insecure defaults, missing security headers |

## Sources

- **OWASP WrongSecrets** (Java/Spring Boot) - Secrets management challenges
- **swiss-cheese** (Python/Flask) - OWASP Top 10 vulnerabilities
