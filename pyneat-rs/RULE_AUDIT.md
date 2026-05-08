# PyNEAT Rule Naming Audit

**Audit Date:** 2026-04-21
**Auditor:** Automated analysis
**Status:** COMPLETE

---

## 1. Existing Rule ID Scheme

| Prefix | Category | Count | Range |
|--------|----------|-------|-------|
| SEC | Core Security (Python) | ~50 | SEC-001 to SEC-110 |
| SEC-EXT | Extended Security (multi-lang) | 38 | SEC-073 to SEC-110 |
| PHP-SEC | PHP Security | 18 | PHP-SEC-001 to PHP-SEC-018 |
| JS | JavaScript Quality/Security | 5 | JS-001 to JS-005 |
| IAC | Infrastructure as Code | 10 | IAC-001 to IAC-010 |
| GDPR | GDPR/PII | 3 | GDPR-001 to GDPR-003 |
| PCI | PCI-DSS | 5 | PCI-001 to PCI-005 |
| AUDIT | Audit Trail | 3 | AUDIT-001 to AUDIT-003 |
| SSO | OAuth/SSO | 5 | SSO-001 to SSO-005 |
| RATE | Rate Limiting | 4 | RATE-001 to RATE-004 |
| SAAS | Multi-Tenant Isolation | 5 | SAAS-001 to SAAS-005 |
| DLP | Data Loss Prevention | 5 | DLP-001 to DLP-005 |
| LOCK | Supply Chain Lock | 4 | LOCK-001 to LOCK-004 |
| QUAL | Code Quality | 7 | QUAL-001 to QUAL-007 |
| RUST | Rust Quality | TBD | RUST-001+ |
| JAVA | Java Quality | TBD | JAVA-001+ |
| GO | Go Quality | TBD | GO-001+ |
| C# | C# Quality | TBD | CSHARP-001+ |

---

## 2. Core Security Rules (Python)

### 2.1 SEC-001 to SEC-023 (Core Security)

| ID | Rule Name | File | Status |
|----|-----------|------|--------|
| SEC-001 | Command Injection | security.rs | OK |
| SEC-002 | SQL Injection | security.rs | OK |
| SEC-003 | Eval/Exec Usage | security.rs | OK |
| SEC-004 | Deserialization RCE | security.rs | OK |
| SEC-005 | Path Traversal | security.rs | OK |
| **SEC-006** | **GAP** | - | **MISSING** |
| **SEC-007** | **GAP** | - | **MISSING** |
| **SEC-008** | **GAP** | - | **MISSING** |
| **SEC-009** | **GAP** | - | **MISSING** |
| SEC-010 | Hardcoded Secrets | security.rs | OK |
| SEC-011 | Weak Cryptography | security.rs | OK |
| SEC-012 | Insecure SSL/TLS | security.rs | OK |
| SEC-013 | XML External Entity (XXE) | security.rs | OK |
| SEC-014 | YAML Unsafe Load | security.rs | OK |
| SEC-015 | Assert in Production | security.rs | OK |
| SEC-016 | Debug Mode Enabled | security.rs | OK |
| SEC-017 | CORS Wildcard | security.rs | OK |
| SEC-018 | JWT None Algorithm | security.rs | OK |
| SEC-019 | Weak Random (Security Context) | security.rs | OK |
| **SEC-020** | **GAP** | - | **MISSING** |
| **SEC-021** | **GAP** | - | **MISSING** |
| **SEC-022** | **GAP** | - | **MISSING** |
| **SEC-023** | **GAP** | - | **MISSING** |
| **SEC-024** | AuthBypass / Open Redirect | sec024.rs | **MISMATCH**: Used for different purposes |
| **SEC-025** | **GAP** | - | **MISSING** |
| **SEC-026** | **GAP** | - | **MISSING** |

### 2.2 Extended Security (SEC-060 to SEC-110)

See Section 3 for extended security rules. Note: These overlap with core security ranges.

### 2.3 Individual Files

| File | Rule ID | Issue |
|------|---------|-------|
| sec024.rs | SEC-024 | AuthBypass |
| sec025.rs | SEC-025 | Auth issues |
| sec026.rs | SEC-026 | SSRF |
| sec042.rs | SEC-042 | In band |
| sec043.rs | SEC-043 | Race condition |
| sec044.rs | SEC-044 | Path traversal |
| sec060.rs | SEC-060 | Server errors |
| sec061.rs | SEC-061 | Auth bypass |
| sec062.rs | SEC-062 | JWT issues |
| sec063.rs | SEC-063 | AuthN issues |
| sec064.rs | SEC-064 | Auth issues |
| sec065.rs | SEC-065 | Config issues |
| sec066.rs | SEC-066 | SSRF |
| sec067.rs | SEC-067 | Security misconfig |
| sec068.rs | SEC-068 | SQL |
| sec069.rs | SEC-069 | Auth |
| sec070.rs | SEC-070 | Config |
| sec071.rs | SEC-071 | JWT |
| sec072.rs | SEC-072 | Auth |
| php_rules/php.rs | PHP-SEC-001 to PHP-SEC-018 | PHP-specific |

---

## 3. Extended Security Rules (Multi-language)

These rules span SEC-073 to SEC-110 and cover multi-language security issues:

| ID | Category | Rule Name |
|----|----------|-----------|
| SEC-073 | Auth | Authz bypass |
| SEC-074 | Auth | Privilege escalation |
| SEC-075 | Security | Improper privilege |
| SEC-076 | Crypto | Weak crypto (MD5/SHA1) |
| SEC-077 | Crypto | Inadequate encryption strength |
| SEC-078 | Crypto | Use of broken crypto |
| SEC-079 | Injection | LDAP injection |
| SEC-080 | Privacy | XPath injection |
| SEC-081 | XSS | Template injection |
| SEC-082 | Injection | OS command injection |
| SEC-083 | Config | Leftover debug |
| SEC-084 | Config | Permissive CORS |
| SEC-085 | Auth | Weak password |
| SEC-086 | Auth | Brute force (TODO) |
| SEC-087 | Serial | Insecure deserialization |
| SEC-088 | Network | Cleartext transmission |
| SEC-089 | Info | Information exposure |
| SEC-090 | SSRF | Server-side request forgery |
| SEC-091 | XXE | XML external entity |
| SEC-092 | Path | Path traversal |
| SEC-093 | Input | Mass assignment |
| SEC-094 | Session | Session fixation |
| SEC-095 | Crypto | Insufficient entropy |
| SEC-096 | Path | Path traversal (alt) |
| SEC-097 | ReDoS | Regex DoS |
| SEC-098 | Crypto | Weak random |
| SEC-099 | Injection | Dynamic code execution |
| SEC-100 | Race | TOCTOU |
| SEC-101 | Resource | Missing resource limits |
| SEC-102 | Crypto | Predictable RNG |
| SEC-103 | Trust | Missing TLS validation |
| SEC-104 | Upload | Unrestricted file upload |
| SEC-105 | DoS | Memory exhaustion |
| SEC-106 | XSS | Cross-site scripting |
| SEC-107 | XSS | CSRF |
| SEC-108 | Auth | Missing function access control |
| SEC-109 | Permissions | Incorrect default permissions |
| SEC-110 | Crypto | Use of weak crypto (alt) |

---

## 4. Language-Specific Rules

### 4.1 JavaScript (JS-001 to JS-005)
| ID | Rule Name | File |
|----|-----------|------|
| JS-001 | eval() usage | javascript/rules.rs |
| JS-002 | console.log usage | javascript/rules.rs |
| JS-003 | TODO comment | javascript/rules.rs |
| JS-004 | Hardcoded secret | javascript/rules.rs |
| JS-005 | TODO comment | javascript/rules.rs |

### 4.2 Infrastructure as Code (IAC-001 to IAC-010)
| ID | Rule Name | File |
|----|-----------|------|
| IAC-001 | Hardcoded secret | infrastructure.rs |
| IAC-002 | Insecure port | infrastructure.rs |
| IAC-003 | TODO comment | infrastructure.rs |
| IAC-004 | Public bucket | infrastructure.rs |
| IAC-005 | TODO comment | infrastructure.rs |
| IAC-006 | TODO comment | infrastructure.rs |
| IAC-007 | TODO comment | infrastructure.rs |
| IAC-008 | TODO comment | infrastructure.rs |
| IAC-009 | TODO comment | infrastructure.rs |
| IAC-010 | TODO comment | infrastructure.rs |

---

## 5. Enterprise Rules

### 5.1 GDPR/PII (GDPR-001 to GDPR-003)
| ID | Rule Name |
|----|-----------|
| GDPR-001 | Hardcoded PII |
| GDPR-002 | PII in logs |
| GDPR-003 | Missing retention policy |

### 5.2 PCI-DSS (PCI-001 to PCI-005)
| ID | Rule Name |
|----|-----------|
| PCI-001 | Unencrypted card data |
| PCI-002 | Hardcoded PAN |
| PCI-003 | Prohibited data (CVV/PIN) |
| PCI-004 | Missing encryption annotation |
| PCI-005 | Cardholder data not documented |

### 5.3 Audit Trail (AUDIT-001 to AUDIT-003)
| ID | Rule Name |
|----|-----------|
| AUDIT-001 | Missing audit trail |
| AUDIT-002 | Log without context |
| AUDIT-003 | Exec without logging |

### 5.4 OAuth/SSO (SSO-001 to SSO-005)
| ID | Rule Name |
|----|-----------|
| SSO-001 | Hardcoded client secret |
| SSO-002 | Skip SAML validation |
| SSO-003 | Infinite session |
| SSO-004 | MFA disabled |
| SSO-005 | Token no expiration |

### 5.5 Rate Limiting (RATE-001 to RATE-004)
| ID | Rule Name |
|----|-----------|
| RATE-001 | Endpoint without rate limit |
| RATE-002 | Quota not enforced |
| RATE-003 | Upload without size limit |
| RATE-004 | Unlimited semaphore |

### 5.6 Multi-Tenant Isolation (SAAS-001 to SAAS-005)
| ID | Rule Name |
|----|-----------|
| SAAS-001 | Tenant data leak |
| SAAS-002 | ORM without tenant scope |
| SAAS-003 | Cache without tenant prefix |
| SAAS-004 | Upload without tenant check |
| SAAS-005 | Admin API key default |

### 5.7 Data Loss Prevention (DLP-001 to DLP-005)
| ID | Rule Name |
|----|-----------|
| DLP-001 | Sensitive data external |
| DLP-002 | DB creds exfil |
| DLP-003 | Cloud hardcoded creds |
| DLP-004 | API token/key |
| DLP-005 | Private key |

### 5.8 Supply Chain Lock (LOCK-001 to LOCK-004)
| ID | Rule Name |
|----|-----------|
| LOCK-001 | package-lock without integrity |
| LOCK-002 | go.mod without go.sum |
| LOCK-003 | yarn.lock without checksum |
| LOCK-004 | requirements without hash |

---

## 6. Issues Found

### 6.1 ID Gaps in Core Security Range (SEC-006 to SEC-009)

The IDs SEC-006, SEC-007, SEC-008, SEC-009 are **not used** anywhere in the codebase. The sequence jumps from SEC-005 directly to SEC-010.

**Recommendation:** These IDs should be either:
- **Reclaimed** for future security rules (recommended), or
- **Documented** as reserved

### 6.2 ID Gaps in Core Security Range (SEC-020 to SEC-023)

Similar gaps exist between SEC-019 and SEC-024.

### 6.3 Overlapping Ranges

The extended security rules (SEC-073 to SEC-110) overlap with the original SEC numbering. While these serve different purposes (extended/multi-language), it creates confusion.

**Recommendation:** Consider using a separate prefix for extended rules (e.g., `EXT-001` through `EXT-038`) instead of reusing SEC-073+.

### 6.4 PHP Rules Use `PHP-SEC-XXX` Format

PHP rules use `PHP-SEC-XXX` instead of a PHP-specific prefix. This is inconsistent with other language-specific rules (JS, IAC) which don't use a language prefix.

**Recommendation:** Standardize on:
- `PHP-001` through `PHP-018` (matching JS pattern), or
- Keep `PHP-SEC-XXX` if PHP rules are security-only

### 6.5 Inline vs. Standalone Rule Definitions

Some rules are defined inline in `security.rs` while others are in separate files (`sec024.rs`, `sec025.rs`, etc.). This inconsistency makes the codebase harder to navigate.

**Recommendation:** Either:
- Keep all rules in separate files (preferred), or
- Document the organization scheme clearly

### 6.6 TODO Rules in IAC

IAC-003, IAC-005, IAC-006, IAC-007, IAC-008, IAC-009, IAC-010 are marked with `TODO` in comments but still return findings. These need actual rule implementations.

**Recommendation:** Implement real IAC scanning rules or remove the placeholder rules.

---

## 7. Total Rule Count

| Category | Count |
|----------|-------|
| Core Security (SEC-001 to SEC-059) | ~59 |
| Extended Security (SEC-073 to SEC-110) | 38 |
| PHP Security | 18 |
| JavaScript | 5 |
| Infrastructure as Code | 10 |
| Code Quality | 7 |
| Enterprise (GDPR/PCI/AUDIT/SSO/RATE/SAAS/DLP/LOCK) | 34 |
| **TOTAL** | **~171** |

---

## 8. Recommendations Summary

1. **Document gaps**: Reserve SEC-006 through SEC-009 and SEC-020 through SEC-023 as "reserved for future security rules"
2. **Rename extended rules**: Consider `EXT-001` to `EXT-038` instead of `SEC-073` to `SEC-110`
3. **PHP rules**: Choose between `PHP-XXX` (consistent with JS) or `PHP-SEC-XXX` (emphasizes security)
4. **TODO rules**: Implement or remove IAC placeholder rules
5. **Organization**: Document the rule file organization scheme
