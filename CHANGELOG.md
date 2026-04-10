# Changelog

Tất cả thay đổi đáng chú ý của dự án này sẽ được ghi chép trong tệp này.

Dự án tuân theo [Semantic Versioning](https://semver.org/lang/vi/) và [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.4.0] - 2026-04-10

### Added

#### Interactive Feature Menu
- Menu hiển thị sau mỗi lệnh `check` và `clean`
- Gợi ý thông minh theo context (thay đổi tùy command vừa chạy)
- 7 tính năng: Security Check, Explain Rule, Clean Code, Export Report, View Diff, View Rules, Configure
- Option tiếng Anh, mô tả tiếng Việt (chuyên nghiệp)
- Nhấn Enter hoặc q để thoát

## [2.3.0] - 2026-04-10

### Added

#### AgentMarker (Issue Tracking Metadata)
- `AgentMarker` dataclass in `pyneat.core.types` - metadata cho từng issue
- Fields: `marker_id`, `issue_type`, `rule_id`, `severity`, `line`, `end_line`, `hint`, `why`, `confidence`, `cwe_id`, `can_auto_fix`, `fix_diff`, `auto_fix_before/after`, `requires_user_input`, `related_markers`
- Methods: `to_dict()`, `from_dict()`, `to_json()`, `from_json()`, `to_comment()`
- Auto-export as `# PYNAGENT: {...}` comments in source code

#### ManifestExporter & Export Formats
- `ManifestExporter` class - ghi markers ra `.pyneat.manifest.json`
- `export_to_sarif()` - SARIF 2.1.0 format (GitHub Security tab, Azure DevOps)
- `export_to_codeclimate()` - Code Climate format cho CI integration
- `export_to_markdown()` - Markdown report đọc bằng người
- `MarkerParser` class - parse markers từ source và manifest file

#### MarkerCleanup (Stale Marker Removal)
- `MarkerCleanup` class - xóa markers sau khi issues đã fix
- `remove_stale_markers()` - chỉ xóa markers không còn trong remaining_issues
- `remove_all_markers()` - xóa tất cả markers
- Hỗ trợ malformed markers

#### AI Bug Pattern Detection (`AIBugRule`)
- `AIBugRule` - phát hiện lỗi đặc trưng của AI-generated code
- **Resource Leaks**: `open()` không `with`, `requests.*` không timeout
- **Boundary Errors**: `list[0]` không check empty, `.split()[0]`
- **Phantom Packages**: import tên ngắn, tên generic (utils, helpers, ai)
- **Fake Parameters**: `param1=x`, `fake=True`, `dummy_arg`
- **Redundant I/O**: Gọi API lặp 3+ lần với cùng args
- **Naming Inconsistency**: `userId` vs `user_id` trong cùng file

#### Additional Rules
- `NamingInconsistencyRule` - phát hiện mixed camelCase/snake_case
- `CodeDuplicationRule` - phát hiện duplicate function bodies
- `TransformationResult.agent_markers` field - lưu markers từ rule execution

## [2.2.1] - 2026-04-10

### Added

#### Auto Manifest Export Integration
- **Config-driven Export**: `export_manifest = true` in `[tool.pyneat]` section
- **Pre-commit Hook**: Auto-generate `.pyneat.manifest.json` on commit
- **GitHub Actions**: CI/CD job for automated manifest export on push/PR

#### Enhanced CLI
- `--export-manifest` flag for both `clean` and `clean-dir` commands
- Auto-export based on `pyproject.toml` configuration

## [2.0.0-beta.2] - 2026-04-09

### Added

#### Rust Security Rules (SEC-001 ~ SEC-059)
- SEC-001: Command Injection Detection
- SEC-002: SQL Injection Detection
- SEC-003: Eval/Exec Usage Detection
- SEC-004: Deserialization RCE Detection
- SEC-005: Path Traversal Detection
- SEC-010: Hardcoded Secrets Detection
- SEC-011: Weak Cryptography Detection
- SEC-012: Insecure SSL/TLS Usage
- SEC-013: XXE (XML External Entity) Detection
- SEC-014: YAML Unsafe Load (Auto-fix available)
- SEC-015: Assert in Production
- SEC-016: Debug Mode Enabled
- SEC-017: CORS Wildcard
- SEC-018: JWT None Algorithm
- SEC-019: Weak Random for Security
- SEC-020: LDAP Injection
- SEC-021: Cross-Site Scripting (XSS)
- SEC-022: Server-Side Request Forgery (SSRF)
- SEC-023: Open Redirect
- SEC-024~SEC-034: Medium severity rules
- SEC-040~SEC-049: Low severity rules
- SEC-050~SEC-059: Info severity rules

#### Rust Quality Rules
- QUAL-001: Unused Import Detection
- QUAL-002: Redundant Expression Detection
- QUAL-003: Magic Number Detection
- QUAL-004: Empty Except Block Detection
- QUAL-005: Complex Function Detection

#### Rust Architecture Improvements
- Tree-sitter Python grammar integration
- Auto-fix system với fixer module
- Diff generation cho code changes
- PyO3 extension module (cdylib)

### Changed

#### Performance Improvements
- Rust binary build với LTO và strip symbols
- Parallel scanning với Rayon
- Pre-compiled regex patterns với OnceLock
- Không có GIL contention

### Fixed

- Cargo.toml output filename collision (bin vs lib)
- Tree-sitter parser integration

## [2.0.0-beta.1] - 2026-04-08

### Added

#### Tài liệu
- Tạo CHANGELOG.md để theo dõi thay đổi phiên bản
- Tạo CONTRIBUTING.md với hướng dẫn phát triển
- Tạo CODE_OF_CONDUCT.md với quy tắc ứng xử cộng đồng

#### Kiến trúc Rust (pyneat-rs)
- Khởi tạo project Rust với PyO3 bindings
- Implement 5 security rules cơ bản (SEC-001 ~ SEC-005):
  - SEC-001: Command Injection Detection
  - SEC-002: SQL Injection Detection
  - SEC-003: Eval/Exec Usage Detection
  - SEC-004: Deserialization RCE Detection
  - SEC-005: Path Traversal Detection
- Parallel scanning với Rayon
- Pre-compiled regex patterns với OnceLock
- Benchmark suite để so sánh Python vs Rust performance

#### Cấu trúc thư mục mới
```
pyneat-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs          # PyO3 bindings
│   ├── main.rs         # CLI entry point
│   ├── scanner.rs      # Regex-based scanner
│   ├── rules.rs         # Rule definitions
│   └── findings.rs      # Finding struct
├── benches/
│   └── benchmark.rs
└── tests/
    └── test_scanner.rs
```

### Changed

#### Performance Improvements
- Regex patterns được pre-compile 1 lần và reuse
- Parallel pattern matching với Rayon
- Không có GIL contention

### Planned for 2.0.0 (Full Release)

- [x] Tree-sitter Python grammar integration ✅
- [x] Full 50+ security rules (SEC-001 ~ SEC-059) ✅
- [x] Auto-fix system cho các vulnerabilities phổ biến ✅
- [x] Quality rules (imports, naming, dead code) ✅
- [ ] CLI integration với `--rust` flag
- [ ] Binary wheels cho pip install pyneat[rust]
- [ ] Windows wheels với proper Python 3.10+ support

## [2.0.0] - 2026-03-XX

### Added

#### New Rules
- `IsNotNoneRule` - Chuyển đổi các pattern `x is not None`
- `MagicNumberRule` - Phát hiện và flag magic numbers
- `RangeLenRule` - Sửa anti-pattern `range(len())`
- `DeadCodeRule` - Xóa functions và classes không sử dụng qua AST analysis
- `FStringRule` - Chuyển đổi `.format()` sang f-strings
- `TypingRule` - Gợi ý type annotations cho functions không có typing
- `MatchCaseRule` - Gợi ý chuyển đổi if-elif chains sang match-case (Python 3.10+)
- `DataclassSuggestionRule` - Gợi ý `@dataclass` cho các class đơn giản

#### Rule System
- Refactored comprehensive rule system với priority ordering
- Cleaner CI/CD workflow với lint và stress tests
- Enhanced isolated block processing cho nested code
- Fixed Unicode encoding issues trong CLI output

### Changed

- Refactored comprehensive rule system với priority ordering
- Added comprehensive test samples cho real-world scenarios
- Cleaner CI/CD workflow với lint và stress tests
- Enhanced isolated block processing cho nested code
- Fixed Unicode encoding issues trong CLI output
- Fixed CI configuration để sử dụng proper Linux Python paths
- Fixed compileall verification cho package integrity

### Removed

- Removed redundant test files cho leaner test suite
- Simplified CI pipeline (single pytest run thay vì multiple jobs)

## [1.0.0] - 2026-01-XX

### Added

- Initial release với core cleaning rules:
  - ImportCleaningRule
  - NamingConventionRule
  - RefactoringRule
  - DebugCleaner
  - CommentCleaner
- Security scanning với SecurityScannerRule
- Security registry với 50+ security rules (SEC-001 ~ SEC-059)
- CLI với Click framework
- Pre-commit hooks integration
- GitHub Actions workflow
- 7-layer protection system
- AST và CST caching
- Semantic guards
- Type shields
