# Contributing to PyNEAT

Thank you for your interest in contributing to PyNEAT! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

Please read and follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We are committed to creating an open and friendly environment for everyone.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/pyneat.git
   cd pyneat
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/khanhnam-nathan/Pyneat.git
   ```

## Development Setup

### Python Development

```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Or install Rust version
pip install -e ".[dev,rust]"
```

### Rust Development (pyneat-rs)

```bash
# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Navigate to pyneat-rs directory
cd pyneat-rs

# Build release
cargo build --release

# Run tests
cargo test

# Build Python bindings
maturin develop
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| click | >=8.0.0 | CLI framework |
| libcst | >=0.4.0 | AST manipulation |
| pytest | >=7.0.0 | Testing |
| pytest-asyncio | >=0.21.0 | Async testing |
| ruff | >=0.1.0 | Linting |
| mypy | >=1.0.0 | Type checking |

## Project Structure

```
pyneat/
├── pyneat/
│   ├── __init__.py          # Public API
│   ├── cli.py               # CLI entry point
│   ├── config.py            # Configuration
│   ├── core/
│   │   ├── engine.py        # Rule engine
│   │   └── types.py         # Type definitions
│   ├── rules/
│   │   ├── base.py          # Rule base class
│   │   ├── security.py      # Security rules
│   │   ├── quality.py       # Code quality rules
│   │   └── ...              # Other rules
│   └── utils/
│       └── ...
├── pyneat-rs/               # Rust implementation
│   ├── src/
│   │   ├── lib.rs           # PyO3 bindings
│   │   ├── scanner.rs       # Scanner
│   │   ├── rules.rs         # Rule definitions
│   │   └── findings.rs      # Finding struct
│   └── Cargo.toml
├── tests/
│   ├── test_engine.py
│   ├── test_rules/
│   └── ...
└── docs/
    └── ...
```

## Making Changes

1. **Create a new branch**

```bash
# Always create branch from main
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

2. **Commit changes**

```bash
# Use conventional commits
git commit -m "feat: add new security rule for JWT validation"
git commit -m "fix: correct regex pattern for SQL injection detection"
git commit -m "docs: update contributing guidelines"
git commit -m "test: add unit tests for naming convention rule"
```

3. **Commit Message Format**

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, missing semicolons, etc
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(security): add SEC-018 JWT None algorithm detection

Implements detection of JWT tokens using 'none' algorithm,
which allows attackers to forge valid tokens.

Closes #123
```

```
fix(scanner): correct regex for command injection detection

The previous regex was too aggressive and caused false positives
in cases where os.system was used in test files.

Fixes #456
```

## Pull Request Process

1. **Ensure all tests pass**

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=pyneat --cov-report=html

# Type check
mypy pyneat/

# Lint code
ruff check pyneat/
```

2. **Update documentation**

- If adding a new feature, update README.md
- If adding a new rule, update CHANGELOG.md
- If changing the API, update docstrings

3. **Create Pull Request**

```bash
# Push branch
git push origin feature/your-feature-name
```

- Use a descriptive title
- Describe changes in detail
- Add screenshots if there are UI changes
- Reference related issues

4. **Review Process**

- At least 1 maintainer review
- Address all feedback
- Do not merge with unresolved conversations

## Coding Standards

### Python

- Use type hints for all functions
- Follow PEP 8
- Maximum line length: 100 characters
- Use f-strings instead of .format()
- Docstrings for public APIs

```python
def scan_security(code: str) -> list[SecurityFinding]:
    """Scan code for security vulnerabilities.

    Args:
        code: Python source code to scan.

    Returns:
        List of SecurityFinding objects.

    Raises:
        SyntaxError: If code has syntax errors.
    """
    ...
```

### Rust

- Use 2021 edition
- Run `cargo fmt` before committing
- Follow Rust idioms
- Use `?` instead of `match` for Result types

```rust
pub fn scan_security(code: &str) -> Result<Vec<Finding>, ScanError> {
    let tree = tree_sitter::parse(code)?;
    let findings = rules::scan(&tree, code)?;
    Ok(findings)
}
```

### Git

- Do not commit generated files
- Do not commit secrets or credentials
- Use reasonable `.gitignore`
- Commit messages in English

## Testing

### Unit Tests

```bash
# Run a specific test file
pytest tests/test_engine.py -v

# Run a specific test
pytest tests/test_engine.py::test_clean_code -v

# Run with verbose output
pytest -vv
```

### Integration Tests

```bash
# Run integration tests
pytest tests/test_integration.py

# Test with real-world files
python test_real/pytest_python.py
```

### Fuzz Testing

```bash
# Run fuzz tests
pytest tests/test_fuzz.py

# Test with GitHub samples
python tests/test_fuzz_github.py
```

### Writing Tests

```python
def test_security_rule_detection():
    """Test that SEC-001 detects command injection."""
    code = 'os.system("rm -rf /")'
    result = security_rule.apply(CodeFile(code))

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-001"
    assert result.findings[0].severity == "CRITICAL"
```

## Documentation

### Docstrings

Use Google-style docstrings:

```python
def clean_file(path: Path, in_place: bool = False) -> TransformationResult:
    """Clean a single Python file.

    Performs a multi-pass analysis to identify and fix code quality
    issues, security vulnerabilities, and AI-generated artifacts.

    Args:
        path: Path to the Python file to clean.
        in_place: If True, modify the file in place. Otherwise, print diff.

    Returns:
        TransformationResult containing all findings and transformations.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read or written.

    Example:
        >>> result = clean_file(Path("example.py"))
        >>> print(f"Found {len(result.findings)} issues")
    """
```

### README Updates

When adding a new feature:
1. Add to the Features table
2. Add a usage example
3. Add a screenshot if there is CLI output

### CHANGELOG Updates

Follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/):

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Description of changed functionality

### Deprecated
- Description of soon-to-be removed feature

### Removed
- Description of removed feature

### Fixed
- Description of bug fix

### Security
- Description of security improvement
```

## Questions?

- Create a GitHub Issue
- Join discussions
- Email: khanhnam.copywriting@gmail.com

## License

By contributing, you agree that your contributions will be licensed under the GNU AGPLv3 License.
