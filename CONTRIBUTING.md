# Contributing to PyNeat

Thank you for your interest in contributing to PyNeat! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Rust 1.70+ (for pyneat-rs development)
- Git

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"

# Install Rust backend dependencies
cd pyneat-rs
cargo build --release
cd ..
```

### Install Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

## Code Style

We use several tools to maintain code quality:

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
ruff check .

# Type checking
mypy pyneat/
```

### Python Style Guide

- Follow PEP 8
- Use type hints for function signatures
- Add docstrings for public functions and classes
- Keep lines under 100 characters

### Rust Style Guide

- Follow Rust idioms (use `rustfmt`)
- Write unit tests for new functionality
- Use `clippy` for additional linting

## Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_agent_marker/test_marker_data.py

# Run with coverage
pytest --cov=pyneat --cov-report=html

# Run pyneat-rs tests
cd pyneat-rs
cargo test
```

## Project Structure

```
pyneat/
├── core/           # Core data structures (AgentMarker, Manifest)
├── rules/          # Rule implementations
│   ├── safe/       # Safe package rules
│   ├── conservative/ # Conservative package rules
│   ├── destructive/ # Destructive package rules
│   └── security/   # Security rules
├── scanner/        # Language-specific scanners
├── cli.py         # Command-line interface
├── benchmark.py   # Performance benchmarks
└── ...
```

## Adding New Rules

### 1. Create the Rule Class

```python
from pyneat.rules.base import AIBugRule, FixResult

class MyNewRule(AIBugRule):
    """Description of what this rule detects."""

    RULE_ID = "MYRULE-001"
    SEVERITY = "medium"
    LANGUAGES = ["python"]

    def detect(self, node: Any, context: Dict[str, Any]) -> List[FixResult]:
        # Detection logic
        return []

    def fix(self, node: Any, context: Dict[str, Any]) -> Optional[str]:
        # Fix logic
        return None
```

### 2. Register the Rule

```python
# In pyneat/rules/__init__.py
from .my_new_rule import MyNewRule

ALL_RULES = [
    # ... existing rules
    MyNewRule(),
]
```

### 3. Add Tests

```python
# tests/test_my_new_rule/
def test_detects_issue():
    rule = MyNewRule()
    result = rule.detect(sample_code)
    assert len(result) > 0
```

## Submitting Changes

### 1. Create a Feature Branch

```bash
git checkout -b feature/my-new-feature
```

### 2. Make Your Changes

- Write code following our style guidelines
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Your Changes

```bash
git add .
git commit -m "Add feature: my new feature"
```

Commit message format:
- Use imperative mood ("Add feature" not "Added feature")
- Start with capital letter
- Keep the first line under 72 characters
- Add body for complex changes

### 4. Push and Create Pull Request

```bash
git push origin feature/my-new-feature
```

Then open a Pull Request on GitHub with:
- Clear title and description
- Reference to related issues
- Screenshots for UI changes

## Release Process

1. Update version in `pyneat/__init__.py`
2. Update CHANGELOG.md
3. Create git tag: `git tag v2.x.x`
4. Push tag: `git push origin v2.x.x`
5. GitHub Actions will build and publish to PyPI

## Questions?

- Open an issue on GitHub
- Check the [documentation](./docs/)
- Review existing issues and PRs

## License

By contributing to PyNeat, you agree that your contributions will be licensed under the MIT License.
