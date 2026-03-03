# Contributing to SecPostureIQ

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to SecPostureIQ.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](../../issues) to report bugs or suggest features.
- Search existing issues before creating a new one.
- Include steps to reproduce, expected behaviour, and actual behaviour.

### Pull Requests

1. **Fork** the repository and create a feature branch from `main`.
2. **Install** dependencies:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   ```
3. **Make changes** following the conventions below.
4. **Run tests**:
   ```bash
   pytest
   ```
5. **Lint**:
   ```bash
   ruff check . && ruff format --check .
   ```
6. **Commit** with a clear, descriptive message (e.g., `fix: handle empty secure score response`).
7. **Push** and open a Pull Request against `main`.

### Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `chore:` — maintenance (deps, CI, configs)
- `test:` — adding or updating tests
- `refactor:` — code change that neither fixes a bug nor adds a feature

## Development Setup

### Prerequisites

- Python 3.11+
- Docker (for container builds)
- Azure CLI (`az`) if testing infrastructure

### Local Development

```bash
# Clone
git clone <repo-url>
cd posture-iq

# Virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev extras
pip install -e ".[dev]"

# Run locally
uvicorn src.api.app:app --reload --port 8000
```

### Running Tests

```bash
# All tests
pytest

# Unit only
pytest tests/unit/

# With coverage
pytest --cov=src --cov-report=term-missing
```

## Style Guide

- **Formatter**: `ruff format`
- **Linter**: `ruff check`
- **Type hints**: Use throughout; run `pyright` or `mypy` for static analysis.
- **Docstrings**: Google style.
- **Line length**: 88 characters (ruff default).

## Security

If you discover a security vulnerability, please follow the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
