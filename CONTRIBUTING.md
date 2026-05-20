# Contributing to cfn-drift-extended

We welcome contributions! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/your-org/cfn-drift-extended.git
cd cfn-drift-extended
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# Unit tests
pytest

# With coverage
pytest --cov=cfn_drift_extended --cov-report=term-missing

# Integration tests (requires AWS credentials)
cd integration-tests
./deploy.sh
./introduce-drift.sh
./validate.sh
./cleanup.sh
```

## Code Quality

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass and lint is clean
4. Update README.md if adding user-facing features
5. Submit a PR with a clear description of the change

## Architecture

```
src/cfn_drift_extended/
├── cli.py              # Click CLI (user-facing)
├── auditor.py          # Orchestrator (collect → compare → report)
├── models.py           # Pydantic domain models
├── exceptions.py       # Error hierarchy
├── collectors/         # Gather state from AWS APIs
│   ├── cfn_collector.py   # Expected state from CFN templates
│   └── iam_collector.py   # Actual state from IAM API
├── comparators/        # Diff expected vs actual
│   └── iam_comparator.py
└── reporters/          # Format output
    ├── console.py
    └── json_report.py
```

## Adding a New Resource Type

To add support for a new resource type (e.g., Lambda env vars):

1. Add a collector in `collectors/` that gathers the expected and actual state
2. Add a comparator in `comparators/` that diffs them
3. Add new `DriftType` enum values in `models.py`
4. Wire it into `auditor.py`
5. Write tests

## Code Style

- Python 3.11+, type hints everywhere
- Pydantic for models, frozen for immutability
- `ruff` for linting (config in pyproject.toml)
- Docstrings on all public methods
