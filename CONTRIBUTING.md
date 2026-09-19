# Contributing to Fang

Thank you for your interest in improving `Fang`! We welcome contributions that uphold our commitment to reliable, lightweight, and secure code.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/X-4xu/fang.git
   cd fang
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests:**
   ```bash
   pytest
   ```

## Development Guidelines

- **Zero Command Execution**: Log data must remain passive text. Under no circumstances should log data be passed to `eval()`, `exec()`, or subshell execution.
- **Fail-Safe Parsing**: Parsers must never crash on malformed, truncated, or non-ASCII log lines.
- **Type Annotations**: All public functions, classes, and methods must have standard Python type annotations.
- **Testing**: Every bugfix or new feature must be accompanied by unit or integration tests with sample log fixtures.
- **Deterministic Logic**: The sliding-window detection algorithm must remain deterministic and testable.

## Submitting a Pull Request

1. Create a descriptive feature branch: `git checkout -b feature/rfc3339-subseconds`
2. Ensure all tests pass: `pytest -v`
3. Commit with concise, descriptive messages.
4. Submit a Pull Request targeting `main`.
