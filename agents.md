# Project Agents.md Guide for OpenAI Codex

This `agents.md` file provides comprehensive guidance for OpenAI Codex and other AI agents contributing to the **DisMAL** codebase.

DisMAL (Discovery-Mod-And-Lookup Toolkit) is a CLI-based Python tool for interacting with BMC Discovery appliances via API or CLI.

---

## Project Structure for OpenAI Codex Navigation

- `/core`: Primary source code for data access, command dispatch, and output formatting
- `/bin`: CLI entry points and scripts
- `/docs`: Documentation files and markdown guides
- `/tests`: Pytest-based unit and integration tests
- `/output_*`: Example directories for generated output (used for testing or demonstration)
- `/tools`: Optional utilities for development, automation, or Codex agent runners

Agents must avoid modifying:
- `*.csv` or generated data under `output_*`
- Any binary log or appliance exports

---

## Coding Conventions for OpenAI Codex

### General Python Conventions

- Use **Python 3.8+** compatible syntax
- Follow **PEP8** style guide unless local conventions differ
- Prefer built-in libraries (`argparse`, `subprocess`, `requests`) unless justified
- Use **meaningful function and variable names**
- Include **inline comments** for any logic branches, string parsing, or regex

### CLI-Specific Guidance

- All CLI commands are defined and dispatched in `dismal.py` using `argparse`
- Agents should preserve subcommand structure and `--access_method` logic
- Add new subcommands only if tested and scoped appropriately

### Output and File Writing

- Generated output should go into a new subdirectory named `output_<appliance>` or a temporary path during tests
- Use `--stdout` only for human inspection, not structured parsing

---

## Testing Requirements for OpenAI Codex

Tests should be created and maintained under `/tests` and follow these conventions:

```bash
# Run all tests
python3 -m pytest

# Run specific test file
python3 -m pytest tests/test_access.py

# Generate coverage report
coverage run -m pytest && coverage report