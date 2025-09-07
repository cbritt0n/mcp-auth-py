Thanks for considering contributing!

Guidelines
- Fork the repo and open a PR against `main`.
- Add tests for new providers or behavior. New features should include at least one unit test.
- Keep changes small and focused. Use type hints and docstrings.

Testing
- Run `pytest` before submitting a PR.

Code style
- Use 4-space indentation and follow the existing project style.

CI status
- This repository uses GitHub Actions for CI. The README contains a status badge that points to the workflow (`.github/workflows/ci.yml`).
- The CI run executes `pre-commit` (formatters/linters) and the test suite; if `pre-commit` fails it will block the workflow.
- To reproduce CI locally:

```bash
# install pre-commit (only needed to run hooks locally)
python -m pip install --user pre-commit
pre-commit install
pre-commit run --all-files
# run tests
pytest -q
```

Please ensure `pre-commit` and tests pass locally before opening a PR.

CI badge

[![CI](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml)

Troubleshooting pre-commit failures

- If `pre-commit` reports formatting issues (black/isort), run the hooks locally to auto-fix:

```bash
pre-commit run black --all-files
pre-commit run isort --all-files
pre-commit run ruff --all-files
```

- If a hook still fails after auto-fix, inspect the reported file and run the applicable formatter manually. Common fixes:
	- Long lines: rewrap code, or move expressions into helper variables.
	- Import ordering: run `isort` as above.
	- Type/linters: run `ruff` and address reported issues.

- If hooks fail in CI but pass locally, ensure you used the same Python version and that any generated files (e.g., virtualenv artifacts) are not accidentally committed.

