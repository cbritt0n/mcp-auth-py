#!/usr/bin/env bash
set -euo pipefail

echo "Setting up development environment for mcp-auth-py"

python -m pip install --upgrade pip
echo "Installing project in editable mode"
python -m pip install -e .

echo "Installing development requirements"
python -m pip install -r requirements-dev.txt

echo "Installing pre-commit hooks"
pre-commit install || true

echo "Done. Run 'pytest' to run tests."
