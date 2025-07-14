#!/bin/bash
set -e

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment in $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

echo "Installing Python dependencies from requirements.txt into virtual environment..."
python -m pip install --prefer-binary --use-deprecated=legacy-resolver -r requirements.txt
echo ""

if [ ! -d "node_modules" ]; then
  npm install --save-dev @mermaid-js/mermaid-cli
fi

echo "Dependency installation complete."