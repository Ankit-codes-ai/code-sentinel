@echo off
setlocal

REM Directory for the virtual environment
set "VENV_DIR=.venv"

REM Create the virtual environment if it does not exist
if not exist "%VENV_DIR%" (
    echo Creating Python virtual environment in %VENV_DIR%...
    python -m venv "%VENV_DIR%"
)

REM Install Python dependencies inside the virtual environment
echo Installing Python dependencies from requirements.txt into virtual environment...
"%VENV_DIR%\Scripts\python.exe" -m pip install --prefer-binary --use-deprecated=legacy-resolver -r requirements.txt

REM Install Mermaid CLI (Node.js dependency)
if not exist node_modules (
    npm install --save-dev @mermaid-js/mermaid-cli
)

echo.