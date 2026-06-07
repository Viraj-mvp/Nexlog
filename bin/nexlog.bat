@echo off
rem NexLog CLI wrapper for Windows Command Prompt and PowerShell
rem Locates the repository root and runs main.py

set SCRIPT_DIR=%~dp0
set REPO_ROOT=%SCRIPT_DIR%..

python "%REPO_ROOT%\main.py" %*
