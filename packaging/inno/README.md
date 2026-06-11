# NexLog Inno Setup Installer
===========================

## Overview

This directory contains a professional Inno Setup project for building a production-ready Windows installer for NexLog!

## Features

- Modern wizard-style installer with all required components (GUI, CLI, System Tray)
- Windows 7+ support
- Registry entries
- Start Menu and desktop shortcuts
- File association for .nexlog case files
- System PATH integration (optional)
- Startup shortcut for system tray mode (optional)
- Complete uninstaller that cleans everything
- Setup with Inno Setup 6.4+ compatible

## Building the Installer

### Prerequisites
1. Inno Setup 6.4 or higher installed from https://jrsoftware.org/isdl.php
2. Python 3.10+
3. NexLog's Python dependencies installed (pip install -e .[gui])

### Steps
1. Run `python scripts/package_release.py --windows-gui-installer`
2. The installer will be created in the `release/` directory!

## Code Signing (Optional, but Recommended)

To digitally sign the installer for Windows security compliance, update the `[Setup]` section in `nexlog.iss` with your code signing certificate details! Uncomment the SignTool lines and configure as needed! You can use tools like `signtool` (from Windows SDK) or third-party tools like `kSign`!
