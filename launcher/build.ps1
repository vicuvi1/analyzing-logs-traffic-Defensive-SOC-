# Build SOCLogAnalyzer.exe — run from project root or launcher folder.
# Requires: Python 3.10+, pip

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "=== Building SOC Log Analyzer Launcher ===" -ForegroundColor Cyan

# Build dependencies
python -m pip install --upgrade pip pyinstaller pillow

# Generate icon
python launcher/create_icon.py

# PyInstaller spec inline
$iconPath = Join-Path $Root "assets\icon.ico"
$launcherPath = Join-Path $Root "launcher\launcher.py"
$distPath = Join-Path $Root "dist"

if (Test-Path $distPath) { Remove-Item $distPath -Recurse -Force }

pyinstaller `
    --onefile `
    --name "SOCLogAnalyzer" `
    --icon $iconPath `
    --console `
    --exclude-module streamlit `
    --exclude-module torch `
    --exclude-module tensorflow `
    $launcherPath

Write-Host ""
Write-Host "SUCCESS: dist\SOCLogAnalyzer.exe" -ForegroundColor Green
Write-Host "Copy this file to your Desktop or pin to Start Menu." -ForegroundColor Yellow
Write-Host "Requires Python 3.10+ installed on the target machine." -ForegroundColor Yellow
