# SOC Log Analyzer — Windows Launcher

One-click `SOCLogAnalyzer.exe` that:

1. Downloads the latest code from GitHub
2. Installs/upgrades all `requirements.txt` packages into `%LOCALAPPDATA%\SOCLogAnalyzer\venv`
3. Starts the Streamlit dashboard and opens your browser

## Build the EXE (developer)

```powershell
cd path\to\Scan_logs
.\launcher\build.ps1
```

Output: `dist\SOCLogAnalyzer.exe`

## Requirements on target PC

- **Windows 10/11**
- **Python 3.10+** installed with **Add to PATH** enabled  
  https://www.python.org/downloads/
- Internet connection (GitHub + PyPI)

## First run

Double-click `SOCLogAnalyzer.exe`. A console window shows sync progress.  
The browser opens at http://localhost:8501 automatically.

**Keep the console window open** while using the app — closing it stops the server.

## Data location

| Path | Contents |
|---|---|
| `%LOCALAPPDATA%\SOCLogAnalyzer\app` | Synced application code |
| `%LOCALAPPDATA%\SOCLogAnalyzer\venv` | Python virtual environment |
| `%LOCALAPPDATA%\SOCLogAnalyzer\app\data` | SQLite case database |

Each launch re-syncs from GitHub `main` and upgrades pip packages.
