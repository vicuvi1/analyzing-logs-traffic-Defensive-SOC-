"""
SOC Log Analyzer — One-click launcher.

On each run:
  1. Syncs the latest code from GitHub (zip download)
  2. Installs/upgrades Python dependencies
  3. Starts the Streamlit dashboard and opens the browser

Packaged as SOCLogAnalyzer.exe via PyInstaller (see launcher/build.ps1).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ZIP_URL = (
    "https://github.com/vicuvi1/analyzing-logs-traffic-Defensive-SOC-"
    "/archive/refs/heads/main.zip"
)
APP_NAME = "SOCLogAnalyzer"
INSTALL_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
APP_DIR = INSTALL_ROOT / "app"
VENV_DIR = INSTALL_ROOT / "venv"
STREAMLIT_URL = "http://localhost:8501"
STREAMLIT_PORT = 8501


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def error(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def find_python() -> str | None:
    """Locate a usable Python 3.10+ interpreter on PATH."""
    candidates: list[str] = []

    if not getattr(sys, "frozen", False):
        candidates.append(sys.executable)

    for name in ("python", "python3"):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    if shutil.which("py"):
        for ver in ("3.12", "3.11", "3.10"):
            candidates.append(f"py -{ver}")

    for cmd in candidates:
        try:
            parts = cmd.split()
            result = subprocess.run(
                parts + ["--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            out = result.stdout + result.stderr
            if result.returncode == 0 and "3." in out:
                # Reject Python 2.x
                if "3.1" in out or "3.11" in out or "3.12" in out or "3.10" in out or "3.13" in out:
                    return cmd
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def download_and_extract(url: str, dest: Path) -> None:
    """Download GitHub main branch zip and extract into dest."""
    dest.mkdir(parents=True, exist_ok=True)
    log(f"Syncing from GitHub → {dest}")

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "repo.zip"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"{APP_NAME}-Launcher/1.0"},
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            zip_path.write_bytes(response.read())

        extract_to = Path(tmp) / "extracted"
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_to)

        # GitHub zips contain a single top-level folder (repo-main).
        roots = [p for p in extract_to.iterdir() if p.is_dir()]
        if not roots:
            raise RuntimeError("Downloaded archive has no root folder.")
        source = roots[0]

        # Replace app directory contents.
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source, dest)

    log("Repository sync complete.")


def ensure_venv(python_cmd: str) -> Path:
    """Create a dedicated venv for the app if missing."""
    VENV_DIR.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        venv_python = VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python = VENV_DIR / "bin" / "python"

    if venv_python.exists():
        return venv_python

    log("Creating isolated virtual environment…")
    parts = python_cmd.split()
    subprocess.run(parts + ["-m", "venv", str(VENV_DIR)], check=True)
    return venv_python


def install_requirements(venv_python: Path) -> None:
    """Install or upgrade all packages from requirements.txt."""
    req_file = APP_DIR / "requirements.txt"
    if not req_file.exists():
        raise FileNotFoundError(f"requirements.txt not found in {APP_DIR}")

    log("Installing / upgrading dependencies (may take a minute)…")
    subprocess.run(
        [
            str(venv_python), "-m", "pip", "install",
            "--upgrade", "pip", "wheel",
        ],
        check=True,
    )
    subprocess.run(
        [
            str(venv_python), "-m", "pip", "install",
            "--upgrade", "-r", str(req_file),
        ],
        check=True,
    )
    log("Dependencies are up to date.")


def wait_for_server(url: str, timeout: int = 45) -> bool:
    """Poll until Streamlit responds."""
    import urllib.error

    for _ in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def start_streamlit(venv_python: Path) -> subprocess.Popen:
    """Launch Streamlit in the background."""
    app_py = APP_DIR / "app.py"
    if not app_py.exists():
        raise FileNotFoundError(f"app.py not found in {APP_DIR}")

    log("Starting SOC dashboard…")
    env = os.environ.copy()
    env["BROWSER"] = "none"  # we open the browser ourselves

    proc = subprocess.Popen(
        [
            str(venv_python), "-m", "streamlit", "run",
            str(app_py),
            "--server.port", str(STREAMLIT_PORT),
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
        ],
        cwd=str(APP_DIR),
        env=env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    return proc


def main() -> int:
    print("=" * 60)
    print("  SOC Log & Traffic Analyzer")
    print("  Defensive SOC Triage Platform")
    print("=" * 60)
    print()

    python_cmd = find_python()
    if not python_cmd:
        error(
            "Python 3.10+ was not found on this system.\n"
            "Install from https://www.python.org/downloads/\n"
            "Enable 'Add Python to PATH' during installation."
        )
        input("\nPress Enter to exit…")
        return 1

    log(f"Using Python: {python_cmd}")

    try:
        download_and_extract(REPO_ZIP_URL, APP_DIR)
        venv_python = ensure_venv(python_cmd)
        install_requirements(venv_python)
        proc = start_streamlit(venv_python)

        log(f"Waiting for server at {STREAMLIT_URL} …")
        if wait_for_server(STREAMLIT_URL):
            log("Opening browser.")
            webbrowser.open(STREAMLIT_URL)
        else:
            error("Server did not start in time. Check the window for errors.")

        print()
        print("Dashboard is running. Keep this window open.")
        print("Close this window to stop the application.")
        print()

        proc.wait()
        return proc.returncode or 0

    except KeyboardInterrupt:
        log("Stopped by user.")
        return 0
    except Exception as exc:
        error(f"Launcher failed: {exc}")
        input("\nPress Enter to exit…")
        return 1


if __name__ == "__main__":
    sys.exit(main())
