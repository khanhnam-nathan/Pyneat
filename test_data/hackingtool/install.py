#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
from pathlib import Path

# ── Python version check (must be before any other local import) ──────────────
if sys.version_info < (3, 10):
    print(
        f"[ERROR] Python 3.10 or newer is required.\n"
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        f"Install with: sudo apt install python3.10"
    )
    sys.exit(1)

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

from constants import (
    REPO_URL, APP_INSTALL_DIR, APP_BIN_PATH,
    VERSION, VERSION_DISPLAY,
    USER_CONFIG_DIR, USER_TOOLS_DIR, USER_CONFIG_FILE,
    DEFAULT_CONFIG,
)
from os_detect import CURRENT_OS, REQUIRED_PACKAGES, PACKAGE_UPDATE_CMDS, PACKAGE_INSTALL_CMDS

console = Console()

VENV_DIR_NAME = "venv"
REQUIREMENTS   = "requirements.txt"


# ── Privilege check ────────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        console.print(Panel(
            "[error]This installer must be run as root.\n"
            "Use: [bold]sudo python3 install.py[/bold][/error]",
            border_style="red",
        ))
        sys.exit(1)


# ── OS compatibility check ─────────────────────────────────────────────────────

def check_os_compatibility():
    """Print detected OS info and exit on unsupported systems."""
    info = CURRENT_OS
    console.print(
        f"[dim]Detected: OS={info.system} | distro={info.distro_id or 'n/a'} | "
        f"pkg_mgr={info.pkg_manager or 'none'} | arch={info.arch}[/dim]"
    )

    if info.system == "windows":
        console.print(Panel(
            "[error]Windows is not supported natively.[/error]\n"
            "Use WSL2 with a Kali or Ubuntu image.",
            border_style="red",
        ))
        sys.exit(1)

    if info.is_wsl:
        console.print("[warning]WSL detected. Wireless tools will NOT work in WSL.[/warning]")

    if info.system == "macos":
        console.print(Panel(
            "[warning]macOS support is partial.[/warning]\n"
            "Network/wireless tools require Linux. OSINT and web tools work.",
            border_style="yellow",
        ))
        if not shutil.which("brew"):
            console.print("[error]Homebrew not found. Install it first: https://brew.sh[/error]")
            sys.exit(1)

    if not info.pkg_manager:
        console.print("[warning]No supported package manager found.[/warning]")
        console.print("[dim]Supported: apt-get, pacman, dnf, zypper, apk, brew[/dim]")


# ── Internet check ─────────────────────────────────────────────────────────────

def check_internet() -> bool:
    console.print("[dim]Checking internet...[/dim]")
    for host in ("https://github.com", "https://www.google.com"):
        r = subprocess.run(
            ["curl", "-sSf", "--max-time", "8", host],
            capture_output=True,
        )
        if r.returncode == 0:
            console.print("[success]✔ Internet connection OK[/success]")
            return True
    console.print("[error]✘ No internet connection[/error]")
    return False


# ── System packages ────────────────────────────────────────────────────────────

def install_system_packages():
    mgr = CURRENT_OS.pkg_manager
    if not mgr:
        console.print("[warning]Skipping system packages — no package manager found.[/warning]")
        return

    # Use sudo only when not already root (uid != 0).
    # Inside Docker we run as root and sudo is not installed.
    priv = "" if os.geteuid() == 0 else "sudo "

    # Update index first (skip for brew — not needed)
    if mgr != "brew":
        update_cmd = PACKAGE_UPDATE_CMDS.get(mgr, "")
        if update_cmd:
            console.print(f"[dim]Updating package index ({mgr})...[/dim]")
            subprocess.run(f"{priv}{update_cmd}", shell=True, check=False)

    packages = REQUIRED_PACKAGES.get(mgr, [])
    if not packages:
        return

    install_tpl = PACKAGE_INSTALL_CMDS[mgr]
    cmd = install_tpl.format(packages=" ".join(packages))
    console.print(f"[dim]Installing system dependencies ({mgr})...[/dim]")
    result = subprocess.run(f"{priv}{cmd}", shell=True, check=False)
    if result.returncode != 0:
        console.print("[warning]Some packages failed — you may need to install them manually.[/warning]")


# ── App directory ──────────────────────────────────────────────────────────────

def _is_source_dir() -> bool:
    """Check if install.py is being run from a local clone (hackingtool.py exists alongside it)."""
    return (Path(__file__).resolve().parent / "hackingtool.py").exists()


def prepare_install_dir():
    if APP_INSTALL_DIR.exists():
        console.print(f"[warning]{APP_INSTALL_DIR} already exists.[/warning]")
        if not Confirm.ask("Replace it? This removes the existing installation.", default=False):
            console.print("[error]Installation aborted.[/error]")
            sys.exit(1)
        subprocess.run(["rm", "-rf", str(APP_INSTALL_DIR)], check=True)
    APP_INSTALL_DIR.mkdir(parents=True, exist_ok=True)


def install_source() -> bool:
    """Clone the repo or copy from local source if already in a clone."""
    source_dir = Path(__file__).resolve().parent

    if _is_source_dir() and source_dir != APP_INSTALL_DIR:
        # Already in a local clone — copy instead of re-cloning
        console.print(f"[dim]Copying source from {source_dir}...[/dim]")
        # Remove first to ensure clean copy (prepare_install_dir may have created it)
        if APP_INSTALL_DIR.exists():
            subprocess.run(["rm", "-rf", str(APP_INSTALL_DIR)], check=True)
        subprocess.run(["cp", "-a", str(source_dir), str(APP_INSTALL_DIR)], check=True)
        # Fix ownership so git doesn't complain about "dubious ownership"
        subprocess.run(["chown", "-R", "root:root", str(APP_INSTALL_DIR)], check=False)
        console.print("[success]✔ Source copied (no re-clone needed)[/success]")
        return True

    # Not running from source — clone from GitHub
    console.print(f"[dim]Cloning {REPO_URL}...[/dim]")
    r = subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(APP_INSTALL_DIR)], check=False)
    if r.returncode == 0:
        console.print("[success]✔ Repository cloned[/success]")
        return True
    console.print("[error]✘ Failed to clone repository[/error]")
    return False


# ── Python venv ────────────────────────────────────────────────────────────────

def create_venv_and_install():
    venv_path = APP_INSTALL_DIR / VENV_DIR_NAME
    console.print("[dim]Creating virtual environment...[/dim]")
    subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)

    pip = str(venv_path / "bin" / "pip")
    req = APP_INSTALL_DIR / REQUIREMENTS
    if req.exists():
        console.print("[dim]Installing Python requirements...[/dim]")
        subprocess.run([pip, "install", "--quiet", "-r", str(req)], check=False)
    else:
        console.print("[warning]requirements.txt not found — skipping pip install.[/warning]")


# ── Launcher script ────────────────────────────────────────────────────────────

def create_launcher():
    launcher = APP_INSTALL_DIR / "hackingtool.sh"
    launcher.write_text(
        "#!/bin/bash\n"
        f'source "{APP_INSTALL_DIR / VENV_DIR_NAME}/bin/activate"\n'
        f'python3 "{APP_INSTALL_DIR / "hackingtool.py"}" "$@"\n'
    )
    launcher.chmod(0o755)
    if APP_BIN_PATH.exists():
        APP_BIN_PATH.unlink()
    shutil.move(str(launcher), str(APP_BIN_PATH))
    console.print(f"[success]✔ Launcher installed at {APP_BIN_PATH}[/success]")


# ── User directories ───────────────────────────────────────────────────────────

def create_user_directories():
    """
    Create ~/.hackingtool/ and write initial config.json.
    Uses Path.home() — always correct regardless of username or OS.
    Safe to run as root (creates /root/.hackingtool/) or as a normal user.
    """
    import json
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    USER_TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if not USER_CONFIG_FILE.exists():
        USER_CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2, sort_keys=True))
        console.print(f"[success]✔ Config created at {USER_CONFIG_FILE}[/success]")
    console.print(f"[success]✔ Tools directory: {USER_TOOLS_DIR}[/success]")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    check_root()
    console.clear()

    console.print(Panel(
        Text(f"HackingTool Installer  {VERSION_DISPLAY}", style="bold magenta"),
        box=box.DOUBLE, border_style="bright_magenta",
    ))

    check_os_compatibility()

    if not check_internet():
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
        p.add_task("Installing system packages...", total=None)
        install_system_packages()

    prepare_install_dir()

    if not install_source():
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
        p.add_task("Setting up virtualenv & requirements...", total=None)
        create_venv_and_install()

    create_launcher()
    create_user_directories()

    console.print(Panel(
        "[bold magenta]Installation complete![/bold magenta]\n\n"
        "Type [bold cyan]hackingtool[/bold cyan] in a terminal to start.",
        border_style="magenta",
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[error]Installation interrupted.[/error]")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        console.print(f"[error]Command failed: {e}[/error]")
        sys.exit(1)
