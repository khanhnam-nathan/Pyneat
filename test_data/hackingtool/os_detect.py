import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OSInfo:
    system: str                    # "linux", "macos", "windows", "unknown"
    distro_id: str        = ""     # "kali", "ubuntu", "arch", "fedora", etc.
    distro_like: str      = ""     # "debian", "rhel", etc. (from ID_LIKE)
    distro_version: str   = ""     # "2024.1", "22.04", etc.
    pkg_manager: str      = ""     # "apt-get", "pacman", "dnf", "brew", etc.
    is_root: bool         = False
    home_dir: Path        = field(default_factory=Path.home)
    is_wsl: bool          = False  # Windows Subsystem for Linux
    arch: str             = ""     # "x86_64", "aarch64", "arm64"


def detect() -> OSInfo:
    """
    Fully detect the current OS, distro, and available package manager.
    Never asks the user — entirely automatic.
    """
    import os

    system_raw = platform.system()
    system = system_raw.lower()
    if system == "darwin":
        system = "macos"

    info = OSInfo(
        system  = system,
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False,
        home_dir = Path.home(),
        arch    = platform.machine(),
    )

    # ── Linux-specific ─────────────────────────────────────────────────────────
    if system == "linux":
        # Detect WSL
        try:
            info.is_wsl = "microsoft" in Path("/proc/version").read_text().lower()
        except (FileNotFoundError, PermissionError):
            pass

        # Read /etc/os-release (standard on all modern distros)
        os_release: dict[str, str] = {}
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                for line in Path(path).read_text().splitlines():
                    k, _, v = line.partition("=")
                    os_release[k.strip()] = v.strip().strip('"')
                break
            except FileNotFoundError:
                continue

        info.distro_id      = os_release.get("ID", "").lower()
        info.distro_like    = os_release.get("ID_LIKE", "").lower()
        info.distro_version = os_release.get("VERSION_ID", "")

    # ── Package manager detection (in priority order) ──────────────────────────
    for mgr in ("apt-get", "pacman", "dnf", "zypper", "apk", "brew", "pkg"):
        if shutil.which(mgr):
            info.pkg_manager = mgr
            break

    return info


# Module-level singleton — computed once on import
CURRENT_OS: OSInfo = detect()


# ── Per-OS package manager commands ────────────────────────────────────────────
PACKAGE_INSTALL_CMDS: dict[str, str] = {
    "apt-get": "apt-get install -y {packages}",
    "pacman":  "pacman -S --noconfirm {packages}",
    "dnf":     "dnf install -y {packages}",
    "zypper":  "zypper install -y {packages}",
    "apk":     "apk add {packages}",
    "brew":    "brew install {packages}",
    "pkg":     "pkg install -y {packages}",
}

PACKAGE_UPDATE_CMDS: dict[str, str] = {
    "apt-get": "apt-get update -qq && apt-get upgrade -y",
    "pacman":  "pacman -Syu --noconfirm",
    "dnf":     "dnf upgrade -y",
    "zypper":  "zypper update -y",
    "apk":     "apk update && apk upgrade",
    "brew":    "brew update && brew upgrade",
    "pkg":     "pkg update && pkg upgrade -y",
}

# Core system packages needed per package manager
REQUIRED_PACKAGES: dict[str, list[str]] = {
    "apt-get": ["git", "python3-pip", "python3-venv", "curl", "wget",
                "ruby", "ruby-dev", "golang-go", "php", "default-jre-headless"],
    "pacman":  ["git", "python-pip", "curl", "wget",
                "ruby", "go", "php", "jre-openjdk-headless"],
    "dnf":     ["git", "python3-pip", "curl", "wget",
                "ruby", "golang", "php", "java-17-openjdk-headless"],
    "zypper":  ["git", "python3-pip", "curl", "wget", "ruby", "go", "php"],
    "brew":    ["git", "python3", "curl", "wget", "ruby", "go", "php"],
    "pkg":     ["git", "python3", "py39-pip", "curl", "wget", "ruby", "go", "php83"],
}


def install_packages(packages: list[str], os_info: OSInfo | None = None) -> bool:
    """Install system packages using the detected package manager."""
    import subprocess
    if os_info is None:
        os_info = CURRENT_OS

    mgr = os_info.pkg_manager
    if mgr not in PACKAGE_INSTALL_CMDS:
        print(f"[warning] Unknown package manager. Install manually: {packages}")
        return False

    cmd_template = PACKAGE_INSTALL_CMDS[mgr]
    pkg_str = " ".join(packages)
    cmd = cmd_template.format(packages=pkg_str)

    # Prepend privilege escalation only on Linux (brew on macOS doesn't need sudo)
    if os_info.system == "linux" and not os_info.is_root:
        from constants import PRIV_CMD
        cmd = f"{PRIV_CMD} {cmd}"

    result = subprocess.run(cmd, shell=True, check=False)
    return result.returncode == 0