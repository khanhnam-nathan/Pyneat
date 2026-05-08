from pathlib import Path
import platform
import shutil as _shutil

# ── Repository ────────────────────────────────────────────────────────────────
REPO_OWNER   = "Z4nzu"
REPO_NAME    = "hackingtool"
REPO_URL     = f"https://github.com/{REPO_OWNER}/{REPO_NAME}.git"
REPO_WEB_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"

# ── Versioning ────────────────────────────────────────────────────────────────
VERSION         = "2.0.0"
VERSION_DISPLAY = f"v{VERSION}"

# ── Python requirement ────────────────────────────────────────────────────────
MIN_PYTHON = (3, 10)

# ── User-scoped paths (cross-platform, always computed at runtime) ─────────────
# NEVER hardcode /home/username — use Path.home() so it works for any user,
# including root (/root), regular users (/home/alice), macOS (/Users/alice).
USER_CONFIG_DIR  = Path.home() / f".{REPO_NAME}"
USER_TOOLS_DIR   = USER_CONFIG_DIR / "tools"
USER_CONFIG_FILE = USER_CONFIG_DIR / "config.json"
USER_LOG_FILE    = USER_CONFIG_DIR / f"{REPO_NAME}.log"

# ── System install paths (set per OS) ─────────────────────────────────────────
_system = platform.system()

if _system == "Darwin":
    # macOS — Homebrew convention
    APP_INSTALL_DIR = Path("/usr/local/share") / REPO_NAME
    APP_BIN_PATH    = Path("/usr/local/bin")   / REPO_NAME
elif _system == "Linux":
    APP_INSTALL_DIR = Path("/usr/share") / REPO_NAME
    APP_BIN_PATH    = Path("/usr/bin")   / REPO_NAME
else:
    # Fallback (Windows, FreeBSD, etc.)
    APP_INSTALL_DIR = USER_CONFIG_DIR / "app"
    APP_BIN_PATH    = USER_CONFIG_DIR / "bin" / REPO_NAME

# ── UI theme ──────────────────────────────────────────────────────────────────
THEME_PRIMARY  = "bold magenta"
THEME_BORDER   = "bright_magenta"
THEME_SUCCESS  = "bold green"
THEME_ERROR    = "bold red"
THEME_WARNING  = "bold yellow"
THEME_DIM      = "dim white"
THEME_ARCHIVED = "dim yellow"
THEME_URL      = "underline bright_blue"
THEME_ACCENT   = "bold cyan"

# ── Default config values ──────────────────────────────────────────────────────
DEFAULT_CONFIG: dict = {
    "tools_dir":      str(USER_TOOLS_DIR),
    "version":        VERSION,
    "theme":          "magenta",
    "show_archived":  False,
    "sudo_binary":    "sudo",
    "go_bin_dir":     str(Path.home() / "go" / "bin"),
    "gem_bin_dir":    str(Path.home() / ".gem" / "ruby"),
}

# ── Privilege escalation ───────────────────────────────────────────────────────
# Prefer doas if present (OpenBSD/some Linux setups), else sudo
PRIV_CMD = "doas" if _shutil.which("doas") else "sudo"