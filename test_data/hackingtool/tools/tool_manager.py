import os
import sys
import subprocess
from time import sleep

from rich.prompt import Confirm

from core import HackingTool, HackingToolsCollection, console
from constants import APP_INSTALL_DIR, APP_BIN_PATH, USER_CONFIG_DIR, REPO_URL


class UpdateTool(HackingTool):
    TITLE = "Update Tool or System"
    DESCRIPTION = "Update system packages or pull the latest hackingtool code"

    def __init__(self):
        super().__init__([
            ("Update System", self.update_sys),
            ("Update Hackingtool", self.update_ht),
        ], installable=False, runnable=False)

    def update_sys(self):
        from os_detect import CURRENT_OS, PACKAGE_UPDATE_CMDS
        mgr = CURRENT_OS.pkg_manager
        cmd = PACKAGE_UPDATE_CMDS.get(mgr)
        if cmd:
            priv = "" if (CURRENT_OS.system == "macos" or os.geteuid() == 0) else "sudo "
            # shell=True needed — cmd contains && chains; strings are hardcoded, not user input
            subprocess.run(f"{priv}{cmd}", shell=True, check=False)
        else:
            console.print("[warning]Unknown package manager — update manually.[/warning]")

    def update_ht(self):
        if not APP_INSTALL_DIR.exists():
            console.print(f"[error]Install directory not found: {APP_INSTALL_DIR}[/error]")
            console.print("[dim]Run install.py first.[/dim]")
            return
        console.print(f"[bold cyan]Pulling latest code from {REPO_URL}...[/bold cyan]")
        result = subprocess.run(
            ["git", "pull", "--rebase"],
            cwd=str(APP_INSTALL_DIR),
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            console.print(f"[error]git pull failed:\n{result.stderr}[/error]")
            return
        pip = str(APP_INSTALL_DIR / "venv" / "bin" / "pip")
        if (APP_INSTALL_DIR / "venv" / "bin" / "pip").exists():
            subprocess.run([pip, "install", "-q", "-r",
                            str(APP_INSTALL_DIR / "requirements.txt")])
        console.print("[success]✔ Hackingtool updated.[/success]")


class UninstallTool(HackingTool):
    TITLE = "Uninstall HackingTool"
    DESCRIPTION = "Remove hackingtool from system"

    def __init__(self):
        super().__init__([
            ("Uninstall", self.uninstall),
        ], installable=False, runnable=False)

    def uninstall(self):
        import shutil
        console.print("[warning]This will remove hackingtool from your system.[/warning]")
        if not Confirm.ask("Continue?", default=False):
            return

        if APP_INSTALL_DIR.exists():
            shutil.rmtree(str(APP_INSTALL_DIR))
            console.print(f"[success]✔ Removed {APP_INSTALL_DIR}[/success]")
        else:
            console.print(f"[dim]{APP_INSTALL_DIR} not found — already removed?[/dim]")

        if APP_BIN_PATH.exists():
            APP_BIN_PATH.unlink()
            console.print(f"[success]✔ Removed launcher {APP_BIN_PATH}[/success]")

        if Confirm.ask(f"Also remove user data at {USER_CONFIG_DIR}?", default=False):
            shutil.rmtree(str(USER_CONFIG_DIR), ignore_errors=True)
            console.print(f"[success]✔ Removed {USER_CONFIG_DIR}[/success]")

        console.print("[bold green]Hackingtool uninstalled. Goodbye.[/bold green]")
        sleep(1)
        sys.exit(0)


class ToolManager(HackingToolsCollection):
    TITLE = "Update or Uninstall | Hackingtool"
    TOOLS = [
        UpdateTool(),
        UninstallTool(),
    ]


if __name__ == "__main__":
    manager = ToolManager()
    manager.show_options()
