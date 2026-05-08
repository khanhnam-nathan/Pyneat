import os
import subprocess

from core import HackingTool, HackingToolsCollection, console


class TheFatRat(HackingTool):
    TITLE = "The FatRat"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "TheFatRat provides an easy way to create backdoors and payloads "
        "which can bypass most anti-virus."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/Screetsec/TheFatRat.git",
        "cd TheFatRat && chmod +x setup.sh",
    ]
    RUN_COMMANDS = ["cd TheFatRat && sudo bash setup.sh"]
    PROJECT_URL = "https://github.com/Screetsec/TheFatRat"

    def __init__(self):
        super().__init__([
            ("Update", self.update),
            ("Troubleshoot", self.troubleshoot),
        ])

    def update(self):
        from config import get_tools_dir
        cwd = str(get_tools_dir() / "TheFatRat")
        subprocess.run(["bash", "update"], cwd=cwd)
        subprocess.run(["chmod", "+x", "setup.sh"], cwd=cwd)
        subprocess.run(["bash", "setup.sh"], cwd=cwd)

    def troubleshoot(self):
        from config import get_tools_dir
        cwd = str(get_tools_dir() / "TheFatRat")
        subprocess.run(["chmod", "+x", "chk_tools"], cwd=cwd)
        subprocess.run(["./chk_tools"], cwd=cwd)


class Brutal(HackingTool):
    TITLE = "Brutal"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "Brutal is a toolkit to quickly create various payloads, powershell attacks, "
        "virus attacks and launch listener for a Human Interface Device."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/Screetsec/Brutal.git",
        "cd Brutal && chmod +x Brutal.sh",
    ]
    RUN_COMMANDS = ["cd Brutal && sudo bash Brutal.sh"]
    PROJECT_URL = "https://github.com/Screetsec/Brutal"

    def show_info(self):
        super().show_info()
        console.print(
            "[bold cyan]Requirements:[/bold cyan]\n"
            "  - Arduino Software (v1.6.7+)\n"
            "  - TeensyDuino\n"
            "  - Linux udev rules\n"
            "  See: https://github.com/Screetsec/Brutal/wiki/Install-Requirements"
        )


class Stitch(HackingTool):
    TITLE = "Stitch"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "Stitch is a Cross Platform Python Remote Administrator Tool.\n"
        "[!] Refer to the project link for Windows & macOS support."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/nathanlopez/Stitch.git",
        "cd Stitch && pip install --user -r lnx_requirements.txt",
    ]
    RUN_COMMANDS = ["cd Stitch && sudo python3 main.py"]
    PROJECT_URL = "https://nathanlopez.github.io/Stitch"


class MSFVenom(HackingTool):
    TITLE = "MSFvenom Payload Creator"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "MSFvenom Payload Creator (MSFPC) is a wrapper to generate multiple "
        "types of payloads, based on user choice."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/g0tmi1k/msfpc.git",
        "cd msfpc && chmod +x msfpc.sh",
    ]
    RUN_COMMANDS = ["cd msfpc && sudo bash msfpc.sh -h -v"]
    PROJECT_URL = "https://github.com/g0tmi1k/msfpc"


class Venom(HackingTool):
    TITLE = "Venom Shellcode Generator"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Venom exploits apache2 webserver to deliver LAN payloads via fake webpages."
    INSTALL_COMMANDS = [
        "git clone https://github.com/r00t-3xp10it/venom.git",
        # Removed "sudo ./venom.sh -u" from install — interactive, runs the tool during install
        "sudo chmod -R 775 venom*/ && cd venom*/ && cd aux && sudo bash setup.sh",
    ]
    RUN_COMMANDS = ["cd venom && sudo ./venom.sh"]
    PROJECT_URL = "https://github.com/r00t-3xp10it/venom"


class Spycam(HackingTool):
    TITLE = "Spycam"
    DESCRIPTION = "Generates a Win32 payload that captures webcam images every 1 minute."
    INSTALL_COMMANDS = [
        "git clone https://github.com/indexnotfound404/spycam.git",
        "cd spycam && bash install.sh && chmod +x spycam",
    ]
    RUN_COMMANDS = ["cd spycam && ./spycam"]
    PROJECT_URL = "https://github.com/indexnotfound404/spycam"


class MobDroid(HackingTool):
    TITLE = "Mob-Droid"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Generates metasploit payloads easily without typing long commands."
    INSTALL_COMMANDS = ["git clone https://github.com/kinghacker0/mob-droid.git"]
    RUN_COMMANDS = ["cd mob-droid && sudo python3 mob-droid.py"]
    PROJECT_URL = "https://github.com/kinghacker0/Mob-Droid"


class Enigma(HackingTool):
    TITLE = "Enigma"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Enigma is a Multiplatform payload dropper."
    INSTALL_COMMANDS = ["git clone https://github.com/UndeadSec/Enigma.git"]
    RUN_COMMANDS = ["cd Enigma && sudo python3 enigma.py"]
    PROJECT_URL = "https://github.com/UndeadSec/Enigma"


class PayloadCreatorTools(HackingToolsCollection):
    TITLE = "Payload creation tools"
    # Bug 11 fix: show_options() override was missing `parent` parameter entirely —
    # the whole override is now deleted and the base class method is used instead.
    TOOLS = [
        TheFatRat(),
        Brutal(),
        Stitch(),
        MSFVenom(),
        Venom(),
        Spycam(),
        MobDroid(),
        Enigma(),
    ]


if __name__ == "__main__":
    tools = PayloadCreatorTools()
    tools.show_options()
