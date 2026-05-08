import subprocess

from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt


class AndroGuard(HackingTool):
    TITLE = "Androguard"
    DESCRIPTION = "Androguard is a Reverse engineering, Malware and goodware " \
                  "analysis of Android applications and more"
    INSTALL_COMMANDS = ["sudo pip3 install -U androguard"]
    PROJECT_URL = "https://github.com/androguard/androguard "

    def __init__(self):
        super().__init__(runnable=False)


class Apk2Gold(HackingTool):
    TITLE = "Apk2Gold"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Apk2Gold is a CLI tool for decompiling Android apps to Java"
    INSTALL_COMMANDS = [
        "git clone https://github.com/lxdvs/apk2gold.git",
        "cd apk2gold;sudo bash make.sh"
    ]
    PROJECT_URL = "https://github.com/lxdvs/apk2gold "

    def run(self):
        uinput = input("Enter (.apk) File >> ")
        subprocess.run(["sudo", "apk2gold", uinput])


class Jadx(HackingTool):
    TITLE = "JadX"
    DESCRIPTION = "Jadx is Dex to Java decompiler.\n" \
                  "[*] decompile Dalvik bytecode to java classes from APK, dex," \
                  " aar and zip files\n" \
                  "[*] decode AndroidManifest.xml and other resources from " \
                  "resources.arsc"
    INSTALL_COMMANDS = [
        "git clone https://github.com/skylot/jadx.git",
        # Bug 30 fix: gradlew dist requires Java — check first
        "java -version 2>&1 | grep -q 'version' && cd jadx && ./gradlew dist || echo '[ERROR] Java not found. Install: sudo apt install default-jdk'",
    ]
    PROJECT_URL = "https://github.com/skylot/jadx"
    REQUIRES_JAVA = True

    def __init__(self):
        # Py3-4 fix: super(Jadx, self) → super()
        super().__init__(runnable=False)


class Ghidra(HackingTool):
    TITLE = "Ghidra (NSA Reverse Engineering)"
    DESCRIPTION = "NSA's software reverse engineering framework — disassembly, decompilation, scripting."
    REQUIRES_JAVA = True
    INSTALL_COMMANDS = [
        "sudo apt-get install -y ghidra || echo 'Download from https://ghidra-sre.org/'",
    ]
    RUN_COMMANDS = ["ghidra --help || echo 'Run: ghidraRun'"]
    PROJECT_URL = "https://github.com/NationalSecurityAgency/ghidra"
    SUPPORTED_OS = ["linux", "macos"]


class Radare2(HackingTool):
    TITLE = "Radare2 (RE Framework)"
    DESCRIPTION = "Portable UNIX-like reverse engineering framework and command-line toolset."
    INSTALL_COMMANDS = [
        "git clone https://github.com/radareorg/radare2.git",
        "cd radare2 && sys/install.sh",
    ]
    RUN_COMMANDS = ["r2 -h"]
    PROJECT_URL = "https://github.com/radareorg/radare2"
    SUPPORTED_OS = ["linux", "macos"]


class ReverseEngineeringTools(HackingToolsCollection):
    TITLE = "Reverse engineering tools"
    TOOLS = [
        AndroGuard(),
        Apk2Gold(),
        Jadx(),
        Ghidra(),
        Radare2(),
    ]

if __name__ == "__main__":
    tools = ReverseEngineeringTools()
    tools.show_options()
