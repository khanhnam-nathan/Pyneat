from core import HackingTool
from core import HackingToolsCollection


class MobSF(HackingTool):
    TITLE = "MobSF (Mobile Security Framework)"
    DESCRIPTION = "All-in-one mobile app pentesting, malware analysis, and security assessment."
    INSTALL_COMMANDS = [
        "git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git",
        "cd Mobile-Security-Framework-MobSF && ./setup.sh",
    ]
    RUN_COMMANDS = ["cd Mobile-Security-Framework-MobSF && ./run.sh"]
    PROJECT_URL = "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
    SUPPORTED_OS = ["linux", "macos"]


class Frida(HackingTool):
    TITLE = "Frida (Dynamic Instrumentation)"
    DESCRIPTION = "Dynamic instrumentation toolkit for runtime hooking on Android, iOS, Windows, macOS, Linux."
    INSTALL_COMMANDS = ["pip install --user frida-tools"]
    RUN_COMMANDS = ["frida --help"]
    PROJECT_URL = "https://github.com/frida/frida"
    SUPPORTED_OS = ["linux", "macos"]


class Objection(HackingTool):
    TITLE = "Objection (Mobile Runtime Exploration)"
    DESCRIPTION = "Runtime mobile exploration toolkit powered by Frida — no jailbreak/root required."
    INSTALL_COMMANDS = ["pip install --user objection"]
    RUN_COMMANDS = ["objection --help"]
    PROJECT_URL = "https://github.com/sensepost/objection"
    SUPPORTED_OS = ["linux", "macos"]


class MobileSecurityTools(HackingToolsCollection):
    TITLE = "Mobile Security Tools"
    DESCRIPTION = "Tools for Android/iOS application security testing and analysis."
    TOOLS = [
        MobSF(),
        Frida(),
        Objection(),
    ]