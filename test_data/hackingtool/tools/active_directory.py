from core import HackingTool
from core import HackingToolsCollection


class BloodHound(HackingTool):
    TITLE = "BloodHound (AD Attack Paths)"
    DESCRIPTION = "Uses graph theory to reveal hidden attack paths in Active Directory/Azure environments."
    INSTALL_COMMANDS = [
        "pip install --user bloodhound",
        "sudo apt-get install -y neo4j",
    ]
    RUN_COMMANDS = ["bloodhound-python --help"]
    PROJECT_URL = "https://github.com/BloodHoundAD/BloodHound"
    SUPPORTED_OS = ["linux", "macos"]


class NetExec(HackingTool):
    TITLE = "NetExec — nxc (Network Pentesting)"
    DESCRIPTION = "Swiss army knife for pentesting Windows/AD networks. Successor to CrackMapExec."
    INSTALL_COMMANDS = ["pip install --user netexec"]
    RUN_COMMANDS = ["nxc --help"]
    PROJECT_URL = "https://github.com/Pennyw0rth/NetExec"
    SUPPORTED_OS = ["linux", "macos"]


class Impacket(HackingTool):
    TITLE = "Impacket (Network Protocol Tools)"
    DESCRIPTION = "Python classes for working with SMB, MSRPC, Kerberos, LDAP, and more."
    INSTALL_COMMANDS = ["pip install --user impacket"]
    RUN_COMMANDS = ["impacket-smbclient --help"]
    PROJECT_URL = "https://github.com/fortra/impacket"
    SUPPORTED_OS = ["linux", "macos"]


class Responder(HackingTool):
    TITLE = "Responder (LLMNR/NBT-NS Poisoner)"
    DESCRIPTION = "LLMNR/NBT-NS/MDNS poisoner with rogue authentication servers for credential capture."
    INSTALL_COMMANDS = ["git clone https://github.com/lgandx/Responder.git"]
    RUN_COMMANDS = ["cd Responder && sudo python3 Responder.py --help"]
    PROJECT_URL = "https://github.com/lgandx/Responder"
    SUPPORTED_OS = ["linux"]


class Certipy(HackingTool):
    TITLE = "Certipy (AD Certificate Abuse)"
    DESCRIPTION = "Active Directory Certificate Services enumeration and abuse tool."
    INSTALL_COMMANDS = ["pip install --user certipy-ad"]
    RUN_COMMANDS = ["certipy --help"]
    PROJECT_URL = "https://github.com/ly4k/Certipy"
    SUPPORTED_OS = ["linux", "macos"]


class Kerbrute(HackingTool):
    TITLE = "Kerbrute (Kerberos Brute Force)"
    DESCRIPTION = "Kerberos pre-auth brute-forcer for username enumeration and password spraying."
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install github.com/ropnop/kerbrute@latest",
    ]
    RUN_COMMANDS = ["kerbrute --help"]
    PROJECT_URL = "https://github.com/ropnop/kerbrute"
    SUPPORTED_OS = ["linux", "macos"]


class ActiveDirectoryTools(HackingToolsCollection):
    TITLE = "Active Directory Tools"
    DESCRIPTION = "Tools for AD enumeration, attack path discovery, and credential attacks."
    TOOLS = [
        BloodHound(),
        NetExec(),
        Impacket(),
        Responder(),
        Certipy(),
        Kerbrute(),
    ]