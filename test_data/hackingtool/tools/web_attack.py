import subprocess
from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt


class Web2Attack(HackingTool):
    TITLE = "Web2Attack"
    DESCRIPTION = "Web hacking framework with tools, exploits by python"
    INSTALL_COMMANDS = [
        "git clone https://github.com/santatic/web2attack.git"
    ]
    RUN_COMMANDS = ["cd web2attack && sudo python3 w2aconsole"]
    PROJECT_URL = "https://github.com/santatic/web2attack"


class Skipfish(HackingTool):
    TITLE = "Skipfish"
    DESCRIPTION = (
        "Skipfish – Fully automated, active web application "
        "security reconnaissance tool \n "
        "Usage: skipfish -o [FolderName] targetip/site"
    )
    RUN_COMMANDS = [
        "sudo skipfish -h",
        'echo "skipfish -o [FolderName] targetip/site"|boxes -d headline | lolcat'
    ]

    def __init__(self):
        super().__init__(installable=False)


class SubDomainFinder(HackingTool):
    TITLE = "SubDomain Finder"
    DESCRIPTION = (
        "Sublist3r is a python tool designed to enumerate "
        "subdomains of websites using OSINT \n "
        "Usage:\n\t[1] python3 sublist3r.py -d example.com \n"
        "[2] python3 sublist3r.py -d example.com -p 80,443"
    )
    INSTALL_COMMANDS = [
        "sudo pip3 install requests argparse dnspython",
        "git clone https://github.com/aboul3la/Sublist3r.git",
        "cd Sublist3r && sudo pip3 install -r requirements.txt"
    ]
    RUN_COMMANDS = ["cd Sublist3r && python3 sublist3r.py -h"]
    PROJECT_URL = "https://github.com/aboul3la/Sublist3r"


class CheckURL(HackingTool):
    TITLE = "CheckURL"
    DESCRIPTION = (
        "Detect evil urls that uses IDN Homograph Attack.\n\t"
        "[!] python3 checkURL.py --url google.com"
    )
    INSTALL_COMMANDS = ["git clone https://github.com/UndeadSec/checkURL.git"]
    RUN_COMMANDS = ["cd checkURL && python3 checkURL.py --help"]
    PROJECT_URL = "https://github.com/UndeadSec/checkURL"


class Blazy(HackingTool):
    TITLE = "Blazy(Also Find ClickJacking)"
    DESCRIPTION = "Blazy is a modern login page bruteforcer"
    INSTALL_COMMANDS = []
    RUN_COMMANDS = []
    PROJECT_URL = "https://github.com/UltimateHackers/Blazy"
    ARCHIVED = True
    ARCHIVED_REASON = "Python 2 only (pip2.7/python2.7). Repo archived/unmaintained."

    def __init__(self):
        super().__init__(installable=False, runnable=False)


class SubDomainTakeOver(HackingTool):
    TITLE = "Sub-Domain TakeOver"
    DESCRIPTION = (
        "Sub-domain takeover vulnerability occur when a sub-domain "
        "\n (subdomain.example.com) is pointing to a service "
        "(e.g: GitHub, AWS/S3,..)\nthat has been removed or deleted.\n"
        "Usage:python3 takeover.py -d www.domain.com -v"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/edoardottt/takeover.git",
        "cd takeover && pip install --user ."
    ]
    PROJECT_URL = "https://github.com/edoardottt/takeover"

    def __init__(self):
        super().__init__(runnable=False)


class Dirb(HackingTool):
    TITLE = "Dirb"
    DESCRIPTION = (
        "DIRB is a Web Content Scanner. It looks for existing "
        "(and/or hidden) Web Objects.\n"
        "It basically works by launching a dictionary based "
        "attack against \n a web server and analyzing the response."
    )
    INSTALL_COMMANDS = [
        "git clone https://gitlab.com/kalilinux/packages/dirb.git",
        "cd dirb;sudo bash configure;make"
    ]
    PROJECT_URL = "https://gitlab.com/kalilinux/packages/dirb"

    def run(self):
        uinput = input("Enter Url >> ")
        subprocess.run(["sudo", "dirb", uinput])


class Nuclei(HackingTool):
    TITLE = "Nuclei (Vulnerability Scanner)"
    DESCRIPTION = (
        "Fast, template-based vulnerability scanner used by 50k+ security teams.\n"
        "Usage: nuclei -u https://example.com"
    )
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "nuclei -update-templates",
    ]
    RUN_COMMANDS = ["nuclei -h"]
    PROJECT_URL = "https://github.com/projectdiscovery/nuclei"


class Ffuf(HackingTool):
    TITLE = "ffuf (Web Fuzzer)"
    DESCRIPTION = (
        "Fast web fuzzer — content discovery, parameter fuzzing, vhost discovery.\n"
        "Usage: ffuf -w wordlist.txt -u https://example.com/FUZZ"
    )
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/ffuf/ffuf/v2@latest",
    ]
    RUN_COMMANDS = ["ffuf -h"]
    PROJECT_URL = "https://github.com/ffuf/ffuf"


class Feroxbuster(HackingTool):
    TITLE = "Feroxbuster (Directory Brute Force)"
    DESCRIPTION = (
        "Fast, recursive content discovery tool written in Rust.\n"
        "Usage: feroxbuster -u https://example.com -w wordlist.txt"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = [
        "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh "
        "| sudo bash -s /usr/local/bin",
    ]
    RUN_COMMANDS = ["feroxbuster -h"]
    PROJECT_URL = "https://github.com/epi052/feroxbuster"


class Nikto(HackingTool):
    TITLE = "Nikto (Web Server Scanner)"
    DESCRIPTION = (
        "Scan web servers for dangerous files, outdated software, misconfigurations.\n"
        "Usage: nikto -h https://example.com"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = ["sudo apt-get install -y nikto"]
    RUN_COMMANDS = ["nikto -Help"]
    PROJECT_URL = "https://github.com/sullo/nikto"


class Wafw00f(HackingTool):
    TITLE = "wafw00f (WAF Detector)"
    DESCRIPTION = (
        "Fingerprint and identify Web Application Firewalls (WAF).\n"
        "Usage: wafw00f https://example.com"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/EnableSecurity/wafw00f.git",
        "cd wafw00f && pip install --user .",
    ]
    RUN_COMMANDS = ["wafw00f --help"]
    PROJECT_URL = "https://github.com/EnableSecurity/wafw00f"


class Katana(HackingTool):
    TITLE = "Katana (Web Crawler)"
    DESCRIPTION = (
        "Next-generation crawling and spidering framework from ProjectDiscovery.\n"
        "Usage: katana -u https://example.com"
    )
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    ]
    RUN_COMMANDS = ["katana -h"]
    PROJECT_URL = "https://github.com/projectdiscovery/katana"


class Gobuster(HackingTool):
    TITLE = "Gobuster (Dir/DNS/Vhost Brute Force)"
    DESCRIPTION = "Directory/file, DNS, and vhost brute-forcing tool written in Go."
    REQUIRES_GO = True
    INSTALL_COMMANDS = ["go install github.com/OJ/gobuster/v3@latest"]
    RUN_COMMANDS = ["gobuster --help"]
    PROJECT_URL = "https://github.com/OJ/gobuster"


class Dirsearch(HackingTool):
    TITLE = "Dirsearch (Web Path Discovery)"
    DESCRIPTION = "Web path brute-forcing tool for discovering directories and files on web servers."
    INSTALL_COMMANDS = ["pip install --user dirsearch"]
    RUN_COMMANDS = ["dirsearch --help"]
    PROJECT_URL = "https://github.com/maurosoria/dirsearch"


class OwaspZap(HackingTool):
    TITLE = "OWASP ZAP (Web App Scanner)"
    DESCRIPTION = "Full-featured web application security scanner — proxy, spider, fuzzer, scanner."
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = ["sudo apt-get install -y zaproxy"]
    RUN_COMMANDS = ["zaproxy --help"]
    PROJECT_URL = "https://github.com/zaproxy/zaproxy"


class TestSSL(HackingTool):
    TITLE = "testssl.sh (TLS/SSL Checker)"
    DESCRIPTION = "Check TLS/SSL ciphers, protocols, and cryptographic flaws on any port."
    INSTALL_COMMANDS = ["git clone https://github.com/drwetter/testssl.sh.git"]
    RUN_COMMANDS = ["cd testssl.sh && ./testssl.sh --help"]
    PROJECT_URL = "https://github.com/drwetter/testssl.sh"


class Arjun(HackingTool):
    TITLE = "Arjun (HTTP Parameter Discovery)"
    DESCRIPTION = "HTTP parameter discovery suite that finds hidden GET/POST parameters."
    INSTALL_COMMANDS = ["pip install --user arjun"]
    RUN_COMMANDS = ["arjun --help"]
    PROJECT_URL = "https://github.com/s0md3v/Arjun"


class Caido(HackingTool):
    TITLE = "Caido (Web Security Auditing)"
    DESCRIPTION = "Lightweight, modern web security auditing toolkit — Burp Suite alternative written in Rust."
    INSTALL_COMMANDS = [
        "curl -sSL https://caido.download/releases/latest/caido-cli-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin",
    ]
    RUN_COMMANDS = ["caido --help"]
    PROJECT_URL = "https://github.com/caido/caido"
    SUPPORTED_OS = ["linux", "macos"]


class Mitmproxy(HackingTool):
    TITLE = "mitmproxy (Intercepting Proxy)"
    DESCRIPTION = "Interactive TLS-capable intercepting HTTP proxy for pentesters and developers."
    INSTALL_COMMANDS = ["pip install --user mitmproxy"]
    RUN_COMMANDS = ["mitmproxy --version"]
    PROJECT_URL = "https://github.com/mitmproxy/mitmproxy"


class WebAttackTools(HackingToolsCollection):
    TITLE = "Web Attack tools"
    DESCRIPTION = ""
    TOOLS = [
        Web2Attack(),
        Skipfish(),
        SubDomainFinder(),
        CheckURL(),
        Blazy(),
        SubDomainTakeOver(),
        Dirb(),
        Nuclei(),
        Ffuf(),
        Feroxbuster(),
        Nikto(),
        Wafw00f(),
        Katana(),
        Gobuster(),
        Dirsearch(),
        OwaspZap(),
        TestSSL(),
        Arjun(),
        Caido(),
        Mitmproxy(),
    ]

if __name__ == "__main__":
    tools = WebAttackTools()
    tools.show_options()
