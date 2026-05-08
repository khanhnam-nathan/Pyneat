import os
import socket
import subprocess
import webbrowser
import sys

from core import HackingTool, HackingToolsCollection, console
from core import clear_screen

from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt


class NMAP(HackingTool):
    TITLE = "Network Map (nmap)"
    DESCRIPTION = "Free and open source utility for network discovery and security auditing"
    INSTALL_COMMANDS = [
        "git clone https://github.com/nmap/nmap.git",
        "sudo chmod -R 755 nmap && cd nmap && sudo ./configure && make && sudo make install"
    ]
    PROJECT_URL = "https://github.com/nmap/nmap"

    def __init__(self):
        super().__init__(runnable=False)


class Dracnmap(HackingTool):
    TITLE = "Dracnmap"
    DESCRIPTION = "Dracnmap is an open source program which is using to \n" \
                  "exploit the network and gathering information with nmap help."
    INSTALL_COMMANDS = [
        "git clone https://github.com/Screetsec/Dracnmap.git",
        "cd Dracnmap && chmod +x dracnmap-v2.2-dracOs.sh  dracnmap-v2.2.sh"
    ]
    RUN_COMMANDS = ["cd Dracnmap;sudo ./dracnmap-v2.2.sh"]
    PROJECT_URL = "https://github.com/Screetsec/Dracnmap"


class PortScan(HackingTool):
    TITLE = "Port scanning"

    def __init__(self):
        super().__init__(installable=False)

    def run(self):
        clear_screen()
        console.print(Panel(Text(self.TITLE, justify="center"), style="bold magenta"))
        target = Prompt.ask("[bold]Select a Target IP[/bold magenta]", default="", show_default=False)
        subprocess.run(["sudo", "nmap", "-O", "-Pn", target])


class Host2IP(HackingTool):
    TITLE = "Host to IP "

    def __init__(self):
        super().__init__(installable=False)

    def run(self):
        clear_screen()
        console.print(Panel(Text(self.TITLE, justify="center"), style="bold magenta"))
        host = Prompt.ask("Enter host name (e.g. www.google.com):-  ")
        ips = socket.gethostbyname(host)
        console.print("[bold magenta]{host} -> {ips}[/bold magenta]")


class XeroSploit(HackingTool):
    TITLE = "Xerosploit"
    DESCRIPTION = "Xerosploit is a penetration testing toolkit whose goal is to perform\n" \
                  "man-in-the-middle attacks for testing purposes"
    INSTALL_COMMANDS = [
        "git clone https://github.com/LionSec/xerosploit.git",
        "cd xerosploit && sudo python install.py"
    ]
    RUN_COMMANDS = ["sudo xerosploit"]
    PROJECT_URL = "https://github.com/LionSec/xerosploit"


class RedHawk(HackingTool):
    TITLE = "RED HAWK (All In One Scanning)"
    DESCRIPTION = "All in one tool for Information Gathering and Vulnerability Scanning."
    INSTALL_COMMANDS = [
        "git clone https://github.com/Tuhinshubhra/RED_HAWK.git"]
    RUN_COMMANDS = ["cd RED_HAWK;php rhawk.php"]
    PROJECT_URL = "https://github.com/Tuhinshubhra/RED_HAWK"


class ReconSpider(HackingTool):
    TITLE = "ReconSpider(For All Scanning)"
    DESCRIPTION = "ReconSpider is most Advanced Open Source Intelligence (OSINT)" \
                  " Framework for scanning IP Address, Emails, \n" \
                  "Websites, Organizations and find out information from" \
                  " different sources.\n"
    INSTALL_COMMANDS = [
        "git clone https://github.com/bhavsec/reconspider.git",
        "sudo apt install -y python3 python3-pip && cd reconspider && pip install --user ."
    ]
    RUN_COMMANDS = ["cd reconspider;python3 reconspider.py"]
    PROJECT_URL = "https://github.com/bhavsec/reconspider"


class IsItDown(HackingTool):
    TITLE = "IsItDown (Check Website Down/Up)"
    DESCRIPTION = "Check Website Is Online or Not"

    def __init__(self):
        super().__init__(
            [('Open', self.open)], installable=False, runnable=False)

    def open(self):
        console.print(Panel("Opening isitdownrightnow.com", style="bold magenta"))
        webbrowser.open_new_tab("https://www.isitdownrightnow.com/")


class Infoga(HackingTool):
    TITLE = "Infoga - Email OSINT"
    DESCRIPTION = "Infoga is a tool gathering email accounts information\n" \
                  "(ip, hostname, country,...) from different public source"
    INSTALL_COMMANDS = [
        "git clone https://github.com/m4ll0k/Infoga.git",
        "cd Infoga && pip install --user ."
    ]
    RUN_COMMANDS = ["cd Infoga;python3 infoga.py"]
    PROJECT_URL = "https://github.com/m4ll0k/Infoga"


class ReconDog(HackingTool):
    TITLE = "ReconDog"
    DESCRIPTION = "ReconDog Information Gathering Suite"
    INSTALL_COMMANDS = ["git clone https://github.com/s0md3v/ReconDog.git"]
    RUN_COMMANDS = ["cd ReconDog;sudo python dog"]
    PROJECT_URL = "https://github.com/s0md3v/ReconDog"


class Striker(HackingTool):
    TITLE = "Striker"
    DESCRIPTION = "Recon & Vulnerability Scanning Suite"
    INSTALL_COMMANDS = [
        "git clone https://github.com/s0md3v/Striker.git",
        "cd Striker && pip3 install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/s0md3v/Striker"

    def run(self):
        from config import get_tools_dir
        site = Prompt.ask("Enter Site Name (example.com)")
        # Bug 3 fix: os.chdir() corrupts the process CWD permanently — use cwd= instead
        subprocess.run(
            ["sudo", "python3", "striker.py", site],
            cwd=str(get_tools_dir() / "Striker"),
        )


class SecretFinder(HackingTool):
    TITLE = "SecretFinder (like API & etc)"
    DESCRIPTION = "SecretFinder - A python script for find sensitive data \n" \
                  "like apikeys, accesstoken, authorizations, jwt,..etc \n " \
                  "and search anything on javascript files.\n\n " \
                  "Usage: python SecretFinder.py -h"
    INSTALL_COMMANDS = [
        "git clone https://github.com/m4ll0k/SecretFinder.git secretfinder",
        "cd secretfinder; sudo pip3 install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/m4ll0k/SecretFinder"

    def __init__(self):
        super().__init__(runnable=False)


class Shodan(HackingTool):
    TITLE = "Find Info Using Shodan"
    DESCRIPTION = "Get ports, vulnerabilities, information, banners,..etc \n " \
                  "for any IP with Shodan (no apikey! no rate limit!)\n" \
                  "[X] Don't use this tool because your ip will be blocked by Shodan!"
    INSTALL_COMMANDS = ["git clone https://github.com/m4ll0k/Shodanfy.py.git"]
    PROJECT_URL = "https://github.com/m4ll0k/Shodanfy.py"

    def __init__(self):
        super().__init__(runnable=False)


class PortScannerRanger(HackingTool):
    TITLE = "Port Scanner - rang3r"
    DESCRIPTION = "rang3r is a python script which scans in multi thread\n " \
                  "all alive hosts within your range that you specify."
    INSTALL_COMMANDS = [
        "git clone https://github.com/floriankunushevci/rang3r.git;"
        "pip install --user termcolor"]
    PROJECT_URL = "https://github.com/floriankunushevci/rang3r"

    def run(self):
        from config import get_tools_dir
        ip = Prompt.ask("Enter IP")
        # Bug 3 fix: os.chdir() replaced with cwd= parameter
        subprocess.run(
            ["sudo", "python3", "rang3r.py", "--ip", ip],
            cwd=str(get_tools_dir() / "rang3r"),
        )


class Breacher(HackingTool):
    TITLE = "Breacher"
    DESCRIPTION = "An advanced multithreaded admin panel finder written in python."
    INSTALL_COMMANDS = ["git clone https://github.com/s0md3v/Breacher.git"]
    PROJECT_URL = "https://github.com/s0md3v/Breacher"

    def run(self):
        from config import get_tools_dir
        domain = Prompt.ask("Enter domain (example.com)")
        # Bug 3 fix: os.chdir() replaced with cwd= parameter
        subprocess.run(
            ["python3", "breacher.py", "-u", domain],
            cwd=str(get_tools_dir() / "Breacher"),
        )


class TheHarvester(HackingTool):
    TITLE = "theHarvester (OSINT)"
    DESCRIPTION = (
        "Gather emails, names, subdomains, IPs and URLs from public sources.\n"
        "Usage: theHarvester -d example.com -b all"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/laramies/theHarvester.git",
        "cd theHarvester && pip install --user -r requirements/base.txt",
    ]
    RUN_COMMANDS = ["cd theHarvester && python3 theHarvester.py -h"]
    PROJECT_URL = "https://github.com/laramies/theHarvester"


class Amass(HackingTool):
    TITLE = "Amass (Attack Surface Mapping)"
    DESCRIPTION = (
        "In-depth subdomain enumeration and attack surface mapping.\n"
        "Usage: amass enum -d example.com"
    )
    SUPPORTED_OS = ["linux"]
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/owasp-amass/amass/v4/...@master",
    ]
    RUN_COMMANDS = ["amass -h"]
    PROJECT_URL = "https://github.com/owasp-amass/amass"


class Masscan(HackingTool):
    TITLE = "Masscan (Fast Port Scanner)"
    DESCRIPTION = (
        "Fastest internet port scanner — 10 million packets/sec.\n"
        "Usage: masscan -p1-65535 <IP> --rate=1000"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = ["sudo apt-get install -y masscan"]
    RUN_COMMANDS = ["masscan --help"]
    PROJECT_URL = "https://github.com/robertdavidgraham/masscan"


class RustScan(HackingTool):
    TITLE = "RustScan (Modern Port Scanner)"
    DESCRIPTION = (
        "Scans all 65k ports in 3 seconds, passes results to nmap automatically.\n"
        "Usage: rustscan -a <IP> -- -sV"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = [
        "curl -sLO https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb",
        "sudo dpkg -i rustscan_2.3.0_amd64.deb",
    ]
    RUN_COMMANDS = ["rustscan --help"]
    PROJECT_URL = "https://github.com/RustScan/RustScan"


class Holehe(HackingTool):
    TITLE = "Holehe (Email → Social Accounts)"
    DESCRIPTION = (
        "Check if an email address is registered on 120+ websites.\n"
        "Usage: holehe user@example.com"
    )
    INSTALL_COMMANDS = ["pip install --user holehe"]
    RUN_COMMANDS = ["holehe --help"]
    PROJECT_URL = "https://github.com/megadose/holehe"


class Maigret(HackingTool):
    TITLE = "Maigret (Username OSINT)"
    DESCRIPTION = (
        "Collect a dossier on a person by username across 3000+ sites.\n"
        "Usage: maigret <username>"
    )
    INSTALL_COMMANDS = ["pip install --user maigret"]
    RUN_COMMANDS = ["maigret --help"]
    PROJECT_URL = "https://github.com/soxoj/maigret"


class Httpx(HackingTool):
    TITLE = "httpx (HTTP Toolkit)"
    DESCRIPTION = (
        "Fast multi-purpose HTTP probing tool.\n"
        "Usage: httpx -l urls.txt -status-code -title -tech-detect"
    )
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ]
    RUN_COMMANDS = ["httpx -h"]
    PROJECT_URL = "https://github.com/projectdiscovery/httpx"


class SpiderFoot(HackingTool):
    TITLE = "SpiderFoot (OSINT Automation)"
    DESCRIPTION = "Automates OSINT collection for threat intelligence and attack surface mapping."
    INSTALL_COMMANDS = ["pip install --user spiderfoot"]
    RUN_COMMANDS = ["spiderfoot -h"]
    PROJECT_URL = "https://github.com/smicallef/spiderfoot"


class Subfinder(HackingTool):
    TITLE = "Subfinder (Subdomain Enumeration)"
    DESCRIPTION = "Fast passive subdomain enumeration using multiple sources."
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ]
    RUN_COMMANDS = ["subfinder -h"]
    PROJECT_URL = "https://github.com/projectdiscovery/subfinder"


class TruffleHog(HackingTool):
    TITLE = "TruffleHog (Secret Scanner)"
    DESCRIPTION = "Find, verify, and analyze leaked credentials across git repos, S3 buckets, filesystems."
    INSTALL_COMMANDS = ["pip install --user trufflehog"]
    RUN_COMMANDS = ["trufflehog --help"]
    PROJECT_URL = "https://github.com/trufflesecurity/trufflehog"


class Gitleaks(HackingTool):
    TITLE = "Gitleaks (Git Secret Scanner)"
    DESCRIPTION = "Fast secret scanner for git repos — detects hardcoded passwords, API keys, tokens."
    REQUIRES_GO = True
    INSTALL_COMMANDS = [
        "go install github.com/gitleaks/gitleaks/v8@latest",
    ]
    RUN_COMMANDS = ["gitleaks --help"]
    PROJECT_URL = "https://github.com/gitleaks/gitleaks"


class InformationGatheringTools(HackingToolsCollection):
    TITLE = "Information gathering tools"
    TOOLS = [
        NMAP(),
        Dracnmap(),
        PortScan(),
        Host2IP(),
        XeroSploit(),
        RedHawk(),
        ReconSpider(),
        IsItDown(),
        Infoga(),
        ReconDog(),
        Striker(),
        SecretFinder(),
        Shodan(),
        PortScannerRanger(),
        Breacher(),
        TheHarvester(),
        Amass(),
        Masscan(),
        RustScan(),
        Holehe(),
        Maigret(),
        Httpx(),
        SpiderFoot(),
        Subfinder(),
        TruffleHog(),
        Gitleaks(),
    ]

if __name__ == "__main__":
    tools = InformationGatheringTools()
    tools.show_options()
