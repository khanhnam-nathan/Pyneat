import os

from core import HackingTool, HackingToolsCollection, console


class Autophisher(HackingTool):
    TITLE = "Autophisher RK"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Automated Phishing Toolkit"
    INSTALL_COMMANDS = [
        "git clone https://github.com/CodingRanjith/autophisher.git",
    ]
    RUN_COMMANDS = ["cd autophisher && sudo bash autophisher.sh"]
    PROJECT_URL = "https://github.com/CodingRanjith/autophisher"


class Pyphisher(HackingTool):
    TITLE = "Pyphisher"
    DESCRIPTION = "Easy to use phishing tool with 77 website templates"
    # Bug 9 fix: pip must reference the full path, not rely on a no-op "cd" call
    INSTALL_COMMANDS = [
        "git clone https://github.com/KasRoudra/PyPhisher",
        "pip3 install --user -r PyPhisher/files/requirements.txt",
    ]
    RUN_COMMANDS = ["cd PyPhisher && sudo python3 pyphisher.py"]
    # Bug 8 fix: PROJECT_URL was a git clone command, not a URL
    PROJECT_URL = "https://github.com/KasRoudra/PyPhisher"


class AdvPhishing(HackingTool):
    TITLE = "AdvPhishing"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "This is Advance Phishing Tool ! OTP PHISHING"
    INSTALL_COMMANDS = [
        "git clone https://github.com/Ignitetch/AdvPhishing.git",
        # Vuln 2 fix: chmod 777 → chmod +x
        "cd AdvPhishing && chmod +x Linux-Setup.sh && bash Linux-Setup.sh",
    ]
    RUN_COMMANDS = ["cd AdvPhishing && sudo bash AdvPhishing.sh"]
    PROJECT_URL = "https://github.com/Ignitetch/AdvPhishing"


class Setoolkit(HackingTool):
    TITLE = "Setoolkit"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "The Social-Engineer Toolkit is an open-source penetration\n"
        "testing framework designed for social engineering."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/trustedsec/social-engineer-toolkit/",
        "cd social-engineer-toolkit && pip install --user .",
    ]
    RUN_COMMANDS = ["sudo setoolkit"]
    PROJECT_URL = "https://github.com/trustedsec/social-engineer-toolkit"


class SocialFish(HackingTool):
    TITLE = "SocialFish"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Automated Phishing Tool & Information Collector NOTE: username is 'root' and password is 'pass'"
    INSTALL_COMMANDS = [
        "git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y",
        "cd SocialFish && sudo python3 -m pip install -r requirements.txt",
    ]
    RUN_COMMANDS = ["cd SocialFish && sudo python3 SocialFish.py root pass"]
    PROJECT_URL = "https://github.com/UndeadSec/SocialFish"


class HiddenEye(HackingTool):
    TITLE = "HiddenEye"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "Modern Phishing Tool With Advanced Functionality And Multiple Tunnelling Services\n"
        "\t[!] https://github.com/DarkSecDevelopers/HiddenEye"
    )
    INSTALL_COMMANDS = [
        # Vuln 2 fix: chmod 777 → chmod 755
        "git clone https://github.com/Morsmalleo/HiddenEye.git && chmod -R 755 HiddenEye",
        "cd HiddenEye && sudo pip3 install -r requirements.txt && pip3 install pyngrok",
    ]
    RUN_COMMANDS = ["cd HiddenEye && sudo python3 HiddenEye.py"]
    PROJECT_URL = "https://github.com/Morsmalleo/HiddenEye"


class Evilginx3(HackingTool):
    TITLE = "Evilginx3"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "evilginx is a man-in-the-middle attack framework used for phishing login credentials\n"
        "along with session cookies, bypassing 2-factor authentication.\n"
        "Requires Go >= 1.18 installed."
    )
    # Bug 6 fix: removed 'sudo evilginx' (interactive) from INSTALL_COMMANDS
    INSTALL_COMMANDS = [
        "sudo apt-get install -y git make golang-go",
        "go install github.com/kgretzky/evilginx/v3@latest",
    ]
    RUN_COMMANDS = ["evilginx"]
    PROJECT_URL = "https://github.com/kgretzky/evilginx2"
    REQUIRES_GO = True


class ISeeYou(HackingTool):
    TITLE = "I-See_You"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "[!] ISeeYou finds the exact location of a target via social engineering.\n"
        "[!] Expose local servers to the internet and decode location from log file."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/Viralmaniar/I-See-You.git",
        "cd I-See-You && sudo chmod u+x ISeeYou.sh",
    ]
    RUN_COMMANDS = ["cd I-See-You && sudo bash ISeeYou.sh"]
    PROJECT_URL = "https://github.com/Viralmaniar/I-See-You"


class SayCheese(HackingTool):
    TITLE = "SayCheese"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Take webcam shots from target just by sending a malicious link"
    INSTALL_COMMANDS = ["git clone https://github.com/hangetzzu/saycheese"]
    RUN_COMMANDS = ["cd saycheese && sudo bash saycheese.sh"]
    PROJECT_URL = "https://github.com/hangetzzu/saycheese"


class QRJacking(HackingTool):
    TITLE = "QR Code Jacking"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "QR Code Jacking (Any Website)"
    INSTALL_COMMANDS = [
        "git clone https://github.com/cryptedwolf/ohmyqr.git && sudo apt -y install scrot",
    ]
    RUN_COMMANDS = ["cd ohmyqr && sudo bash ohmyqr.sh"]
    PROJECT_URL = "https://github.com/cryptedwolf/ohmyqr"


# Bug 10 fix: WifiPhisher removed from phishing tools — it belongs in wireless_attack.py


class BlackEye(HackingTool):
    TITLE = "BlackEye"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "The ultimate phishing tool with 38 websites available!"
    INSTALL_COMMANDS = [
        "git clone https://github.com/thelinuxchoice/blackeye",
    ]
    RUN_COMMANDS = ["cd blackeye && sudo bash blackeye.sh"]
    PROJECT_URL = "https://github.com/An0nUD4Y/blackeye"


class ShellPhish(HackingTool):
    TITLE = "ShellPhish"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Phishing Tool for 18 social media"
    INSTALL_COMMANDS = ["git clone https://github.com/An0nUD4Y/shellphish.git"]
    RUN_COMMANDS = ["cd shellphish && sudo bash shellphish.sh"]
    PROJECT_URL = "https://github.com/An0nUD4Y/shellphish"


class Thanos(HackingTool):
    TITLE = "Thanos"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Browser to Browser Phishing toolkit"
    INSTALL_COMMANDS = [
        "git clone https://github.com/TridevReddy/Thanos.git",
        # Vuln 2 fix: chmod -R 777 → chmod +x
        "cd Thanos && chmod +x Thanos.sh",
    ]
    RUN_COMMANDS = ["cd Thanos && sudo bash Thanos.sh"]
    PROJECT_URL = "https://github.com/TridevReddy/Thanos"


class QRLJacking(HackingTool):
    TITLE = "QRLJacking"
    DESCRIPTION = "QRLJacking — session hijacking attack vector targeting QR code based login"
    INSTALL_COMMANDS = [
        "git clone https://github.com/OWASP/QRLJacking.git",
        # Bug fix: geckodriver must be fetched as a binary, not cloned from source
        "GECKO_VER=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | grep tag_name | cut -d '\"' -f4) && "
        "wget -q https://github.com/mozilla/geckodriver/releases/download/$GECKO_VER/geckodriver-$GECKO_VER-linux64.tar.gz -O /tmp/geckodriver.tar.gz && "
        "tar -xzf /tmp/geckodriver.tar.gz -C /tmp && sudo mv /tmp/geckodriver /usr/local/bin/",
        "cd QRLJacking && pip3 install --user -r QRLJacker/requirements.txt",
    ]
    RUN_COMMANDS = ["cd QRLJacking/QRLJacker && python3 QrlJacker.py"]
    PROJECT_URL = "https://github.com/OWASP/QRLJacking"


class Maskphish(HackingTool):
    TITLE = "Maskphish"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "Hide phishing URL under a normal looking URL (google.com or facebook.com)"
    INSTALL_COMMANDS = [
        "git clone https://github.com/jaykali/maskphish.git",
    ]
    RUN_COMMANDS = ["cd maskphish && sudo bash maskphish.sh"]
    PROJECT_URL = "https://github.com/jaykali/maskphish"


class BlackPhish(HackingTool):
    TITLE = "BlackPhish"
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = [
        "git clone https://github.com/iinc0gnit0/BlackPhish.git",
        "cd BlackPhish && sudo bash install.sh",
    ]
    RUN_COMMANDS = ["cd BlackPhish && sudo python3 blackphish.py"]
    PROJECT_URL = "https://github.com/iinc0gnit0/BlackPhish"

    def __init__(self):
        # Bug fix: super() Python 3 style
        super().__init__([("Update", self.update)])

    def update(self):
        import subprocess
        from config import get_tools_dir
        subprocess.run(["bash", "update.sh"], cwd=str(get_tools_dir() / "BlackPhish"))


class Dnstwist(HackingTool):
    # Bug 2 fix: all attributes were wrong case (Title, Install_commands, etc.)
    # They are now the correct uppercase names the base class reads.
    TITLE = "dnstwist"
    DESCRIPTION = "Domain name permutation engine for detecting typosquatting, phishing and brand impersonation"
    INSTALL_COMMANDS = ["pip3 install --user dnstwist"]
    RUN_COMMANDS = ["dnstwist --help"]
    PROJECT_URL = "https://github.com/elceef/dnstwist"


class PhishingAttackTools(HackingToolsCollection):
    TITLE = "Phishing attack tools"
    TOOLS = [
        Autophisher(),
        Pyphisher(),
        AdvPhishing(),
        Setoolkit(),
        SocialFish(),
        HiddenEye(),
        Evilginx3(),
        ISeeYou(),
        SayCheese(),
        QRJacking(),
        BlackEye(),
        ShellPhish(),
        Thanos(),
        QRLJacking(),
        BlackPhish(),
        Maskphish(),
        Dnstwist(),
    ]


if __name__ == "__main__":
    tools = PhishingAttackTools()
    tools.show_options()
