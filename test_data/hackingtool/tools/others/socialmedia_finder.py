import os
import subprocess

from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class FacialFind(HackingTool):
    TITLE = "Find SocialMedia By Facial Recognation System"
    DESCRIPTION = "A Social Media Mapping Tool that correlates profiles\n " \
                  "via facial recognition across different sites."
    INSTALL_COMMANDS = [
        "sudo apt install -y software-properties-common",
        "sudo add-apt-repository ppa:mozillateam/firefox-next && sudo apt update && sudo apt upgrade",
        "git clone https://github.com/Greenwolf/social_mapper.git",
        "sudo apt install -y build-essential cmake libgtk-3-dev libboost-all-dev",
        "cd social_mapper/setup",
        "sudo python3 -m pip install --no-cache-dir -r requirements.txt",
        'echo "[!]Now You have To do some Manually\n'
        '[!] Install the Geckodriver for your operating system\n'
        '[!] Copy & Paste Link And Download File As System Configuration\n'
        '[#] https://github.com/mozilla/geckodriver/releases\n'
        '[!!] On Linux you can place it in /usr/bin "| boxes | lolcat'
    ]
    PROJECT_URL = "https://github.com/Greenwolf/social_mapper"

    def run(self):
        from config import get_tools_dir
        import subprocess
        setup_dir = get_tools_dir() / "social_mapper" / "setup"
        subprocess.run(["python3", "social_mapper.py", "-h"], cwd=str(setup_dir))
        console.print(
            "[bold magenta]Set username and password in social_mapper.py before running.[/]\n"
            "[magenta]Usage: python social_mapper.py -f <folder> -i <path> -m fast <AcName> -fb -tw[/]"
        )


class FindUser(HackingTool):
    TITLE = "Find SocialMedia By UserName"
    DESCRIPTION = "Find usernames across over 75 social networks"
    INSTALL_COMMANDS = [
        "git clone https://github.com/xHak9x/finduser.git",
        "cd finduser && sudo chmod +x finduser.sh"
    ]
    RUN_COMMANDS = ["cd finduser && sudo bash finduser.sh"]
    PROJECT_URL = "https://github.com/xHak9x/finduser"


class Sherlock(HackingTool):
    TITLE = "Sherlock"
    DESCRIPTION = "Hunt down social media accounts by username across social networks \n " \
                  "For More Usage \n" \
                  "\t >>python3 sherlock --help"
    INSTALL_COMMANDS = [
        "git clone https://github.com/sherlock-project/sherlock.git",
        "cd sherlock;sudo python3 -m pip install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/sherlock-project/sherlock"

    def run(self):
        from config import get_tools_dir
        from rich.prompt import Prompt
        name = Prompt.ask("Enter Username")
        # Bug 3 fix: os.chdir() replaced with cwd= parameter
        subprocess.run(
            ["python3", "sherlock", name],
            cwd=str(get_tools_dir() / "sherlock"),
        )


class SocialScan(HackingTool):
    TITLE = "SocialScan | Username or Email"
    DESCRIPTION = "Check email address and username availability on online " \
                  "platforms with 100% accuracy"
    INSTALL_COMMANDS = ["pip install --user socialscan"]
    PROJECT_URL = "https://github.com/iojw/socialscan"

    def run(self):
        name = input(
            "Enter Username or Emailid (if both then please space between email & username) >> ")
        subprocess.run(["sudo", "socialscan", f"{name}"])


class SocialMediaFinderTools(HackingToolsCollection):
    TITLE = "SocialMedia Finder"
    TOOLS = [
        FacialFind(),
        FindUser(),
        Sherlock(),
        SocialScan()
    ]

if __name__ == "__main__":
    tools = SocialMediaFinderTools()
    tools.show_options()
