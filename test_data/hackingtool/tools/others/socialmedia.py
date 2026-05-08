import contextlib
import os
import subprocess

from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class InstaBrute(HackingTool):
    TITLE = "Instagram Attack"
    DESCRIPTION = "Brute force attack against Instagram"
    PROJECT_URL = "https://github.com/chinoogawa/instaBrute"
    # Py3-7: Python 2 only (pip2.7); also violates Instagram ToS
    ARCHIVED = True
    ARCHIVED_REASON = "Python 2 only — EOL January 2020. Repo unmaintained since 2017."
    INSTALL_COMMANDS = []
    RUN_COMMANDS = []

    def __init__(self):
        super().__init__(installable=False, runnable=False)


class BruteForce(HackingTool):
    TITLE = "AllinOne SocialMedia Attack"
    DESCRIPTION = "Brute_Force_Attack Gmail Hotmail Twitter Facebook Netflix \n" \
                  "[!] python3 Brute_Force.py -g <Account@gmail.com> -l <File_list>"
    INSTALL_COMMANDS = [
        "git clone https://github.com/Matrix07ksa/Brute_Force.git",
        "cd Brute_Force;sudo pip3 install proxylist;pip3 install mechanize"
    ]
    RUN_COMMANDS = ["cd Brute_Force;python3 Brute_Force.py -h"]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"


class Faceshell(HackingTool):
    TITLE = "Facebook Attack"
    DESCRIPTION = "Facebook BruteForcer"
    INSTALL_COMMANDS = [
        "git clone https://github.com/Matrix07ksa/Brute_Force.git",
        "cd Brute_Force;sudo pip3 install proxylist;pip3 install mechanize"
    ]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"

    def run(self):
        from config import get_tools_dir
        name = Prompt.ask("Enter Username")
        wordlist = Prompt.ask("Enter Wordlist path")
        # Bug 3 fix: os.chdir() replaced with cwd= parameter
        subprocess.run(
            ["python3", "Brute_Force.py", "-f", name, "-l", wordlist],
            cwd=str(get_tools_dir() / "Brute_Force"),
        )


class AppCheck(HackingTool):
    TITLE = "Application Checker"
    DESCRIPTION = "Tool to check if an app is installed on the target device through a link."
    INSTALL_COMMANDS = [
        "git clone https://github.com/jakuta-tech/underhanded.git",
        "cd underhanded && sudo chmod +x underhanded.sh"
    ]
    RUN_COMMANDS = ["cd underhanded;sudo bash underhanded.sh"]
    PROJECT_URL = "https://github.com/jakuta-tech/underhanded"


class SocialMediaBruteforceTools(HackingToolsCollection):
    TITLE = "SocialMedia Bruteforce"
    TOOLS = [
        InstaBrute(),
        BruteForce(),
        Faceshell(),
        AppCheck()
    ]

if __name__ == "__main__":
    tools = SocialMediaBruteforceTools()
    tools.show_options()
