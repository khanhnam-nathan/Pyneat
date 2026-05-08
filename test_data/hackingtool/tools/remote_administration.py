from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt


# Bug 17 fix: Stitch was defined in both payload_creator.py and remote_administration.py.
# It is kept in payload_creator.py (its correct category) and removed from here.


class Pyshell(HackingTool):
    TITLE = "Pyshell"
    DESCRIPTION = "Pyshell is a Rat Tool that can be able to download & upload " \
                  "files,\n Execute OS Command and more.."
    INSTALL_COMMANDS = [
        "git clone https://github.com/knassar702/Pyshell.git;"
        "pip install --user pyscreenshot python-nmap requests"
    ]
    RUN_COMMANDS = ["cd Pyshell;./Pyshell"]
    PROJECT_URL = "https://github.com/knassar702/pyshell"


class RemoteAdministrationTools(HackingToolsCollection):
    TITLE = "Remote Administrator Tools (RAT)"
    TOOLS = [
        Pyshell()
    ]

if __name__ == "__main__":
    tools = RemoteAdministrationTools()
    tools.show_options()
