from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class EvilURL(HackingTool):
    TITLE = "EvilURL"
    DESCRIPTION = "Generate unicode evil domains for IDN Homograph Attack " \
                  "and detect them."
    INSTALL_COMMANDS = ["git clone https://github.com/UndeadSec/EvilURL.git"]
    RUN_COMMANDS = ["cd EvilURL;python3 evilurl.py"]
    PROJECT_URL = "https://github.com/UndeadSec/EvilURL"


class IDNHomographAttackTools(HackingToolsCollection):
    TITLE = "IDN Homograph Attack"
    TOOLS = [EvilURL()]

if __name__ == "__main__":
    tools = IDNHomographAttackTools()
    tools.show_options()
