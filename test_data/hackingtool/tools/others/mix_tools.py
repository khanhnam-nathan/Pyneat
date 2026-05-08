from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class TerminalMultiplexer(HackingTool):
    TITLE = "Terminal Multiplexer"
    DESCRIPTION = (
        "Terminal Multiplexer (tilix) is a tiling terminal emulator that "
        "allows opening several terminal sessions inside one window."
    )
    # Bug 19 fix: tilix is a Debian/Ubuntu package only — mark Linux-only
    INSTALL_COMMANDS = ["sudo apt-get install -y tilix"]
    SUPPORTED_OS = ["linux"]

    def __init__(self):
        # Py3-4 fix: super(TerminalMultiplexer, self) → super()
        super().__init__(runnable=False)


class Crivo(HackingTool):
    TITLE = "Crivo"
    DESCRIPTION = (
        "A tool for extracting and filtering URLs, IPs, domains, and subdomains\n"
        "from web pages or text, with built-in web scraping capabilities.\n"
        "See: python3 crivo_cli.py -h"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/GMDSantana/crivo.git",
        # Bug 18 verify: this is correct — cd and pip in same string works
        "cd crivo && pip install --user -r requirements.txt",
    ]
    PROJECT_URL = "https://github.com/GMDSantana/crivo"

    def __init__(self):
        # Py3-4 fix: super(Crivo, self) → super()
        super().__init__(runnable=False)


class MixTools(HackingToolsCollection):
    TITLE = "Mix tools"
    TOOLS = [
        TerminalMultiplexer(),
        Crivo()
    ]

if __name__ == "__main__":
    tools = MixTools()
    tools.show_options()
