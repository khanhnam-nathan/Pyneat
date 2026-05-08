from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class DebInject(HackingTool):
    TITLE = "Debinject"
    DESCRIPTION = "Debinject is a tool that inject malicious code into *.debs"
    INSTALL_COMMANDS = [
        "git clone https://github.com/UndeadSec/Debinject.git"]
    RUN_COMMANDS = ["cd Debinject;python debinject.py"]
    PROJECT_URL = "https://github.com/UndeadSec/Debinject"


class Pixload(HackingTool):
    TITLE = "Pixload"
    DESCRIPTION = "Pixload -- Image Payload Creating tools \n " \
                  "Pixload is Set of tools for creating/injecting payload into images."
    INSTALL_COMMANDS = [
        "sudo apt install libgd-perl libimage-exiftool-perl libstring-crc32-perl",
        "git clone https://github.com/chinarulezzz/pixload.git"
    ]
    PROJECT_URL = "https://github.com/chinarulezzz/pixload"

    def __init__(self):
        super().__init__(runnable = False)


class PayloadInjectorTools(HackingToolsCollection):
    TITLE = "Payload Injector"
    TOOLS = [
        DebInject(),
        Pixload()
    ]

if __name__ == "__main__":
    tools = PayloadInjectorTools()
    tools.show_options()
