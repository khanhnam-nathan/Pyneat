from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class WifiJammerNG(HackingTool):
    TITLE = "WifiJammer-NG"
    DESCRIPTION = "Continuously jam all wifi clients and access points within range."
    SUPPORTED_OS = ["linux"]
    REQUIRES_WIFI = True
    INSTALL_COMMANDS = [
        "git clone https://github.com/MisterBianco/wifijammer-ng.git",
        "cd wifijammer-ng;pip install --user -r requirements.txt"
    ]
    RUN_COMMANDS = [
        "cd wifijammer-ng && sudo python3 wifijammer.py --help",
    ]
    PROJECT_URL = "https://github.com/MisterBianco/wifijammer-ng"


class KawaiiDeauther(HackingTool):
    TITLE = "KawaiiDeauther"
    DESCRIPTION = "Kawaii Deauther is a pentest toolkit whose goal is to perform \n " \
                  "jam on WiFi clients/routers and spam many fake AP for testing purposes."
    SUPPORTED_OS = ["linux"]
    REQUIRES_WIFI = True
    INSTALL_COMMANDS = [
        "git clone https://github.com/aryanrtm/KawaiiDeauther.git",
        "cd KawaiiDeauther;sudo bash install.sh"
    ]
    RUN_COMMANDS = ["cd KawaiiDeauther;sudo bash KawaiiDeauther.sh"]
    PROJECT_URL = "https://github.com/aryanrtm/KawaiiDeauther"


class WifiJammingTools(HackingToolsCollection):
    TITLE = "Wifi Deauthenticate"
    TOOLS = [
        WifiJammerNG(),
        KawaiiDeauther()
    ]

if __name__ == "__main__":
    tools = WifiJammingTools()
    tools.show_options()
