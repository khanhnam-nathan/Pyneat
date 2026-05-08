import subprocess

from rich.prompt import Prompt

from core import HackingTool, HackingToolsCollection, console


class DDoSTool(HackingTool):
    TITLE = "DDoS"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "Best DDoS Attack Script With 36 Plus Methods. "
        "DDoS attacks for SECURITY TESTING PURPOSES ONLY!"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/the-deepnet/ddos.git",
        "cd ddos && sudo pip3 install -r requirements.txt",
    ]
    PROJECT_URL = "https://github.com/the-deepnet/ddos"

    def run(self):
        from config import get_tools_dir
        method     = Prompt.ask("Enter Method")
        url        = Prompt.ask("Enter URL")
        threads    = Prompt.ask("Enter Threads")
        proxylist  = Prompt.ask("Enter ProxyList")
        multiple   = Prompt.ask("Enter Multiple")
        timer      = Prompt.ask("Enter Timer")
        # Bug 4 fix: removed os.system("cd ddos;") — use cwd= instead
        subprocess.run(
            ["sudo", "python3", "ddos.py", method, url,
             "socks_type5.4.1", threads, proxylist, multiple, timer],
            cwd=str(get_tools_dir() / "ddos"),
        )


class SlowLoris(HackingTool):
    TITLE = "SlowLoris"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "Slowloris is basically an HTTP Denial of Service attack. "
        "It sends lots of HTTP requests."
    )
    INSTALL_COMMANDS = ["sudo pip3 install slowloris"]

    def run(self):
        target_site = Prompt.ask("Enter Target Site")
        subprocess.run(["slowloris", target_site])


class Asyncrone(HackingTool):
    TITLE = "Asyncrone | Multifunction SYN Flood DDoS Weapon"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "aSYNcrone is a C language based, multifunction SYN Flood DDoS Weapon.\n"
        "Disable the destination system by sending SYN packets intensively."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/fatih4842/aSYNcrone.git",
        "cd aSYNcrone && sudo gcc aSYNcrone.c -o aSYNcrone -lpthread",
    ]
    PROJECT_URL = "https://github.com/fatihsnsy/aSYNcrone"

    def run(self):
        from config import get_tools_dir
        source_port = Prompt.ask("Enter Source Port")
        target_ip   = Prompt.ask("Enter Target IP")
        target_port = Prompt.ask("Enter Target Port")
        # Bug 5 fix: 1000 was int — subprocess requires all args str
        # Bug 4 fix: removed os.system("cd aSYNcrone;") — use cwd= instead
        subprocess.run(
            ["sudo", "./aSYNcrone", str(source_port), str(target_ip), str(target_port), "1000"],
            cwd=str(get_tools_dir() / "aSYNcrone"),
        )


class UFONet(HackingTool):
    TITLE = "UFOnet"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "UFONet is a free software, P2P and cryptographic disruptive toolkit "
        "that allows performing DoS and DDoS attacks."
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/epsylon/ufonet.git",
        "cd ufonet && pip install --user .",
    ]
    RUN_COMMANDS = ["python3 ufonet --gui"]
    PROJECT_URL = "https://github.com/epsylon/ufonet"


class GoldenEye(HackingTool):
    TITLE = "GoldenEye"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = (
        "GoldenEye is a python3 app for SECURITY TESTING PURPOSES ONLY!\n"
        "GoldenEye is a HTTP DoS Test Tool.\n"
        "Usage: ./goldeneye.py <url> [OPTIONS]"
    )
    INSTALL_COMMANDS = [
        "git clone https://github.com/jseidl/GoldenEye.git",
        "chmod -R 755 GoldenEye",
    ]
    PROJECT_URL = "https://github.com/jseidl/GoldenEye"

    def run(self):
        from config import get_tools_dir
        # Bug 4 fix: removed os.system("cd GoldenEye; ...") — no-op cd subshell
        url = Prompt.ask("Enter target URL")
        subprocess.run(["sudo", "./goldeneye.py", url],
                       cwd=str(get_tools_dir() / "GoldenEye"))


class Saphyra(HackingTool):
    TITLE = "SaphyraDDoS"
    SUPPORTED_OS = ["linux"]
    DESCRIPTION = "A Python DDoS script for SECURITY TESTING PURPOSES ONLY."
    INSTALL_COMMANDS = [
        # Bug 7 fix: removed "sudo su" (first step was dropping into interactive root shell)
        "git clone https://github.com/anonymous24x7/Saphyra-DDoS.git",
        "chmod +x Saphyra-DDoS/saphyra.py",
    ]
    PROJECT_URL = "https://github.com/anonymous24x7/Saphyra-DDoS"

    def run(self):
        from config import get_tools_dir
        url = Prompt.ask("Enter URL")
        # Vuln 1 fix: was os.system("python saphyra.py " + url) — command injection
        # Now uses subprocess list form — url is never interpolated into a shell string
        subprocess.run(
            ["python3", "saphyra.py", url],
            cwd=str(get_tools_dir() / "Saphyra-DDoS"),
        )


class DDOSTools(HackingToolsCollection):
    TITLE = "DDOS Attack Tools"
    TOOLS = [DDoSTool(), SlowLoris(), Asyncrone(), UFONet(), GoldenEye(), Saphyra()]


if __name__ == "__main__":
    tools = DDOSTools()
    tools.show_options()
