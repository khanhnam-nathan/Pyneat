import os
import subprocess

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import box

from core import HackingTool, HackingToolsCollection, console


class Cupp(HackingTool):
    TITLE = "Cupp"
    # Bug 24 fix: DESCRIPTION was copy-pasted from WlCreator — completely wrong
    DESCRIPTION = "Common User Passwords Profiler — generates personalized wordlists based on target info."
    INSTALL_COMMANDS = ["git clone https://github.com/Mebus/cupp.git"]
    RUN_COMMANDS = ["cd cupp && python3 cupp.py -i"]
    PROJECT_URL = "https://github.com/Mebus/cupp"

    def show_info(self):
        panel = Panel(
            f"[bold purple]{self.TITLE}[/bold purple]\n\n"
            f"[cyan]{self.DESCRIPTION}[/cyan]\n\n"
            f"[green]Repository:[/green] [underline blue]{self.PROJECT_URL}[/underline blue]",
            border_style="purple",
            box=box.ROUNDED,
        )
        console.print(panel)


class WlCreator(HackingTool):
    TITLE = "WordlistCreator"
    DESCRIPTION = "WlCreator is a C program that can create all possibilities" \
                  " of passwords,\n and you can choose Length, Lowercase, " \
                  "Capital, Numbers and Special Chars"
    INSTALL_COMMANDS = ["git clone https://github.com/Z4nzu/wlcreator.git"]
    RUN_COMMANDS = [
        "cd wlcreator && sudo gcc -o wlcreator wlcreator.c && ./wlcreator 5"]
    PROJECT_URL = "https://github.com/Z4nzu/wlcreator"

    def show_info(self):
        panel = Panel(
            f"[bold purple]{self.TITLE}[/bold purple]\n\n"
            f"[cyan]{self.DESCRIPTION}[/cyan]\n\n"
            f"[green]Repository:[/green] [underline blue]{self.PROJECT_URL}[/underline blue]",
            border_style="purple",
            box=box.ROUNDED,
        )
        console.print(panel)


class GoblinWordGenerator(HackingTool):
    TITLE = "Goblin WordGenerator"
    DESCRIPTION = "Goblin WordGenerator"
    INSTALL_COMMANDS = [
        "git clone https://github.com/UndeadSec/GoblinWordGenerator.git"]
    RUN_COMMANDS = ["cd GoblinWordGenerator && python3 goblin.py"]
    PROJECT_URL = "https://github.com/UndeadSec/GoblinWordGenerator.git"

    def show_info(self):
        panel = Panel(
            f"[bold purple]{self.TITLE}[/bold purple]\n\n"
            f"[cyan]{self.DESCRIPTION}[/cyan]\n\n"
            f"[green]Repository:[/green] [underline blue]{self.PROJECT_URL}[/underline blue]",
            border_style="purple",
            box=box.ROUNDED,
        )
        console.print(panel)


class showme(HackingTool):
    TITLE = "Password list (1.4 Billion Clear Text Password)"
    DESCRIPTION = "This tool allows you to perform OSINT and reconnaissance on " \
                  "an organisation or an individual. It allows one to search " \
                  "1.4 Billion clear text credentials which was dumped as " \
                  "part of BreachCompilation leak. This database makes " \
                  "finding passwords faster and easier than ever before."
    INSTALL_COMMANDS = [
        "git clone https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got.git",
        "cd SMWYG-Show-Me-What-You-Got && pip3 install -r requirements.txt"
    ]
    RUN_COMMANDS = ["cd SMWYG-Show-Me-What-You-Got && python SMWYG.py"]
    PROJECT_URL = "https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got"

    def show_info(self):
        panel = Panel(
            f"[bold purple]{self.TITLE}[/bold purple]\n\n"
            f"[cyan]{self.DESCRIPTION}[/cyan]\n\n"
            f"[green]Repository:[/green] [underline blue]{self.PROJECT_URL}[/underline blue]",
            border_style="purple",
            box=box.ROUNDED,
        )
        console.print(panel)


class Hashcat(HackingTool):
    TITLE = "Hashcat (Password Cracker)"
    DESCRIPTION = (
        "World's fastest GPU/CPU password recovery tool — supports 300+ hash types.\n"
        "Usage: hashcat -m 0 -a 0 hashes.txt wordlist.txt"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = ["sudo apt-get install -y hashcat"]
    RUN_COMMANDS = ["hashcat --help"]
    PROJECT_URL = "https://github.com/hashcat/hashcat"


class JohnTheRipper(HackingTool):
    TITLE = "John the Ripper"
    DESCRIPTION = (
        "Open-source password security auditing and recovery tool.\n"
        "Usage: john --wordlist=wordlist.txt hashfile"
    )
    SUPPORTED_OS = ["linux"]
    INSTALL_COMMANDS = ["sudo apt-get install -y john"]
    RUN_COMMANDS = ["john --help"]
    PROJECT_URL = "https://github.com/openwall/john"


class Haiti(HackingTool):
    TITLE = "haiti (Hash Type Identifier)"
    DESCRIPTION = (
        "Identify hash types — supports 300+ algorithms.\n"
        "Usage: haiti <hash>"
    )
    REQUIRES_RUBY = True
    INSTALL_COMMANDS = ["gem install haiti-hash"]
    RUN_COMMANDS = ["haiti --help"]
    PROJECT_URL = "https://github.com/noraj/haiti"


class WordlistGeneratorTools(HackingToolsCollection):
    TITLE = "Wordlist Generator"
    TOOLS = [
        Cupp(),
        WlCreator(),
        GoblinWordGenerator(),
        showme(),
        Hashcat(),
        JohnTheRipper(),
        Haiti(),
    ]

    def show_info(self):
        header = Panel(f"[bold white on purple] {self.TITLE} [/bold white on purple]",
                       border_style="purple", box=box.DOUBLE)
        console.print(header)
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold purple")
        table.add_column("#", justify="center", style="cyan", width=4)
        table.add_column("Tool", style="bold")
        table.add_column("Description", style="dim", overflow="fold")

        for idx, t in enumerate(self.TOOLS, start=1):
            desc = getattr(t, "DESCRIPTION", "") or ""
            table.add_row(str(idx), t.TITLE, desc)

        table.add_row("[red]99[/red]", "[bold red]Exit[/bold red]", "Return to previous menu")
        console.print(table)

if __name__ == "__main__":
    tools = WordlistGeneratorTools()
    tools.show_info()
    tools.show_options()
