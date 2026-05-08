from core import HackingTool, HackingToolsCollection, console

from rich.panel import Panel
from rich.prompt import Prompt


class Sqlmap(HackingTool):
    TITLE = "Sqlmap tool"
    DESCRIPTION = "sqlmap is an open source penetration testing tool that " \
                  "automates the process of detecting and exploiting SQL injection flaws " \
                  "and taking over database servers. [!] python3 sqlmap.py -u [http://example.com] --batch --banner. More usage: https://github.com/sqlmapproject/sqlmap/wiki/Usage"
    INSTALL_COMMANDS = ["git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev"]
    RUN_COMMANDS = ["cd sqlmap-dev;python3 sqlmap.py --wizard"]
    PROJECT_URL = "https://github.com/sqlmapproject/sqlmap"


class NoSqlMap(HackingTool):
    TITLE = "NoSqlMap"
    DESCRIPTION = "NoSQLMap is an open source Python tool designed to audit and automate injection attacks. [*] Please install MongoDB."
    INSTALL_COMMANDS = [
        "git clone https://github.com/codingo/NoSQLMap.git",
        # Bug 25 fix: was "python setup.py install" (Python 2) and "python NoSQLMap"
        "cd NoSQLMap && pip install --user .",
    ]
    # Bug 25 fix: "python" → "python3"
    RUN_COMMANDS = ["python3 -m nosqlmap"]
    PROJECT_URL = "https://github.com/codingo/NoSQLMap"


class SQLiScanner(HackingTool):
    TITLE = "Damn Small SQLi Scanner"
    DESCRIPTION = "DSSS is a fully functional SQL injection vulnerability scanner also supporting GET and POST parameters. Usage: python3 dsss.py -h | -u [URL]"
    INSTALL_COMMANDS = ["git clone https://github.com/stamparm/DSSS.git"]
    PROJECT_URL = "https://github.com/stamparm/DSSS"

    def __init__(self):
        super().__init__(runnable=False)


class Explo(HackingTool):
    TITLE = "Explo"
    DESCRIPTION = "Explo is a simple tool to describe web security issues in human and machine readable format. Usage: explo [--verbose|-v] testcase.yaml | explo [--verbose|-v] examples/*.yaml"
    INSTALL_COMMANDS = [
        "git clone https://github.com/dtag-dev-sec/explo.git",
        "cd explo && pip install --user .",
    ]
    PROJECT_URL = "https://github.com/dtag-dev-sec/explo"

    def __init__(self):
        super().__init__(runnable=False)


class Blisqy(HackingTool):
    TITLE = "Blisqy - Exploit Time-based blind-SQL injection"
    DESCRIPTION = "Blisqy helps web security researchers find time-based blind SQL injections on HTTP headers and exploit them."
    INSTALL_COMMANDS = ["git clone https://github.com/JohnTroony/Blisqy.git"]
    PROJECT_URL = "https://github.com/JohnTroony/Blisqy"

    def __init__(self):
        super().__init__(runnable=False)


class Leviathan(HackingTool):
    TITLE = "Leviathan - Wide Range Mass Audit Toolkit"
    DESCRIPTION = "Leviathan is a mass audit toolkit with service discovery, brute force, SQL injection detection, and custom exploit capabilities. Requires API keys."
    INSTALL_COMMANDS = ["git clone https://github.com/leviathan-framework/leviathan.git",
                        "cd leviathan;pip install --user -r requirements.txt"]
    RUN_COMMANDS = ["cd leviathan;python leviathan.py"]
    PROJECT_URL = "https://github.com/leviathan-framework/leviathan"


class SQLScan(HackingTool):
    TITLE = "SQLScan"
    DESCRIPTION = "SQLScan is a quick web scanner to find SQL injection points. Not for educational purposes."
    INSTALL_COMMANDS = ["sudo apt install php php-bz2 php-curl php-mbstring curl",
                        "sudo curl https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/build/main.phar --output /usr/local/bin/sqlscan",
                        "chmod +x /usr/local/bin/sqlscan"]
    RUN_COMMANDS = ["sudo sqlscan"]
    PROJECT_URL = "https://github.com/Cvar1984/sqlscan"


class SqlInjectionTools(HackingToolsCollection):
    TITLE = "SQL Injection Tools"
    TOOLS = [Sqlmap(), NoSqlMap(), SQLiScanner(), Explo(), Blisqy(), Leviathan(), SQLScan()]

if __name__ == "__main__":
    tools = SqlInjectionTools()
    tools.show_options()
