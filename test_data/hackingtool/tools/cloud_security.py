from core import HackingTool
from core import HackingToolsCollection


class Prowler(HackingTool):
    TITLE = "Prowler (Cloud Security Scanner)"
    DESCRIPTION = "Open-source security tool for AWS, Azure, GCP, and Kubernetes assessments."
    INSTALL_COMMANDS = ["pip install --user prowler"]
    RUN_COMMANDS = ["prowler --help"]
    PROJECT_URL = "https://github.com/prowler-cloud/prowler"
    SUPPORTED_OS = ["linux", "macos"]


class ScoutSuite(HackingTool):
    TITLE = "ScoutSuite (Multi-Cloud Auditing)"
    DESCRIPTION = "Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba, and Oracle."
    INSTALL_COMMANDS = ["pip install --user scoutsuite"]
    RUN_COMMANDS = ["scout --help"]
    PROJECT_URL = "https://github.com/nccgroup/ScoutSuite"
    SUPPORTED_OS = ["linux", "macos"]


class Pacu(HackingTool):
    TITLE = "Pacu (AWS Exploitation Framework)"
    DESCRIPTION = "AWS exploitation framework for offensive security testing of AWS environments."
    INSTALL_COMMANDS = ["pip install --user pacu"]
    RUN_COMMANDS = ["pacu --help"]
    PROJECT_URL = "https://github.com/RhinoSecurityLabs/pacu"
    SUPPORTED_OS = ["linux", "macos"]


class Trivy(HackingTool):
    TITLE = "Trivy (Container/K8s Scanner)"
    DESCRIPTION = "Comprehensive vulnerability scanner for containers, Kubernetes, IaC, and code."
    INSTALL_COMMANDS = [
        "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin",
    ]
    RUN_COMMANDS = ["trivy --help"]
    PROJECT_URL = "https://github.com/aquasecurity/trivy"
    SUPPORTED_OS = ["linux", "macos"]


class CloudSecurityTools(HackingToolsCollection):
    TITLE = "Cloud Security Tools"
    DESCRIPTION = "Tools for cloud infrastructure security assessment and exploitation."
    TOOLS = [
        Prowler(),
        ScoutSuite(),
        Pacu(),
        Trivy(),
    ]
