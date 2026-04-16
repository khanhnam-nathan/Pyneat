"""Dependency vulnerability scanner.

Copyright (c) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, contact: khanhnam.copywriting@gmail.com

Scans project dependency files (requirements.txt, package.json, etc.)
for known vulnerabilities using CVE and GitHub Advisory databases.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from pyneat.core.types import DependencyFinding, SecuritySeverity


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

def parse_requirements_txt(content: str) -> List[Tuple[str, str]]:
    """Parse requirements.txt and return list of (package, version) tuples.

    Handles:
    - package==1.2.3
    - package>=1.0,<2.0
    - package@https://...
    - package[extra]>=1.0
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Remove comments
        if "#" in line:
            line = line.split("#")[0].strip()

        # Extract package name and version
        # Patterns: name==version, name>=version, name~=version
        match = re.match(
            r'^([a-zA-Z0-9_\-\.]+)'
            r'(?:\[.*?\])?'
            r'(?:==|>=|<=|~=|!=|>|<)?'
            r'([0-9a-zA-Z_\.\-]+)?',
            line
        )
        if match:
            name = match.group(1).lower().replace("_", "-")
            version = match.group(2) or ""
            packages.append((name, version))

    return packages


def parse_package_json(content: str) -> List[Tuple[str, str, str]]:
    """Parse package.json and return list of (name, version, ecosystem) tuples.

    Returns dependencies and devDependencies.
    """
    import json
    packages = []

    try:
        data = json.loads(content)
    except Exception:
        return []

    for dep_type in ("dependencies", "devDependencies"):
        deps = data.get(dep_type, {})
        for name, version_spec in deps.items():
            # Extract version from spec: "1.2.3", "^1.2.3", "~1.2.3", ">=1.0.0"
            version = re.sub(r"[\^~>=<]+", "", version_spec)
            version = version.strip().strip('"').strip("'")
            if version:
                packages.append((name, version, "npm"))

    return packages


def parse_pipfile(content: str) -> List[Tuple[str, str]]:
    """Parse Pipfile and return list of (package, version) tuples."""
    packages = []
    in_packages = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[packages]":
            in_packages = True
            continue
        if line.startswith("[") and line != "[packages]":
            in_packages = False
        if in_packages and "=" in line and not line.startswith("#"):
            name, version = line.split("=", 1)
            name = name.strip().lower().replace("_", "-")
            version = version.strip().strip('"').strip("'")
            # Remove version operators
            version = re.sub(r"[\^~>=<]+", "", version)
            if version:
                packages.append((name, version))
    return packages


def parse_pyproject_toml(content: str) -> List[Tuple[str, str]]:
    """Parse pyproject.toml [project.dependencies] and return (package, version) tuples."""
    packages = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[project.dependencies]" or line == "[project.optional-dependencies]":
            in_deps = True
            continue
        if line.startswith("[") and not line.startswith("[project"):
            in_deps = False
        if in_deps and "=" in line:
            # Format: package = {version = "1.0"}
            # or: package = ">=1.0"
            match = re.match(r'([a-zA-Z0-9_\-\.]+)\s*=\s*(.+)', line)
            if match:
                name = match.group(1).strip().lower().replace("_", "-")
                version_raw = match.group(2).strip()
                # Extract version from various formats
                version_match = re.search(r'["\']?([0-9][0-9a-zA-Z_\.\-]*)["\']?', version_raw)
                version = version_match.group(1) if version_match else ""
                if version:
                    packages.append((name, version))
    return packages


# --------------------------------------------------------------------------
# Dependency Scanner
# --------------------------------------------------------------------------

class DependencyScanner:
    """Scans dependency files for known vulnerabilities.

    Uses CVE and GitHub Advisory databases to detect vulnerable dependencies.
    """

    def __init__(
        self,
        cve_db=None,
        gh_advisory_db=None,
    ):
        """Initialize scanner with optional database references.

        Args:
            cve_db: CVEDatabase instance (lazy-loaded if not provided)
            gh_advisory_db: GitHubAdvisoryDB instance (lazy-loaded if not provided)
        """
        self._cve_db = cve_db
        self._gh_advisory_db = gh_advisory_db

    @property
    def cve_db(self):
        """Lazy-load CVE database."""
        if self._cve_db is None:
            from pyneat.tools.security.advisory_db import CVEDatabase
            self._cve_db = CVEDatabase()
        return self._cve_db

    @property
    def gh_advisory_db(self):
        """Lazy-load GitHub Advisory database."""
        if self._gh_advisory_db is None:
            from pyneat.tools.security.advisory_db import GitHubAdvisoryDB
            self._gh_advisory_db = GitHubAdvisoryDB()
        return self._gh_advisory_db

    def scan_file(self, file_path: Path) -> List[DependencyFinding]:
        """Scan a dependency file for vulnerabilities.

        Args:
            file_path: Path to requirements.txt, package.json, Pipfile, etc.

        Returns:
            List of DependencyFinding objects for each vulnerability found.
        """
        if not file_path.exists():
            return []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return []

        name = file_path.name.lower()

        if name == "requirements.txt":
            packages = parse_requirements_txt(content)
            return self._scan_packages(packages, "pip", str(file_path))
        elif name == "package.json":
            packages = parse_package_json(content)
            return self._scan_packages_npm(packages, str(file_path))
        elif name == "pipfile":
            packages = parse_pipfile(content)
            return self._scan_packages(packages, "pip", str(file_path))
        elif name == "pyproject.toml":
            packages = parse_pyproject_toml(content)
            return self._scan_packages(packages, "pip", str(file_path))

        return []

    def scan_requirements_content(self, content: str) -> List[DependencyFinding]:
        """Scan requirements.txt content directly."""
        packages = parse_requirements_txt(content)
        return self._scan_packages(packages, "pip", "requirements.txt")

    def _scan_packages(
        self,
        packages: List[Tuple[str, str]],
        ecosystem: str,
        source_file: str,
    ) -> List[DependencyFinding]:
        """Scan Python packages (pip) for vulnerabilities."""
        findings = []
        dep_counter = 100

        for name, version in packages:
            if not version:
                continue

            dep_counter += 1

            # Check CVE database
            cve_record = None
            try:
                cve_record = self.cve_db.check_package(name, version)
            except Exception:
                pass

            # Check GitHub Advisory
            gh_advisories = []
            try:
                gh_advisories = self.gh_advisory_db.check_package(ecosystem, name, version)
            except Exception:
                pass

            if not cve_record and not gh_advisories:
                continue

            # Determine severity
            severity = "high"
            if cve_record:
                if cve_record.severity == "CRITICAL":
                    severity = "critical"
                elif cve_record.severity == "HIGH":
                    severity = "high"
                elif cve_record.severity == "MEDIUM":
                    severity = "medium"
                elif cve_record.severity == "LOW":
                    severity = "low"

            # Build description
            sources = []
            cve_id = None
            ghsa_id = None
            fixed_version = None

            if cve_record:
                sources.append(f"CVE: {cve_record.cve_id}")
                cve_id = cve_record.cve_id
                if cve_record.affected_packages:
                    for pkg in cve_record.affected_packages:
                        if pkg.get("fixed_version"):
                            fixed_version = pkg["fixed_version"]
                            break

            if gh_advisories:
                for adv in gh_advisories:
                    sources.append(f"GHSA: {adv.ghsa_id}")
                    ghsa_id = adv.ghsa_id
                    if adv.patched_version:
                        fixed_version = adv.patched_version

            source_str = ", ".join(sources) if sources else "Unknown"
            description = cve_record.description if cve_record else (gh_advisories[0].description if gh_advisories else "")

            # Truncate description
            if len(description) > 200:
                description = description[:197] + "..."

            recommendation = f"Upgrade {name} to a safe version"
            if fixed_version:
                recommendation = f"Upgrade {name}>={fixed_version}"

            findings.append(DependencyFinding(
                rule_id=f"SEC-DEP-{dep_counter:03d}",
                severity=severity,
                package=name,
                version=version,
                ecosystem=ecosystem,
                cve_id=cve_id,
                ghsa_id=ghsa_id,
                description=description or f"Vulnerable {ecosystem} package: {name}=={version}",
                fixed_version=fixed_version,
                source=source_str,
                recommendation=recommendation,
            ))

        return findings

    def _scan_packages_npm(
        self,
        packages: List[Tuple[str, str, str]],
        source_file: str,
    ) -> List[DependencyFinding]:
        """Scan npm packages for vulnerabilities."""
        findings = []
        dep_counter = 100

        for name, version, ecosystem in packages:
            if not version:
                continue

            dep_counter += 1

            gh_advisories = []
            try:
                gh_advisories = self.gh_advisory_db.check_package(ecosystem, name, version)
            except Exception:
                pass

            if not gh_advisories:
                continue

            # Get most severe advisory
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            gh_advisories.sort(key=lambda a: severity_order.get(a.severity, 5))
            adv = gh_advisories[0]

            sources = [f"GHSA: {adv.ghsa_id}"]
            ghsa_id = adv.ghsa_id
            cve_id = adv.cve_id
            fixed_version = adv.patched_version

            source_str = ", ".join(sources)

            description = adv.description
            if len(description) > 200:
                description = description[:197] + "..."

            recommendation = f"Upgrade {name} to a safe version"
            if fixed_version:
                recommendation = f"Upgrade {name}@{fixed_version}"

            findings.append(DependencyFinding(
                rule_id=f"SEC-DEP-{dep_counter:03d}",
                severity=adv.severity.lower(),
                package=name,
                version=version,
                ecosystem=ecosystem,
                cve_id=cve_id,
                ghsa_id=ghsa_id,
                description=description,
                fixed_version=fixed_version,
                source=source_str,
                recommendation=recommendation,
            ))

        return findings

    def scan_directory(self, dir_path: Path) -> List[DependencyFinding]:
        """Scan all dependency files in a directory."""
        all_findings = []

        dep_files = [
            "requirements.txt",
            "package.json",
            "Pipfile",
            "pyproject.toml",
        ]

        for pattern in dep_files:
            for file_path in dir_path.rglob(pattern):
                findings = self.scan_file(file_path)
                all_findings.extend(findings)

        return all_findings
