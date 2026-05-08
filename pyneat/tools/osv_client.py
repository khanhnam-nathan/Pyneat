"""OSV.dev API client for vulnerability database queries.

Provides programmatic access to the OSV.dev vulnerability database for Python packages.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0
"""

import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import time


@dataclass
class OsvVulnerability:
    """A vulnerability entry from OSV database."""
    id: str
    summary: str
    details: str
    severity: str
    published: str
    modified: str
    fixed_version: Optional[str]
    affected_packages: List[Dict[str, Any]] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    credits: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "details": self.details,
            "severity": self.severity,
            "published": self.published,
            "modified": self.modified,
            "fixed_version": self.fixed_version,
            "affected_packages": self.affected_packages,
            "references": self.references,
            "credits": self.credits,
        }


class OsvClient:
    """Client for OSV.dev API.

    API documentation: https://osv.dev/docs/

    Example:
        client = OsvClient()
        vulns = client.query_package("requests", "2.28.0")
        for vuln in vulns:
            print(f"{vuln.id}: {vuln.summary}")
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 30, rate_limit_delay: float = 0.1):
        """Initialize OSV client.

        Args:
            timeout: Request timeout in seconds
            rate_limit_delay: Delay between requests to avoid rate limiting
        """
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

    def _rate_limit(self):
        """Apply rate limiting between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def query_package(
        self,
        package: str,
        version: str,
        ecosystem: str = "PyPI"
    ) -> List[OsvVulnerability]:
        """Query OSV for vulnerabilities affecting a specific package version.

        Args:
            package: Package name (e.g., "requests")
            version: Package version (e.g., "2.28.0")
            ecosystem: Package ecosystem (default: "PyPI")

        Returns:
            List of vulnerabilities affecting this package version
        """
        self._rate_limit()

        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json={
                    "package": {"name": package, "ecosystem": ecosystem},
                    "version": version
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            return self._parse_response(response.json())
        except requests.RequestException as e:
            print(f"OSV query failed for {package}@{version}: {e}")
            return []

    def query_package_name(self, package: str, ecosystem: str = "PyPI") -> List[OsvVulnerability]:
        """Query OSV for all vulnerabilities affecting a package (any version).

        Args:
            package: Package name
            ecosystem: Package ecosystem

        Returns:
            List of all vulnerabilities for this package
        """
        self._rate_limit()

        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json={
                    "package": {"name": package, "ecosystem": ecosystem},
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            return self._parse_response(response.json())
        except requests.RequestException as e:
            print(f"OSV query failed for {package}: {e}")
            return []

    def query_batch(
        self,
        packages: List[tuple],
        ecosystem: str = "PyPI"
    ) -> Dict[str, List[OsvVulnerability]]:
        """Batch query for multiple packages.

        Args:
            packages: List of (package_name, version) tuples
            ecosystem: Package ecosystem

        Returns:
            Dict mapping package names to their vulnerabilities
        """
        queries = [
            {"package": {"name": pkg, "ecosystem": ecosystem}, "version": ver}
            for pkg, ver in packages
        ]

        self._rate_limit()

        try:
            response = requests.post(
                f"{self.BASE_URL}/querybatch",
                json={"queries": queries},
                timeout=self.timeout * len(packages)
            )
            response.raise_for_status()

            results = {}
            for i, (pkg, _) in enumerate(packages):
                vulns = []
                if i < len(response.json().get("results", [])):
                    vulns = self._parse_response(response.json()["results"][i])
                results[pkg] = vulns

            return results
        except requests.RequestException as e:
            print(f"OSV batch query failed: {e}")
            return {pkg: [] for pkg, _ in packages}

    def _parse_response(self, data: Dict[str, Any]) -> List[OsvVulnerability]:
        """Parse OSV API response into vulnerability objects."""
        vulns = []

        for vuln_data in data.get("vulns", []):
            vuln = OsvVulnerability(
                id=vuln_data.get("id", ""),
                summary=vuln_data.get("summary", ""),
                details=vuln_data.get("details", ""),
                severity=self._calculate_severity(vuln_data),
                published=vuln_data.get("published", ""),
                modified=vuln_data.get("modified", ""),
                fixed_version=self._extract_fixed_version(vuln_data),
                affected_packages=vuln_data.get("affected", []),
                references=vuln_data.get("references", []),
                credits=[c.get("name", "") for c in vuln_data.get("credits", [])],
            )
            vulns.append(vuln)

        return vulns

    def _extract_fixed_version(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract the first fixed version from vulnerability data."""
        for affected in vuln_data.get("affected", []):
            for ranges in affected.get("ranges", []):
                for event in ranges.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    def _calculate_severity(self, vuln_data: Dict[str, Any]) -> str:
        """Calculate severity from CVSS or database_specific."""
        severity = "unknown"

        # Try database_specific first
        db_specific = vuln_data.get("database_specific", {})
        if "severity" in db_specific:
            if isinstance(db_specific["severity"], list):
                for seg in db_specific["severity"]:
                    if seg.get("type") == "CVSS_V3":
                        severity = seg.get("score", "unknown")
                        break
            elif isinstance(db_specific["severity"], str):
                severity = db_specific["severity"]

        # Try CVSS in severity field
        if severity == "unknown":
            for affected in vuln_data.get("affected", []):
                severity_info = affected.get("database_specific", {}).get("severity", [])
                for seg in severity_info:
                    if seg.get("type") == "CVSS_V3":
                        severity = seg.get("score", "unknown")
                        break

        return severity

    def get_vulnerability(self, vuln_id: str) -> Optional[OsvVulnerability]:
        """Get details for a specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (e.g., "OSV-2021-1001")

        Returns:
            Vulnerability details or None if not found
        """
        self._rate_limit()

        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json={"id": vuln_id},
                timeout=self.timeout
            )
            response.raise_for_status()
            vulns = self._parse_response(response.json())
            return vulns[0] if vulns else None
        except requests.RequestException as e:
            print(f"OSV query failed for {vuln_id}: {e}")
            return None


# Example usage
if __name__ == "__main__":
    client = OsvClient()

    # Test with requests package
    print("Querying OSV for requests@2.28.0...")
    vulns = client.query_package("requests", "2.28.0")

    print(f"Found {len(vulns)} vulnerabilities:")
    for vuln in vulns:
        print(f"  - {vuln.id}: {vuln.summary}")
        if vuln.fixed_version:
            print(f"    Fixed in: {vuln.fixed_version}")
