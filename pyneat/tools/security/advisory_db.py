"""Security advisory database integration.

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

For commercial licensing, contact: license@pyneat.dev

Provides access to:
- NVD CVE Database (National Vulnerability Database)
- GitHub Security Advisories API

The databases are cached locally to avoid repeated API calls. Use
`pyneat security-db --update` to refresh the cache.
"""

import json
import gzip
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CVERecord:
    """A CVE vulnerability record from NVD."""
    cve_id: str              # CVE-2021-1234
    description: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, NONE
    cvss_score: float        # 0.0 - 10.0
    cvss_vector: str         # Full CVSS vector
    published_date: str
    last_modified_date: str
    references: List[str]
    affected_packages: List[Dict[str, str]]  # [{ecosystem, package, version, fixed_version}]
    cwe_ids: List[str]


@dataclass(frozen=True)
class AdvisoryRecord:
    """A security advisory from GitHub Advisory Database."""
    ghsa_id: str             # GHSA-xxxx-xxxx-xxxx
    cve_id: Optional[str]    # CVE-xxxx-xxxx if published
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    cvss_vector: str
    description: str
    ecosystem: str           # pip, npm, maven, go, nuget, rubygems, composer
    package: str
    vulnerable_version_range: str  # <1.0.0, >=2.0.0,<3.0.0
    patched_version: Optional[str]
    опубликовано_at: str
    html_url: str
    references: List[str]


# --------------------------------------------------------------------------
# Cache management
# --------------------------------------------------------------------------

def _get_cache_dir() -> Path:
    """Get the cache directory for security databases."""
    if sys.platform == "win32":
        cache_base = Path.home() / "AppData" / "Local" / "pyneat"
    else:
        cache_base = Path.home() / ".cache" / "pyneat"
    security_dir = cache_base / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    return security_dir


def _get_cache_meta(cache_file: Path) -> Dict[str, Any]:
    """Get cache metadata."""
    meta_file = cache_file.with_suffix(".meta.json")
    if meta_file.exists():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"version": 1, "created_at": "", "updated_at": "", "count": 0}


def _save_cache_meta(cache_file: Path, meta: Dict[str, Any]) -> None:
    """Save cache metadata."""
    meta_file = cache_file.with_suffix(".meta.json")
    try:
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass


# --------------------------------------------------------------------------
# CVE Database
# --------------------------------------------------------------------------

class CVEDatabase:
    """Client for the NVD CVE Database via the CVE Services API.

    Uses a local JSON cache to minimize API calls. Cache expires after 24 hours.
    """

    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_FILE = "cve_cache.json.gz"
    CACHE_MAX_AGE = timedelta(hours=24)

    def __init__(self, cache_dir: Optional[Path] = None):
        self._cache_dir = cache_dir or _get_cache_dir()
        self._cache_file = self._cache_dir / self.CACHE_FILE
        self._cache: Dict[str, CVERecord] = {}
        self._loaded = False

    def _load_cache(self) -> None:
        """Load CVE data from local cache."""
        if self._loaded:
            return
        self._loaded = True

        if not self._cache_file.exists():
            return

        meta = _get_cache_meta(self._cache_file)
        updated_at = meta.get("updated_at", "")
        if updated_at:
            try:
                updated_dt = datetime.fromisoformat(updated_at)
                if datetime.now() - updated_dt > self.CACHE_MAX_AGE:
                    # Cache expired
                    return
            except Exception:
                return

        try:
            with gzip.open(self._cache_file, "rt", encoding="utf-8") as f:
                data = json.load(f)
            for cve_id, record_data in data.items():
                self._cache[cve_id] = CVERecord(**record_data)
        except Exception:
            pass

    def _save_cache(self) -> None:
        """Save CVE data to local cache."""
        try:
            data = {k: {
                "cve_id": v.cve_id,
                "description": v.description,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "published_date": v.published_date,
                "last_modified_date": v.last_modified_date,
                "references": v.references,
                "affected_packages": v.affected_packages,
                "cwe_ids": v.cwe_ids,
            } for k, v in self._cache.items()}

            with gzip.open(self._cache_file, "wt", encoding="utf-8") as f:
                json.dump(data, f)

            _save_cache_meta(self._cache_file, {
                "version": 1,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "count": len(self._cache),
            })
        except Exception:
            pass

    def check_package(self, package_name: str, version: str) -> Optional[CVERecord]:
        """Check if a package version has known CVEs.

        Returns the most severe CVE affecting this version, or None if no CVE found.
        """
        self._load_cache()

        # Simple keyword search in CVE descriptions
        package_lower = package_name.lower()
        candidates = []

        for cve_id, cve in self._cache.items():
            for pkg in cve.affected_packages:
                pkg_name = pkg.get("package", "").lower()
                if package_lower in pkg_name or pkg_name in package_lower:
                    fixed = pkg.get("fixed_version", "")
                    if fixed:
                        # Check if current version is less than fixed
                        if self._version_compare(version, fixed) < 0:
                            candidates.append(cve)
                    else:
                        candidates.append(cve)

        if not candidates:
            return None

        # Return the most severe
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        candidates.sort(key=lambda c: severity_order.get(c.severity, 5))
        return candidates[0]

    def _version_compare(self, version: str, fixed: str) -> int:
        """Compare versions. Returns -1 if version < fixed, 0 if >=, 1 if >."""
        import re

        def parse_v(s: str) -> List[int]:
            # Remove leading 'v' or '='
            s = re.sub(r"^[v=><!~]", "", s.strip())
            parts = re.split(r"[-._]", s)
            result = []
            for p in parts[:3]:  # major.minor.patch
                try:
                    result.append(int(re.sub(r"\D+", "", p)))
                except ValueError:
                    result.append(0)
            while len(result) < 3:
                result.append(0)
            return result

        v1 = parse_v(version)
        v2 = parse_v(fixed)

        for a, b in zip(v1, v2):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0

    def update(self, force: bool = False) -> int:
        """Update CVE cache from NVD API.

        Downloads CVE data for Python ecosystem (and common web frameworks).
        Returns number of CVEs cached.
        """
        if not force:
            self._load_cache()
            meta = _get_cache_meta(self._cache_file)
            updated_at = meta.get("updated_at", "")
            if updated_at:
                try:
                    updated_dt = datetime.fromisoformat(updated_at)
                    if datetime.now() - updated_dt < self.CACHE_MAX_AGE:
                        return len(self._cache)
                except Exception:
                    pass

        # Use the NVD API for common Python packages
        # In practice, you'd want to paginate through results
        popular_packages = [
            "django", "flask", "requests", "urllib3", "numpy", "pandas",
            "pillow", "cryptography", "pyyaml", "jinja2", "werkzeug",
            "sqlalchemy", "fastapi", "aiohttp", "matplotlib", "scipy",
            "scikit-learn", "torch", "tensorflow", "keras", "opencv-python",
            "pillow", "lxml", "beautifulsoup4", "twisted", "pyjwt",
            "paramiko", "mysql-connector-python", "psycopg2", "pymongo",
            "redis", "celery", "rq", "huey", "pip", "setuptools",
            "twine", "wheel", "pytest", "unittest", "coverage",
            "black", "ruff", "mypy", "pylint", "flake8", "isort",
            "tox", "nox", "pre-commit", "bandit", "safety",
        ]

        new_count = 0
        for pkg in popular_packages:
            try:
                cves = self._fetch_cves_for_package(pkg)
                for cve in cves:
                    if cve.cve_id not in self._cache:
                        self._cache[cve.cve_id] = cve
                        new_count += 1
            except Exception:
                pass

        self._save_cache()
        return new_count

    def _fetch_cves_for_package(self, package: str) -> List[CVERecord]:
        """Fetch CVEs for a specific package from NVD API."""
        import urllib.request
        import urllib.parse
        import urllib.error

        params = urllib.parse.urlencode({
            "keywordSearch": package,
            "resultsPerPage": 50,
        })
        url = f"{self.API_URL}?{params}"

        try:
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "PyNeat-Security/1.0",
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            records = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Get description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Get CVSS
                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                cvss_vector = ""
                severity = "NONE"

                # Try CVSS 3.1 first, then 3.0, then 2.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        m = metrics[version][0]
                        cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                        cvss_vector = m.get("cvssData", {}).get("vectorString", "")
                        severity = m.get("cvssData", {}).get("baseSeverity", "NONE")
                        break

                # Get affected configurations
                configurations = cve.get("configurations", [])
                affected_packages = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable", False):
                                cpe = match.get("criteria", "")
                                # Parse CPE: cpe:2.3:a:vendor:package:version
                                parts = cpe.split(":")
                                if len(parts) >= 5:
                                    pkg_name = parts[4]
                                    pkg_version = match.get("versionEndIncluding", match.get("versionStartExcluding", ""))
                                    fixed_version = match.get("versionStartIncluding", "")
                                    if fixed_version:
                                        pass  # already set
                                    affected_packages.append({
                                        "ecosystem": "pip",
                                        "package": pkg_name,
                                        "version": pkg_version,
                                        "fixed_version": fixed_version,
                                    })

                # Get CWE
                cwe_ids = []
                for problem in cve.get("problemTypes", []):
                    for desc in problem.get("descriptions", []):
                        if desc.get("type") == "CWE":
                            cwe_ids.append(desc.get("value", ""))

                # Get references
                references = [ref.get("url", "") for ref in cve.get("references", [])[:5]]

                # Get dates
                published = cve.get("published", "")
                modified = cve.get("lastModified", "")

                if cve_id:
                    records.append(CVERecord(
                        cve_id=cve_id,
                        description=description,
                        severity=severity.upper(),
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        published_date=published,
                        last_modified_date=modified,
                        references=references,
                        affected_packages=affected_packages,
                        cwe_ids=cwe_ids,
                    ))

            return records

        except Exception:
            return []

    def search(self, keyword: str) -> List[CVERecord]:
        """Search CVE database by keyword."""
        self._load_cache()
        keyword_lower = keyword.lower()
        results = []
        for cve in self._cache.values():
            if keyword_lower in cve.description.lower():
                results.append(cve)
        return results

    def get_status(self) -> Dict[str, Any]:
        """Get database cache status."""
        self._load_cache()
        meta = _get_cache_meta(self._cache_file)
        updated_at = meta.get("updated_at", "never")
        try:
            updated_dt = datetime.fromisoformat(updated_at)
            age = datetime.now() - updated_dt
            age_str = f"{age.days}d {age.seconds // 3600}h ago" if age.days > 0 else f"{age.seconds // 3600}h ago"
        except Exception:
            age_str = "unknown"

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for cve in self._cache.values():
            severity_counts[cve.severity] = severity_counts.get(cve.severity, 0) + 1

        return {
            "database": "NVD CVE",
            "total_records": len(self._cache),
            "last_updated": updated_at,
            "age": age_str,
            "severity_counts": severity_counts,
            "cache_file": str(self._cache_file),
        }


# --------------------------------------------------------------------------
# GitHub Advisory Database
# --------------------------------------------------------------------------

class GitHubAdvisoryDB:
    """Client for the GitHub Security Advisories API.

    Uses the GitHub GraphQL API to query the Security Advisories database.
    """

    API_URL = "https://api.github.com/graphql"
    CACHE_FILE = "gh_advisory_cache.json.gz"
    CACHE_MAX_AGE = timedelta(hours=48)

    # Ecosystems supported by GitHub Advisory DB
    SUPPORTED_ECOSYSTEMS = ["pip", "npm", "maven", "go", "nuget", "rubygems", "composer", "cargo"]

    def __init__(self, cache_dir: Optional[Path] = None, token: Optional[str] = None):
        self._cache_dir = cache_dir or _get_cache_dir()
        self._cache_file = self._cache_dir / self.CACHE_FILE
        self._cache: Dict[str, AdvisoryRecord] = {}
        self._loaded = False
        self._token = token or self._get_token()

    def _get_token(self) -> Optional[str]:
        """Try to get GitHub token from environment."""
        import os
        return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def _load_cache(self) -> None:
        """Load advisory data from local cache."""
        if self._loaded:
            return
        self._loaded = True

        if not self._cache_file.exists():
            return

        meta = _get_cache_meta(self._cache_file)
        updated_at = meta.get("updated_at", "")
        if updated_at:
            try:
                updated_dt = datetime.fromisoformat(updated_at)
                if datetime.now() - updated_dt > self.CACHE_MAX_AGE:
                    return
            except Exception:
                return

        try:
            with gzip.open(self._cache_file, "rt", encoding="utf-8") as f:
                data = json.load(f)
            for ghsa_id, record_data in data.items():
                self._cache[ghsa_id] = AdvisoryRecord(**record_data)
        except Exception:
            pass

    def _save_cache(self) -> None:
        """Save advisory data to local cache."""
        try:
            data = {k: {
                "ghsa_id": v.ghsa_id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "description": v.description,
                "ecosystem": v.ecosystem,
                "package": v.package,
                "vulnerable_version_range": v.vulnerable_version_range,
                "patched_version": v.patched_version,
                " опубликовано_at": v. опубликовано_at,
                "html_url": v.html_url,
                "references": v.references,
            } for k, v in self._cache.items()}

            with gzip.open(self._cache_file, "wt", encoding="utf-8") as f:
                json.dump(data, f)

            _save_cache_meta(self._cache_file, {
                "version": 1,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "count": len(self._cache),
            })
        except Exception:
            pass

    def check_package(self, ecosystem: str, package: str, version: str) -> List[AdvisoryRecord]:
        """Check if a package version has known advisories."""
        self._load_cache()

        results = []
        ecosystem_lower = ecosystem.lower()
        package_lower = package.lower()

        for advisory in self._cache.values():
            if advisory.ecosystem.lower() != ecosystem_lower:
                continue
            if advisory.package.lower() != package_lower:
                continue

            # Check if version is in vulnerable range
            if self._version_in_range(version, advisory.vulnerable_version_range):
                results.append(advisory)

        return results

    def _version_in_range(self, version: str, range_str: str) -> bool:
        """Check if a version falls within a vulnerable range."""
        import re

        def parse_v(s: str) -> List[int]:
            s = re.sub(r"^[v=><!~]", "", s.strip())
            parts = re.split(r"[-._]", s)
            result = []
            for p in parts[:3]:
                try:
                    result.append(int(re.sub(r"\D+", "", p)))
                except ValueError:
                    result.append(0)
            while len(result) < 3:
                result.append(0)
            return result

        def compare(v1_str: str, v2_str: str, op: str) -> bool:
            v1 = parse_v(v1_str)
            v2 = parse_v(v2_str)
            for a, b in zip(v1, v2):
                if op in ("<", "<=") and a > b:
                    return False
                if op in (">", ">=") and a < b:
                    return False
            return True

        version = re.sub(r"^[v=]", "", version.strip())
        range_str = range_str.strip()

        # Parse range operators: <, <=, >, >=, =
        ops = re.findall(r"[<>]=?", range_str)
        versions = re.split(r"[<>]=?", range_str)
        versions = [v.strip() for v in versions if v.strip()]

        if not ops or not versions:
            return True

        # Simple case: single version comparison
        if len(ops) == 1 and len(versions) == 1:
            return compare(version, versions[0], ops[0])

        # Multiple conditions (AND)
        for op, ver in zip(ops, versions):
            if not compare(version, ver, op):
                return False
        return True

    def update(self, force: bool = False, ecosystems: Optional[List[str]] = None) -> int:
        """Update GitHub Advisory cache.

        Uses the GitHub REST API (free, no token required for public advisories).
        Returns number of advisories cached.
        """
        if not force:
            self._load_cache()
            meta = _get_cache_meta(self._cache_file)
            updated_at = meta.get("updated_at", "")
            if updated_at:
                try:
                    updated_dt = datetime.fromisoformat(updated_at)
                    if datetime.now() - updated_dt < self.CACHE_MAX_AGE:
                        return len(self._cache)
                except Exception:
                    pass

        ecos = ecosystems or ["pip", "npm", "maven", "go"]
        new_count = 0

        for ecosystem in ecos:
            try:
                advisories = self._fetch_advisories_for_ecosystem(ecosystem)
                for adv in advisories:
                    if adv.ghsa_id not in self._cache:
                        self._cache[adv.ghsa_id] = adv
                        new_count += 1
            except Exception:
                pass

        self._save_cache()
        return new_count

    def _fetch_advisories_for_ecosystem(self, ecosystem: str) -> List[AdvisoryRecord]:
        """Fetch advisories for a specific ecosystem from GitHub REST API."""
        import urllib.request
        import urllib.parse

        per_page = 100
        page = 1
        all_advisories = []

        while page <= 5:  # Limit to 500 results per ecosystem
            params = urllib.parse.urlencode({
                "ecosystem": ecosystem,
                "per_page": per_page,
                "page": page,
            })
            url = f"https://api.github.com/advisories?{params}"

            try:
                headers = {
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "PyNeat-Security/1.0",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if self._token:
                    headers["Authorization"] = f"Bearer {self._token}"

                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                if not data:
                    break

                for item in data:
                    ghsa_id = item.get("ghsa_id", "")
                    cve_id = item.get("cve_id")
                    severity = item.get("severity", "MEDIUM").upper()
                    cvss_score = item.get("cvss_score", 5.0)
                    cvss_vector = item.get("cvss_vector", "")
                    description = item.get("description", "")
                    published_at = item.get("published_at", "")
                    html_url = item.get("html_url", "")
                    references = item.get("references", [])

                    for vuln in item.get("vulnerabilities", []):
                        pkg = vuln.get("package", {})
                        package_name = pkg.get("name", "")
                        ecosystem_name = pkg.get("ecosystem", ecosystem)
                        vuln_range = ""
                        patched = None

                        for range_info in vuln.get("ranges", []):
                            for r in range_info.get("events", []):
                                if "introduced" in r:
                                    vuln_range = f">={r['introduced']}"
                                if "fixed" in r:
                                    vuln_range += f", <{r['fixed']}"
                                    patched = r["fixed"]

                        if package_name:
                            all_advisories.append(AdvisoryRecord(
                                ghsa_id=ghsa_id,
                                cve_id=cve_id,
                                severity=severity,
                                cvss_score=cvss_score,
                                cvss_vector=cvss_vector,
                                description=description,
                                ecosystem=ecosystem_name,
                                package=package_name,
                                vulnerable_version_range=vuln_range,
                                patched_version=patched,
                                опубликовано_at=published_at,
                                html_url=html_url,
                                references=references,
                            ))

                page += 1

            except Exception:
                break

        return all_advisories

    def get_advisory(self, ghsa_id: str) -> Optional[AdvisoryRecord]:
        """Get a specific advisory by GHSA ID."""
        self._load_cache()
        return self._cache.get(ghsa_id)

    def get_status(self) -> Dict[str, Any]:
        """Get database cache status."""
        self._load_cache()
        meta = _get_cache_meta(self._cache_file)
        updated_at = meta.get("updated_at", "never")
        try:
            updated_dt = datetime.fromisoformat(updated_at)
            age = datetime.now() - updated_dt
            age_str = f"{age.days}d {age.seconds // 3600}h ago" if age.days > 0 else f"{age.seconds // 3600}h ago"
        except Exception:
            age_str = "unknown"

        ecosystem_counts: Dict[str, int] = {}
        for adv in self._cache.values():
            ecosystem_counts[adv.ecosystem] = ecosystem_counts.get(adv.ecosystem, 0) + 1

        return {
            "database": "GitHub Security Advisories",
            "total_records": len(self._cache),
            "last_updated": updated_at,
            "age": age_str,
            "ecosystem_counts": ecosystem_counts,
            "cache_file": str(self._cache_file),
        }
