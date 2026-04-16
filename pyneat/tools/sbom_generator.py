"""SBOM (Software Bill of Materials) generator using CycloneDX.

Generates SBOM documents in CycloneDX JSON/XML format with vulnerability data.

Copyright (c) 2026 PyNEAT Authors
License: AGPL-3.0
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class SBOMComponent:
    """A component in the SBOM."""
    name: str
    version: str
    purl: str
    license: Optional[str] = None
    group: Optional[str] = None
    type: str = "library"
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    properties: Dict[str, str] = field(default_factory=dict)


@dataclass
class SBOMDocument:
    """A complete SBOM document."""
    components: List[SBOMComponent] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    spec_version: str = "1.4"

    def to_cyclonedx_json(self) -> str:
        """Generate CycloneDX 1.4 JSON SBOM."""
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "version": 1,
            "metadata": self._build_metadata(),
            "components": self._build_components(),
        }

        # Add vulnerability info as services (CycloneDX approach)
        vulns = []
        for comp in self.components:
            for vuln in comp.vulnerabilities:
                vulns.append({
                    "id": vuln.get("id", "UNKNOWN"),
                    "source": {"name": "OSV", "url": "https://osv.dev"},
                    "ratings": [{
                        "score": vuln.get("cvss_score", 0) / 10.0,
                        "severity": vuln.get("severity", "unknown").upper(),
                        "method": {"id": "CVSSv31"},
                    }],
                    "description": vuln.get("description", ""),
                    "affected": [{
                        "ranges": [{
                            "type": "Semver",
                            "fixed": vuln.get("fixed_version", "999999.999999.999999"),
                        }],
                        "versions": [comp.version],
                    }],
                    "references": [{
                        "id": vuln.get("id", ""),
                        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}"},
                    }],
                })

        if vulns:
            bom["vulnerabilities"] = vulns

        return json.dumps(bom, indent=2)

    def to_cyclonedx_xml(self) -> str:
        """Generate CycloneDX 1.4 XML SBOM."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<bom xmlns="http://cyclonedx.org/schema/bom/{self.spec_version}">',
            f'  <metadata>',
            f'    <timestamp>{datetime.utcnow().isoformat()}Z</timestamp>',
            f'  </metadata>',
            f'  <components>',
        ]

        for comp in self.components:
            lines.append('    <component type="library">')
            lines.append(f'      <name>{self._escape_xml(comp.name)}</name>')
            lines.append(f'      <version>{self._escape_xml(comp.version)}</version>')
            if comp.purl:
                lines.append(f'      <purl>{self._escape_xml(comp.purl)}</purl>')
            if comp.license:
                lines.append(f'      <licensedata><id>{self._escape_xml(comp.license)}</id></licensedata>')
            lines.append('    </component>')

        lines.extend(['  </components>', '</bom>'])
        return '\n'.join(lines)

    def to_spdx_json(self) -> str:
        """Generate SPDX 2.3 JSON SBOM."""
        packages = []
        for i, comp in enumerate(self.components):
            pkg = {
                "SPDXID": f"SPDXRef-{i + 1}",
                "name": comp.name,
                "versionInfo": comp.version,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }] if comp.purl else [],
            }
            if comp.license:
                pkg["licenseConcluded"] = comp.license
            packages.append(pkg)

        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.metadata.get("name", "unknown"),
            "documentNamespace": self.metadata.get("namespace", "https://example.com/spdx"),
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: PyNEAT SBOM Generator"],
            },
            "packages": packages,
        }

        return json.dumps(doc, indent=2)

    def _build_metadata(self) -> Dict[str, Any]:
        """Build metadata section."""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{
                "vendor": "PyNEAT",
                "name": "pyneat-sbom",
                "version": "3.0.0",
            }],
            "component": {
                "type": "application",
                "name": self.metadata.get("name", "unknown"),
                "version": self.metadata.get("version", "0.0.0"),
            } if self.metadata else None,
        }

    def _build_components(self) -> List[Dict[str, Any]]:
        """Build components section."""
        components = []

        for comp in self.components:
            c = {
                "type": comp.type,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
            }
            if comp.group:
                c["group"] = comp.group
            if comp.license:
                c["license"] = {"id": comp.license}

            # Add vulnerability properties
            if comp.vulnerabilities:
                c["properties"] = [
                    {"name": f"vulnerability:{v.get('id', 'unknown')}", "value": json.dumps(v)}
                    for v in comp.vulnerabilities
                ]

            components.append(c)

        return components

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape special XML characters."""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;"))


class SBOMGenerator:
    """Generate SBOM documents from project dependencies."""

    def __init__(self, project_name: str, project_version: str = "1.0.0"):
        self.project_name = project_name
        self.project_version = project_version
        self._components: Dict[str, SBOMComponent] = {}

    def add_dependency(
        self,
        name: str,
        version: str,
        ecosystem: str = "pypi",
        license: Optional[str] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    ) -> SBOMComponent:
        """Add a dependency to the SBOM.

        Args:
            name: Package name
            version: Package version
            ecosystem: Package ecosystem (pypi, npm, maven, etc.)
            license: Package license
            vulnerabilities: List of vulnerability dicts

        Returns:
            Created SBOMComponent
        """
        purl = f"pkg:{ecosystem}/{name}@{version}"

        component = SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            license=license,
            vulnerabilities=vulnerabilities or [],
        )

        self._components[f"{name}@{version}"] = component
        return component

    def generate(
        self,
        format: str = "cyclonedx-json",
        include_vulnerabilities: bool = True,
    ) -> str:
        """Generate SBOM document.

        Args:
            format: Output format (cyclonedx-json, cyclonedx-xml, spdx-json)
            include_vulnerabilities: Include vulnerability data

        Returns:
            SBOM document as string
        """
        doc = SBOMDocument(
            components=list(self._components.values()),
            metadata={
                "name": self.project_name,
                "version": self.project_version,
                "namespace": f"https://pyneat.dev/sbom/{self.project_name}",
            },
        )

        format_lower = format.lower()
        if format_lower in ("cyclonedx-json", "cyclonedx_json"):
            return doc.to_cyclonedx_json()
        elif format_lower in ("cyclonedx-xml", "cyclonedx_xml"):
            return doc.to_cyclonedx_xml()
        elif format_lower in ("spdx-json", "spdx_json"):
            return doc.to_spdx_json()
        else:
            raise ValueError(f"Unsupported format: {format}")


# Example usage
if __name__ == "__main__":
    # Create SBOM generator
    sbom = SBOMGenerator("my-project", "1.0.0")

    # Add dependencies
    sbom.add_dependency(
        name="requests",
        version="2.28.0",
        ecosystem="pypi",
        license="Apache-2.0",
        vulnerabilities=[{
            "id": "OSV-2023-1001",
            "description": "Security vulnerability in requests",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "fixed_version": "2.31.0",
        }],
    )

    sbom.add_dependency(
        name="flask",
        version="2.0.0",
        ecosystem="pypi",
        license="BSD-3-Clause",
    )

    # Generate SBOM
    print("CycloneDX JSON:")
    print(sbom.generate("cyclonedx-json"))
