"""
BloodHound CE Exporter - Export ADCS data to BloodHound CE format.

This module provides the export functionality for generating BloodHound CE
compatible JSON output from collected ADCS data.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .output.nodes import NodeGenerator
from .output.edges import EdgeGenerator
from .acl.parser import SecurityDescriptorParser

if TYPE_CHECKING:
    from .collector import ADCSData
    from .objects.certtemplate import CertTemplate
    from .objects.enterpriseca import EnterpriseCA
    from .objects.rootca import RootCA
    from .objects.ntauthstore import NTAuthStore
    from .objects.aiaca import AIACA


@dataclass
class ExportResult:
    """Result of BloodHound CE export."""

    certtemplates: dict[str, Any]
    enterprisecas: dict[str, Any]
    rootcas: dict[str, Any]
    ntauthstores: dict[str, Any]
    aiacas: dict[str, Any]
    meta: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "certtemplates": self.certtemplates,
            "enterprisecas": self.enterprisecas,
            "rootcas": self.rootcas,
            "ntauthstores": self.ntauthstores,
            "aiacas": self.aiacas,
        }

    def to_zip_bytes(self, timestamp: str | None = None) -> bytes:
        """
        Export as ZIP file bytes.

        Args:
            timestamp: Optional timestamp prefix for filenames

        Returns:
            ZIP file as bytes
        """
        ts = timestamp or datetime.now().strftime("%Y%m%d%H%M%S")
        buffer = BytesIO()

        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for obj_type, data in [
                ("certtemplates", self.certtemplates),
                ("enterprisecas", self.enterprisecas),
                ("rootcas", self.rootcas),
                ("ntauthstores", self.ntauthstores),
                ("aiacas", self.aiacas),
            ]:
                if data.get("data"):
                    json_content = json.dumps(data, indent=2, default=str)
                    zf.writestr(f"{ts}_{obj_type}.json", json_content)

        return buffer.getvalue()

    def write_zip(self, path: str | Path, timestamp: str | None = None) -> Path:
        """
        Write export to ZIP file.

        Args:
            path: Output file path
            timestamp: Optional timestamp prefix for filenames

        Returns:
            Path to written file
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            f.write(self.to_zip_bytes(timestamp))

        return path

    def write_json_files(self, directory: str | Path, timestamp: str | None = None) -> list[Path]:
        """
        Write export as separate JSON files.

        Args:
            directory: Output directory
            timestamp: Optional timestamp prefix for filenames

        Returns:
            List of paths to written files
        """
        ts = timestamp or datetime.now().strftime("%Y%m%d%H%M%S")
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        written = []
        for obj_type, data in [
            ("certtemplates", self.certtemplates),
            ("enterprisecas", self.enterprisecas),
            ("rootcas", self.rootcas),
            ("ntauthstores", self.ntauthstores),
            ("aiacas", self.aiacas),
        ]:
            if data.get("data"):
                filepath = directory / f"{ts}_{obj_type}.json"
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2, default=str)
                written.append(filepath)

        return written


class BloodHoundCEExporter:
    """
    Exports ADCS data to BloodHound CE v6 format.

    Example - Basic usage:
        ```python
        from certihound import ADCSCollector, BloodHoundCEExporter

        # Collect data
        collector = ADCSCollector(connection)
        data = collector.collect_all()

        # Export to BloodHound CE format
        exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
        result = exporter.export(data)

        # Write to file
        result.write_zip("output.zip")
        ```

    Example - Get raw dict for integration:
        ```python
        exporter = BloodHoundCEExporter(domain, domain_sid)
        result = exporter.export(data)

        # Get as dictionary for further processing
        output_dict = result.to_dict()
        ```
    """

    BHCE_VERSION = 6

    def __init__(self, domain: str, domain_sid: str):
        """
        Initialize exporter.

        Args:
            domain: Domain FQDN (e.g., "CORP.LOCAL")
            domain_sid: Domain SID (e.g., "S-1-5-21-...")
        """
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self._node_generator = NodeGenerator(domain, domain_sid)
        self._edge_generator = EdgeGenerator(domain_sid)

    def _process_template_acls(self, templates: list["CertTemplate"]) -> None:
        """Process ACLs for templates."""
        for template in templates:
            if template.security_descriptor_raw:
                sd_parser = SecurityDescriptorParser(template.security_descriptor_raw)
                template.aces = sd_parser.get_aces_for_bloodhound()

                # Extract enrollment principals
                rights = sd_parser.get_enrollment_rights()
                template.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def _process_ca_acls(self, cas: list["EnterpriseCA"]) -> None:
        """Process ACLs for CAs."""
        for ca in cas:
            if ca.security_descriptor_raw:
                sd_parser = SecurityDescriptorParser(ca.security_descriptor_raw)
                ca.aces = sd_parser.get_aces_for_bloodhound()

                rights = sd_parser.get_enrollment_rights()
                ca.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def export(
        self,
        data: "ADCSData",
        process_acls: bool = True,
    ) -> ExportResult:
        """
        Export ADCS data to BloodHound CE format.

        Args:
            data: ADCSData container from collector
            process_acls: Whether to process ACLs (default True)

        Returns:
            ExportResult with BloodHound CE formatted data
        """
        # Process ACLs if requested
        if process_acls:
            self._process_template_acls(data.templates)
            self._process_ca_acls(data.enterprise_cas)

        # Generate nodes
        certtemplates = {
            "meta": {
                "methods": 0,
                "type": "certtemplates",
                "count": len(data.templates),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_certtemplate_node(t)
                for t in data.templates
            ],
        }

        enterprisecas = {
            "meta": {
                "methods": 0,
                "type": "enterprisecas",
                "count": len(data.enterprise_cas),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_enterpriseca_node(ca, data.templates)
                for ca in data.enterprise_cas
            ],
        }

        rootcas = {
            "meta": {
                "methods": 0,
                "type": "rootcas",
                "count": len(data.root_cas),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_rootca_node(ca)
                for ca in data.root_cas
            ],
        }

        ntauthstores = {
            "meta": {
                "methods": 0,
                "type": "ntauthstores",
                "count": len(data.ntauth_stores),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_ntauthstore_node(s)
                for s in data.ntauth_stores
            ],
        }

        aiacas = {
            "meta": {
                "methods": 0,
                "type": "aiacas",
                "count": len(data.aia_cas),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_aiaca_node(ca)
                for ca in data.aia_cas
            ],
        }

        return ExportResult(
            certtemplates=certtemplates,
            enterprisecas=enterprisecas,
            rootcas=rootcas,
            ntauthstores=ntauthstores,
            aiacas=aiacas,
            meta={
                "domain": self.domain,
                "domain_sid": self.domain_sid,
                "version": self.BHCE_VERSION,
                "generated": datetime.now().isoformat(),
            },
        )

    def export_templates(self, templates: list["CertTemplate"]) -> dict[str, Any]:
        """
        Export only certificate templates.

        Useful for partial exports or when integrating with existing BloodHound data.

        Args:
            templates: List of CertTemplate objects

        Returns:
            BloodHound CE formatted certtemplates data
        """
        self._process_template_acls(templates)

        return {
            "meta": {
                "methods": 0,
                "type": "certtemplates",
                "count": len(templates),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_certtemplate_node(t)
                for t in templates
            ],
        }

    def export_enterprise_cas(
        self,
        cas: list["EnterpriseCA"],
        templates: list["CertTemplate"] | None = None,
    ) -> dict[str, Any]:
        """
        Export only Enterprise CAs.

        Args:
            cas: List of EnterpriseCA objects
            templates: Optional templates for EnabledCertTemplates

        Returns:
            BloodHound CE formatted enterprisecas data
        """
        self._process_ca_acls(cas)

        return {
            "meta": {
                "methods": 0,
                "type": "enterprisecas",
                "count": len(cas),
                "version": self.BHCE_VERSION,
            },
            "data": [
                self._node_generator.generate_enterpriseca_node(ca, templates)
                for ca in cas
            ],
        }
