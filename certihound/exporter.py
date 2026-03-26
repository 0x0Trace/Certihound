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
from .detection import (
    detect_esc1,
    detect_esc2,
    detect_esc3_agent,
    detect_esc3_target,
    detect_esc4,
    detect_esc6,
    detect_esc7,
    detect_esc8,
    detect_esc9,
    detect_esc10,
    detect_esc11,
    detect_esc13,
    detect_esc14,
    detect_esc15,
    detect_esc16,
    detect_esc17,
)

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
    edges: list[dict] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format (node types only, BH CE compatible)."""
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

    def _run_detection(self, data: "ADCSData") -> None:
        """Run vulnerability detection and generate attack path edges."""
        import logging
        logger = logging.getLogger(__name__)

        # CA-level detections
        for ca in data.enterprise_cas:
            # ESC7
            if ca.security_descriptor_raw:
                ca_sd_parser = SecurityDescriptorParser(ca.security_descriptor_raw)
                esc7_result = detect_esc7(ca, ca_sd_parser, self.domain_sid)
                if esc7_result:
                    for vuln_principal in esc7_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc7_edge(
                            vuln_principal["sid"], ca
                        )
                        self._edge_generator.edges.append(edge)

            # ESC8
            esc8_result = detect_esc8(ca)
            if esc8_result:
                edge = self._edge_generator.generate_adcsesc8_edge(
                    ca, esc8_result.web_enrollment_url
                )
                self._edge_generator.edges.append(edge)

            # ESC11
            esc11_result = detect_esc11(ca)
            if esc11_result:
                edge = self._edge_generator.generate_adcsesc11_edge(ca)
                self._edge_generator.edges.append(edge)

        # Template-level detections
        for template in data.templates:
            for ca in data.enterprise_cas:
                # ESC1
                result = detect_esc1(template, ca, self.domain_sid)
                if result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC1")
                    for principal in result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc1_edge(
                            principal, template, ca
                        )
                        self._edge_generator.edges.append(edge)

                # ESC2
                esc2_result = detect_esc2(template, ca, self.domain_sid)
                if esc2_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC2")
                    for principal in esc2_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc2_edge(
                            principal, template, ca
                        )
                        self._edge_generator.edges.append(edge)

                # ESC3 Agent
                agent_result = detect_esc3_agent(template, ca, self.domain_sid)
                if agent_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC3-Agent")

                # ESC3 Target
                target_result = detect_esc3_target(template, ca)
                if target_result:
                    template.vulnerabilities.append("ESC3-Target")

                # ESC4
                if template.security_descriptor_raw:
                    sd_parser = SecurityDescriptorParser(template.security_descriptor_raw)
                    esc4_result = detect_esc4(template, ca, sd_parser, self.domain_sid)
                    if esc4_result:
                        template.is_vulnerable = True
                        template.vulnerabilities.append("ESC4")
                        for vuln_principal in esc4_result.vulnerable_principals:
                            edge = self._edge_generator.generate_adcsesc4_edge(
                                vuln_principal["sid"], template, ca
                            )
                            self._edge_generator.edges.append(edge)

                # ESC6
                esc6_results = detect_esc6(template, ca, self.domain_sid)
                for esc6_result in esc6_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC6{esc6_result.variant}")

                # ESC9
                esc9_results = detect_esc9(template, ca, self.domain_sid)
                for esc9_result in esc9_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC9{esc9_result.variant}")
                    for principal in esc9_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc9_edge(
                            principal, template, ca, esc9_result.variant
                        )
                        self._edge_generator.edges.append(edge)

                # ESC10
                esc10_results = detect_esc10(template, ca, self.domain_sid)
                for esc10_result in esc10_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC10{esc10_result.variant}")
                    for principal in esc10_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc10_edge(
                            principal, template, ca, esc10_result.variant
                        )
                        self._edge_generator.edges.append(edge)

                # ESC14
                esc14_result = detect_esc14(template, ca, self.domain_sid)
                if esc14_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC14")
                    for principal in esc14_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc14_edge(
                            principal, template, ca
                        )
                        self._edge_generator.edges.append(edge)

                # ESC15
                if template.security_descriptor_raw:
                    sd_parser = SecurityDescriptorParser(template.security_descriptor_raw)
                    esc15_result = detect_esc15(template, ca, sd_parser, self.domain_sid)
                    if esc15_result:
                        template.is_vulnerable = True
                        template.vulnerabilities.append("ESC15")
                        for vuln_principal in esc15_result.vulnerable_principals:
                            edge = self._edge_generator.generate_adcsesc15_edge(
                                vuln_principal["sid"], template, ca
                            )
                            self._edge_generator.edges.append(edge)

                # ESC16 (CA-level: edge from CA to Domain, not per-principal)
                esc16_result = detect_esc16(template, ca, self.domain_sid)
                if esc16_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC16")
                    edge = self._edge_generator.generate_adcsesc16_edge(
                        template, ca
                    )
                    self._edge_generator.edges.append(edge)

                # ESC17
                esc17_result = detect_esc17(template, ca, self.domain_sid)
                if esc17_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC17")
                    for principal in esc17_result.vulnerable_principals:
                        edge = self._edge_generator.generate_adcsesc17_edge(
                            principal, template, ca
                        )
                        self._edge_generator.edges.append(edge)

        logger.info(
            f"Detection complete: {len(self._edge_generator.edges)} attack path edges, "
            f"{sum(1 for t in data.templates if t.is_vulnerable)} vulnerable templates"
        )

    def _generate_relationship_edges(self, data: "ADCSData") -> None:
        """Generate structural relationship edges."""
        # PublishedTo edges
        for template in data.templates:
            for ca in data.enterprise_cas:
                if template.cn in ca.certificate_templates:
                    edge = self._edge_generator.generate_publishedto_edge(template, ca)
                    self._edge_generator.edges.append(edge)

        # TrustedForNTAuth edges
        for ca in data.enterprise_cas:
            for ntauth in data.ntauth_stores:
                ntauth_edge = self._edge_generator.generate_trustedforntauth_edge(ca, ntauth)
                if ntauth_edge:
                    self._edge_generator.edges.append(ntauth_edge)

        # NTAuthStoreFor edges
        for ntauth in data.ntauth_stores:
            edge = self._edge_generator.generate_ntauthstorefor_edge(ntauth)
            self._edge_generator.edges.append(edge)

        # HostsCAService edges
        for ca in data.enterprise_cas:
            hosts_edge = self._edge_generator.generate_hostscaservice_edge(ca)
            if hosts_edge:
                self._edge_generator.edges.append(hosts_edge)

        # Enroll edges for templates
        for template in data.templates:
            template_id = template.object_guid.upper().strip("{}") if template.object_guid else ""
            for principal_sid in template.enrollment_principals:
                edge = self._edge_generator.generate_enroll_edge(principal_sid, template_id)
                self._edge_generator.edges.append(edge)

        # Enroll edges for CAs
        for ca in data.enterprise_cas:
            ca_id = ca.object_guid.upper().strip("{}") if ca.object_guid else ""
            for principal_sid in ca.enrollment_principals:
                edge = self._edge_generator.generate_enroll_edge(principal_sid, ca_id)
                self._edge_generator.edges.append(edge)

        # GoldenCert edges
        for ca in data.enterprise_cas:
            golden_edge = self._edge_generator.generate_goldencert_edge(ca)
            if golden_edge:
                self._edge_generator.edges.append(golden_edge)

    def export(
        self,
        data: "ADCSData",
        process_acls: bool = True,
        run_detection: bool = True,
    ) -> ExportResult:
        """
        Export ADCS data to BloodHound CE format.

        Args:
            data: ADCSData container from collector
            process_acls: Whether to process ACLs (default True)
            run_detection: Whether to run vulnerability detection (default True)

        Returns:
            ExportResult with BloodHound CE formatted data
        """
        # Process ACLs if requested
        if process_acls:
            self._process_template_acls(data.templates)
            self._process_ca_acls(data.enterprise_cas)

        # Run vulnerability detection and generate edges
        if run_detection:
            self._run_detection(data)

        # Generate structural relationship edges
        self._generate_relationship_edges(data)

        # Generate nodes (AFTER detection so highvalue flags are set)
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
            edges=self._edge_generator.get_all_edges(),
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
