"""BloodHound CE output generation orchestrator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .nodes import NodeGenerator
from .edges import EdgeGenerator
from ..acl.parser import SecurityDescriptorParser
from ..detection import (
    detect_esc1,
    detect_esc3_agent,
    detect_esc3_target,
    detect_esc4,
    detect_esc6,
    detect_esc9,
    detect_esc10,
    detect_esc13,
)
from ..detection.esc13 import enumerate_issuance_policies
from ..acl.rights import is_low_privileged_sid

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..objects.rootca import RootCA
    from ..objects.ntauthstore import NTAuthStore
    from ..objects.aiaca import AIACA
    from ..ldap.connection import LDAPConnection


class BloodHoundOutput:
    """Orchestrates BloodHound CE output generation."""

    BHCE_VERSION = 6

    def __init__(
        self,
        domain: str,
        domain_sid: str,
        connection: "LDAPConnection" | None = None,
    ):
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self.connection = connection

        self.node_generator = NodeGenerator(domain, domain_sid)
        self.edge_generator = EdgeGenerator(domain_sid)

        # Collected data
        self.templates: list["CertTemplate"] = []
        self.enterprise_cas: list["EnterpriseCA"] = []
        self.root_cas: list["RootCA"] = []
        self.ntauth_stores: list["NTAuthStore"] = []
        self.aia_cas: list["AIACA"] = []

        # Detection results
        self.vulnerabilities: list[dict] = []
        self.issuance_policies: dict[str, str] = {}

    def add_templates(self, templates: list["CertTemplate"]) -> None:
        """Add certificate templates."""
        self.templates.extend(templates)

    def add_enterprise_cas(self, cas: list["EnterpriseCA"]) -> None:
        """Add Enterprise CAs."""
        self.enterprise_cas.extend(cas)

    def add_root_cas(self, cas: list["RootCA"]) -> None:
        """Add Root CAs."""
        self.root_cas.extend(cas)

    def add_ntauth_stores(self, stores: list["NTAuthStore"]) -> None:
        """Add NTAuth stores."""
        self.ntauth_stores.extend(stores)

    def add_aia_cas(self, cas: list["AIACA"]) -> None:
        """Add AIA CAs."""
        self.aia_cas.extend(cas)

    def process_template_acls(self) -> None:
        """Process ACLs for all templates to extract enrollment rights."""
        for template in self.templates:
            if template.security_descriptor_raw:
                sd_parser = SecurityDescriptorParser(template.security_descriptor_raw)
                template.aces = sd_parser.get_aces_for_bloodhound()

                # Extract enrollment principals
                rights = sd_parser.get_enrollment_rights()
                template.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def process_ca_acls(self) -> None:
        """Process ACLs for all CAs to extract enrollment rights."""
        for ca in self.enterprise_cas:
            if ca.security_descriptor_raw:
                sd_parser = SecurityDescriptorParser(ca.security_descriptor_raw)
                ca.aces = sd_parser.get_aces_for_bloodhound()

                rights = sd_parser.get_enrollment_rights()
                ca.enrollment_principals = [r.sid for r in rights if r.can_enroll]

    def enumerate_issuance_policies(self) -> None:
        """Enumerate issuance policies with group links for ESC13."""
        if self.connection:
            self.issuance_policies = enumerate_issuance_policies(self.connection)

    def detect_vulnerabilities(self) -> None:
        """Run all vulnerability detection."""
        for template in self.templates:
            for ca in self.enterprise_cas:
                # ESC1
                result = detect_esc1(template, ca, self.domain_sid)
                if result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC1")
                    self.vulnerabilities.append({
                        "type": "ESC1",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": result.vulnerable_principals,
                        "reasons": result.reasons,
                    })

                    # Generate edges
                    for principal in result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc1_edge(
                            principal, template, ca
                        )
                        self.edge_generator.edges.append(edge)

                # ESC3 Agent
                agent_result = detect_esc3_agent(template, ca, self.domain_sid)
                if agent_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC3-Agent")
                    self.vulnerabilities.append({
                        "type": "ESC3-Agent",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": agent_result.vulnerable_principals,
                        "reasons": agent_result.reasons,
                    })

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
                        self.vulnerabilities.append({
                            "type": "ESC4",
                            "template": template.cn,
                            "ca": ca.cn,
                            "principals": [p["sid"] for p in esc4_result.vulnerable_principals],
                            "reasons": esc4_result.reasons,
                        })

                        for vuln_principal in esc4_result.vulnerable_principals:
                            edge = self.edge_generator.generate_adcsesc4_edge(
                                vuln_principal["sid"], template, ca
                            )
                            self.edge_generator.edges.append(edge)

                # ESC6
                esc6_results = detect_esc6(template, ca, self.domain_sid)
                for esc6_result in esc6_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC6{esc6_result.variant}")
                    self.vulnerabilities.append({
                        "type": f"ESC6{esc6_result.variant}",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc6_result.vulnerable_principals,
                        "reasons": esc6_result.reasons,
                    })

                # ESC13
                if self.issuance_policies:
                    esc13_result = detect_esc13(
                        template, ca, self.domain_sid, self.issuance_policies
                    )
                    if esc13_result:
                        template.is_vulnerable = True
                        template.vulnerabilities.append("ESC13")
                        self.vulnerabilities.append({
                            "type": "ESC13",
                            "template": template.cn,
                            "ca": ca.cn,
                            "principals": esc13_result.vulnerable_principals,
                            "issuance_policy": esc13_result.issuance_policy_oid,
                            "linked_group": esc13_result.linked_group_dn,
                            "reasons": esc13_result.reasons,
                        })

    def generate_relationship_edges(self) -> None:
        """Generate non-traversable relationship edges."""
        # PublishedTo edges
        for template in self.templates:
            for ca in self.enterprise_cas:
                if template.cn in ca.certificate_templates:
                    edge = self.edge_generator.generate_publishedto_edge(template, ca)
                    self.edge_generator.edges.append(edge)

        # TrustedForNTAuth edges
        for ca in self.enterprise_cas:
            for ntauth in self.ntauth_stores:
                ntauth_edge = self.edge_generator.generate_trustedforntauth_edge(ca, ntauth)
                if ntauth_edge:
                    self.edge_generator.edges.append(ntauth_edge)

        # NTAuthStoreFor edges
        for ntauth in self.ntauth_stores:
            edge = self.edge_generator.generate_ntauthstorefor_edge(ntauth)
            self.edge_generator.edges.append(edge)

        # HostsCAService edges
        for ca in self.enterprise_cas:
            hosts_edge = self.edge_generator.generate_hostscaservice_edge(ca)
            if hosts_edge:
                self.edge_generator.edges.append(hosts_edge)

        # Enroll edges for templates
        for template in self.templates:
            # BloodHound expects just the GUID in uppercase
            template_id = template.object_guid.upper().strip("{}") if template.object_guid else ""
            for principal_sid in template.enrollment_principals:
                edge = self.edge_generator.generate_enroll_edge(principal_sid, template_id)
                self.edge_generator.edges.append(edge)

        # Enroll edges for CAs
        for ca in self.enterprise_cas:
            # BloodHound expects just the GUID in uppercase
            ca_id = ca.object_guid.upper().strip("{}") if ca.object_guid else ""
            for principal_sid in ca.enrollment_principals:
                edge = self.edge_generator.generate_enroll_edge(principal_sid, ca_id)
                self.edge_generator.edges.append(edge)

        # GoldenCert edges
        for ca in self.enterprise_cas:
            golden_edge = self.edge_generator.generate_goldencert_edge(ca)
            if golden_edge:
                self.edge_generator.edges.append(golden_edge)

    def generate_output(self) -> dict[str, Any]:
        """Generate complete BloodHound CE output.

        Note: Call process_template_acls(), process_ca_acls(),
        detect_vulnerabilities(), and generate_relationship_edges()
        before calling this method.
        """
        # Build output structure
        output = {
            "certtemplates": {
                "meta": {
                    "methods": 0,
                    "type": "certtemplates",
                    "count": len(self.templates),
                    "version": self.BHCE_VERSION,
                },
                "data": [
                    self.node_generator.generate_certtemplate_node(t)
                    for t in self.templates
                ],
            },
            "enterprisecas": {
                "meta": {
                    "methods": 0,
                    "type": "enterprisecas",
                    "count": len(self.enterprise_cas),
                    "version": self.BHCE_VERSION,
                },
                "data": [
                    self.node_generator.generate_enterpriseca_node(ca, self.templates)
                    for ca in self.enterprise_cas
                ],
            },
            "rootcas": {
                "meta": {
                    "methods": 0,
                    "type": "rootcas",
                    "count": len(self.root_cas),
                    "version": self.BHCE_VERSION,
                },
                "data": [self.node_generator.generate_rootca_node(ca) for ca in self.root_cas],
            },
            "ntauthstores": {
                "meta": {
                    "methods": 0,
                    "type": "ntauthstores",
                    "count": len(self.ntauth_stores),
                    "version": self.BHCE_VERSION,
                },
                "data": [
                    self.node_generator.generate_ntauthstore_node(s) for s in self.ntauth_stores
                ],
            },
            "aiacas": {
                "meta": {
                    "methods": 0,
                    "type": "aiacas",
                    "count": len(self.aia_cas),
                    "version": self.BHCE_VERSION,
                },
                "data": [self.node_generator.generate_aiaca_node(ca) for ca in self.aia_cas],
            },
            "edges": self.edge_generator.get_all_edges(),
            "vulnerabilities": self.vulnerabilities,
        }

        return output

    def get_summary(self) -> dict:
        """Get summary of collected data and findings."""
        return {
            "domain": self.domain,
            "templates": len(self.templates),
            "enterprise_cas": len(self.enterprise_cas),
            "root_cas": len(self.root_cas),
            "ntauth_stores": len(self.ntauth_stores),
            "aia_cas": len(self.aia_cas),
            "vulnerabilities": len(self.vulnerabilities),
            "edges": len(self.edge_generator.edges),
            "vulnerable_templates": len([t for t in self.templates if t.is_vulnerable]),
        }
