"""BloodHound CE output generation orchestrator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .nodes import NodeGenerator
from .edges import EdgeGenerator
from ..acl.parser import SecurityDescriptorParser
from ..detection import (
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

        # External signals required by ESC14. Default None/empty means
        # "unknown" and detection will decline rather than guess.
        # Populate via set_strong_cert_binding_enforced() and
        # set_alt_security_identities_users() before detect_vulnerabilities().
        self.strong_cert_binding_enforced: bool | None = None
        self.alt_security_identities_users: list[str] = []

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
        # CA-level detections (not per-template)
        for ca in self.enterprise_cas:
            # ESC7 - Dangerous CA Permissions
            if ca.security_descriptor_raw:
                ca_sd_parser = SecurityDescriptorParser(ca.security_descriptor_raw)
                esc7_result = detect_esc7(ca, ca_sd_parser, self.domain_sid)
                if esc7_result:
                    self.vulnerabilities.append({
                        "type": "ESC7",
                        "ca": ca.cn,
                        "principals": [p["sid"] for p in esc7_result.vulnerable_principals],
                        "reasons": esc7_result.reasons,
                    })
                    for vuln_principal in esc7_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc7_edge(
                            vuln_principal["sid"], ca
                        )
                        self.edge_generator.edges.append(edge)

            # ESC8 - NTLM Relay to Web Enrollment
            esc8_result = detect_esc8(ca)
            if esc8_result:
                self.vulnerabilities.append({
                    "type": "ESC8",
                    "ca": ca.cn,
                    "web_enrollment_url": esc8_result.web_enrollment_url,
                    "reasons": esc8_result.reasons,
                })
                edge = self.edge_generator.generate_adcsesc8_edge(
                    ca, esc8_result.web_enrollment_url
                )
                self.edge_generator.edges.append(edge)

            # ESC11 - NTLM Relay to RPC Endpoints
            esc11_result = detect_esc11(ca)
            if esc11_result:
                self.vulnerabilities.append({
                    "type": "ESC11",
                    "ca": ca.cn,
                    "reasons": esc11_result.reasons,
                })
                edge = self.edge_generator.generate_adcsesc11_edge(ca)
                self.edge_generator.edges.append(edge)

        # Template-level detections
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

                # ESC2 - Any Purpose / No EKU
                esc2_result = detect_esc2(template, ca, self.domain_sid)
                if esc2_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC2")
                    self.vulnerabilities.append({
                        "type": "ESC2",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc2_result.vulnerable_principals,
                        "reasons": esc2_result.reasons,
                    })
                    for principal in esc2_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc2_edge(
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

                # ESC9
                esc9_results = detect_esc9(template, ca, self.domain_sid)
                for esc9_result in esc9_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC9{esc9_result.variant}")
                    self.vulnerabilities.append({
                        "type": f"ESC9{esc9_result.variant}",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc9_result.vulnerable_principals,
                        "reasons": esc9_result.reasons,
                    })
                    for principal in esc9_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc9_edge(
                            principal, template, ca, esc9_result.variant
                        )
                        self.edge_generator.edges.append(edge)

                # ESC10
                esc10_results = detect_esc10(template, ca, self.domain_sid)
                for esc10_result in esc10_results:
                    template.is_vulnerable = True
                    template.vulnerabilities.append(f"ESC10{esc10_result.variant}")
                    self.vulnerabilities.append({
                        "type": f"ESC10{esc10_result.variant}",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc10_result.vulnerable_principals,
                        "reasons": esc10_result.reasons,
                    })
                    for principal in esc10_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc10_edge(
                            principal, template, ca, esc10_result.variant
                        )
                        self.edge_generator.edges.append(edge)

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

                # ESC14 - Weak Explicit Certificate Mappings
                esc14_result = detect_esc14(
                    template,
                    ca,
                    self.domain_sid,
                    strong_cert_binding_enforced=self.strong_cert_binding_enforced,
                    alt_security_identities_users=self.alt_security_identities_users,
                )
                if esc14_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC14")
                    self.vulnerabilities.append({
                        "type": "ESC14",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc14_result.vulnerable_principals,
                        "reasons": esc14_result.reasons,
                    })
                    for principal in esc14_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc14_edge(
                            principal, template, ca
                        )
                        self.edge_generator.edges.append(edge)

                # ESC15 - EKUwu (Schema V1 Application Policy abuse)
                if template.security_descriptor_raw:
                    sd_parser = SecurityDescriptorParser(template.security_descriptor_raw)
                    esc15_result = detect_esc15(template, ca, sd_parser, self.domain_sid)
                    if esc15_result:
                        template.is_vulnerable = True
                        template.vulnerabilities.append("ESC15")
                        self.vulnerabilities.append({
                            "type": "ESC15",
                            "template": template.cn,
                            "ca": ca.cn,
                            "principals": [
                                p["sid"] for p in esc15_result.vulnerable_principals
                            ],
                            "reasons": esc15_result.reasons,
                        })
                        for vuln_principal in esc15_result.vulnerable_principals:
                            edge = self.edge_generator.generate_adcsesc15_edge(
                                vuln_principal["sid"], template, ca
                            )
                            self.edge_generator.edges.append(edge)

                # ESC16 - Security Extension Disabled on CA (CA-level edge)
                esc16_result = detect_esc16(template, ca, self.domain_sid)
                if esc16_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC16")
                    self.vulnerabilities.append({
                        "type": "ESC16",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": [],
                        "reasons": esc16_result.reasons,
                    })
                    edge = self.edge_generator.generate_adcsesc16_edge(
                        template, ca
                    )
                    self.edge_generator.edges.append(edge)

                # ESC17 - Server Authentication + Enrollee Supplies Subject (TLS MITM)
                esc17_result = detect_esc17(template, ca, self.domain_sid)
                if esc17_result:
                    template.is_vulnerable = True
                    template.vulnerabilities.append("ESC17")
                    self.vulnerabilities.append({
                        "type": "ESC17",
                        "template": template.cn,
                        "ca": ca.cn,
                        "principals": esc17_result.vulnerable_principals,
                        "reasons": esc17_result.reasons,
                    })
                    for principal in esc17_result.vulnerable_principals:
                        edge = self.edge_generator.generate_adcsesc17_edge(
                            principal, template, ca
                        )
                        self.edge_generator.edges.append(edge)

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
