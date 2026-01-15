"""BloodHound CE edge generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..objects.ntauthstore import NTAuthStore
    from ..objects.rootca import RootCA


@dataclass
class EdgeDefinition:
    """Edge definition for BloodHound CE."""

    start_node: str  # ObjectIdentifier
    end_node: str  # ObjectIdentifier
    edge_type: str
    edge_props: dict


class EdgeGenerator:
    """Generate BloodHound CE compatible edges."""

    def __init__(self, domain_sid: str):
        self.domain_sid = domain_sid
        self.edges: list[dict] = []

    def add_edge(
        self,
        start_node: str,
        end_node: str,
        edge_type: str,
        edge_props: dict | None = None,
    ) -> None:
        """Add an edge to the collection."""
        self.edges.append({
            "StartNode": start_node,
            "EndNode": end_node,
            "EdgeType": edge_type,
            "EdgeProps": edge_props or {"isacl": False},
        })

    # ==================== Non-Traversable Edges ====================

    def _normalize_guid(self, guid: str | None) -> str:
        """Normalize GUID to uppercase without curly braces."""
        if not guid:
            return ""
        return guid.upper().strip("{}")

    def generate_publishedto_edge(
        self,
        template: "CertTemplate",
        ca: "EnterpriseCA",
    ) -> dict:
        """Generate PublishedTo edge (CertTemplate -> EnterpriseCA)."""
        template_id = self._normalize_guid(template.object_guid)
        ca_id = self._normalize_guid(ca.object_guid)
        return {
            "StartNode": template_id,
            "EndNode": ca_id,
            "EdgeType": "PublishedTo",
            "EdgeProps": {"isacl": False},
        }

    def generate_trustedforntauth_edge(
        self,
        ca: "EnterpriseCA",
        ntauth: "NTAuthStore",
    ) -> dict | None:
        """Generate TrustedForNTAuth edge (EnterpriseCA -> NTAuthStore)."""
        # Check if CA cert is in NTAuth store
        if not ntauth.is_ca_trusted(ca.cert_thumbprint):
            return None

        ca_id = self._normalize_guid(ca.object_guid)
        ntauth_id = self._normalize_guid(ntauth.object_guid)
        return {
            "StartNode": ca_id,
            "EndNode": ntauth_id,
            "EdgeType": "TrustedForNTAuth",
            "EdgeProps": {"isacl": False},
        }

    def generate_ntauthstorefor_edge(
        self,
        ntauth: "NTAuthStore",
    ) -> dict:
        """Generate NTAuthStoreFor edge (NTAuthStore -> Domain)."""
        ntauth_id = self._normalize_guid(ntauth.object_guid)
        return {
            "StartNode": ntauth_id,
            "EndNode": self.domain_sid,
            "EdgeType": "NTAuthStoreFor",
            "EdgeProps": {"isacl": False},
        }

    def generate_hostscaservice_edge(
        self,
        ca: "EnterpriseCA",
    ) -> dict | None:
        """Generate HostsCAService edge (Computer -> EnterpriseCA)."""
        if not ca.hosting_computer_sid:
            return None

        ca_id = self._normalize_guid(ca.object_guid)
        return {
            "StartNode": ca.hosting_computer_sid,
            "EndNode": ca_id,
            "EdgeType": "HostsCAService",
            "EdgeProps": {"isacl": False},
        }

    def generate_enroll_edge(
        self,
        principal_id: str,
        target_id: str,
        is_inherited: bool = False,
    ) -> dict:
        """Generate Enroll edge (Principal -> CertTemplate/EnterpriseCA)."""
        return {
            "StartNode": principal_id,
            "EndNode": target_id,
            "EdgeType": "Enroll",
            "EdgeProps": {
                "isacl": True,
                "isinherited": is_inherited,
            },
        }

    def generate_enrollonbehalfof_edge(
        self,
        agent_template_id: str,
        target_template_id: str,
    ) -> dict:
        """Generate EnrollOnBehalfOf edge (CertTemplate -> CertTemplate)."""
        return {
            "StartNode": agent_template_id,
            "EndNode": target_template_id,
            "EdgeType": "EnrollOnBehalfOf",
            "EdgeProps": {"isacl": False},
        }

    def generate_issuedsignedby_edge(
        self,
        ca: "EnterpriseCA",
        signer_id: str,
    ) -> dict:
        """Generate IssuedSignedBy edge (EnterpriseCA -> EnterpriseCA/RootCA)."""
        ca_id = self._normalize_guid(ca.object_guid)
        signer_id_normalized = self._normalize_guid(signer_id)
        return {
            "StartNode": ca_id,
            "EndNode": signer_id_normalized,
            "EdgeType": "IssuedSignedBy",
            "EdgeProps": {"isacl": False},
        }

    def generate_enterprisecafor_edge(
        self,
        ca: "EnterpriseCA",
        root_ca: "RootCA",
    ) -> dict:
        """Generate EnterpriseCAFor edge (EnterpriseCA -> RootCA)."""
        ca_id = self._normalize_guid(ca.object_guid)
        root_ca_id = self._normalize_guid(root_ca.object_guid)
        return {
            "StartNode": ca_id,
            "EndNode": root_ca_id,
            "EdgeType": "EnterpriseCAFor",
            "EdgeProps": {"isacl": False},
        }

    def generate_rootcafor_edge(
        self,
        root_ca: "RootCA",
    ) -> dict:
        """Generate RootCAFor edge (RootCA -> Domain)."""
        root_ca_id = self._normalize_guid(root_ca.object_guid)
        return {
            "StartNode": root_ca_id,
            "EndNode": self.domain_sid,
            "EdgeType": "RootCAFor",
            "EdgeProps": {"isacl": False},
        }

    def generate_delegatedenrollmentagent_edge(
        self,
        agent_principal_id: str,
        template: "CertTemplate",
    ) -> dict:
        """Generate DelegatedEnrollmentAgent edge (Principal -> CertTemplate)."""
        template_id = self._normalize_guid(template.object_guid)
        return {
            "StartNode": agent_principal_id,
            "EndNode": template_id,
            "EdgeType": "DelegatedEnrollmentAgent",
            "EdgeProps": {"isacl": False},
        }

    # ==================== Traversable Edges (Attack Paths) ====================

    def generate_adcsesc1_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
    ) -> dict:
        """Generate ADCSESC1 edge (Principal -> Domain)."""
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": "ADCSESC1",
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc3_edge(
        self,
        principal_id: str,
        agent_template: "CertTemplate",
        target_template: "CertTemplate",
        ca: "EnterpriseCA",
    ) -> dict:
        """Generate ADCSESC3 edge (Principal -> Domain)."""
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": "ADCSESC3",
            "EdgeProps": {
                "isacl": False,
                "agenttemplate": agent_template.distinguished_name,
                "targettemplate": target_template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc4_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
    ) -> dict:
        """Generate ADCSESC4 edge (Principal -> Domain)."""
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": "ADCSESC4",
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc6_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
        variant: str = "a",
    ) -> dict:
        """Generate ADCSESC6a/ADCSESC6b edge (Principal -> Domain)."""
        edge_type = f"ADCSESC6{variant}"
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": edge_type,
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc9_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
        variant: str = "a",
    ) -> dict:
        """Generate ADCSESC9a/ADCSESC9b edge (Principal -> Domain)."""
        edge_type = f"ADCSESC9{variant}"
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": edge_type,
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc10_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
        variant: str = "a",
    ) -> dict:
        """Generate ADCSESC10a/ADCSESC10b edge (Principal -> Domain)."""
        edge_type = f"ADCSESC10{variant}"
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": edge_type,
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
            },
        }

    def generate_adcsesc13_edge(
        self,
        principal_id: str,
        template: "CertTemplate",
        ca: "EnterpriseCA",
        issuance_policy_oid: str,
        linked_group_dn: str,
    ) -> dict:
        """Generate ADCSESC13 edge (Principal -> Domain)."""
        return {
            "StartNode": principal_id,
            "EndNode": self.domain_sid,
            "EdgeType": "ADCSESC13",
            "EdgeProps": {
                "isacl": False,
                "certtemplate": template.distinguished_name,
                "enterpriseca": ca.distinguished_name,
                "issuancepolicyoid": issuance_policy_oid,
                "linkedgroup": linked_group_dn,
            },
        }

    def generate_goldencert_edge(
        self,
        ca: "EnterpriseCA",
    ) -> dict | None:
        """Generate GoldenCert edge (Computer -> Domain)."""
        if not ca.hosting_computer_sid:
            return None

        return {
            "StartNode": ca.hosting_computer_sid,
            "EndNode": self.domain_sid,
            "EdgeType": "GoldenCert",
            "EdgeProps": {
                "isacl": False,
                "caname": ca.cn,
                "cadistinguishedname": ca.distinguished_name,
            },
        }

    def get_all_edges(self) -> list[dict]:
        """Get all generated edges."""
        return self.edges

    def clear_edges(self) -> None:
        """Clear all edges."""
        self.edges = []
