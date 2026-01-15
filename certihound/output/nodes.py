"""BloodHound CE node generation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..objects.rootca import RootCA
    from ..objects.ntauthstore import NTAuthStore
    from ..objects.aiaca import AIACA


class NodeGenerator:
    """Generate BloodHound CE compatible nodes."""

    BHCE_VERSION = 6

    def __init__(self, domain: str, domain_sid: str):
        self.domain = domain.upper()
        self.domain_sid = domain_sid

    def generate_certtemplate_node(
        self,
        template: "CertTemplate",
    ) -> dict:
        """Generate CertTemplate node for BloodHound CE."""
        # BloodHound expects just the GUID in uppercase, no domain SID prefix
        object_id = template.object_guid.upper().strip("{}") if template.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{template.cn.upper()}@{self.domain}",
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": template.distinguished_name,
                "displayname": template.display_name or template.cn,
                "certificatenameflag": template.certificate_name_flag,
                "enrollmentflag": template.enrollment_flag,
                "authorizedsignatures": template.ra_signature,
                "ekus": template.ekus,
                "applicationpolicies": template.application_policies,
                "effectiveekus": template.effective_ekus,
                "schemaversion": template.schema_version,
                "requiresmanagerapproval": template.requires_manager_approval,
                "enrolleesuppliessubject": template.enrollee_supplies_subject,
                "subjectaltrequireupn": template.subject_alt_require_upn,
                "subjectaltrequiredns": template.subject_alt_require_dns,
                "subjectaltrequirespn": template.subject_alt_require_spn,
                "subjectaltrequiredomaindns": template.subject_alt_require_domain_dns,
                "subjectaltrequireemail": template.subject_alt_require_email,
                "subjectrequireemail": template.subject_require_email,
                "nosecurityextension": template.no_security_extension,
                "authenticationenabled": template.authentication_enabled,
                "validityperiod": template.validity_period,
                "renewalperiod": template.renewal_period,
                "oid": template.oid,
                "highvalue": template.is_vulnerable,
            },
            "Aces": template.aces,
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
        }

    def generate_enterpriseca_node(
        self,
        ca: "EnterpriseCA",
        templates: list["CertTemplate"] | None = None,
    ) -> dict:
        """Generate EnterpriseCA node for BloodHound CE."""
        # Build EnabledCertTemplates - TypedPrincipal format
        # BloodHound expects just the GUID in uppercase, no domain SID prefix
        enabled_templates = []
        if templates:
            for template in templates:
                if template.cn in ca.certificate_templates:
                    template_id = template.object_guid.upper().strip("{}") if template.object_guid else ""
                    if template_id:
                        enabled_templates.append({
                            "ObjectIdentifier": template_id,
                            "ObjectType": "CertTemplate",
                        })

        # BloodHound expects just the GUID in uppercase
        object_id = ca.object_guid.upper().strip("{}") if ca.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{ca.cn.upper()}@{self.domain}",
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": ca.distinguished_name,
                "dnshostname": ca.dns_hostname,
                "caname": ca.cn,
                "certthumbprint": ca.cert_thumbprint,
                "certchain": [],
                "certname": ca.cert_name,
                "flags": ca.flags,
                "isuserspecifiessanenabled": ca.is_user_specifies_san_enabled,
                "hasbasicconstraints": ca.has_basic_constraints,
                "basicconstraintpathlength": ca.basic_constraint_path_length,
                "highvalue": True,
            },
            "Aces": ca.aces,
            "IsDeleted": False,
            "IsACLProtected": False,
            "EnabledCertTemplates": enabled_templates,
            "HostingComputer": ca.hosting_computer_sid,
            "DomainSID": self.domain_sid,
            "ContainedBy": None,
        }

    def generate_rootca_node(self, ca: "RootCA") -> dict:
        """Generate RootCA node for BloodHound CE."""
        # BloodHound expects just the GUID in uppercase
        object_id = ca.object_guid.upper().strip("{}") if ca.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{ca.cn.upper()}@{self.domain}",
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": ca.distinguished_name,
                "certthumbprint": ca.cert_thumbprint,
                "certname": ca.cert_subject,
                "hasbasicconstraints": ca.has_basic_constraints,
                "highvalue": True,
            },
            "IsDeleted": False,
            "IsACLProtected": False,
            "DomainSID": self.domain_sid,
            "ContainedBy": None,
        }

    def generate_ntauthstore_node(self, store: "NTAuthStore") -> dict:
        """Generate NTAuthStore node for BloodHound CE."""
        # BloodHound expects just the GUID in uppercase
        object_id = store.object_guid.upper().strip("{}") if store.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{store.cn.upper()}@{self.domain}",
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": store.distinguished_name,
                "certthumbprints": store.trusted_thumbprints,
                "certificatecount": store.certificate_count,
                "highvalue": True,
            },
            "IsDeleted": False,
            "IsACLProtected": False,
            "DomainSID": self.domain_sid,
            "ContainedBy": None,
        }

    def generate_aiaca_node(self, ca: "AIACA") -> dict:
        """Generate AIACA node for BloodHound CE."""
        # BloodHound expects just the GUID in uppercase
        object_id = ca.object_guid.upper().strip("{}") if ca.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{ca.cn.upper()}@{self.domain}",
                "domain": self.domain,
                "domainsid": self.domain_sid,
                "distinguishedname": ca.distinguished_name,
                "certthumbprint": ca.cert_thumbprint,
                "certname": ca.cert_subject,
                "highvalue": False,
            },
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None,
        }
