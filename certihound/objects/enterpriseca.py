"""Enterprise CA object model."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from ..utils.crypto import (
    calculate_thumbprint,
    get_certificate_subject,
    has_basic_constraints,
)


class EnterpriseCA(BaseModel):
    """Enterprise CA (pKIEnrollmentService) object model."""

    cn: str
    name: str
    display_name: str = ""
    object_guid: str = ""
    distinguished_name: str = ""
    domain: str = ""
    domain_sid: str = ""

    # CA-specific attributes
    dns_hostname: str = ""
    certificate_templates: list[str] = Field(default_factory=list)
    ca_certificate_raw: bytes = b""
    ca_certificate_dn: str = ""
    flags: int = 0

    # Security descriptor
    security_descriptor_raw: bytes = b""

    # Registry flags (collected separately if available)
    is_user_specifies_san_enabled: bool = False  # EDITF_ATTRIBUTESUBJECTALTNAME2

    # ACL data
    aces: list[dict] = Field(default_factory=list)
    enrollment_principals: list[str] = Field(default_factory=list)

    # Hosting computer SID
    hosting_computer_sid: str = ""

    model_config = {"arbitrary_types_allowed": True}

    @computed_field
    @property
    def cert_thumbprint(self) -> str:
        """Calculate CA certificate thumbprint."""
        return calculate_thumbprint(self.ca_certificate_raw)

    @computed_field
    @property
    def cert_name(self) -> str:
        """Get CA certificate subject."""
        return get_certificate_subject(self.ca_certificate_raw)

    @computed_field
    @property
    def has_basic_constraints(self) -> bool:
        """Check if CA cert has basic constraints."""
        has_bc, _ = has_basic_constraints(self.ca_certificate_raw)
        return has_bc

    @computed_field
    @property
    def basic_constraint_path_length(self) -> int | None:
        """Get basic constraints path length."""
        _, path_len = has_basic_constraints(self.ca_certificate_raw)
        return path_len

    @classmethod
    def from_ldap_entry(cls, entry: dict, domain: str, domain_sid: str) -> "EnterpriseCA":
        """Create EnterpriseCA from parsed LDAP entry."""
        return cls(
            cn=entry.get("cn", ""),
            name=entry.get("name", entry.get("cn", "")),
            display_name=entry.get("displayName", entry.get("cn", "")),
            object_guid=str(entry.get("objectGUID", "")),
            distinguished_name=entry.get("distinguishedName", ""),
            domain=domain,
            domain_sid=domain_sid,
            dns_hostname=entry.get("dNSHostName", ""),
            certificate_templates=entry.get("certificateTemplates", []),
            ca_certificate_raw=entry.get("cACertificate", b""),
            ca_certificate_dn=entry.get("cACertificateDN", ""),
            flags=entry.get("flags", 0),
            security_descriptor_raw=entry.get("nTSecurityDescriptor", b""),
        )

    def to_bloodhound_node(self) -> dict:
        """Convert to BloodHound CE node format."""
        return {
            "ObjectIdentifier": self.object_guid,
            "Properties": {
                "name": f"{self.cn.upper()}@{self.domain.upper()}",
                "domain": self.domain.upper(),
                "domainsid": self.domain_sid,
                "distinguishedname": self.distinguished_name,
                "dnshostname": self.dns_hostname,
                "caname": self.cn,
                "certthumbprint": self.cert_thumbprint,
                "certchain": [],
                "certname": self.cert_name,
                "flags": self.flags,
                "isuserspecifiessanenabled": self.is_user_specifies_san_enabled,
                "hasbasicconstraints": self.has_basic_constraints,
                "basicconstraintpathlength": self.basic_constraint_path_length,
                "highvalue": True,
            },
            "Aces": self.aces,
            "IsDeleted": False,
            "IsACLProtected": False,
            "HostingComputer": self.hosting_computer_sid,
        }

    def publishes_template(self, template_name: str) -> bool:
        """Check if CA publishes a specific template."""
        return template_name in self.certificate_templates
