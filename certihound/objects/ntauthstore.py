"""NTAuth Store object model."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from ..utils.crypto import calculate_thumbprint


class NTAuthStore(BaseModel):
    """NTAuth Certificate Store object model."""

    cn: str = "NTAuthCertificates"
    object_guid: str = ""
    distinguished_name: str = ""
    domain: str = ""
    domain_sid: str = ""

    # Trusted CA certificates (can be multiple)
    ca_certificates_raw: list[bytes] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    @computed_field
    @property
    def trusted_thumbprints(self) -> list[str]:
        """Get thumbprints of all trusted CA certificates."""
        return [calculate_thumbprint(cert) for cert in self.ca_certificates_raw if cert]

    @computed_field
    @property
    def certificate_count(self) -> int:
        """Get number of trusted certificates."""
        return len(self.ca_certificates_raw)

    @classmethod
    def from_ldap_entry(cls, entry: dict, domain: str, domain_sid: str) -> "NTAuthStore":
        """Create NTAuthStore from parsed LDAP entry."""
        return cls(
            cn=entry.get("cn", "NTAuthCertificates"),
            object_guid=str(entry.get("objectGUID", "")),
            distinguished_name=entry.get("distinguishedName", ""),
            domain=domain,
            domain_sid=domain_sid,
            ca_certificates_raw=entry.get("cACertificate", []),
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
                "certthumbprints": self.trusted_thumbprints,
                "certificatecount": self.certificate_count,
                "highvalue": True,
            },
            "IsDeleted": False,
            "IsACLProtected": False,
        }

    def is_ca_trusted(self, ca_thumbprint: str) -> bool:
        """Check if a CA is trusted for NT authentication."""
        return ca_thumbprint.upper() in [t.upper() for t in self.trusted_thumbprints]
