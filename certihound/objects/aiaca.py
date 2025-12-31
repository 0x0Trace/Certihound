"""AIA CA object model."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from ..utils.crypto import (
    calculate_thumbprint,
    get_certificate_subject,
    get_certificate_issuer,
)


class AIACA(BaseModel):
    """AIA (Authority Information Access) CA object model."""

    cn: str
    name: str
    object_guid: str = ""
    distinguished_name: str = ""
    domain: str = ""
    domain_sid: str = ""

    # Certificate data
    ca_certificate_raw: bytes = b""

    model_config = {"arbitrary_types_allowed": True}

    @computed_field
    @property
    def cert_thumbprint(self) -> str:
        """Calculate CA certificate thumbprint."""
        return calculate_thumbprint(self.ca_certificate_raw)

    @computed_field
    @property
    def cert_subject(self) -> str:
        """Get CA certificate subject."""
        return get_certificate_subject(self.ca_certificate_raw)

    @computed_field
    @property
    def cert_issuer(self) -> str:
        """Get CA certificate issuer."""
        return get_certificate_issuer(self.ca_certificate_raw)

    @classmethod
    def from_ldap_entry(cls, entry: dict, domain: str, domain_sid: str) -> "AIACA":
        """Create AIACA from parsed LDAP entry."""
        return cls(
            cn=entry.get("cn", ""),
            name=entry.get("name", entry.get("cn", "")),
            object_guid=str(entry.get("objectGUID", "")),
            distinguished_name=entry.get("distinguishedName", ""),
            domain=domain,
            domain_sid=domain_sid,
            ca_certificate_raw=entry.get("cACertificate", b""),
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
                "certthumbprint": self.cert_thumbprint,
                "certname": self.cert_subject,
                "highvalue": False,
            },
            "IsDeleted": False,
            "IsACLProtected": False,
        }
