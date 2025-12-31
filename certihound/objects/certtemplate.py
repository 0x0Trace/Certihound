"""Certificate Template object model."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field
from typing import Any

from ..utils.crypto import OID
from ..utils.time import parse_validity_period


class CertificateNameFlags:
    """Certificate name flag constants."""

    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    ADD_EMAIL = 0x00000002
    ADD_OBJ_GUID = 0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    ADD_DIRECTORY_PATH = 0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000


class EnrollmentFlags:
    """Enrollment flag constants."""

    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002  # Manager approval required
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    SKIP_AUTO_RENEWAL = 0x00040000
    NO_SECURITY_EXTENSION = 0x00080000  # CT_FLAG_NO_SECURITY_EXTENSION - ESC9


class CertTemplate(BaseModel):
    """Certificate Template object model."""

    cn: str
    name: str
    display_name: str = ""
    object_guid: str = ""
    distinguished_name: str = ""
    domain: str = ""
    domain_sid: str = ""

    # Security descriptor (raw bytes stored as base64 or handled separately)
    security_descriptor_raw: bytes = b""

    # PKI flags
    certificate_name_flag: int = 0
    enrollment_flag: int = 0
    ra_signature: int = 0
    private_key_flag: int = 0
    minimal_key_size: int = 0

    # EKUs and policies
    ekus: list[str] = Field(default_factory=list)
    application_policies: list[str] = Field(default_factory=list)
    ra_application_policies: list[str] = Field(default_factory=list)

    # Validity periods
    expiration_period_raw: bytes = b""
    overlap_period_raw: bytes = b""

    # Schema version
    schema_version: int = 1
    minor_revision: int = 0
    flags: int = 0
    revision: int = 0
    oid: str = ""  # msPKI-Cert-Template-OID

    # ACL data
    aces: list[dict] = Field(default_factory=list)
    enrollment_principals: list[str] = Field(default_factory=list)

    # Vulnerability flags
    is_vulnerable: bool = False
    vulnerabilities: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    @computed_field
    @property
    def enrollee_supplies_subject(self) -> bool:
        """Check if enrollee can supply subject."""
        return bool(self.certificate_name_flag & CertificateNameFlags.ENROLLEE_SUPPLIES_SUBJECT)

    @computed_field
    @property
    def requires_manager_approval(self) -> bool:
        """Check if manager approval is required."""
        return bool(self.enrollment_flag & EnrollmentFlags.PEND_ALL_REQUESTS)

    @computed_field
    @property
    def subject_alt_require_upn(self) -> bool:
        """Check if UPN is required in SAN."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_ALT_REQUIRE_UPN)

    @computed_field
    @property
    def subject_alt_require_dns(self) -> bool:
        """Check if DNS is required in SAN."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_ALT_REQUIRE_DNS)

    @computed_field
    @property
    def subject_alt_require_email(self) -> bool:
        """Check if email is required in SAN."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_ALT_REQUIRE_EMAIL)

    @computed_field
    @property
    def subject_require_email(self) -> bool:
        """Check if email is required in subject."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_REQUIRE_EMAIL)

    @computed_field
    @property
    def subject_alt_require_spn(self) -> bool:
        """Check if SPN is required in SAN."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_ALT_REQUIRE_SPN)

    @computed_field
    @property
    def subject_alt_require_domain_dns(self) -> bool:
        """Check if domain DNS is required in SAN."""
        return bool(self.certificate_name_flag & CertificateNameFlags.SUBJECT_ALT_REQUIRE_DOMAIN_DNS)

    @computed_field
    @property
    def no_security_extension(self) -> bool:
        """Check if NO_SECURITY_EXTENSION flag is set (ESC9)."""
        return bool(self.enrollment_flag & EnrollmentFlags.NO_SECURITY_EXTENSION)

    @computed_field
    @property
    def has_authentication_eku(self) -> bool:
        """Check if template has authentication EKU."""
        if not self.ekus:
            return True  # No EKUs = any purpose

        auth_ekus = {
            OID.CLIENT_AUTHENTICATION,
            OID.SMART_CARD_LOGON,
            OID.PKINIT_CLIENT_AUTHENTICATION,
            OID.ANY_PURPOSE,
        }
        return bool(auth_ekus.intersection(set(self.ekus)))

    @computed_field
    @property
    def has_enrollment_agent_eku(self) -> bool:
        """Check if template has enrollment agent EKU."""
        return OID.CERTIFICATE_REQUEST_AGENT in self.ekus

    @computed_field
    @property
    def no_signature_required(self) -> bool:
        """Check if no authorized signature is required."""
        return self.ra_signature <= 0

    @computed_field
    @property
    def authentication_enabled(self) -> bool:
        """Check if template enables Kerberos authentication (BHCE property)."""
        return self.has_authentication_eku

    @computed_field
    @property
    def effective_ekus(self) -> list[str]:
        """Get effective EKUs (combination of ekus and application policies)."""
        # BloodHound uses this for combined EKU checking
        combined = set(self.ekus) | set(self.application_policies)
        return list(combined)

    @computed_field
    @property
    def validity_period(self) -> str:
        """Get human-readable validity period."""
        return parse_validity_period(self.expiration_period_raw)

    @computed_field
    @property
    def renewal_period(self) -> str:
        """Get human-readable renewal period."""
        return parse_validity_period(self.overlap_period_raw)

    @classmethod
    def from_ldap_entry(cls, entry: dict, domain: str, domain_sid: str) -> "CertTemplate":
        """Create CertTemplate from parsed LDAP entry."""
        return cls(
            cn=entry.get("cn", ""),
            name=entry.get("name", entry.get("cn", "")),
            display_name=entry.get("displayName", entry.get("cn", "")),
            object_guid=str(entry.get("objectGUID", "")),
            distinguished_name=entry.get("distinguishedName", ""),
            domain=domain,
            domain_sid=domain_sid,
            security_descriptor_raw=entry.get("nTSecurityDescriptor", b""),
            certificate_name_flag=entry.get("msPKI-Certificate-Name-Flag", 0),
            enrollment_flag=entry.get("msPKI-Enrollment-Flag", 0),
            ra_signature=entry.get("msPKI-RA-Signature", 0),
            private_key_flag=entry.get("msPKI-Private-Key-Flag", 0),
            minimal_key_size=entry.get("msPKI-Minimal-Key-Size", 0),
            ekus=entry.get("pKIExtendedKeyUsage", []),
            application_policies=entry.get("msPKI-Certificate-Application-Policy", []),
            ra_application_policies=entry.get("msPKI-RA-Application-Policies", []),
            expiration_period_raw=entry.get("pKIExpirationPeriod", b""),
            overlap_period_raw=entry.get("pKIOverlapPeriod", b""),
            schema_version=entry.get("msPKI-Template-Schema-Version", 1),
            minor_revision=entry.get("msPKI-Template-Minor-Revision", 0),
            flags=entry.get("flags", 0),
            revision=entry.get("revision", 0),
            oid=entry.get("msPKI-Cert-Template-OID", ""),
        )

    def to_bloodhound_node(self) -> dict:
        """Convert to BloodHound CE node format."""
        object_id = f"{self.domain_sid}-{self.object_guid}" if self.object_guid else ""

        return {
            "ObjectIdentifier": object_id,
            "Properties": {
                "name": f"{self.cn.upper()}@{self.domain.upper()}",
                "domain": self.domain.upper(),
                "domainsid": self.domain_sid,
                "distinguishedname": self.distinguished_name,
                "displayname": self.display_name,
                "certificatenameflag": self.certificate_name_flag,
                "enrollmentflag": self.enrollment_flag,
                "authorizedsignatures": self.ra_signature,
                "ekus": self.ekus,
                "applicationpolicies": self.application_policies,
                "effectiveekus": self.effective_ekus,
                "schemaversion": self.schema_version,
                "requiresmanagerapproval": self.requires_manager_approval,
                "enrolleesuppliessubject": self.enrollee_supplies_subject,
                "subjectaltrequireupn": self.subject_alt_require_upn,
                "subjectaltrequiredns": self.subject_alt_require_dns,
                "subjectaltrequirespn": self.subject_alt_require_spn,
                "subjectaltrequiredomaindns": self.subject_alt_require_domain_dns,
                "subjectrequireemail": self.subject_require_email,
                "nosecurityextension": self.no_security_extension,
                "authenticationenabled": self.authentication_enabled,
                "validityperiod": self.validity_period,
                "renewalperiod": self.renewal_period,
                "highvalue": self.is_vulnerable,
            },
            "Aces": self.aces,
            "IsDeleted": False,
            "IsACLProtected": False,
        }
