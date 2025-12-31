"""ACE rights constants and definitions."""

from __future__ import annotations

from enum import IntFlag
from typing import NamedTuple


class AccessMask(IntFlag):
    """Standard Windows access mask flags."""

    # Generic rights
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000

    # Standard rights
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000

    # Directory service rights
    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_LIST_CONTENTS = 0x00000004
    DS_SELF = 0x00000008
    DS_READ_PROPERTY = 0x00000010
    DS_WRITE_PROPERTY = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080
    DS_CONTROL_ACCESS = 0x00000100

    # Combinations
    STANDARD_RIGHTS_ALL = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE


class AceType(IntFlag):
    """ACE type flags."""

    ACCESS_ALLOWED = 0x00
    ACCESS_DENIED = 0x01
    SYSTEM_AUDIT = 0x02
    SYSTEM_ALARM = 0x03
    ACCESS_ALLOWED_COMPOUND = 0x04
    ACCESS_ALLOWED_OBJECT = 0x05
    ACCESS_DENIED_OBJECT = 0x06
    SYSTEM_AUDIT_OBJECT = 0x07
    SYSTEM_ALARM_OBJECT = 0x08
    ACCESS_ALLOWED_CALLBACK = 0x09
    ACCESS_DENIED_CALLBACK = 0x0A
    ACCESS_ALLOWED_CALLBACK_OBJECT = 0x0B
    ACCESS_DENIED_CALLBACK_OBJECT = 0x0C
    SYSTEM_AUDIT_CALLBACK = 0x0D
    SYSTEM_ALARM_CALLBACK = 0x0E
    SYSTEM_AUDIT_CALLBACK_OBJECT = 0x0F
    SYSTEM_MANDATORY_LABEL = 0x11


class AceFlags(IntFlag):
    """ACE flags."""

    OBJECT_INHERIT = 0x01
    CONTAINER_INHERIT = 0x02
    NO_PROPAGATE_INHERIT = 0x04
    INHERIT_ONLY = 0x08
    INHERITED = 0x10
    SUCCESSFUL_ACCESS = 0x40
    FAILED_ACCESS = 0x80


class ACERights:
    """ACE rights constants for AD objects."""

    # Extended rights GUIDs (in lowercase for comparison)
    CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    WRITE_PROPERTY = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    WRITE_OWNER = "bf9679a7-0de6-11d0-a285-00aa003049e2"

    # Schema attribute GUIDs for certificate templates
    PKI_CERTIFICATE_NAME_FLAG = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"
    PKI_ENROLLMENT_FLAG = "d15ef7d8-f226-46db-ae79-b34e560bd12c"
    PKI_EXTENDED_KEY_USAGE = "18976af6-3b9e-11d2-90cc-00c04fd91ab1"
    PKI_RA_SIGNATURE = "a8df74bf-c5ea-11d1-bbcb-0080c76670c0"
    PKI_EXPIRATION_PERIOD = "bf9679f0-0de6-11d0-a285-00aa003049e2"

    # All property GUIDs that matter for ESC4
    DANGEROUS_WRITE_PROPERTIES = [
        PKI_CERTIFICATE_NAME_FLAG,
        PKI_ENROLLMENT_FLAG,
        PKI_EXTENDED_KEY_USAGE,
        PKI_RA_SIGNATURE,
    ]


class ADCSRights(NamedTuple):
    """Parsed ADCS-specific rights for a principal."""

    sid: str
    enroll: bool = False
    auto_enroll: bool = False
    write_dacl: bool = False
    write_owner: bool = False
    generic_all: bool = False
    generic_write: bool = False
    write_property: bool = False
    write_property_attributes: list[str] = []  # Specific attributes if object ACE
    inherited: bool = False

    @property
    def has_dangerous_permissions(self) -> bool:
        """Check if principal has permissions that could enable privilege escalation."""
        return (
            self.write_dacl
            or self.write_owner
            or self.generic_all
            or self.generic_write
            or self.write_property
        )

    @property
    def can_enroll(self) -> bool:
        """Check if principal can enroll for certificates."""
        return self.enroll or self.generic_all


# Well-known security principal SIDs
WELL_KNOWN_PRINCIPALS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-7": "Anonymous",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}


def is_low_privileged_sid(sid: str, domain_sid: str) -> bool:
    """
    Check if a SID represents a low-privileged principal.

    Low-privileged includes:
    - Everyone (S-1-1-0)
    - Authenticated Users (S-1-5-11)
    - Domain Users (-513)
    - Domain Computers (-515)
    """
    low_priv_sids = {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        f"{domain_sid}-513",  # Domain Users
        f"{domain_sid}-515",  # Domain Computers
    }
    return sid in low_priv_sids


def is_high_privileged_sid(sid: str, domain_sid: str) -> bool:
    """
    Check if a SID represents a high-privileged principal.

    High-privileged includes:
    - Domain Admins (-512)
    - Enterprise Admins (-519)
    - SYSTEM (S-1-5-18)
    - Administrators (S-1-5-32-544)
    """
    high_priv_sids = {
        "S-1-5-18",  # SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
        f"{domain_sid}-512",  # Domain Admins
        f"{domain_sid}-519",  # Enterprise Admins
        f"{domain_sid}-518",  # Schema Admins
    }
    return sid in high_priv_sids
