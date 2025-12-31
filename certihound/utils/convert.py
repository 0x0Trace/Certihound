"""Data type conversion utilities."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any
from uuid import UUID


def guid_to_string(guid_bytes: bytes) -> str:
    """Convert binary GUID to string representation."""
    if not guid_bytes:
        return ""
    try:
        return str(UUID(bytes_le=guid_bytes))
    except (ValueError, TypeError):
        return ""


def bytes_to_sid(sid_bytes: bytes) -> str:
    """Convert binary SID to string representation (S-1-5-21-...)."""
    if not sid_bytes or len(sid_bytes) < 8:
        return ""

    try:
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]

        # Authority is 6 bytes, big-endian
        authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

        # Sub-authorities are 4 bytes each, little-endian
        sub_authorities = []
        offset = 8
        for _ in range(sub_auth_count):
            if offset + 4 > len(sid_bytes):
                break
            sub_auth = struct.unpack("<I", sid_bytes[offset : offset + 4])[0]
            sub_authorities.append(sub_auth)
            offset += 4

        # Build SID string
        sid = f"S-{revision}-{authority}"
        for sub_auth in sub_authorities:
            sid += f"-{sub_auth}"

        return sid

    except (struct.error, IndexError, ValueError):
        return ""


def sid_to_bytes(sid_string: str) -> bytes:
    """Convert SID string to binary representation."""
    if not sid_string or not sid_string.startswith("S-"):
        return b""

    try:
        parts = sid_string.split("-")
        revision = int(parts[1])
        authority = int(parts[2])
        sub_authorities = [int(x) for x in parts[3:]]

        # Build binary SID
        sid_bytes = bytes([revision, len(sub_authorities)])
        sid_bytes += authority.to_bytes(6, byteorder="big")
        for sub_auth in sub_authorities:
            sid_bytes += struct.pack("<I", sub_auth)

        return sid_bytes

    except (ValueError, IndexError):
        return b""


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME to Python datetime."""
    if not filetime or filetime == 0:
        return None

    try:
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        # Unix epoch is January 1, 1970
        # Difference is 116444736000000000 100-nanosecond intervals
        EPOCH_DIFF = 116444736000000000
        unix_time = (filetime - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(unix_time, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def datetime_to_filetime(dt: datetime) -> int:
    """Convert Python datetime to Windows FILETIME."""
    if not dt:
        return 0

    try:
        EPOCH_DIFF = 116444736000000000
        unix_time = dt.timestamp()
        return int(unix_time * 10000000 + EPOCH_DIFF)
    except (ValueError, OSError):
        return 0


def format_guid(guid: Any) -> str:
    """Format GUID for BloodHound output."""
    if isinstance(guid, bytes):
        return guid_to_string(guid).upper()
    if isinstance(guid, str):
        return guid.upper()
    return str(guid).upper() if guid else ""


def parse_dn_domain(dn: str) -> str:
    """Extract domain FQDN from distinguished name."""
    if not dn:
        return ""

    dc_parts = []
    for part in dn.split(","):
        if part.strip().upper().startswith("DC="):
            dc_parts.append(part.strip()[3:])

    return ".".join(dc_parts)


def dn_to_domain_sid_format(dn: str, domain_sid: str) -> str:
    """Create object identifier in domain-SID format."""
    # For ADCS objects, we typically use GUID or create composite IDs
    return f"{domain_sid}"


# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
}


def get_well_known_sid_name(sid: str) -> str | None:
    """Get the name of a well-known SID."""
    return WELL_KNOWN_SIDS.get(sid)


# Well-known domain RIDs
WELL_KNOWN_RIDS = {
    500: "Administrator",
    501: "Guest",
    502: "KRBTGT",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}


def get_domain_rid_name(rid: int) -> str | None:
    """Get the name of a well-known domain RID."""
    return WELL_KNOWN_RIDS.get(rid)
