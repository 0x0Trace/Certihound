"""Security descriptor parsing for nTSecurityDescriptor."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from .rights import AccessMask, AceFlags, AceType, ACERights, ADCSRights


@dataclass
class ACE:
    """Represents a single Access Control Entry."""

    ace_type: int
    ace_flags: int
    access_mask: int
    sid: str
    object_type: str | None = None  # GUID for object-specific ACE
    inherited_object_type: str | None = None
    is_inherited: bool = False

    @property
    def is_allow(self) -> bool:
        """Check if this is an allow ACE."""
        return self.ace_type in (
            AceType.ACCESS_ALLOWED,
            AceType.ACCESS_ALLOWED_OBJECT,
            AceType.ACCESS_ALLOWED_CALLBACK,
            AceType.ACCESS_ALLOWED_CALLBACK_OBJECT,
        )

    @property
    def is_deny(self) -> bool:
        """Check if this is a deny ACE."""
        return self.ace_type in (
            AceType.ACCESS_DENIED,
            AceType.ACCESS_DENIED_OBJECT,
            AceType.ACCESS_DENIED_CALLBACK,
            AceType.ACCESS_DENIED_CALLBACK_OBJECT,
        )

    @property
    def is_object_ace(self) -> bool:
        """Check if this is an object-specific ACE."""
        return self.ace_type in (
            AceType.ACCESS_ALLOWED_OBJECT,
            AceType.ACCESS_DENIED_OBJECT,
            AceType.ACCESS_ALLOWED_CALLBACK_OBJECT,
            AceType.ACCESS_DENIED_CALLBACK_OBJECT,
        )


@dataclass
class ACL:
    """Represents an Access Control List."""

    revision: int = 0
    aces: list[ACE] = field(default_factory=list)


@dataclass
class SecurityDescriptor:
    """Represents a Windows Security Descriptor."""

    revision: int = 0
    control: int = 0
    owner_sid: str = ""
    group_sid: str = ""
    dacl: ACL | None = None
    sacl: ACL | None = None


class SecurityDescriptorParser:
    """Parse Windows Security Descriptor from binary format."""

    # Control flags
    SE_OWNER_DEFAULTED = 0x0001
    SE_GROUP_DEFAULTED = 0x0002
    SE_DACL_PRESENT = 0x0004
    SE_DACL_DEFAULTED = 0x0008
    SE_SACL_PRESENT = 0x0010
    SE_SACL_DEFAULTED = 0x0020
    SE_DACL_AUTO_INHERIT_REQ = 0x0100
    SE_SACL_AUTO_INHERIT_REQ = 0x0200
    SE_DACL_AUTO_INHERITED = 0x0400
    SE_SACL_AUTO_INHERITED = 0x0800
    SE_DACL_PROTECTED = 0x1000
    SE_SACL_PROTECTED = 0x2000
    SE_SELF_RELATIVE = 0x8000

    def __init__(self, raw_sd: bytes):
        self.raw_sd = raw_sd
        self._sd: SecurityDescriptor | None = None

    def parse(self) -> SecurityDescriptor:
        """Parse the security descriptor."""
        if self._sd:
            return self._sd

        if not self.raw_sd or len(self.raw_sd) < 20:
            return SecurityDescriptor()

        try:
            # Parse header
            revision = self.raw_sd[0]
            # sbz1 = self.raw_sd[1]
            control = struct.unpack("<H", self.raw_sd[2:4])[0]
            owner_offset = struct.unpack("<I", self.raw_sd[4:8])[0]
            group_offset = struct.unpack("<I", self.raw_sd[8:12])[0]
            sacl_offset = struct.unpack("<I", self.raw_sd[12:16])[0]
            dacl_offset = struct.unpack("<I", self.raw_sd[16:20])[0]

            self._sd = SecurityDescriptor(
                revision=revision,
                control=control,
            )

            # Parse owner SID
            if owner_offset > 0:
                self._sd.owner_sid = self._parse_sid(owner_offset)

            # Parse group SID
            if group_offset > 0:
                self._sd.group_sid = self._parse_sid(group_offset)

            # Parse DACL
            if dacl_offset > 0 and (control & self.SE_DACL_PRESENT):
                self._sd.dacl = self._parse_acl(dacl_offset)

            # Parse SACL
            if sacl_offset > 0 and (control & self.SE_SACL_PRESENT):
                self._sd.sacl = self._parse_acl(sacl_offset)

            return self._sd

        except (struct.error, IndexError, ValueError) as e:
            return SecurityDescriptor()

    def _parse_sid(self, offset: int) -> str:
        """Parse SID at given offset."""
        if offset >= len(self.raw_sd):
            return ""

        try:
            revision = self.raw_sd[offset]
            sub_auth_count = self.raw_sd[offset + 1]
            authority = int.from_bytes(self.raw_sd[offset + 2 : offset + 8], byteorder="big")

            sub_auths = []
            for i in range(sub_auth_count):
                sub_offset = offset + 8 + (i * 4)
                sub_auth = struct.unpack("<I", self.raw_sd[sub_offset : sub_offset + 4])[0]
                sub_auths.append(sub_auth)

            sid = f"S-{revision}-{authority}"
            for sub_auth in sub_auths:
                sid += f"-{sub_auth}"

            return sid

        except (struct.error, IndexError):
            return ""

    def _parse_acl(self, offset: int) -> ACL:
        """Parse ACL at given offset."""
        if offset >= len(self.raw_sd):
            return ACL()

        try:
            acl_revision = self.raw_sd[offset]
            # sbz1 = self.raw_sd[offset + 1]
            acl_size = struct.unpack("<H", self.raw_sd[offset + 2 : offset + 4])[0]
            ace_count = struct.unpack("<H", self.raw_sd[offset + 4 : offset + 6])[0]
            # sbz2 = struct.unpack("<H", self.raw_sd[offset + 6 : offset + 8])[0]

            acl = ACL(revision=acl_revision)

            ace_offset = offset + 8
            for _ in range(ace_count):
                if ace_offset >= len(self.raw_sd):
                    break

                ace, ace_size = self._parse_ace(ace_offset)
                if ace:
                    acl.aces.append(ace)

                ace_offset += ace_size

            return acl

        except (struct.error, IndexError):
            return ACL()

    def _parse_ace(self, offset: int) -> tuple[ACE | None, int]:
        """Parse ACE at given offset. Returns (ACE, size)."""
        if offset + 4 > len(self.raw_sd):
            return (None, 0)

        try:
            ace_type = self.raw_sd[offset]
            ace_flags = self.raw_sd[offset + 1]
            ace_size = struct.unpack("<H", self.raw_sd[offset + 2 : offset + 4])[0]

            if offset + ace_size > len(self.raw_sd):
                return (None, ace_size)

            access_mask = struct.unpack("<I", self.raw_sd[offset + 4 : offset + 8])[0]

            is_inherited = bool(ace_flags & AceFlags.INHERITED)

            # Check if this is an object ACE
            if ace_type in (
                AceType.ACCESS_ALLOWED_OBJECT,
                AceType.ACCESS_DENIED_OBJECT,
                AceType.ACCESS_ALLOWED_CALLBACK_OBJECT,
                AceType.ACCESS_DENIED_CALLBACK_OBJECT,
            ):
                return self._parse_object_ace(
                    offset, ace_type, ace_flags, ace_size, access_mask, is_inherited
                )

            # Standard ACE - SID follows access mask
            sid = self._parse_sid_at(self.raw_sd[offset + 8 : offset + ace_size])

            return (
                ACE(
                    ace_type=ace_type,
                    ace_flags=ace_flags,
                    access_mask=access_mask,
                    sid=sid,
                    is_inherited=is_inherited,
                ),
                ace_size,
            )

        except (struct.error, IndexError):
            return (None, 4)

    def _parse_object_ace(
        self,
        offset: int,
        ace_type: int,
        ace_flags: int,
        ace_size: int,
        access_mask: int,
        is_inherited: bool,
    ) -> tuple[ACE | None, int]:
        """Parse object-specific ACE."""
        try:
            flags = struct.unpack("<I", self.raw_sd[offset + 8 : offset + 12])[0]

            current_offset = offset + 12
            object_type = None
            inherited_object_type = None

            # ACE_OBJECT_TYPE_PRESENT = 0x1
            if flags & 0x1:
                guid_bytes = self.raw_sd[current_offset : current_offset + 16]
                object_type = str(UUID(bytes_le=guid_bytes)).lower()
                current_offset += 16

            # ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
            if flags & 0x2:
                guid_bytes = self.raw_sd[current_offset : current_offset + 16]
                inherited_object_type = str(UUID(bytes_le=guid_bytes)).lower()
                current_offset += 16

            # Parse SID
            sid = self._parse_sid_at(self.raw_sd[current_offset : offset + ace_size])

            return (
                ACE(
                    ace_type=ace_type,
                    ace_flags=ace_flags,
                    access_mask=access_mask,
                    sid=sid,
                    object_type=object_type,
                    inherited_object_type=inherited_object_type,
                    is_inherited=is_inherited,
                ),
                ace_size,
            )

        except (struct.error, IndexError, ValueError):
            return (None, ace_size)

    def _parse_sid_at(self, data: bytes) -> str:
        """Parse SID from byte data."""
        if not data or len(data) < 8:
            return ""

        try:
            revision = data[0]
            sub_auth_count = data[1]
            authority = int.from_bytes(data[2:8], byteorder="big")

            sub_auths = []
            for i in range(sub_auth_count):
                sub_offset = 8 + (i * 4)
                if sub_offset + 4 > len(data):
                    break
                sub_auth = struct.unpack("<I", data[sub_offset : sub_offset + 4])[0]
                sub_auths.append(sub_auth)

            sid = f"S-{revision}-{authority}"
            for sub_auth in sub_auths:
                sid += f"-{sub_auth}"

            return sid

        except (struct.error, IndexError):
            return ""

    def get_enrollment_rights(self) -> list[ADCSRights]:
        """Extract ADCS enrollment rights from the security descriptor."""
        sd = self.parse()
        if not sd.dacl:
            return []

        rights_by_sid: dict[str, dict] = {}

        for ace in sd.dacl.aces:
            if not ace.is_allow:
                continue

            sid = ace.sid
            if sid not in rights_by_sid:
                rights_by_sid[sid] = {
                    "enroll": False,
                    "auto_enroll": False,
                    "write_dacl": False,
                    "write_owner": False,
                    "generic_all": False,
                    "generic_write": False,
                    "write_property": False,
                    "write_property_attributes": [],
                    "inherited": ace.is_inherited,
                }

            rights = rights_by_sid[sid]

            # Check for generic rights
            if ace.access_mask & AccessMask.GENERIC_ALL:
                rights["generic_all"] = True
            if ace.access_mask & AccessMask.GENERIC_WRITE:
                rights["generic_write"] = True
            if ace.access_mask & AccessMask.WRITE_DAC:
                rights["write_dacl"] = True
            if ace.access_mask & AccessMask.WRITE_OWNER:
                rights["write_owner"] = True

            # Check for enrollment extended rights
            if ace.access_mask & AccessMask.DS_CONTROL_ACCESS:
                if ace.object_type:
                    if ace.object_type == ACERights.CERTIFICATE_ENROLLMENT:
                        rights["enroll"] = True
                    elif ace.object_type == ACERights.CERTIFICATE_AUTOENROLLMENT:
                        rights["auto_enroll"] = True
                else:
                    # No object type means all extended rights
                    rights["enroll"] = True
                    rights["auto_enroll"] = True

            # Check for write property
            if ace.access_mask & AccessMask.DS_WRITE_PROPERTY:
                if ace.object_type:
                    rights["write_property_attributes"].append(ace.object_type)
                    if ace.object_type in ACERights.DANGEROUS_WRITE_PROPERTIES:
                        rights["write_property"] = True
                else:
                    # No object type means all properties
                    rights["write_property"] = True

        # Convert to ADCSRights objects
        result = []
        for sid, rights_dict in rights_by_sid.items():
            result.append(
                ADCSRights(
                    sid=sid,
                    enroll=rights_dict["enroll"],
                    auto_enroll=rights_dict["auto_enroll"],
                    write_dacl=rights_dict["write_dacl"],
                    write_owner=rights_dict["write_owner"],
                    generic_all=rights_dict["generic_all"],
                    generic_write=rights_dict["generic_write"],
                    write_property=rights_dict["write_property"],
                    write_property_attributes=rights_dict["write_property_attributes"],
                    inherited=rights_dict["inherited"],
                )
            )

        return result

    def get_aces_for_bloodhound(self) -> list[dict]:
        """Get ACEs formatted for BloodHound CE output."""
        sd = self.parse()
        if not sd.dacl:
            return []

        aces = []
        for ace in sd.dacl.aces:
            if not ace.is_allow:
                continue

            ace_dict = {
                "PrincipalSID": ace.sid,
                "PrincipalType": "Unknown",  # Will be resolved later
                "RightName": "",
                "IsInherited": ace.is_inherited,
            }

            # Determine right name based on access mask and object type
            if ace.access_mask & AccessMask.GENERIC_ALL:
                ace_dict["RightName"] = "GenericAll"
                aces.append(ace_dict.copy())
            else:
                if ace.access_mask & AccessMask.GENERIC_WRITE:
                    ace_dict["RightName"] = "GenericWrite"
                    aces.append(ace_dict.copy())
                if ace.access_mask & AccessMask.WRITE_DAC:
                    ace_dict["RightName"] = "WriteDacl"
                    aces.append(ace_dict.copy())
                if ace.access_mask & AccessMask.WRITE_OWNER:
                    ace_dict["RightName"] = "WriteOwner"
                    aces.append(ace_dict.copy())
                if ace.access_mask & AccessMask.DS_CONTROL_ACCESS:
                    if ace.object_type == ACERights.CERTIFICATE_ENROLLMENT:
                        ace_dict["RightName"] = "Enroll"
                        aces.append(ace_dict.copy())
                    elif ace.object_type == ACERights.CERTIFICATE_AUTOENROLLMENT:
                        ace_dict["RightName"] = "AutoEnroll"
                        aces.append(ace_dict.copy())
                    elif not ace.object_type:
                        ace_dict["RightName"] = "AllExtendedRights"
                        aces.append(ace_dict.copy())
                if ace.access_mask & AccessMask.DS_WRITE_PROPERTY:
                    if not ace.object_type:
                        ace_dict["RightName"] = "WriteAllProperties"
                        aces.append(ace_dict.copy())

        return aces
