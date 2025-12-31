"""
Impacket LDAP adapter for CertiHound.

This adapter allows CertiHound to work with impacket-based LDAP connections,
such as those used by NetExec, Impacket scripts, and similar tools.

Example usage with NetExec:
    from certihound import ADCSCollector, BloodHoundCEExporter
    from certihound.adapters import ImpacketLDAPAdapter

    # In NetExec's ldap.py adcs() method:
    adapter = ImpacketLDAPAdapter(
        search_func=self.search,
        domain=self.domain,
        domain_sid=self.sid_domain,
    )

    collector = ADCSCollector.from_external(
        ldap_connection=adapter,
        domain=self.domain,
        domain_sid=self.sid_domain,
    )
    data = collector.collect_all()
"""

from __future__ import annotations

import struct
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    pass


def _bin_to_guid(binary: bytes) -> str:
    """Convert binary objectGUID to string format."""
    try:
        if len(binary) != 16:
            return ""
        parts = struct.unpack('<IHH', binary[:8])
        rest = binary[8:]
        guid = f"{parts[0]:08X}-{parts[1]:04X}-{parts[2]:04X}-{rest[0]:02X}{rest[1]:02X}-"
        guid += "".join(f"{b:02X}" for b in rest[2:])
        return guid
    except Exception:
        return ""


class ImpacketLDAPAttribute:
    """Wrapper for impacket LDAP attribute values to match ldap3-style interface."""

    def __init__(self, vals: Any, attr_name: str = ""):
        self._vals = vals
        self._attr_name = attr_name

        # Get raw bytes first (always safe)
        self.raw_values = []
        if vals:
            for v in vals:
                try:
                    self.raw_values.append(bytes(v))
                except Exception:
                    self.raw_values.append(b"")

        # Get single value - handle special attributes
        self.value = None
        if vals:
            first_val = vals[0]

            # Special handling for objectGUID (binary -> GUID string)
            if attr_name.lower() == "objectguid":
                try:
                    raw_bytes = bytes(first_val)
                    self.value = _bin_to_guid(raw_bytes)
                except Exception:
                    self.value = ""
            else:
                try:
                    if hasattr(first_val, 'hasValue') and first_val.hasValue():
                        self.value = str(first_val)
                    else:
                        self.value = str(first_val) if first_val else None
                except (UnicodeDecodeError, Exception):
                    # Binary data that can't be decoded as string
                    self.value = None

        # Get all string values - skip ones that can't be decoded
        self.values = []
        if vals:
            for v in vals:
                try:
                    if attr_name.lower() == "objectguid":
                        self.values.append(_bin_to_guid(bytes(v)))
                    else:
                        self.values.append(str(v))
                except (UnicodeDecodeError, Exception):
                    pass


class ImpacketLDAPEntry:
    """Wrapper to make impacket LDAP entries look like ldap3 entries."""

    def __init__(self, ldap_entry: Any):
        self._entry = ldap_entry
        self._attrs = {}
        # Parse attributes from impacket format
        for attr in ldap_entry["attributes"]:
            attr_name = str(attr["type"])
            vals = attr["vals"]
            self._attrs[attr_name] = ImpacketLDAPAttribute(vals, attr_name)

    def __getitem__(self, key: str) -> ImpacketLDAPAttribute | None:
        return self._attrs.get(key)

    def __contains__(self, key: str) -> bool:
        return key in self._attrs


class ImpacketLDAPAdapter:
    """
    Adapter that wraps impacket-based LDAP search for CertiHound compatibility.

    This adapter provides an ldap3-compatible interface that CertiHound's
    ExternalADCSCollector can use with impacket-based LDAP connections.

    Args:
        search_func: The search function from the tool (e.g., NetExec's self.search)
                     Expected signature: search(searchFilter, attributes, baseDN, searchControls=None)
        domain: Domain FQDN
        domain_sid: Domain SID
        ldapasn1_module: The impacket ldapasn1 module (for SearchResultEntry type checking)
    """

    def __init__(
        self,
        search_func: Callable,
        domain: str,
        domain_sid: str,
        ldapasn1_module: Any = None,
    ):
        self._search_func = search_func
        self._domain = domain
        self._domain_sid = domain_sid
        self._ldapasn1 = ldapasn1_module
        self.entries = []  # ldap3-style entries storage

        # Import ldapasn1 if not provided
        if self._ldapasn1 is None:
            try:
                from impacket.ldap import ldapasn1
                self._ldapasn1 = ldapasn1
            except ImportError:
                raise ImportError(
                    "impacket is required for ImpacketLDAPAdapter. "
                    "Install with: pip install impacket"
                )

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
    ) -> None:
        """
        Execute search and store results in ldap3-compatible format.

        After calling this method, results are available in self.entries.
        """
        # Build search controls - include SD_FLAGS if requesting nTSecurityDescriptor
        search_controls = None
        if "nTSecurityDescriptor" in attributes:
            # LDAP_SERVER_SD_FLAGS_OID control to request security descriptor
            # Value 7 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            sd_flags_control = self._ldapasn1.SDFlagsControl(criticality=True, flags=0x07)
            paged_control = self._ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
            search_controls = [paged_control, sd_flags_control]

        # Execute search using the provided search function
        resp = self._search_func(
            searchFilter=search_filter,
            attributes=attributes,
            baseDN=search_base,
            searchControls=search_controls,
        )

        # Convert impacket results to ldap3-like entry objects
        self.entries = []
        if resp:
            for item in resp:
                if isinstance(item, self._ldapasn1.SearchResultEntry):
                    entry = ImpacketLDAPEntry(item)
                    self.entries.append(entry)
