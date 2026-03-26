"""
ADCS Collector - Main interface for enumerating AD Certificate Services.

This module provides the primary API for collecting ADCS data from Active Directory.
It can work with its own LDAP connection or accept an external one from tools like NetExec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .ldap.parsers import (
    parse_cert_templates,
    parse_enterprise_cas,
    parse_root_cas,
    parse_ntauth_stores,
    parse_aia_cas,
)
from .ldap.queries import ADCSQueries

if TYPE_CHECKING:
    from .ldap.connection import LDAPConnection
    from .objects.certtemplate import CertTemplate
    from .objects.enterpriseca import EnterpriseCA
    from .objects.rootca import RootCA
    from .objects.ntauthstore import NTAuthStore
    from .objects.aiaca import AIACA


@runtime_checkable
class LDAPConnectionProtocol(Protocol):
    """Protocol for LDAP connection objects from external tools."""

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
        **kwargs: Any,
    ) -> list[Any]:
        """Execute LDAP search."""
        ...


@dataclass
class ADCSData:
    """Container for all collected ADCS data."""

    domain: str
    domain_sid: str
    templates: list["CertTemplate"] = field(default_factory=list)
    enterprise_cas: list["EnterpriseCA"] = field(default_factory=list)
    root_cas: list["RootCA"] = field(default_factory=list)
    ntauth_stores: list["NTAuthStore"] = field(default_factory=list)
    aia_cas: list["AIACA"] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        """Get summary counts."""
        return {
            "templates": len(self.templates),
            "enterprise_cas": len(self.enterprise_cas),
            "root_cas": len(self.root_cas),
            "ntauth_stores": len(self.ntauth_stores),
            "aia_cas": len(self.aia_cas),
        }

    def apply_registry_flags(self, smb_connection: Any) -> None:
        """Read CA registry flags via RPC and apply to Enterprise CAs.

        This enriches CA objects with flags only available from the
        Windows registry (not LDAP), enabling ESC6/ESC11/ESC16 detection.

        Args:
            smb_connection: An impacket SMBConnection to the CA host.
        """
        from .rpc.ca_registry import CARegistryReader

        try:
            with CARegistryReader(smb_connection) as reader:
                for ca in self.enterprise_cas:
                    flags = reader.read_ca_flags(ca.cn, ca.dns_hostname)
                    if flags.success:
                        ca.is_user_specifies_san_enabled = flags.san_flag_enabled
                        ca.is_security_extension_disabled = flags.security_extension_disabled
                        # Override enforce_encrypt_rpc with registry value if available
                        if flags.interface_flags is not None:
                            base = ca.flags if ca.flags is not None else 0
                            ca.flags = (base & ~0x200) | (
                                flags.interface_flags & 0x200
                            )
        except ImportError:
            pass  # impacket not available
        except Exception:
            pass  # Registry access failed (non-admin, service stopped, etc.)


class ADCSCollector:
    """
    Collects ADCS data from Active Directory via LDAP.

    Can be used standalone or integrated into other tools like NetExec.

    Example - Standalone usage:
        ```python
        from certihound import ADCSCollector
        from certihound.ldap import LDAPConnection, LDAPConfig

        config = LDAPConfig(domain="corp.local", username="user", password="pass")
        with LDAPConnection(config) as conn:
            collector = ADCSCollector(conn)
            data = collector.collect_all()
        ```

    Example - Integration with external tools:
        ```python
        from certihound import ADCSCollector

        # Use existing LDAP connection from NetExec or other tool
        collector = ADCSCollector.from_external(
            ldap_connection=existing_conn,
            domain="corp.local",
            domain_sid="S-1-5-21-...",
            base_dn="DC=corp,DC=local",
        )
        data = collector.collect_all()
        ```
    """

    def __init__(self, connection: "LDAPConnection"):
        """
        Initialize collector with CertiHound's LDAPConnection.

        Args:
            connection: CertiHound LDAPConnection instance
        """
        self._connection = connection
        self._queries = ADCSQueries(connection)
        self._domain = connection.config.domain
        self._domain_sid = connection.domain_sid
        self._config_dn = connection.config.config_dn
        self._domain_dn = connection.config.domain_dn

    @classmethod
    def from_external(
        cls,
        ldap_connection: Any,
        domain: str,
        domain_sid: str,
        base_dn: str | None = None,
    ) -> "ADCSCollector":
        """
        Create collector from an external LDAP connection.

        This allows integration with tools like NetExec that have their own
        LDAP connection handling.

        Args:
            ldap_connection: External LDAP connection object with search method
            domain: Domain FQDN (e.g., "corp.local")
            domain_sid: Domain SID (e.g., "S-1-5-21-...")
            base_dn: Optional base DN, derived from domain if not provided

        Returns:
            ADCSCollector instance
        """
        return ExternalADCSCollector(
            ldap_connection=ldap_connection,
            domain=domain,
            domain_sid=domain_sid,
            base_dn=base_dn,
        )

    @property
    def domain(self) -> str:
        """Get domain name."""
        return self._domain

    @property
    def domain_sid(self) -> str:
        """Get domain SID."""
        return self._domain_sid

    def collect_templates(self, verbose: bool = False) -> list["CertTemplate"]:
        """Collect certificate templates."""
        raw_entries = self._queries.get_certificate_templates()
        return parse_cert_templates(raw_entries)

    def collect_enterprise_cas(self, verbose: bool = False) -> list["EnterpriseCA"]:
        """Collect Enterprise CAs."""
        raw_entries = self._queries.get_enterprise_cas()
        return parse_enterprise_cas(raw_entries)

    def collect_root_cas(self, verbose: bool = False) -> list["RootCA"]:
        """Collect Root CAs."""
        raw_entries = self._queries.get_root_cas()
        return parse_root_cas(raw_entries)

    def collect_ntauth_stores(self, verbose: bool = False) -> list["NTAuthStore"]:
        """Collect NTAuth stores."""
        raw_entries = self._queries.get_ntauth_store()
        return parse_ntauth_stores(raw_entries)

    def collect_aia_cas(self, verbose: bool = False) -> list["AIACA"]:
        """Collect AIA CAs."""
        raw_entries = self._queries.get_aia_cas()
        return parse_aia_cas(raw_entries)

    def collect_all(self, verbose: bool = False) -> ADCSData:
        """
        Collect all ADCS data.

        Args:
            verbose: Print progress information

        Returns:
            ADCSData container with all collected objects
        """
        return ADCSData(
            domain=self._domain,
            domain_sid=self._domain_sid,
            templates=self.collect_templates(verbose),
            enterprise_cas=self.collect_enterprise_cas(verbose),
            root_cas=self.collect_root_cas(verbose),
            ntauth_stores=self.collect_ntauth_stores(verbose),
            aia_cas=self.collect_aia_cas(verbose),
        )


class ExternalADCSCollector(ADCSCollector):
    """
    ADCS Collector that works with external LDAP connections.

    This class allows integration with tools that have their own LDAP handling,
    like NetExec, Impacket-based tools, or custom scripts.
    """

    def __init__(
        self,
        ldap_connection: Any,
        domain: str,
        domain_sid: str,
        base_dn: str | None = None,
    ):
        """
        Initialize with external LDAP connection.

        Args:
            ldap_connection: External connection with search capability
            domain: Domain FQDN
            domain_sid: Domain SID
            base_dn: Base DN for searches
        """
        self._external_conn = ldap_connection
        self._domain = domain.upper()
        self._domain_sid = domain_sid

        # Derive DNs
        if base_dn:
            self._domain_dn = base_dn
        else:
            self._domain_dn = ",".join(f"DC={part}" for part in domain.split("."))
        self._config_dn = f"CN=Configuration,{self._domain_dn}"

    # LDAP_SERVER_SD_FLAGS_OID - required to retrieve nTSecurityDescriptor
    _SD_FLAGS_OID = "1.2.840.113556.1.4.801"
    # DACL (0x04) | OWNER (0x01) | GROUP (0x02) = 0x07
    _SD_FLAGS_VALUE = 0x07

    def _build_sd_control(self) -> list[tuple]:
        """Build LDAP SD_FLAGS control for ldap3 connections.

        The value is BER-encoded: SEQUENCE { INTEGER sd_flags }
        """
        import struct

        # BER encode: sequence tag (0x30), length (3), integer tag (0x02), length (1), value
        sd_value = b"\x30\x03\x02\x01" + struct.pack("B", self._SD_FLAGS_VALUE)
        return [(self._SD_FLAGS_OID, True, sd_value)]

    def _search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
    ) -> list[Any]:
        """Execute search using external connection."""
        # Handle different connection types
        conn = self._external_conn

        # Build search kwargs - add SD_FLAGS control if requesting nTSecurityDescriptor
        needs_sd = "nTSecurityDescriptor" in attributes

        # Check if this is a true ldap3 Connection (has 'server' attr)
        # vs ImpacketLDAPAdapter (which handles SD_FLAGS internally)
        is_ldap3 = hasattr(conn, 'server')

        # Try ldap3 style
        if hasattr(conn, 'search') and hasattr(conn, 'entries'):
            search_kwargs: dict[str, Any] = {
                "search_base": search_base,
                "search_filter": search_filter,
                "attributes": attributes,
            }
            # Only pass controls to real ldap3 connections
            # ImpacketLDAPAdapter handles SD_FLAGS in its own search()
            if needs_sd and is_ldap3:
                search_kwargs["controls"] = self._build_sd_control()
            conn.search(**search_kwargs)
            return list(conn.entries)

        # Try generic search method (e.g., ImpacketLDAPAdapter)
        if hasattr(conn, 'search'):
            return conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
            )

        raise TypeError(
            f"Unsupported connection type: {type(conn)}. "
            "Connection must have a 'search' method."
        )

    def collect_templates(self, verbose: bool = False) -> list["CertTemplate"]:
        """Collect certificate templates."""
        from .ldap.queries import ADCSQueries

        search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self._config_dn}"
        raw_entries = self._search(
            search_base=search_base,
            search_filter=ADCSQueries.CERT_TEMPLATE.filter,
            attributes=ADCSQueries.CERT_TEMPLATE.attributes,
        )
        return parse_cert_templates(raw_entries, self._domain, self._domain_sid)

    def collect_enterprise_cas(self, verbose: bool = False) -> list["EnterpriseCA"]:
        """Collect Enterprise CAs."""
        from .ldap.queries import ADCSQueries

        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self._config_dn}"
        raw_entries = self._search(
            search_base=search_base,
            search_filter=ADCSQueries.ENTERPRISE_CA.filter,
            attributes=ADCSQueries.ENTERPRISE_CA.attributes,
        )
        return parse_enterprise_cas(raw_entries, self._domain, self._domain_sid)

    def collect_root_cas(self, verbose: bool = False) -> list["RootCA"]:
        """Collect Root CAs."""
        from .ldap.queries import ADCSQueries

        search_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,{self._config_dn}"
        raw_entries = self._search(
            search_base=search_base,
            search_filter=ADCSQueries.ROOT_CA.filter,
            attributes=ADCSQueries.ROOT_CA.attributes,
        )
        return parse_root_cas(raw_entries, self._domain, self._domain_sid)

    def collect_ntauth_stores(self, verbose: bool = False) -> list["NTAuthStore"]:
        """Collect NTAuth stores."""
        from .ldap.queries import ADCSQueries

        search_base = f"CN=Public Key Services,CN=Services,{self._config_dn}"
        raw_entries = self._search(
            search_base=search_base,
            search_filter=ADCSQueries.NTAUTH_STORE.filter,
            attributes=ADCSQueries.NTAUTH_STORE.attributes,
        )
        return parse_ntauth_stores(raw_entries, self._domain, self._domain_sid)

    def collect_aia_cas(self, verbose: bool = False) -> list["AIACA"]:
        """Collect AIA CAs."""
        from .ldap.queries import ADCSQueries

        search_base = f"CN=AIA,CN=Public Key Services,CN=Services,{self._config_dn}"
        raw_entries = self._search(
            search_base=search_base,
            search_filter=ADCSQueries.AIA_CA.filter,
            attributes=ADCSQueries.AIA_CA.attributes,
        )
        return parse_aia_cas(raw_entries, self._domain, self._domain_sid)
