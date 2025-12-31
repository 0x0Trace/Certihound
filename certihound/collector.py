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

    def _search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
    ) -> list[Any]:
        """Execute search using external connection."""
        # Handle different connection types
        conn = self._external_conn

        # Try ldap3 style
        if hasattr(conn, 'search') and hasattr(conn, 'entries'):
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
            )
            return list(conn.entries)

        # Try generic search method
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
