"""
CertiHound - Linux-native AD CS collector for BloodHound CE

A Python library for enumerating Active Directory Certificate Services (ADCS)
and exporting to BloodHound CE format for attack path visualization.

Basic Usage (Standalone):
    ```python
    from certihound import ADCSCollector, BloodHoundCEExporter
    from certihound.ldap.connection import LDAPConnection, LDAPConfig

    # Setup connection
    config = LDAPConfig(
        domain="corp.local",
        username="user",
        password="password",
        dc_ip="10.10.10.10",
        use_ldaps=True,
    )

    # Collect and export
    with LDAPConnection(config) as conn:
        collector = ADCSCollector(conn)
        data = collector.collect_all()

        exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
        result = exporter.export(data)
        result.write_zip("bloodhound_adcs.zip")
    ```

Integration with NetExec (impacket-based):
    ```python
    from certihound import ADCSCollector, BloodHoundCEExporter
    from certihound.adapters import ImpacketLDAPAdapter

    # In your NetExec ldap.py adcs() method:
    adapter = ImpacketLDAPAdapter(
        search_func=self.search,  # NetExec's search method
        domain=self.domain,
        domain_sid=self.sid_domain,
    )

    collector = ADCSCollector.from_external(
        ldap_connection=adapter,
        domain=self.domain,
        domain_sid=self.sid_domain,
    )
    data = collector.collect_all()

    exporter = BloodHoundCEExporter(data.domain, data.domain_sid)
    result = exporter.export(data)
    result.write_zip("adcs_bloodhound.zip")
    ```

Integration with ldap3:
    ```python
    from certihound import ADCSCollector, BloodHoundCEExporter

    # ldap3 connections work directly (no adapter needed)
    collector = ADCSCollector.from_external(
        ldap_connection=your_ldap3_conn,
        domain="corp.local",
        domain_sid="S-1-5-21-...",
    )
    data = collector.collect_all()
    ```
"""

__version__ = "0.1.0"
__author__ = "CertiHound Contributors"

# Main API classes
from .collector import ADCSCollector, ADCSData, ExternalADCSCollector
from .exporter import BloodHoundCEExporter, ExportResult

# LDAP utilities (for standalone usage)
from .ldap.connection import LDAPConnection, LDAPConfig

# Adapters for external tool integration
from .adapters import ImpacketLDAPAdapter

# Data models
from .objects.certtemplate import CertTemplate
from .objects.enterpriseca import EnterpriseCA
from .objects.rootca import RootCA
from .objects.ntauthstore import NTAuthStore
from .objects.aiaca import AIACA

# Detection (optional)
from .detection import (
    detect_esc1,
    detect_esc3_agent,
    detect_esc3_target,
    detect_esc4,
    detect_esc6,
    detect_esc9,
    detect_esc10,
    detect_esc13,
)

__all__ = [
    # Version
    "__version__",
    # Main API
    "ADCSCollector",
    "ADCSData",
    "ExternalADCSCollector",
    "BloodHoundCEExporter",
    "ExportResult",
    # LDAP
    "LDAPConnection",
    "LDAPConfig",
    # Adapters
    "ImpacketLDAPAdapter",
    # Models
    "CertTemplate",
    "EnterpriseCA",
    "RootCA",
    "NTAuthStore",
    "AIACA",
    # Detection
    "detect_esc1",
    "detect_esc3_agent",
    "detect_esc3_target",
    "detect_esc4",
    "detect_esc6",
    "detect_esc9",
    "detect_esc10",
    "detect_esc13",
]
