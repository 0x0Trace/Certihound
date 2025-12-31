"""LDAP result parsing utilities."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..objects.certtemplate import CertTemplate
    from ..objects.enterpriseca import EnterpriseCA
    from ..objects.rootca import RootCA
    from ..objects.ntauthstore import NTAuthStore
    from ..objects.aiaca import AIACA


class LDAPResultParser:
    """Parse raw LDAP results into usable data structures."""

    @staticmethod
    def get_attribute(entry: Any, attr_name: str, default: Any = None) -> Any:
        """Safely get an attribute value from an LDAP entry."""
        try:
            value = entry[attr_name]
            if value is None:
                return default
            # Check for multi-valued first (values), then single-valued (value)
            # This ensures multi-valued attributes like certificateTemplates work correctly
            if hasattr(value, "values") and value.values:
                # Return list if multiple values, single value otherwise
                if len(value.values) > 1:
                    return list(value.values)
                elif len(value.values) == 1:
                    return value.values[0]
            if hasattr(value, "value"):
                return value.value
            return value
        except (KeyError, IndexError, AttributeError):
            return default

    @staticmethod
    def get_attribute_raw(entry: Any, attr_name: str, default: bytes = b"") -> bytes:
        """Get raw bytes value of an attribute."""
        try:
            value = entry[attr_name]
            if hasattr(value, "raw_values") and value.raw_values:
                raw_value = value.raw_values[0]
                return raw_value if isinstance(raw_value, bytes) else default
            return default
        except (KeyError, IndexError, AttributeError):
            return default

    @staticmethod
    def get_int_attribute(entry: Any, attr_name: str, default: int = 0) -> int:
        """Get integer attribute value."""
        value = LDAPResultParser.get_attribute(entry, attr_name, default)
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def get_list_attribute(entry: Any, attr_name: str) -> list[str]:
        """Get list attribute value."""
        try:
            attr = entry[attr_name]
            if attr is None:
                return []
            # Prefer .values for multi-valued attributes
            if hasattr(attr, "values") and attr.values:
                return [str(v) for v in attr.values]
            if hasattr(attr, "value") and attr.value is not None:
                return [str(attr.value)]
            # Fallback for dict-like or direct list
            if isinstance(attr, list):
                return [str(v) for v in attr]
            if attr:
                return [str(attr)]
            return []
        except (KeyError, IndexError, AttributeError):
            return []

    @staticmethod
    def get_string_attribute(entry: Any, attr_name: str, default: str = "") -> str:
        """Get string attribute value."""
        value = LDAPResultParser.get_attribute(entry, attr_name, default)
        if value is None:
            return default
        return str(value)

    @staticmethod
    def parse_certificate_template(entry: Any, domain: str, domain_sid: str) -> dict:
        """Parse a certificate template LDAP entry."""
        parser = LDAPResultParser

        return {
            "cn": parser.get_string_attribute(entry, "cn"),
            "name": parser.get_string_attribute(entry, "name"),
            "displayName": parser.get_string_attribute(
                entry, "displayName", parser.get_string_attribute(entry, "cn")
            ),
            "objectGUID": parser.get_string_attribute(entry, "objectGUID"),
            "distinguishedName": parser.get_string_attribute(entry, "distinguishedName"),
            "domain": domain,
            "domain_sid": domain_sid,
            "nTSecurityDescriptor": parser.get_attribute_raw(entry, "nTSecurityDescriptor"),
            "msPKI-Certificate-Name-Flag": parser.get_int_attribute(
                entry, "msPKI-Certificate-Name-Flag"
            ),
            "msPKI-Enrollment-Flag": parser.get_int_attribute(entry, "msPKI-Enrollment-Flag"),
            "msPKI-RA-Signature": parser.get_int_attribute(entry, "msPKI-RA-Signature"),
            "msPKI-Certificate-Application-Policy": parser.get_list_attribute(
                entry, "msPKI-Certificate-Application-Policy"
            ),
            "msPKI-RA-Application-Policies": parser.get_list_attribute(
                entry, "msPKI-RA-Application-Policies"
            ),
            "pKIExtendedKeyUsage": parser.get_list_attribute(entry, "pKIExtendedKeyUsage"),
            "pKIExpirationPeriod": parser.get_attribute_raw(entry, "pKIExpirationPeriod"),
            "pKIOverlapPeriod": parser.get_attribute_raw(entry, "pKIOverlapPeriod"),
            "msPKI-Template-Schema-Version": parser.get_int_attribute(
                entry, "msPKI-Template-Schema-Version", 1
            ),
            "msPKI-Template-Minor-Revision": parser.get_int_attribute(
                entry, "msPKI-Template-Minor-Revision"
            ),
            "msPKI-Private-Key-Flag": parser.get_int_attribute(entry, "msPKI-Private-Key-Flag"),
            "msPKI-Minimal-Key-Size": parser.get_int_attribute(entry, "msPKI-Minimal-Key-Size"),
            "flags": parser.get_int_attribute(entry, "flags"),
            "revision": parser.get_int_attribute(entry, "revision"),
        }

    @staticmethod
    def parse_enterprise_ca(entry: Any, domain: str, domain_sid: str) -> dict:
        """Parse an Enterprise CA LDAP entry."""
        parser = LDAPResultParser

        return {
            "cn": parser.get_string_attribute(entry, "cn"),
            "name": parser.get_string_attribute(entry, "name"),
            "displayName": parser.get_string_attribute(
                entry, "displayName", parser.get_string_attribute(entry, "cn")
            ),
            "objectGUID": parser.get_string_attribute(entry, "objectGUID"),
            "distinguishedName": parser.get_string_attribute(entry, "distinguishedName"),
            "domain": domain,
            "domain_sid": domain_sid,
            "dNSHostName": parser.get_string_attribute(entry, "dNSHostName"),
            "certificateTemplates": parser.get_list_attribute(entry, "certificateTemplates"),
            "cACertificate": parser.get_attribute_raw(entry, "cACertificate"),
            "cACertificateDN": parser.get_string_attribute(entry, "cACertificateDN"),
            "nTSecurityDescriptor": parser.get_attribute_raw(entry, "nTSecurityDescriptor"),
            "flags": parser.get_int_attribute(entry, "flags"),
        }

    @staticmethod
    def parse_root_ca(entry: Any, domain: str, domain_sid: str) -> dict:
        """Parse a Root CA LDAP entry."""
        parser = LDAPResultParser

        return {
            "cn": parser.get_string_attribute(entry, "cn"),
            "name": parser.get_string_attribute(entry, "name"),
            "objectGUID": parser.get_string_attribute(entry, "objectGUID"),
            "distinguishedName": parser.get_string_attribute(entry, "distinguishedName"),
            "domain": domain,
            "domain_sid": domain_sid,
            "cACertificate": parser.get_attribute_raw(entry, "cACertificate"),
            "certificateRevocationList": parser.get_attribute_raw(
                entry, "certificateRevocationList"
            ),
        }

    @staticmethod
    def parse_ntauth_store(entry: Any, domain: str, domain_sid: str) -> dict:
        """Parse NTAuth store LDAP entry."""
        parser = LDAPResultParser

        # cACertificate can be multi-valued
        ca_certs = []
        try:
            raw_values = entry["cACertificate"].raw_values
            ca_certs = list(raw_values) if raw_values else []
        except (KeyError, AttributeError):
            pass

        return {
            "cn": parser.get_string_attribute(entry, "cn"),
            "objectGUID": parser.get_string_attribute(entry, "objectGUID"),
            "distinguishedName": parser.get_string_attribute(entry, "distinguishedName"),
            "domain": domain,
            "domain_sid": domain_sid,
            "cACertificate": ca_certs,
        }

    @staticmethod
    def parse_aia_ca(entry: Any, domain: str, domain_sid: str) -> dict:
        """Parse an AIA CA LDAP entry."""
        parser = LDAPResultParser

        return {
            "cn": parser.get_string_attribute(entry, "cn"),
            "name": parser.get_string_attribute(entry, "name"),
            "objectGUID": parser.get_string_attribute(entry, "objectGUID"),
            "distinguishedName": parser.get_string_attribute(entry, "distinguishedName"),
            "domain": domain,
            "domain_sid": domain_sid,
            "cACertificate": parser.get_attribute_raw(entry, "cACertificate"),
        }


# Convenience functions for converting LDAP entries to object models

def parse_cert_templates(
    entries: list[Any], domain: str = "", domain_sid: str = ""
) -> list["CertTemplate"]:
    """Convert LDAP entries to CertTemplate objects."""
    from ..objects.certtemplate import CertTemplate

    templates = []
    for entry in entries:
        try:
            # Try parsing as dict first (from LDAPResultParser)
            if isinstance(entry, dict):
                template = CertTemplate.from_ldap_entry(entry, domain, domain_sid)
            else:
                # Parse raw LDAP entry
                parsed = LDAPResultParser.parse_certificate_template(entry, domain, domain_sid)
                template = CertTemplate.from_ldap_entry(parsed, domain, domain_sid)
            templates.append(template)
        except Exception:
            # Skip entries that fail to parse
            pass
    return templates


def parse_enterprise_cas(
    entries: list[Any], domain: str = "", domain_sid: str = ""
) -> list["EnterpriseCA"]:
    """Convert LDAP entries to EnterpriseCA objects."""
    from ..objects.enterpriseca import EnterpriseCA

    cas = []
    for entry in entries:
        try:
            if isinstance(entry, dict):
                ca = EnterpriseCA.from_ldap_entry(entry, domain, domain_sid)
            else:
                parsed = LDAPResultParser.parse_enterprise_ca(entry, domain, domain_sid)
                ca = EnterpriseCA.from_ldap_entry(parsed, domain, domain_sid)
            cas.append(ca)
        except Exception:
            pass
    return cas


def parse_root_cas(
    entries: list[Any], domain: str = "", domain_sid: str = ""
) -> list["RootCA"]:
    """Convert LDAP entries to RootCA objects."""
    from ..objects.rootca import RootCA

    cas = []
    for entry in entries:
        try:
            if isinstance(entry, dict):
                ca = RootCA.from_ldap_entry(entry, domain, domain_sid)
            else:
                parsed = LDAPResultParser.parse_root_ca(entry, domain, domain_sid)
                ca = RootCA.from_ldap_entry(parsed, domain, domain_sid)
            cas.append(ca)
        except Exception:
            pass
    return cas


def parse_ntauth_stores(
    entries: list[Any], domain: str = "", domain_sid: str = ""
) -> list["NTAuthStore"]:
    """Convert LDAP entries to NTAuthStore objects."""
    from ..objects.ntauthstore import NTAuthStore

    stores = []
    for entry in entries:
        try:
            if isinstance(entry, dict):
                store = NTAuthStore.from_ldap_entry(entry, domain, domain_sid)
            else:
                parsed = LDAPResultParser.parse_ntauth_store(entry, domain, domain_sid)
                store = NTAuthStore.from_ldap_entry(parsed, domain, domain_sid)
            stores.append(store)
        except Exception:
            pass
    return stores


def parse_aia_cas(
    entries: list[Any], domain: str = "", domain_sid: str = ""
) -> list["AIACA"]:
    """Convert LDAP entries to AIACA objects."""
    from ..objects.aiaca import AIACA

    cas = []
    for entry in entries:
        try:
            if isinstance(entry, dict):
                ca = AIACA.from_ldap_entry(entry, domain, domain_sid)
            else:
                parsed = LDAPResultParser.parse_aia_ca(entry, domain, domain_sid)
                ca = AIACA.from_ldap_entry(parsed, domain, domain_sid)
            cas.append(ca)
        except Exception:
            pass
    return cas
