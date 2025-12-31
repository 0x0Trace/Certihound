"""LDAP connection adapters for integrating with external tools."""

from .impacket_adapter import ImpacketLDAPAdapter

__all__ = ["ImpacketLDAPAdapter"]
