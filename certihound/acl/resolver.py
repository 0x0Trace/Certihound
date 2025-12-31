"""SID resolution for ACE principals."""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from ldap3 import SUBTREE

if TYPE_CHECKING:
    from ..ldap.connection import LDAPConnection


class ResolvedPrincipal(NamedTuple):
    """Resolved principal information."""

    sid: str
    name: str
    distinguished_name: str
    object_type: str  # User, Group, Computer, etc.


class SIDResolver:
    """Resolve SIDs to principal names via LDAP."""

    # Well-known SIDs that don't need LDAP resolution
    WELL_KNOWN_SIDS = {
        "S-1-0-0": ("Null SID", "Unknown"),
        "S-1-1-0": ("Everyone", "Group"),
        "S-1-2-0": ("Local", "Group"),
        "S-1-2-1": ("Console Logon", "Group"),
        "S-1-3-0": ("Creator Owner", "User"),
        "S-1-3-1": ("Creator Group", "Group"),
        "S-1-5-1": ("Dialup", "Group"),
        "S-1-5-2": ("Network", "Group"),
        "S-1-5-3": ("Batch", "Group"),
        "S-1-5-4": ("Interactive", "Group"),
        "S-1-5-6": ("Service", "Group"),
        "S-1-5-7": ("Anonymous", "Group"),
        "S-1-5-9": ("Enterprise Domain Controllers", "Group"),
        "S-1-5-10": ("Self", "User"),
        "S-1-5-11": ("Authenticated Users", "Group"),
        "S-1-5-12": ("Restricted Code", "Group"),
        "S-1-5-13": ("Terminal Server User", "Group"),
        "S-1-5-14": ("Remote Interactive Logon", "Group"),
        "S-1-5-15": ("This Organization", "Group"),
        "S-1-5-17": ("IUSR", "User"),
        "S-1-5-18": ("NT AUTHORITY\\SYSTEM", "User"),
        "S-1-5-19": ("NT AUTHORITY\\LOCAL SERVICE", "User"),
        "S-1-5-20": ("NT AUTHORITY\\NETWORK SERVICE", "User"),
        "S-1-5-32-544": ("BUILTIN\\Administrators", "Group"),
        "S-1-5-32-545": ("BUILTIN\\Users", "Group"),
        "S-1-5-32-546": ("BUILTIN\\Guests", "Group"),
        "S-1-5-32-547": ("BUILTIN\\Power Users", "Group"),
        "S-1-5-32-548": ("BUILTIN\\Account Operators", "Group"),
        "S-1-5-32-549": ("BUILTIN\\Server Operators", "Group"),
        "S-1-5-32-550": ("BUILTIN\\Print Operators", "Group"),
        "S-1-5-32-551": ("BUILTIN\\Backup Operators", "Group"),
        "S-1-5-32-552": ("BUILTIN\\Replicators", "Group"),
        "S-1-5-32-554": ("BUILTIN\\Pre-Windows 2000 Compatible Access", "Group"),
        "S-1-5-32-555": ("BUILTIN\\Remote Desktop Users", "Group"),
        "S-1-5-32-556": ("BUILTIN\\Network Configuration Operators", "Group"),
        "S-1-5-32-557": ("BUILTIN\\Incoming Forest Trust Builders", "Group"),
        "S-1-5-32-558": ("BUILTIN\\Performance Monitor Users", "Group"),
        "S-1-5-32-559": ("BUILTIN\\Performance Log Users", "Group"),
        "S-1-5-32-560": ("BUILTIN\\Windows Authorization Access Group", "Group"),
        "S-1-5-32-561": ("BUILTIN\\Terminal Server License Servers", "Group"),
        "S-1-5-32-562": ("BUILTIN\\Distributed COM Users", "Group"),
        "S-1-5-32-568": ("BUILTIN\\IIS_IUSRS", "Group"),
        "S-1-5-32-569": ("BUILTIN\\Cryptographic Operators", "Group"),
        "S-1-5-32-573": ("BUILTIN\\Event Log Readers", "Group"),
        "S-1-5-32-574": ("BUILTIN\\Certificate Service DCOM Access", "Group"),
        "S-1-5-32-575": ("BUILTIN\\RDS Remote Access Servers", "Group"),
        "S-1-5-32-576": ("BUILTIN\\RDS Endpoint Servers", "Group"),
        "S-1-5-32-577": ("BUILTIN\\RDS Management Servers", "Group"),
        "S-1-5-32-578": ("BUILTIN\\Hyper-V Administrators", "Group"),
        "S-1-5-32-579": ("BUILTIN\\Access Control Assistance Operators", "Group"),
        "S-1-5-32-580": ("BUILTIN\\Remote Management Users", "Group"),
    }

    # Well-known domain RIDs
    WELL_KNOWN_RIDS = {
        500: ("Administrator", "User"),
        501: ("Guest", "User"),
        502: ("KRBTGT", "User"),
        512: ("Domain Admins", "Group"),
        513: ("Domain Users", "Group"),
        514: ("Domain Guests", "Group"),
        515: ("Domain Computers", "Group"),
        516: ("Domain Controllers", "Group"),
        517: ("Cert Publishers", "Group"),
        518: ("Schema Admins", "Group"),
        519: ("Enterprise Admins", "Group"),
        520: ("Group Policy Creator Owners", "Group"),
        521: ("Read-only Domain Controllers", "Group"),
        522: ("Cloneable Domain Controllers", "Group"),
        525: ("Protected Users", "Group"),
        526: ("Key Admins", "Group"),
        527: ("Enterprise Key Admins", "Group"),
        553: ("RAS and IAS Servers", "Group"),
        571: ("Allowed RODC Password Replication Group", "Group"),
        572: ("Denied RODC Password Replication Group", "Group"),
    }

    def __init__(self, connection: "LDAPConnection | None" = None):
        self.connection = connection
        self._cache: dict[str, ResolvedPrincipal] = {}
        self._domain_sid: str | None = None

    def set_domain_sid(self, domain_sid: str) -> None:
        """Set the domain SID for RID resolution."""
        self._domain_sid = domain_sid

    def resolve(self, sid: str) -> ResolvedPrincipal:
        """Resolve a SID to principal information."""
        # Check cache first
        if sid in self._cache:
            return self._cache[sid]

        # Check well-known SIDs
        if sid in self.WELL_KNOWN_SIDS:
            name, obj_type = self.WELL_KNOWN_SIDS[sid]
            result = ResolvedPrincipal(
                sid=sid,
                name=name,
                distinguished_name="",
                object_type=obj_type,
            )
            self._cache[sid] = result
            return result

        # Check well-known domain RIDs
        if self._domain_sid and sid.startswith(self._domain_sid):
            try:
                rid = int(sid.split("-")[-1])
                if rid in self.WELL_KNOWN_RIDS:
                    name, obj_type = self.WELL_KNOWN_RIDS[rid]
                    result = ResolvedPrincipal(
                        sid=sid,
                        name=name,
                        distinguished_name="",
                        object_type=obj_type,
                    )
                    self._cache[sid] = result
                    return result
            except (ValueError, IndexError):
                pass

        # Try LDAP resolution
        if self.connection:
            ldap_result = self._resolve_via_ldap(sid)
            if ldap_result:
                self._cache[sid] = ldap_result
                return ldap_result

        # Return unresolved
        result = ResolvedPrincipal(
            sid=sid,
            name=sid,
            distinguished_name="",
            object_type="Unknown",
        )
        self._cache[sid] = result
        return result

    def _resolve_via_ldap(self, sid: str) -> ResolvedPrincipal | None:
        """Resolve SID via LDAP query."""
        if not self.connection:
            return None

        try:
            # Convert SID to binary for LDAP search
            from ..utils.convert import sid_to_bytes

            sid_bytes = sid_to_bytes(sid)
            if not sid_bytes:
                return None

            # Escape for LDAP filter
            sid_escaped = "".join(f"\\{b:02x}" for b in sid_bytes)

            self.connection.search(
                search_base=self.connection.config.domain_dn,
                search_filter=f"(objectSid={sid_escaped})",
                attributes=["sAMAccountName", "distinguishedName", "objectClass", "name"],
                search_scope=SUBTREE,
            )

            if self.connection.connection.entries:
                entry = self.connection.connection.entries[0]

                name = str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.name)
                dn = str(entry.distinguishedName)
                object_classes = list(entry.objectClass.values) if entry.objectClass else []

                # Determine object type
                obj_type = "Unknown"
                if "user" in object_classes:
                    obj_type = "User"
                elif "computer" in object_classes:
                    obj_type = "Computer"
                elif "group" in object_classes:
                    obj_type = "Group"

                return ResolvedPrincipal(
                    sid=sid,
                    name=name,
                    distinguished_name=dn,
                    object_type=obj_type,
                )

        except Exception:
            pass

        return None

    def resolve_many(self, sids: list[str]) -> dict[str, ResolvedPrincipal]:
        """Resolve multiple SIDs."""
        results = {}
        for sid in sids:
            results[sid] = self.resolve(sid)
        return results

    def get_principal_type_for_bloodhound(self, sid: str) -> str:
        """Get principal type in BloodHound format."""
        resolved = self.resolve(sid)
        type_mapping = {
            "User": "User",
            "Group": "Group",
            "Computer": "Computer",
            "Unknown": "Base",
        }
        return type_mapping.get(resolved.object_type, "Base")
