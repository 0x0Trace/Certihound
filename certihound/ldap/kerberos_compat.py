"""
Work around ldap3's default Kerberos hostname handling.

ldap3 builds its GSSAPI target name as ``ldap@<host>`` with NameType
``hostbased_service``. On Linux this delegates hostname canonicalization to
MIT krb5, which — unless the user disables ``dns_canonicalize_hostname`` and
``rdns`` in ``krb5.conf`` — will do forward+reverse DNS on the hostname and
lowercase it before constructing the SPN. In pentest environments (HTB, lab
networks, VPNs) the result is almost always ``KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN``
surfaced as::

    Major (851968): Unspecified GSS failure. Minor code may provide more
    information, Minor (2529638919): Server not found in Kerberos database

This module patches ``ldap3.protocol.sasl.kerberos._posix_sasl_gssapi`` so
that when ``sasl_credentials[0]`` is a fully-qualified principal of the form
``service/host[@REALM]`` we use NameType ``kerberos_principal`` and skip krb5's
canonicalization entirely. Plain hostnames keep the original behavior.
"""

from __future__ import annotations

_patched = False


def install_kerberos_principal_shim() -> bool:
    """Monkey-patch ldap3 to honor fully-qualified Kerberos principals.

    Safe to call multiple times. Returns ``True`` if patched, ``False`` if
    the patch couldn't be applied (for example, ``gssapi`` is not installed
    or ldap3's internals changed).
    """
    global _patched
    if _patched:
        return True

    try:
        import gssapi  # noqa: F401
        from ldap3.protocol.sasl import kerberos as _k
    except ImportError:
        return False

    if getattr(_k, "_certihound_principal_patched", False):
        _patched = True
        return True

    original_posix = getattr(_k, "_posix_sasl_gssapi", None)
    if original_posix is None:
        return False

    def _patched_posix(connection, controls):
        target = None
        if connection.sasl_credentials:
            first = connection.sasl_credentials[0]
            if isinstance(first, str) and "/" in first:
                target = first

        if target is None:
            return original_posix(connection, controls)

        # Re-implement _posix_sasl_gssapi but with kerberos_principal NameType
        # and without the ldap@host canonicalization path.
        target_name = gssapi.Name(target, gssapi.NameType.kerberos_principal)
        authz_id, creds = _k._common_determine_authz_id_and_creds(connection)

        ctx = gssapi.SecurityContext(
            name=target_name,
            mech=gssapi.MechType.kerberos,
            creds=creds,
            channel_bindings=_k.get_channel_bindings(connection.socket),
        )
        in_token = None
        try:
            while True:
                out_token = ctx.step(in_token)
                if out_token is None:
                    out_token = ""
                result = _k.send_sasl_negotiation(connection, controls, out_token)
                in_token = result["saslCreds"]
                try:
                    if ctx.complete:
                        break
                except gssapi.exceptions.MissingContextError:
                    pass

            unwrapped = ctx.unwrap(in_token)
            client_security_layers = _k._common_process_end_token_get_security_layers(
                unwrapped.message
            )
            out_token = ctx.wrap(bytes(client_security_layers) + authz_id, False)
            return _k.send_sasl_negotiation(connection, controls, out_token.message)
        except (gssapi.exceptions.GSSError, _k.LDAPCommunicationError):
            _k.abort_sasl_negotiation(connection, controls)
            raise

    _k._posix_sasl_gssapi = _patched_posix
    _k._certihound_principal_patched = True
    _patched = True
    return True
