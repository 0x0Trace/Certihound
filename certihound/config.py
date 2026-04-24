"""Configuration management for CertiHound."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class Config:
    """CertiHound configuration."""

    # Domain settings
    domain: str = ""
    username: str | None = None
    password: str | None = None
    dc_ip: str | None = None

    # Authentication
    use_kerberos: bool = False
    use_ldaps: bool = False
    ca_cert: str | None = None
    ldap_port: int | None = None
    hashes: str | None = None  # LM:NT or :NT hash for pass-the-hash

    # Output settings
    output_dir: str = "./output"
    output_format: Literal["json", "zip", "both"] = "zip"

    # Collection options
    enum_only: bool = False  # Skip vulnerability detection
    collect_esc6_registry: bool = False  # Attempt registry collection for ESC6

    # Verbosity
    verbose: int = 0
    debug: bool = False

    @property
    def output_path(self) -> Path:
        """Get output directory as Path."""
        return Path(self.output_dir)

    def validate(self) -> list[str]:
        """Validate configuration. Returns list of errors."""
        errors = []

        if not self.domain:
            errors.append("Domain is required (-d/--domain)")

        has_secret = bool(self.password) or bool(self.hashes)
        if not self.use_kerberos and not (self.username and has_secret):
            errors.append(
                "Either username with password/hash (-u + -p or -H) or Kerberos (-k) is required"
            )

        if self.password and self.hashes:
            errors.append("Use either -p/--password or -H/--hashes, not both")

        if self.hashes:
            parts = self.hashes.split(":")
            if len(parts) == 1:
                nt = parts[0]
            elif len(parts) == 2:
                nt = parts[1]
            else:
                errors.append("Invalid --hashes format (expected LMHASH:NTHASH or NTHASH)")
                nt = ""
            if nt and (len(nt) != 32 or not all(c in "0123456789abcdefABCDEF" for c in nt)):
                errors.append("NT hash must be 32 hex characters")

        return errors


def get_banner() -> str:
    """Get CertiHound banner."""
    return """
   ______          __  _ __  __                      __
  / ____/__  _____/ /_(_) / / /___  __  ______  ____/ /
 / /   / _ \\/ ___/ __/ / /_/ / __ \\/ / / / __ \\/ __  /
/ /___/  __/ /  / /_/ / __  / /_/ / /_/ / / / / /_/ /
\\____/\\___/_/   \\__/_/_/ /_/\\____/\\__,_/_/ /_/\\__,_/

    Linux-native AD CS collector for BloodHound CE
                     v0.1.0
"""
