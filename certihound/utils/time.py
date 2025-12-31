"""Time and duration parsing utilities."""

from __future__ import annotations

import struct
from datetime import timedelta


def parse_validity_period(period_bytes: bytes) -> str:
    """
    Parse pKIExpirationPeriod or pKIOverlapPeriod to human-readable string.

    These are stored as negative FILETIME intervals (100-nanosecond units).
    """
    if not period_bytes or len(period_bytes) != 8:
        return ""

    try:
        # Unpack as signed 64-bit little-endian
        value = struct.unpack("<q", period_bytes)[0]

        # Convert from negative 100-nanosecond intervals to positive seconds
        if value >= 0:
            return ""

        seconds = abs(value) / 10000000

        # Convert to days, hours, minutes
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)

        if days >= 365:
            years = days // 365
            remaining_days = days % 365
            if remaining_days > 0:
                return f"{years} years, {remaining_days} days"
            return f"{years} years"
        elif days > 0:
            if hours > 0:
                return f"{days} days, {hours} hours"
            return f"{days} days"
        elif hours > 0:
            if minutes > 0:
                return f"{hours} hours, {minutes} minutes"
            return f"{hours} hours"
        else:
            return f"{minutes} minutes"

    except (struct.error, ValueError):
        return ""


def parse_validity_period_seconds(period_bytes: bytes) -> int:
    """Parse validity period to seconds."""
    if not period_bytes or len(period_bytes) != 8:
        return 0

    try:
        value = struct.unpack("<q", period_bytes)[0]
        if value >= 0:
            return 0
        return int(abs(value) / 10000000)
    except (struct.error, ValueError):
        return 0


def validity_to_timedelta(period_bytes: bytes) -> timedelta | None:
    """Parse validity period to timedelta."""
    seconds = parse_validity_period_seconds(period_bytes)
    if seconds > 0:
        return timedelta(seconds=seconds)
    return None


def format_duration(seconds: int) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds <= 0:
        return "0 seconds"

    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if secs > 0 and not parts:
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")

    return ", ".join(parts) if parts else "0 seconds"


def create_validity_period(days: int) -> bytes:
    """Create validity period bytes from days."""
    # Convert days to negative 100-nanosecond intervals
    seconds = days * 86400
    value = -(seconds * 10000000)
    return struct.pack("<q", value)
