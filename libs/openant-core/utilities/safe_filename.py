"""Shared filename sanitizer for checkpoint files."""

import hashlib


def safe_filename(unit_id: str) -> str:
    """Convert a unit ID to a safe filename.

    Handles long filenames by truncating and appending a hash for uniqueness.
    macOS has a 255 character limit for filenames.
    """
    safe = (unit_id
            .replace("/", "__")
            .replace("\\", "__")
            .replace(":", "_")
            .replace(" ", "_"))

    # Leave room for .json extension (5 chars) and hash suffix (17 chars: _ + 16 hex)
    max_len = 255 - 5 - 17  # = 233

    if len(safe) > max_len:
        h = hashlib.sha256(unit_id.encode()).hexdigest()[:16]
        safe = safe[:max_len] + "_" + h

    return safe
