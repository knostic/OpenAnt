"""Shared filename sanitizer for checkpoint files."""

import hashlib


# #317 (panel round-3): the truncation threshold, EXPORTED so the checkpoint
# disambiguator's injectivity early-out imports the same constant instead of
# duplicating the literal (drift in one silently broke the other's
# "by construction" claim).
SAFE_FILENAME_MAX_LEN = 255 - 5 - 17  # leave room for .json (5) and _ + 16 hex (17) = 233


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
    max_len = SAFE_FILENAME_MAX_LEN

    if len(safe) > max_len:
        h = hashlib.sha256(unit_id.encode()).hexdigest()[:16]
        safe = safe[:max_len] + "_" + h

    return safe
