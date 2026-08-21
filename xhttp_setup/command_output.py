"""Small semantic parsers for human-oriented command output.

Only presentation differences (case, whitespace, and punctuation) are
normalized here. Machine fields, paths, rule bodies, keys, and identifiers
must still be validated by their owning module.
"""

from __future__ import annotations

import re
import unicodedata


_WORD = re.compile(r"[^\W_]+", re.UNICODE)


def english_words(value: str) -> tuple[str, ...]:
    """Return case-insensitive words, ignoring presentation punctuation."""

    normalized = unicodedata.normalize("NFKC", value).casefold()
    return tuple(_WORD.findall(normalized))


def parse_ufw_status(output: str) -> bool:
    """Parse the semantic state from ``ufw status numbered`` output.

    ``True`` means active and ``False`` means inactive. An inactive response
    must not contain a table or any other payload; callers validate the
    numbered table separately for an active response.
    """

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("missing UFW status")
    state = english_words(lines[0])
    if state == ("status", "active"):
        return True
    if state == ("status", "inactive") and len(lines) == 1:
        return False
    raise ValueError("ambiguous UFW status")
