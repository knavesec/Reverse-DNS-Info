"""Date normalization.

Registries disagree on date format, and several are genuinely ambiguous:
.pt writes ``03/10/1991`` meaning 3 October, US-influenced registries write the
same string meaning 10 March. We therefore take an explicit day-first hint from
the TLD table rather than guessing, and we try an explicit format list instead
of a fuzzy parser so behaviour is deterministic and testable.
"""
import re
from datetime import datetime
from typing import Optional

# Formats that are unambiguous regardless of locale.
_UNAMBIGUOUS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
    "%Y.%m.%d %H:%M:%S",
    "%Y.%m.%d",
    "%Y%m%d %H:%M:%S",
    "%Y%m%d",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y",
    "%d %b %Y %H:%M:%S",
    "%d %b %Y",
    "%b %d %Y",
    "%a %b %d %Y",
    "%a %b %d %H:%M:%S %Y",
)

# Ambiguous numeric orderings, tried in an order chosen by the day_first hint.
_DAY_FIRST = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
              "%d.%m.%Y %H:%M:%S", "%d.%m.%Y",
              "%d-%m-%Y %H:%M:%S", "%d-%m-%Y")
_MONTH_FIRST = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y",
                "%m.%d.%Y %H:%M:%S", "%m.%d.%Y",
                "%m-%d-%Y %H:%M:%S", "%m-%d-%Y")

# Trailing timezone abbreviations / annotations we discard, e.g. .jp's "(JST)".
_TRAILING_NOISE = re.compile(
    r"\s*(\((?:[A-Z]{2,5}|UTC[+-]?\d{0,4})\)|\b(?:UTC|GMT|JST|CET|CEST|EST|EDT)\b)\s*$",
    re.IGNORECASE,
)
_FRACTION = re.compile(r"(\.\d{1,6})\d+")


def _clean(value: str) -> str:
    s = " ".join(value.strip().split())
    # Drop leading labels some registries prepend, e.g. "before 2020-01-01".
    s = re.sub(r"^(before|after|on)\s+", "", s, flags=re.IGNORECASE)
    for _ in range(2):
        s = _TRAILING_NOISE.sub("", s).strip()
    return s.rstrip(".").strip()


def _try_iso(s: str) -> Optional[datetime]:
    """ISO 8601, including ``Z`` suffix and over-long fractional seconds."""
    t = s.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}[T ]", t):
        return None
    t = t.replace(" ", "T", 1)
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    # datetime.fromisoformat accepts at most 6 fractional digits.
    t = _FRACTION.sub(r"\1", t)
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def parse_date(value: Optional[str], day_first: bool = False) -> Optional[datetime]:
    """Best-effort parse. Returns None rather than guessing wildly."""
    if not value:
        return None
    s = _clean(value)
    if not s or s.lower() in ("none", "null", "-", "n/a", "not available"):
        return None

    dt = _try_iso(s)
    if dt is not None:
        return dt

    ambiguous = _DAY_FIRST + _MONTH_FIRST if day_first else _MONTH_FIRST + _DAY_FIRST
    for fmt in _UNAMBIGUOUS + ambiguous:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    # Last resort: a bare ISO date hiding inside a longer string.
    m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", s)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d")
        except ValueError:
            pass
    return None
