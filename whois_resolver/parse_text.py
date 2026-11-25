"""Generic port-43 response parser.

One tokenizer plus the alias tables in ``aliases.py`` handles every fixture in
``fixtures/`` except .fr and .at, whose responses are structured as separate
blocks joined by handles and get a per-TLD override in ``overrides.py``.

The tokenizer recognizes four line shapes, which between them cover the formats
in the wild:

  ``Key: value``          ICANN gTLDs, .pt, .nl, .dk, .it, .be, .ru, .se, .de
  ``[Key]  value``        .jp
  ``Section`` / ``[Sec]`` .it, .be, .nl, .dk, legacy .de
  indented continuation   multi-line addresses in .it, .jp, .nl, .be

A section's body indentation is learned from its first content line. That
matters because .nl emits top-level keys (``DNSSEC:``, ``Creation Date:``)
*after* its indented ``Registrar:`` block, while .jp's ``Contact Information:``
body is not indented at all — so neither "sections end at a blank line" nor
"sections run to the next header" is correct on its own.
"""
import re
from typing import List, NamedTuple, Optional, Tuple

from . import aliases
from .dates import parse_date
from .model import CONTACT_LIST_FIELDS, CONTACT_ROLES, Registration

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# "[Key] value" but not banner text like "[ JPRS database provides ... ]".
_BRACKET_RE = re.compile(r"^\[([^\]\s][^\]]*)\]\s*(.*)$")
_KV_RE = re.compile(r"^([^:：]{1,60}?)[:：]\s*(.*)$")
_COMMENT_START = ("%", "#", "*", ";")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$")
# Raw DNS records some registries append (.pt emits "dns.pt IN DS 13 2 <hash>").
# Without this they look like bare continuation values and get mistaken for
# nameservers.
_DNS_RECORD_RE = re.compile(r"\bIN\s+(DS|DNSKEY|RRSIG|NS|A|AAAA)\b")

CONTACT_SECTIONS = frozenset(CONTACT_ROLES)


class Event(NamedTuple):
    kind: str          # "kv" | "section" | "bare" | "blank"
    key: str
    value: str
    indented: bool


def _strip_comment_marker(line: str) -> str:
    s = line.strip()
    while s[:1] in _COMMENT_START:
        s = s[1:].strip()
    return s


def detect_not_found(text: str) -> bool:
    """True if the response explicitly says the domain does not exist.

    Two shapes occur. Most registries lead with the phrase ("No match for ..."),
    but some append it instead — whois.dns.pt answers a free domain with
    ``example.pt - No Match``. The suffix form is only accepted on a line with no
    colon, since a data-bearing ``Key: value`` line could legitimately contain
    one of these phrases.
    """
    for raw in text.splitlines():
        s = _strip_comment_marker(raw).lower()
        if not s:
            continue
        if s.startswith(aliases.NOT_FOUND_PREFIXES):
            return True
        if ":" not in s and len(s) < 200:
            if any(marker in s for marker in aliases.NOT_FOUND_PREFIXES):
                return True
    return False


def detect_refusal(text: str) -> Optional[str]:
    """Return the offending line if the server refused to answer."""
    for raw in text.splitlines():
        s = _strip_comment_marker(raw)
        low = s.lower()
        if not low:
            continue
        for marker in aliases.REFUSAL_MARKERS:
            if marker in low:
                return s
    return None


#: Shared with the RDAP parser — both transports carry the same placeholders.
is_redacted_value = aliases.is_redacted_value


def _truncate_footer(lines: List[str]) -> List[str]:
    kept: List[str] = []
    for line in lines:
        if _strip_comment_marker(line).lower().startswith(aliases.FOOTER_PREFIXES):
            break
        kept.append(line)
    return kept


def clean_nameserver(value: str) -> Optional[str]:
    """Extract the hostname from the many nameserver spellings.

    ``ns1.denic.de 77.67.63.106``, ``ns5.nic.ru. 31.177.67.100, 2a02:...``,
    ``ns1.dnsbelgium.be (52.213.12.197)``, ``b.dns.pt | IPv4: 194.0.25.23``
    all reduce to the leading hostname.
    """
    s = value.strip()
    if not s:
        return None
    host = re.split(r"[\s|,(;]", s, maxsplit=1)[0]
    host = host.strip().strip(".,").lower()
    if not host or "." not in host:
        return None
    if not _HOSTNAME_RE.match(host):
        return None
    return host


def split_statuses(value: str) -> List[str]:
    """Handle ``REGISTERED, DELEGATED, VERIFIED`` and EPP ``status <url>``.

    The EPP URL suffix is written bare by the registry (``clientTransferProhibited
    https://icann.org/epp#...``) but parenthesized by some registrars, so both
    spellings must reduce to the same token — otherwise a referral chase reports
    every status twice.
    """
    out: List[str] = []
    for part in value.split(","):
        p = " ".join(part.split())
        if not p:
            continue
        tokens = p.split()
        if len(tokens) > 1 and tokens[1].strip("()[]<>").lower().startswith(
            ("http://", "https://")
        ):
            p = tokens[0]
        if p not in out:
            out.append(p)
    return out


def clean_email(value: str) -> Optional[str]:
    """Return the address in ``value``, or None if there isn't one.

    Registrars often put a web form where an address belongs ("Select Request
    Email Form at https://..."). ``emails`` is the highest-signal field for
    correlating domains, so storing that text would invent a match between every
    domain behind the same registrar.
    """
    s = value.strip().strip("<>").rstrip(".")
    if aliases.looks_like_email(s):
        return s.lower()
    found = _EMAIL_RE.search(value)
    return found.group(0).lower() if found else None


def _is_skippable(stripped: str) -> bool:
    if stripped[:1] in _COMMENT_START:
        return True
    if stripped.startswith("[ ") or stripped.startswith(">>>"):
        return True
    return bool(_DNS_RECORD_RE.search(stripped))


def _opens_a_block(lines: List[str], index: int) -> bool:
    """Does the value-less key at ``lines[index]`` head an indented block?

    ``Registrar:`` with nothing after it heads a block in .nl and .be, but is
    just an empty field in .at — where treating it as a section would swallow
    the rest of the record. The difference is visible only in what follows: a
    block's body is either indented (.nl, .be, .it) or written with bracketed
    keys (.jp's ``Contact Information:`` / ``[Name]``).
    """
    for raw in lines[index + 1:]:
        stripped = raw.strip()
        if not stripped:
            continue
        if _is_skippable(stripped):
            continue
        if raw[:1] in (" ", "\t"):
            return True
        return bool(_BRACKET_RE.match(stripped))
    return False


def tokenize(text: str) -> List[Event]:
    events: List[Event] = []
    lines = _truncate_footer(
        text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    )

    for index, raw in enumerate(lines):
        if not raw.strip():
            events.append(Event("blank", "", "", False))
            continue

        stripped = raw.strip()
        if _is_skippable(stripped):
            continue

        indented = raw[:1] in (" ", "\t")

        m = _BRACKET_RE.match(stripped)
        if m:
            key, value = m.group(1).strip(), m.group(2).strip()
            # "[Holder]" is a section; "[Web Page]" with no value is a key.
            if not value and aliases.resolve_section(key) and _opens_a_block(lines, index):
                events.append(Event("section", key, "", indented))
            else:
                events.append(Event("kv", key, value, indented))
            continue

        m = _KV_RE.match(stripped)
        if m:
            key, value = m.group(1).strip(), m.group(2).strip()
            if not value and aliases.resolve_section(key) and _opens_a_block(lines, index):
                events.append(Event("section", key, "", indented))
            else:
                events.append(Event("kv", key, value, indented))
            continue

        # No colon at all: an unambiguous section header, or a bare value.
        if not indented and aliases.resolve_section(stripped):
            events.append(Event("section", stripped, "", indented))
        else:
            events.append(Event("bare", "", stripped, indented))
    return events


class _Parser:
    def __init__(self, reg: Registration, tld: str):
        self.reg = reg
        self.day_first = tld in aliases.DAY_FIRST_TLDS
        self.section: Optional[str] = None
        # None until the section's first content line reveals its indentation.
        self.section_indent: Optional[bool] = None
        # Where a continuation line appends: ("contact", role, field) | ("list", attr)
        self.last_target: Optional[Tuple[str, ...]] = None
        self.redaction_noted = False

    # -- value application ------------------------------------------------
    def apply(self, target: str, value: str) -> None:
        self.last_target = None
        if not value or target == "!ignore":
            return
        reg = self.reg

        if target in ("created", "updated", "expires", "transferred"):
            dt = parse_date(value, day_first=self.day_first)
            if dt is None:
                reg.add_unmapped(f"!unparsed_date:{target}", value)
            elif getattr(reg, target) is None:
                setattr(reg, target, dt)
            return

        if target == "statuses":
            for s in split_statuses(value):
                reg.add_to_list("statuses", s)
            return

        if target == "name_servers":
            ns = clean_nameserver(value)
            if ns:
                reg.add_to_list("name_servers", ns)
            self.last_target = ("list", "name_servers")
            return

        if target == "emails":
            self.apply_email("emails", "emails", value)
            return

        if "." in target:
            role, attr = target.split(".", 1)
            if is_redacted_value(value):
                self.note_redaction()
                return
            if attr == "email":
                self.apply_email(role, "email", value)
                return
            reg.contact(role).set(attr, value)
            if attr in CONTACT_LIST_FIELDS:
                self.last_target = ("contact", role, attr)
            return

        if target == "registrar_abuse_email":
            email = clean_email(value)
            if email is None:
                reg.add_unmapped("!not_an_email:registrar_abuse", value)
            else:
                reg.set_scalar(target, email)
            return

        reg.set_scalar(target, value)

    def apply_email(self, role: str, attr: str, value: str) -> None:
        """Store an address only if the value actually contains one."""
        email = clean_email(value)
        if email is None:
            if is_redacted_value(value) or "http" in value.lower():
                self.note_redaction()
            else:
                self.reg.add_unmapped(f"!not_an_email:{role}", value)
            return
        if attr == "emails":
            self.reg.add_to_list("emails", email)
        else:
            self.reg.contact(role).set("email", email)

    def note_redaction(self) -> None:
        if not self.redaction_noted:
            self.reg.notes.append("contact data redacted or withheld by registry")
            self.redaction_noted = True

    def add_nameserver(self, value: str) -> None:
        ns = clean_nameserver(value)
        if ns:
            self.reg.add_to_list("name_servers", ns)

    # -- section handling -------------------------------------------------
    def enter_section(self, name: str) -> None:
        resolved = aliases.resolve_section(name)
        self.section = None if resolved in (None, "!none") else resolved
        self.section_indent = None
        self.last_target = None

    def maybe_close_section(self, ev: Event) -> None:
        """Learn the section body's indentation, and close on dedent."""
        if self.section is None:
            return
        if self.section_indent is None:
            self.section_indent = ev.indented
            return
        if self.section_indent and not ev.indented:
            self.section = None
            self.section_indent = None
            self.last_target = None

    # -- event dispatch ---------------------------------------------------
    def feed(self, ev: Event) -> None:
        if ev.kind == "blank":
            self.last_target = None
            return
        if ev.kind == "section":
            self.enter_section(ev.key)
            return

        self.maybe_close_section(ev)

        if ev.kind == "bare":
            self.feed_bare(ev)
        else:
            self.feed_kv(ev)

    def feed_bare(self, ev: Event) -> None:
        value, reg, section = ev.value, self.reg, self.section

        # Continuation of the previous multi-value field wins.
        if self.last_target and self.last_target[0] == "contact":
            if is_redacted_value(value):
                self.note_redaction()
            else:
                reg.contact(self.last_target[1]).set(self.last_target[2], value)
            return
        if self.last_target and self.last_target[0] == "list":
            self.add_nameserver(value)
            return

        if section == "!name_servers":
            self.add_nameserver(value)
        elif section == "!statuses":
            for s in split_statuses(value):
                reg.add_to_list("statuses", s)
        elif section == "!abuse":
            if "@" in value:
                reg.set_scalar("registrar_abuse_email", value.lower())
            else:
                reg.set_scalar("registrar_abuse_phone", value)
        elif section == "!registrar":
            reg.set_scalar("registrar", value)
        elif section in CONTACT_SECTIONS:
            if is_redacted_value(value):
                self.note_redaction()
            else:
                reg.contact(section).set("street", value)
        elif section != "!ignore":
            reg.add_unmapped("!bare", value)

    def feed_kv(self, ev: Event) -> None:
        key, value, section = ev.key, ev.value, self.section

        if section == "!ignore":
            return

        if section == "!name_servers":
            # Either "Hostname: host" or a bare "host  2001:db8::1" line whose
            # IPv6 column made the colon regex split it into key/value.
            if aliases.resolve_global(key) == "name_servers":
                self.apply("name_servers", value)
            else:
                self.add_nameserver(key)
                self.last_target = ("list", "name_servers")
            return

        if section is None:
            target = aliases.resolve_global(key)
        elif section == "!registrar":
            target = aliases.resolve_registrar_field(key)
        elif section == "!statuses":
            target = "statuses"
        elif section == "!abuse":
            target = "registrar_abuse_email" if "@" in value else "registrar_abuse_phone"
        else:
            # Inside a contact block only contact fields apply. This is what
            # stops .it's per-contact "Created:" clobbering the domain's date.
            field_name = aliases.resolve_contact_field(key)
            target = None if field_name is None else (
                field_name if field_name == "!ignore" else f"{section}.{field_name}"
            )

        if target is None:
            label = f"{section or ''}:{aliases.normalize_key(key)}".lstrip(":")
            self.reg.add_unmapped(label, value)
            self.last_target = None
            return

        self.apply(target, value)


def parse_text(
    text: str,
    domain: str,
    tld: str,
    reg: Optional[Registration] = None,
) -> Registration:
    """Parse a port-43 response into a Registration."""
    if reg is None:
        reg = Registration(domain=domain, tld=tld)

    parser = _Parser(reg, tld)
    for ev in tokenize(text):
        parser.feed(ev)

    _harvest_emails(reg, text)
    _promote_trailing_country(reg)
    return reg


def _harvest_emails(reg: Registration, text: str) -> None:
    """Collect every address found, from parsed fields and non-comment lines.

    ``emails`` is the highest-signal field for domain correlation, so it is
    gathered aggressively; whois_comparer.py already filters registrar and
    privacy-proxy mailboxes downstream.
    """
    for role in CONTACT_ROLES:
        email = reg.contact(role).email
        if email:
            reg.add_to_list("emails", email.lower())
    if reg.registrar_abuse_email:
        reg.add_to_list("emails", reg.registrar_abuse_email.lower())

    for raw in _truncate_footer(text.splitlines()):
        if raw.strip()[:1] in _COMMENT_START:
            continue
        for match in _EMAIL_RE.findall(raw):
            reg.add_to_list("emails", match.lower().strip("."))


def _promote_trailing_country(reg: Registration) -> None:
    """Move a trailing 2-letter country code out of a multi-line address.

    .it and .be write addresses as street/city/postcode/province/country with no
    labels; the final line is an ISO country code.
    """
    for role in CONTACT_ROLES:
        c = reg.contact(role)
        if c.country or len(c.street) < 2:
            continue
        last = c.street[-1].strip()
        if len(last) == 2 and last.isalpha() and last.isupper():
            c.country = last
            c.street.pop()
