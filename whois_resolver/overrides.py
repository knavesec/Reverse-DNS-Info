"""Layer C — per-TLD structural overrides.

Only for registries whose response is not a single key/value document, where no
alias table can help. Everything else is handled generically by
``parse_text.py``; keep this module small on purpose.

Currently one shape needs it: **handle indirection**, used by AFNIC (.fr) and
nic.at (.at). The domain block references contacts by handle and the contact
records appear as separate blocks later in the same response::

    domain:     afnic.fr
    holder-c:   AFNI30-FRNIC        <- pointer

    nic-hdl:    AFNI30-FRNIC        <- the record it points at
    contact:    ASS FRANC NOMMAGE INTERNET EN COOP
    e-mail:     contact@nic.fr

Parsed generically, the trailing blocks' ``address:`` / ``e-mail:`` lines would
be attributed to whichever block happened to be parsed last.
"""
from typing import Callable, Dict, List, Optional

from . import aliases
from .model import CONTACT_ROLES, Contact, Registration
from .parse_text import parse_text

_COMMENT_START = ("%", "#", "*", ";")


def _blocks(text: str) -> List[List[str]]:
    """Split into blank-line-separated blocks, dropping comment lines."""
    out: List[List[str]] = []
    current: List[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw.strip()
        if stripped[:1] in _COMMENT_START or stripped.startswith(">>>"):
            continue
        if not stripped:
            if current:
                out.append(current)
                current = []
            continue
        current.append(raw)
    if current:
        out.append(current)
    return out


def _keys(block: List[str]) -> set:
    keys = set()
    for line in block:
        if ":" in line:
            keys.add(aliases.normalize_key(line.split(":", 1)[0]))
    return keys


def _contact_from_block(block: List[str]) -> Optional[Contact]:
    """Build a Contact from a ``nic-hdl:`` block."""
    contact = Contact()
    for line in block:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if not value:
            continue
        field = aliases.resolve_contact_field(key)
        if field in (None, "!ignore"):
            continue
        contact.set(field, value)
    return contact if contact.handle else None


def _merge_contact(dst: Contact, src: Contact) -> None:
    for name in Contact.__dataclass_fields__:  # type: ignore[attr-defined]
        value = getattr(src, name)
        if isinstance(value, list):
            for item in value:
                dst.set(name, item)
        elif value:
            dst.set(name, value)


def parse_handle_indirection(
    text: str, domain: str, tld: str, reg: Optional[Registration] = None
) -> Registration:
    """Parser for .fr / .at style responses."""
    if reg is None:
        reg = Registration(domain=domain, tld=tld)

    blocks = _blocks(text)

    contacts: Dict[str, Contact] = {}
    domain_lines: List[str] = []
    registrar_blocks: List[List[str]] = []

    for block in blocks:
        keys = _keys(block)
        if "nic-hdl" in keys:
            contact = _contact_from_block(block)
            if contact and contact.handle:
                contacts[contact.handle.strip().upper()] = contact
        elif "domain" in keys:
            domain_lines.extend(block)
        elif keys and keys <= {"nserver", "source", "ds-rdata"} or (
            "nserver" in keys and "registrar" not in keys
        ):
            # AFNIC emits nameservers in their own block.
            domain_lines.extend(block)
        elif "registrar" in keys:
            registrar_blocks.append(block)

    # The domain block is an ordinary key/value document, so reuse layer B.
    parse_text("\n".join(domain_lines), domain, tld, reg=reg)

    _attach_contacts(reg, contacts)
    _apply_registrar_block(reg, registrar_blocks)

    for role in CONTACT_ROLES:
        email = reg.contact(role).email
        if email:
            reg.add_to_list("emails", email.lower())
    return reg


def _attach_contacts(reg: Registration, contacts: Dict[str, Contact]) -> None:
    """Resolve each role's handle pointer against the contact blocks.

    .fr uses a dedicated pointer key (``holder-c``) that the alias table already
    maps to ``handle``. .at reuses ``registrant:`` for the pointer, which the
    alias table maps to ``name`` because that is what it means everywhere else —
    so a name that turns out to be a known handle is treated as the pointer.
    """
    for role in CONTACT_ROLES:
        target = reg.contact(role)
        handle = (target.handle or "").strip().upper()
        if handle not in contacts and target.name:
            candidate = target.name.strip().upper()
            if candidate in contacts:
                handle = candidate
                target.handle = target.name.strip()
                target.name = None
        source = contacts.get(handle)
        if source:
            _merge_contact(target, source)


def _apply_registrar_block(reg: Registration, blocks: List[List[str]]) -> None:
    for block in blocks:
        for line in block:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key, value = aliases.normalize_key(key), value.strip()
            if not value:
                continue
            if key in ("website", "web", "url"):
                reg.set_scalar("registrar_url", value)
            elif key in ("e-mail", "email"):
                reg.set_scalar("registrar_abuse_email", value.lower())
            elif key == "phone":
                reg.set_scalar("registrar_abuse_phone", value)


#: TLD -> parser. Consulted before the generic parser.
OVERRIDES: Dict[str, Callable[..., Registration]] = {
    "fr": parse_handle_indirection,
    "re": parse_handle_indirection,     # AFNIC also runs .re/.tf/.pm/.wf/.yt
    "tf": parse_handle_indirection,
    "pm": parse_handle_indirection,
    "wf": parse_handle_indirection,
    "yt": parse_handle_indirection,
    "at": parse_handle_indirection,
}


def get_override(tld: str) -> Optional[Callable[..., Registration]]:
    return OVERRIDES.get(tld.lower())
