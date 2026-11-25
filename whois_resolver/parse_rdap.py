"""RDAP response parser — layer A.

RDAP is JSON (RFC 9083), so there is nothing to guess at: no per-TLD regexes, no
date-format ambiguity. IANA's bootstrap covers 1200 of the ~1438 delegated TLDs,
which is why this is tried first. Contact details arrive as jCard (RFC 7095),
a positional array format that this module flattens into Contact objects.
"""
from typing import Any, Dict, List, Optional

from .aliases import is_redacted_value, looks_like_email
from .dates import parse_date
from .model import Contact, Registration

#: Fields where a registry may substitute a privacy placeholder.
_REDACTABLE = ("name", "organization", "street", "city", "state", "postal_code")

#: RDAP entity role -> our contact role.
ROLE_MAP = {
    "registrant": "registrant",
    "administrative": "admin",
    "technical": "tech",
    "billing": "billing",
}

#: RDAP eventAction -> Registration attribute.
EVENT_MAP = {
    "registration": "created",
    "last changed": "updated",
    "last update of rdap database": None,   # about the database, not the domain
    "expiration": "expires",
    "transfer": "transferred",
}


def _vcard_entries(entity: Dict[str, Any]) -> List[List[Any]]:
    """Pull the entry list out of ``vcardArray: ["vcard", [...entries...]]``."""
    arr = entity.get("vcardArray")
    if not isinstance(arr, list) or len(arr) < 2 or not isinstance(arr[1], list):
        return []
    return [e for e in arr[1] if isinstance(e, list) and len(e) >= 4]


def _tel_type(entry: List[Any]) -> str:
    params = entry[1] if isinstance(entry[1], dict) else {}
    types = params.get("type", [])
    if isinstance(types, str):
        types = [types]
    return " ".join(str(t).lower() for t in types)


def _scalar(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return " ".join(parts) or None
    s = str(value).strip()
    return s or None


def _set(contact: Contact, field: str, value: str, redacted: List[bool]) -> None:
    """Assign a jCard value, dropping privacy placeholders."""
    if not value:
        return
    if field in _REDACTABLE and is_redacted_value(value):
        redacted.append(True)
        return
    contact.set(field, value)


def contact_from_entity(entity: Dict[str, Any], redacted: Optional[List[bool]] = None) -> Contact:
    c = Contact()
    if redacted is None:
        redacted = []
    handle = entity.get("handle")
    if handle:
        c.handle = str(handle).strip()

    for entry in _vcard_entries(entity):
        prop = str(entry[0]).lower()
        value = entry[3]

        if prop == "fn":
            _set(c, "name", _scalar(value) or "", redacted)
        elif prop == "org":
            _set(c, "organization", _scalar(value) or "", redacted)
        elif prop == "email":
            raw = _scalar(value) or ""
            # Same guard as the port-43 parser: a registrar may put a web form
            # here, and that must not end up in the emails correlation field.
            if looks_like_email(raw):
                c.set("email", raw.lower())
            elif raw:
                redacted.append(True)
        elif prop == "tel":
            raw = _scalar(value) or ""
            # jCard tel values are often "tel:+31.263525555" URIs.
            if raw.lower().startswith("tel:"):
                raw = raw[4:]
            if "fax" in _tel_type(entry):
                c.set("fax", raw)
            else:
                c.set("phone", raw)
        elif prop == "adr":
            _apply_address(c, entry, value, redacted)
    return c


def _apply_address(c: Contact, entry: List[Any], value: Any,
                   redacted: Optional[List[bool]] = None) -> None:
    """jCard ``adr`` is [pobox, ext, street, locality, region, code, country]."""
    if redacted is None:
        redacted = []
    params = entry[1] if isinstance(entry[1], dict) else {}

    def add_lines(text: str) -> None:
        for line in str(text).splitlines():
            if line.strip():
                _set(c, "street", line.strip(), redacted)

    if not isinstance(value, list):
        # Some servers send a preformatted label instead of the structured form.
        label = params.get("label") or _scalar(value)
        if label:
            add_lines(label)
        return

    parts = [(_scalar(v) or "") for v in value] + [""] * 7
    for chunk in (parts[0], parts[1], parts[2]):
        if chunk:
            add_lines(chunk)
    _set(c, "city", parts[3], redacted)
    _set(c, "state", parts[4], redacted)
    _set(c, "postal_code", parts[5], redacted)
    c.set("country", parts[6])

    if not any(parts[:7]) and params.get("label"):
        add_lines(params["label"])


def _apply_registrar(reg: Registration, entity: Dict[str, Any]) -> None:
    c = contact_from_entity(entity)
    reg.set_scalar("registrar", c.organization or c.name or "")

    for pid in entity.get("publicIds") or []:
        if not isinstance(pid, dict):
            continue
        if "iana" in str(pid.get("type", "")).lower():
            reg.set_scalar("registrar_iana_id", str(pid.get("identifier", "")))

    for link in entity.get("links") or []:
        if isinstance(link, dict) and link.get("rel") in ("about", "self"):
            href = str(link.get("href", ""))
            if href.startswith("http") and "rdap" not in href:
                reg.set_scalar("registrar_url", href)

    # Abuse contact is a nested entity with role "abuse".
    for nested in entity.get("entities") or []:
        if not isinstance(nested, dict):
            continue
        roles = [str(r).lower() for r in nested.get("roles") or []]
        if "abuse" in roles:
            ac = contact_from_entity(nested)
            if ac.email:
                reg.set_scalar("registrar_abuse_email", ac.email)
            if ac.phone:
                reg.set_scalar("registrar_abuse_phone", ac.phone)


def parse_rdap(
    data: Dict[str, Any],
    domain: str,
    tld: str,
    reg: Optional[Registration] = None,
) -> Registration:
    """Parse an RDAP domain object into a Registration."""
    if reg is None:
        reg = Registration(domain=domain, tld=tld)

    reg.set_scalar("domain_name", str(data.get("ldhName") or data.get("unicodeName") or ""))
    if data.get("handle"):
        reg.set_scalar("registry_domain_id", str(data["handle"]))

    for status in data.get("status") or []:
        reg.add_to_list("statuses", str(status))

    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).lower()
        attr = EVENT_MAP.get(action)
        if not attr:
            continue
        dt = parse_date(str(event.get("eventDate") or ""))
        if dt and getattr(reg, attr) is None:
            setattr(reg, attr, dt)

    for ns in data.get("nameservers") or []:
        if isinstance(ns, dict):
            host = ns.get("ldhName") or ns.get("unicodeName")
            if host:
                reg.add_to_list("name_servers", str(host).strip(".").lower())

    secure = data.get("secureDNS")
    if isinstance(secure, dict):
        if secure.get("delegationSigned"):
            reg.set_scalar("dnssec", "signedDelegation")
        elif secure.get("delegationSigned") is False:
            reg.set_scalar("dnssec", "unsigned")

    redacted: List[bool] = []
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in entity.get("roles") or []]
        if "registrar" in roles:
            _apply_registrar(reg, entity)
        for role in roles:
            target = ROLE_MAP.get(role)
            if not target:
                continue
            parsed = contact_from_entity(entity, redacted)
            existing = reg.contact(target)
            for name, field_def in Contact.__dataclass_fields__.items():  # type: ignore[attr-defined]
                value = getattr(parsed, name)
                if isinstance(value, list):
                    for item in value:
                        existing.set(name, item)
                elif value:
                    existing.set(name, value)

    if redacted:
        note = "contact data redacted or withheld by registry"
        if note not in reg.notes:
            reg.notes.append(note)

    _harvest_emails(reg)
    return reg


def _harvest_emails(reg: Registration) -> None:
    for role in ("registrant", "admin", "tech", "billing"):
        email = reg.contact(role).email
        if email:
            reg.add_to_list("emails", email.lower())
    if reg.registrar_abuse_email:
        reg.add_to_list("emails", reg.registrar_abuse_email.lower())


def related_rdap_links(data: Dict[str, Any]) -> List[str]:
    """RDAP referral targets — usually the registrar's own RDAP server."""
    out: List[str] = []
    for link in data.get("links") or []:
        if not isinstance(link, dict):
            continue
        if link.get("rel") != "related":
            continue
        media = str(link.get("type", "")).lower()
        href = str(link.get("href", ""))
        if href.startswith("http") and ("rdap" in media or "rdap" in href.lower()):
            if href not in out:
                out.append(href)
    return out
