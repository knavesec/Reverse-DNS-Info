"""Canonical registration model.

Every transport (RDAP, port 43) and every parser layer produces one of these,
so downstream analysis never has to care where the data came from.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

CONTACT_ROLES = ("registrant", "admin", "tech", "billing")

# Fields on Contact that hold a list rather than a scalar.
CONTACT_LIST_FIELDS = ("street",)


@dataclass
class Contact:
    handle: Optional[str] = None
    name: Optional[str] = None
    organization: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    fax: Optional[str] = None
    street: List[str] = field(default_factory=list)
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None

    def is_empty(self) -> bool:
        return not any(
            getattr(self, f.name) for f in self.__dataclass_fields__.values()  # type: ignore[attr-defined]
        )

    def set(self, attr: str, value: str) -> None:
        """First-non-empty wins for scalars; append-unique for list fields."""
        value = value.strip()
        if not value:
            return
        if attr in CONTACT_LIST_FIELDS:
            cur: List[str] = getattr(self, attr)
            if value not in cur:
                cur.append(value)
            return
        if getattr(self, attr, None) in (None, ""):
            setattr(self, attr, value)


@dataclass
class Registration:
    """A domain's registration record, normalized across TLDs."""

    domain: str
    tld: str = ""

    # None means "could not be determined" (server refused, rate limited, ...).
    # That is deliberately distinct from False ("confirmed unregistered").
    registered: Optional[bool] = None

    domain_name: Optional[str] = None
    registry_domain_id: Optional[str] = None

    registrar: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    registrar_url: Optional[str] = None
    registrar_abuse_email: Optional[str] = None
    registrar_abuse_phone: Optional[str] = None
    reseller: Optional[str] = None
    whois_server: Optional[str] = None

    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    expires: Optional[datetime] = None
    transferred: Optional[datetime] = None

    statuses: List[str] = field(default_factory=list)
    name_servers: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    emails: List[str] = field(default_factory=list)

    registrant: Contact = field(default_factory=Contact)
    admin: Contact = field(default_factory=Contact)
    tech: Contact = field(default_factory=Contact)
    billing: Contact = field(default_factory=Contact)

    # Provenance and diagnostics.
    source: Optional[str] = None          # "rdap" | "whois" | "cache"
    source_server: Optional[str] = None
    # Set when a response explicitly said the domain does not exist. Recorded at
    # query time rather than re-derived from ``raw`` later, because ``raw`` is
    # only retained when the caller asks for it — registration state must not
    # depend on an output option.
    not_found_response: bool = False
    servers_queried: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # Keys the parser saw but had no alias for. Feeding these back into
    # aliases.py is how TLD coverage grows.
    unmapped: Dict[str, List[str]] = field(default_factory=dict)
    raw: Optional[str] = None

    # -- mutation helpers -------------------------------------------------
    def set_scalar(self, attr: str, value: str) -> None:
        """First-non-empty wins: registry data is seen before referral data."""
        value = value.strip()
        if not value:
            return
        if getattr(self, attr, None) in (None, ""):
            setattr(self, attr, value)

    def add_to_list(self, attr: str, value: str) -> None:
        value = value.strip()
        if not value:
            return
        cur: List[str] = getattr(self, attr)
        if value not in cur:
            cur.append(value)

    def contact(self, role: str) -> Contact:
        return getattr(self, role)

    def add_unmapped(self, key: str, value: str) -> None:
        self.unmapped.setdefault(key, [])
        if value not in self.unmapped[key]:
            self.unmapped[key].append(value)

    def has_registration_evidence(self) -> bool:
        """Positive evidence that the domain exists.

        Preferred over scanning for "not found" phrases, which misfire badly
        (.be reports a live domain as ``Status: NOT AVAILABLE``).
        """
        if self.created or self.name_servers or self.registrar or self.expires:
            return True
        return any(not self.contact(r).is_empty() for r in CONTACT_ROLES)

    # -- output ----------------------------------------------------------
    def to_flat(self, include_raw: bool = False) -> Dict[str, Any]:
        """Flatten to ``whois_*``-style keys.

        Key names intentionally match ``python-whois`` where an equivalent
        exists (``org``, ``emails``, ``name_servers``, ``creation_date``, ...)
        so existing greppable output and whois_comparer.py keep working, with
        the richer per-role fields added alongside.
        """
        out: Dict[str, Any] = {}

        def put(key: str, value: Any) -> None:
            if value in (None, "", [], {}):
                return
            out[key] = value

        def iso(dt: Optional[datetime]) -> Optional[str]:
            return dt.isoformat() if dt else None

        put("domain_name", self.domain_name or self.domain)
        put("registry_domain_id", self.registry_domain_id)
        put("registrar", self.registrar)
        put("registrar_iana_id", self.registrar_iana_id)
        put("registrar_url", self.registrar_url)
        put("registrar_abuse_email", self.registrar_abuse_email)
        put("registrar_abuse_phone", self.registrar_abuse_phone)
        put("reseller", self.reseller)
        put("whois_server", self.whois_server)
        put("creation_date", iso(self.created))
        put("updated_date", iso(self.updated))
        put("expiration_date", iso(self.expires))
        put("transfer_date", iso(self.transferred))
        put("status", self.statuses)
        put("name_servers", self.name_servers)
        put("dnssec", self.dnssec)
        put("emails", self.emails)

        for role in CONTACT_ROLES:
            c = self.contact(role)
            put(f"{role}_handle", c.handle)
            put(f"{role}_name", c.name)
            put(f"{role}_organization", c.organization)
            put(f"{role}_email", c.email)
            put(f"{role}_phone", c.phone)
            put(f"{role}_fax", c.fax)
            put(f"{role}_street", c.street)
            put(f"{role}_city", c.city)
            put(f"{role}_state", c.state)
            put(f"{role}_postal_code", c.postal_code)
            put(f"{role}_country", c.country)

        # python-whois compatibility aliases (registrant-derived).
        r = self.registrant
        put("name", r.name)
        put("org", r.organization)
        put("address", r.street)
        put("city", r.city)
        put("state", r.state)
        put("zipcode", r.postal_code)
        put("country", r.country)

        put("source", self.source)
        put("source_server", self.source_server)
        if include_raw:
            put("raw", self.raw)
        return out

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        d = asdict(self)
        for key in ("created", "updated", "expires", "transferred"):
            dt = d.get(key)
            d[key] = dt.isoformat() if isinstance(dt, datetime) else None
        if not include_raw:
            d.pop("raw", None)
        return d
