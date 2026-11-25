"""Field alias tables — the layer that makes new TLDs cheap.

Adding support for a registry is normally a few rows here, not a new parser.
Keys are matched twice: first on the normalized form (lowercased, whitespace
collapsed) and then on a "squashed" form with all non-alphanumerics removed, so
``Registrant Name``, ``registrant-name`` and ``registrant_name`` all hit the
same row without needing three entries.

Every alias below is derived from a real response in ``fixtures/``.
"""
import re
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Key normalization
# ---------------------------------------------------------------------------

_SQUASH = re.compile(r"[^a-z0-9]+")


def normalize_key(key: str) -> str:
    return " ".join(key.strip().lower().split()).rstrip(":").strip()


def squash_key(key: str) -> str:
    return _SQUASH.sub("", key.lower())


def _build(table: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (exact, squashed) lookup maps for a raw alias table."""
    exact = {normalize_key(k): v for k, v in table.items()}
    squashed: Dict[str, str] = {}
    for k, v in table.items():
        squashed.setdefault(squash_key(k), v)
    return exact, squashed


def _lookup(key: str, maps: Tuple[Dict[str, str], Dict[str, str]]) -> Optional[str]:
    exact, squashed = maps
    nk = normalize_key(key)
    if nk in exact:
        return exact[nk]
    return squashed.get(squash_key(key))


# ---------------------------------------------------------------------------
# Top-level (no section context) keys
# ---------------------------------------------------------------------------
# Targets are either a Registration attribute, or "<role>.<field>" for contacts.
# "!" prefixes a pseudo-target handled specially by the parser.

_GLOBAL: Dict[str, str] = {
    # -- identity (ICANN gTLD format, .it, .nl, .dk, .be, .ru, .se, .fr) ----
    "domain name": "domain_name",
    "domain": "domain_name",
    "domain.": "domain_name",
    "registry domain id": "registry_domain_id",
    "domain id": "registry_domain_id",

    # -- registrar ---------------------------------------------------------
    "registrar": "registrar",
    "sponsoring registrar": "registrar",
    "registrar name": "registrar",
    "registrar iana id": "registrar_iana_id",
    "sponsoring registrar iana id": "registrar_iana_id",
    "registrar url": "registrar_url",
    "registrar website": "registrar_url",
    "registrar abuse contact email": "registrar_abuse_email",
    "registrar abuse contact phone": "registrar_abuse_phone",
    "abuse contact email": "registrar_abuse_email",
    "abuse contact phone": "registrar_abuse_phone",
    "reseller": "reseller",
    "registrar whois server": "whois_server",
    "whois server": "whois_server",
    "record maintained by": "!ignore",   # .nl footer

    # -- dates -------------------------------------------------------------
    "creation date": "created",
    "created": "created",
    "created on": "created",
    "created date": "created",
    "registered": "created",             # .dk, .be
    "registered on": "created",          # .uk
    "registration date": "created",
    "domain registration date": "created",
    "updated date": "updated",
    "last updated": "updated",           # .jp
    "last update": "updated",            # .it, .fr
    "last modified": "updated",
    "modified": "updated",               # .se
    "changed": "updated",                # .de, .at
    "last updated on": "updated",
    "registry expiry date": "expires",
    "registrar registration expiration date": "expires",
    "expiration date": "expires",        # .pt
    "expiration time": "expires",
    "expires": "expires",                # .se, .dk
    "expires on": "expires",             # .jp
    "expire date": "expires",            # .it
    "expiry date": "expires",            # .fr, .uk
    "paid-till": "expires",              # .ru
    "transferred": "transferred",        # .se
    "transfer date": "transferred",

    # -- status ------------------------------------------------------------
    "domain status": "statuses",
    "status": "statuses",
    "state": "statuses",                 # .ru, .se
    "eppstatus": "statuses",             # .fr
    "registry lock": "statuses",
    "registry-lock": "statuses",
    "lock status": "statuses",           # .jp
    "hold": "!ignore",

    # -- delegation --------------------------------------------------------
    "name server": "name_servers",
    "nameserver": "name_servers",
    "nameservers": "name_servers",
    "nserver": "name_servers",           # .de, .ru, .se, .at, .fr
    "name servers": "name_servers",
    "hostname": "name_servers",          # .dk, inside its Nameservers block
    "dnssec": "dnssec",
    "signed": "dnssec",                  # .it
    "dnssec status": "dnssec",
    "dnskey": "!ignore",                 # .de key material, not useful here
    "signing key": "!ignore",            # .jp
    "ds key tag 1": "!ignore",
    "key1-tag": "!ignore",

    # -- flat holder info --------------------------------------------------
    # Most flat ccTLD formats put holder data at top level with these keys.
    # Formats that instead append separate contact blocks (.fr, .at) are
    # handled by a per-TLD override, so these rows do not misfire there.
    "owner name": "registrant.name",             # .pt
    "owner address": "registrant.street",
    "owner locality": "registrant.city",
    "owner zipcode": "registrant.postal_code",
    "owner country code": "registrant.country",
    "owner email": "registrant.email",
    "owner locality zipcode": "!ignore",         # .pt duplicates city in caps
    "holder": "registrant.handle",               # .se (an opaque handle)
    "registrant": "registrant.name",             # .jp, .at
    "registrant name": "registrant.name",
    "registrant organization": "registrant.organization",
    "registrant organisation": "registrant.organization",
    "registrant street": "registrant.street",
    "registrant city": "registrant.city",
    "registrant state/province": "registrant.state",
    "registrant postal code": "registrant.postal_code",
    "registrant country": "registrant.country",
    "registrant phone": "registrant.phone",
    "registrant fax": "registrant.fax",
    "registrant email": "registrant.email",
    "registry registrant id": "registrant.handle",
    "registrant id": "registrant.handle",
    "org": "registrant.organization",            # .ru
    "org-name": "registrant.organization",
    "holder-c": "registrant.handle",             # .fr (resolved by override)
    "taxpayer-id": "!ignore",

    "admin name": "admin.name",                  # .pt
    "admin address": "admin.street",
    "admin locality": "admin.city",
    "admin zipcode": "admin.postal_code",
    "admin country code": "admin.country",
    "admin email": "admin.email",
    "admin organization": "admin.organization",
    "admin organisation": "admin.organization",
    "admin street": "admin.street",
    "admin city": "admin.city",
    "admin state/province": "admin.state",
    "admin postal code": "admin.postal_code",
    "admin country": "admin.country",
    "admin phone": "admin.phone",
    "admin fax": "admin.fax",
    "registry admin id": "admin.handle",
    "admin id": "admin.handle",
    "admin-c": "admin.handle",                   # .fr, .at
    "admin contact": "admin.handle",             # .ru (a URL, still a pointer)

    "tech name": "tech.name",
    "tech organization": "tech.organization",
    "tech organisation": "tech.organization",
    "tech street": "tech.street",
    "tech city": "tech.city",
    "tech state/province": "tech.state",
    "tech postal code": "tech.postal_code",
    "tech country": "tech.country",
    "tech phone": "tech.phone",
    "tech fax": "tech.fax",
    "tech email": "tech.email",
    "registry tech id": "tech.handle",
    "tech id": "tech.handle",
    "tech-c": "tech.handle",                     # .fr, .at

    "billing name": "billing.name",
    "billing organization": "billing.organization",
    "billing organisation": "billing.organization",
    "billing street": "billing.street",
    "billing city": "billing.city",
    "billing state/province": "billing.state",
    "billing postal code": "billing.postal_code",
    "billing country": "billing.country",
    "billing phone": "billing.phone",
    "billing fax": "billing.fax",
    "billing email": "billing.email",
    "registry billing id": "billing.handle",

    # -- misc --------------------------------------------------------------
    "source": "!ignore",
    "registration period": "!ignore",
    "vid": "!ignore",
    "dns": "!ignore",                    # .dk repeats the zone name here
    "web page": "!ignore",               # .jp
    "remarks": "!ignore",                # .at uses this for NS glue addresses
    "url of the icann whois inaccuracy complaint form": "!ignore",
}

GLOBAL_ALIASES = _build(_GLOBAL)


def resolve_global(key: str) -> Optional[str]:
    return _lookup(key, GLOBAL_ALIASES)


# ---------------------------------------------------------------------------
# Section-relative contact keys
# ---------------------------------------------------------------------------
# Applied when the parser is inside a contact block (.it, .be, .nl, .de).

_CONTACT: Dict[str, str] = {
    "name": "name",
    "contact": "name",                   # .fr nic-hdl blocks
    "contact name": "name",
    "personname": "name",                # .at
    "person": "name",
    "full name": "name",
    "organization": "organization",
    "organisation": "organization",      # .be
    "org": "organization",
    "org-name": "organization",
    "company": "organization",
    "address": "street",
    "street": "street",
    "street address": "street",          # .at
    "postal address": "street",          # .jp
    "city": "city",
    "locality": "city",
    "state": "state",
    "state/province": "state",
    "province": "state",
    "postal code": "postal_code",
    "postalcode": "postal_code",
    "zipcode": "postal_code",
    "zip code": "postal_code",
    "pc": "postal_code",
    "country": "country",
    "country code": "country",
    "phone": "phone",
    "phone number": "phone",
    "voice": "phone",
    "telephone": "phone",
    "fax": "fax",
    "fax-no": "fax",
    "fax number": "fax",
    "facsimile": "fax",
    "email": "email",
    "e-mail": "email",
    "mail": "email",
    "nic-hdl": "handle",
    "handle": "handle",
    "contact id": "handle",
    "registrar handle": "handle",
    # Present inside contact blocks but meaningless as contact data — dropping
    # them here is what stops .it's per-contact "Created:" from overwriting the
    # domain's own creation date.
    "created": "!ignore",
    "last update": "!ignore",
    "changed": "!ignore",
    "type": "!ignore",
    "language": "!ignore",
    "anonymous": "!ignore",
    "registered": "!ignore",
    "source": "!ignore",
    "web": "!ignore",
    "website": "!ignore",
    "web page": "!ignore",
    "obsoleted": "!ignore",
    "eligstatus": "!ignore",
    "eligsource": "!ignore",
    "eligdate": "!ignore",
    "reachstatus": "!ignore",
    "reachsource": "!ignore",
    "reachmedia": "!ignore",
}

CONTACT_ALIASES = _build(_CONTACT)


def resolve_contact_field(key: str) -> Optional[str]:
    return _lookup(key, CONTACT_ALIASES)


# Keys inside a "Registrar" block (.it, .be, .nl).
_REGISTRAR: Dict[str, str] = {
    "name": "registrar",
    "organization": "registrar",
    "organisation": "registrar",
    "web": "registrar_url",
    "website": "registrar_url",
    "url": "registrar_url",
    "email": "registrar_abuse_email",
    "e-mail": "registrar_abuse_email",
    "abuse contact email": "registrar_abuse_email",
    "phone": "registrar_abuse_phone",
    "abuse contact phone": "registrar_abuse_phone",
    "dnssec": "dnssec",
    "language": "!ignore",
    "handle": "!ignore",
    "registrar handle": "!ignore",
    "address": "!ignore",
    "country": "!ignore",
    "fax": "!ignore",
    "fax-no": "!ignore",
    "version": "!ignore",
}

REGISTRAR_ALIASES = _build(_REGISTRAR)


def resolve_registrar_field(key: str) -> Optional[str]:
    return _lookup(key, REGISTRAR_ALIASES)


# ---------------------------------------------------------------------------
# Section headers
# ---------------------------------------------------------------------------
# "!"-prefixed values are pseudo-sections with special value handling.

_SECTIONS: Dict[str, str] = {
    "registrant": "registrant",
    "registrant contact": "registrant",
    "registrant contacts": "registrant",
    "registrant information": "registrant",
    "holder": "registrant",                      # .de legacy [Holder] block
    "owner": "registrant",
    "domain holder": "registrant",
    "contact information": "registrant",         # .jp
    "admin": "admin",
    "admin contact": "admin",
    "admin contacts": "admin",
    "administrative contact": "admin",
    "administrative contacts": "admin",
    "tech": "tech",
    "tech contact": "tech",
    "tech contacts": "tech",
    "technical contact": "tech",
    "technical contacts": "tech",                # .it
    "billing": "billing",
    "billing contact": "billing",
    "billing contacts": "billing",
    "registrar": "!registrar",                   # .it, .be, .nl
    "registrar information": "!registrar",
    "sponsoring registrar": "!registrar",
    "nameservers": "!name_servers",              # .it, .dk, .be
    "name servers": "!name_servers",
    "domain nameservers": "!name_servers",       # .nl
    "abuse contact": "!abuse",                   # .nl
    "flags": "!statuses",                        # .be
    "domain information": "!none",               # .jp — plain top level
    "keys": "!ignore",                           # .be DNSSEC key material
    "dnssec": "!ignore",
    "registrar technical contacts": "!ignore",   # registrar's staff, not the domain's
    "registrar abuse contact": "!ignore",
}

SECTIONS = _build(_SECTIONS)


def resolve_section(name: str) -> Optional[str]:
    return _lookup(name, SECTIONS)


# ---------------------------------------------------------------------------
# Per-TLD hints
# ---------------------------------------------------------------------------

#: TLDs whose numeric dates are day-first (DD/MM/YYYY).
DAY_FIRST_TLDS = frozenset({
    "pt", "be", "es", "it", "fr", "nl", "de", "at", "ch", "li", "dk", "se",
    "no", "fi", "pl", "cz", "sk", "hu", "gr", "ie", "uk", "au", "nz", "za",
    "in", "br", "ar", "cl", "mx", "ru", "ua", "tr", "il", "hk", "sg", "my",
})

#: Non-default port-43 query formats. ``{d}`` is the domain.
QUERY_FORMATS = {
    "whois.verisign-grs.com": "domain {d}",   # otherwise does a substring search
    "whois.jprs.jp": "{d}/e",                 # /e forces English output
    "whois.nic.ad.jp": "{d}/e",
    "whois.denic.de": "-T dn {d}",
    "whois.dk-hostmaster.dk": "--charset=utf8 {d}",
    "whois.punktum.dk": "--charset=utf8 {d}",
    "whois.norid.no": "{d}",
}

#: Per-server minimum seconds between queries. Registry servers rate limit
#: independently, so limits are tracked per host, not globally.
RATE_LIMITS = {
    "whois.denic.de": 2.0,
    "whois.dns.pt": 2.0,
    "whois.dns.be": 3.0,
    "whois.nic.ch": 3.0,
    "whois.nic.it": 2.0,
    "whois.iis.se": 2.0,
    "whois.punktum.dk": 2.0,
    "whois.nic.fr": 1.5,
    "whois.iana.org": 1.0,
}
DEFAULT_RATE_LIMIT = 1.0

#: Phrases that mean "this domain does not exist". Matched against the start of
#: a line whose comment marker and leading whitespace have been stripped, so a
#: live domain's "Status: NOT AVAILABLE" cannot trigger it. Bare "available" is
#: deliberately absent — it is handled precisely via FREE_STATUS_VALUES instead.
NOT_FOUND_PREFIXES = (
    "no match for",
    "no match",
    "not found",
    "domain not found",
    "no data found",
    "no entries found",
    "no object found",
    "nothing found",
    "object does not exist",
    "domain unknown",
    "no information available about domain name",
    "this domain name has not been registered",
    "the queried object does not exist",
    "domain name not known",
    "not registered",
)

#: Substrings marking a value as a privacy placeholder rather than real data.
#: Post-GDPR most gTLD contact fields are one of these, so storing them as
#: contact data would create false correlations between unrelated domains.
REDACTED_MARKERS = (
    "redacted",
    "not shown",
    "not disclosed",
    "not available",
    "data protected",
    "data redacted",
    "withheld",
    "privacy service provided",
    "privacy protect",
    "domains by proxy",
    "whoisguard",
    "gdpr masked",
    "statutory masking enabled",
    "non-public data",
    "hidden by",
    "obscured whois",
    "please query the rdds service",
    "please visit",
    "request email form",                 # MarkMonitor et al. substitute a web form
    "see whois",
    "on behalf of",
)

_EMAIL_FULL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def looks_like_email(value: str) -> bool:
    """True if the whole value is a single address, nothing else."""
    return bool(_EMAIL_FULL_RE.match(value.strip()))


def is_redacted_value(value: str) -> bool:
    """True if a value is a privacy placeholder rather than real contact data.

    Applies to both transports: RDAP registries publish the same placeholders in
    jCard ``fn`` fields that port-43 registries put in ``Registrant Name:``.
    Storing them would make every redacted domain look correlated with every
    other one.
    """
    v = " ".join(str(value).lower().split())
    if not v:
        return True
    return any(marker in v for marker in REDACTED_MARKERS)


#: Parsed status values that mean the domain is free.
FREE_STATUS_VALUES = frozenset({
    "free", "available", "not registered", "no object found", "avail",
})

#: Phrases meaning the server refused to answer — an error, never "unregistered".
REFUSAL_MARKERS = (
    "not permitted",
    "rate limit",
    "rate-limit",
    "exceeded",
    "quota",
    "too many requests",
    "try again later",
    "access denied",
    "connection refused",
    "temporarily unavailable",
    "blocked",
    "your ip has been",
    "excessive querying",
    "lookup quota",
)

#: Line prefixes after which the rest of the response is boilerplate.
FOOTER_PREFIXES = (
    ">>> last update of whois database",
    "url of the icann whois data problem reporting system",
    "url of the icann whois inaccuracy complaint form",
    "notice:",
    "terms of use:",
    "the registry database contains",
    "for more information on whois status codes",
    "please visit ",
    "last updated on ",
    "-- \n",
)
