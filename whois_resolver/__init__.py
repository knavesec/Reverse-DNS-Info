"""whois_resolver — dynamic WHOIS/RDAP lookups across every TLD.

    from whois_resolver import Resolver
    reg = Resolver().lookup("dns.pt")
    print(reg.registrant.name, reg.created, reg.name_servers)

Design in three layers, so adding a registry is normally a table edit:

  A. RDAP (``parse_rdap``)  — structured JSON, covers ~1200 of ~1438 TLDs.
  B. Generic port-43 parser (``parse_text``) + alias table (``aliases``) — one
     tokenizer for every ``Key: value`` dialect, including .pt, which the
     regex-per-TLD approach in python-whois does not handle.
  C. Per-TLD overrides (``overrides``) — only for genuinely different document
     structures. Currently just handle indirection (.fr, .at).

Server discovery is dynamic via IANA (``bootstrap``): the RDAP bootstrap
registry, then ``whois.iana.org`` for anything RDAP does not cover.
"""
from .bootstrap import Bootstrap
from .model import Contact, Registration, CONTACT_ROLES
from .resolver import Resolver, lookup, normalize_domain, tld_of

__all__ = [
    "Bootstrap",
    "CONTACT_ROLES",
    "Contact",
    "Registration",
    "Resolver",
    "lookup",
    "normalize_domain",
    "tld_of",
]

__version__ = "1.0.0"
