#!/usr/bin/env python3
"""Score candidate domains against a known-good baseline of WHOIS records.

Given a set of domains you know belong to the target and a set you are unsure
about, this ranks the unsure ones by how much of the baseline's registrant
identity they share. Matches are weighted by ``WHOIS_FIELD_RELEVANCE`` below: a
shared registrant email is near-proof, a shared registrar is nearly meaningless
because a hundred thousand unrelated domains sit at the same registrar.

WHOIS comes from the in-repo ``whois_resolver`` rather than ``python-whois`` —
it covers ccTLDs over RDAP and port 43, caches, rate-limits per server, and its
``to_flat()`` output deliberately keeps ``python-whois`` key names so the
relevance table below applies unchanged.
"""
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from reverse_whois import noise
from whois_resolver import Resolver

WHOIS_FIELD_RELEVANCE: Dict[str, int] = {
    # Sorted alphabetically by key (scores: 0=not relevant, 5=extremely relevant)
    "whois_address": 0,
    "whois_admin": 3,
    "whois_admin_application_purpose": 1,
    "whois_admin_city": 1,
    "whois_admin_country": 2,
    "whois_admin_email": 5,
    "whois_admin_fax": 0,
    "whois_admin_id": 0,
    "whois_admin_name": 3,
    "whois_admin_nexus_category": 1,
    "whois_admin_organization": 4,
    "whois_admin_phone": 2,
    "whois_admin_postal_code": 0,
    "whois_admin_state_province": 1,
    "whois_admin_street": 0,
    "whois_billing_email": 4,
    "whois_billing_phone": 1,
    "whois_city": 0,
    "whois_country": 1,
    "whois_creation_date": 2,
    "whois_dnssec": 2,
    "whois_domain__id": 0,
    "whois_domain_name": 3,
    "whois_emails": 5,
    "whois_emails_domains": 5,  # derived
    "whois_emails_grouped": 5,  # derived
    "whois_expiration_date": 2,
    "whois_id": 0,
    "whois_name": 4,
    "whois_name_servers": 5,
    "whois_org": 4,
    "whois_referral_url": 0,
    "whois_registrant_application_purpose": 1,
    "whois_registrant_city": 1,
    "whois_registrant_country": 2,
    "whois_registrant_email": 5,
    "whois_registrant_fax": 0,
    "whois_registrant_id": 0,
    "whois_registrant_name": 4,
    "whois_registrant_nexus_category": 1,
    "whois_registrant_organization": 4,
    "whois_registrant_phone": 2,
    "whois_registrant_postal_code": 0,
    "whois_registrant_state": 1,
    "whois_registrant_state_province": 1,
    "whois_registrant_street": 0,
    "whois_registrar": 4,
    "whois_registrar_email": 2,
    "whois_registrar_iana_id": 0,
    "whois_registrar_id": 0,
    "whois_registrar_phone": 1,
    "whois_registrar_url": 1,
    "whois_registry_domain_id": 0,
    "whois_reseller": 0,
    "whois_state": 0,
    "whois_status": 3,
    "whois_tech_application_purpose": 1,
    "whois_tech_city": 1,
    "whois_tech_country": 2,
    "whois_tech_email": 5,
    "whois_tech_fax": 0,
    "whois_tech_id": 0,
    "whois_tech_name": 3,
    "whois_tech_nexus_category": 1,
    "whois_tech_organization": 4,
    "whois_tech_phone": 2,
    "whois_tech_postal_code": 0,
    "whois_tech_state_province": 1,
    "whois_tech_street": 0,
    "whois_updated_date": 1,
    "whois_url": 0,
    "whois_whois_server": 1,
    "whois_zipcode": 0,
}

fortune_test_known: List[str] = [
    "3m.com",
    "abbott.com",
    "abbvie.com",
    "acehardware.com",
    "adobe.com",
    "aep.com",
    "aetna.com",
    "aig.com",
    "airbnb.com",
    "albertsons.com",
    "alcon.com",
    "alcoa.com",
    "allstate.com",
    "ally.com",
    "alphabet.com",
    "amazon.com",
    "amcor.com",
    "amd.com",
    "amex.com",
    "amgen.com",
    "amphenol.com",
    "anadarko.com",
    "anthem.com",
    "aon.com",
    "apachecorp.com",
    "apple.com",
    "aramark.com",
    "archeadgroup.com",
    "arconic.com",
    "ariba.com",
    "assurant.com",
    "atlassian.com",
    "att.com",
    "autonation.com",
    "autozone.com",
    "averydennison.com",
    "avisbudgetgroup.com",
    "bakerhughes.com",
    "ball.com",
    "bankofamerica.com",
    "baxter.com",
    "bbvausa.com",
    "bcbs.com",
    "bms.com",
    "boeing.com",
    "booking.com",
    "bostonscientific.com",
    "bristolmyerssquibb.com",
    "broadcom.com",
    "broadridge.com",
    "bunge.com",
    "cah.com",
    "capitalone.com",
    "cardinalhealth.com",
    "carmax.com",
    "carnival.com",
    "carrier.com",
    "caterpillar.com",
    "cboe.com",
    "cbt.com",
    "cbre.com",
    "cdw.com",
    "centene.com",
    "chevron.com",
    "chick-fil-a.com",
    "chipotle.com",
    "chubb.com",
    "cigna.com",
    "cisco.com",
    "citigroup.com",
    "clorox.com",
    "cocacola.com",
    "cognizant.com",
    "colgatepalmolive.com",
    "comcast.com",
    "conocophillips.com",
    "constellationbrands.com",
    "coreweave.com",
    "costco.com",
    "coupang.com",
    "crh.com",
    "csx.com",
    "cummins.com",
    "cvshealth.com",
    "darden.com",
    "deere.com",
    "dell.com",
    "delta.com",
    "devonenergy.com",
    "disney.com",
    "dollargeneral.com",
    "dominos.com",
    "dow.com",
    "drhorton.com",
    "duke-energy.com",
    "dupont.com",
    "eaton.com",
    "ebay.com",
    "elanco.com",
    "emerson.com",
    "energen.com",
    "enterpriseproducts.com",
    "equifax.com",
    "equinix.com",
    "exeloncorp.com",
    "expedia.com",
    "exxonmobil.com",
    "fanniemae.com",
    "fedex.com",
    "fidelity.com",
    "fisglobal.com",
    "ford.com",
    "freddiemac.com",
    "freeportmcmoran.com",
    "gap.com",
    "gartner.com",
    "generaldynamics.com",
    "generalelectric.com",
    "generalmills.com",
    "generalmotors.com",
    "gilead.com",
    "glencore.com",
    "goldmansachs.com",
    "grainger.com",
    "halliburton.com",
    "hartford.com",
    "hcahealthcare.com",
    "hdfc.com",
    "henkel.com",
    "hess.com",
    "honeywell.com",
    "hp.com",
    "humana.com",
    "ibm.com",
    "idexx.com",
    "illumina.com",
    "intel.com",
    "intuit.com",
    "its.jnj.com",
    "jabil.com",
    "jpmorganchase.com",
    "kelloggcompany.com",
    "kroger.com",
    "l3harris.com",
    "labcorp.com",
    "lasvegassands.com",
    "lennar.com",
    "libertymutual.com",
    "lilly.com",
    "linkedin.com",
    "lockheedmartin.com",
    "lowes.com",
    "lululemon.com",
    "lyondellbasell.com",
    "marathonpetroleum.com",
    "marriott.com",
    "mastercard.com",
    "mcdonalds.com",
    "mckesson.com",
    "medtronic.com",
    "metlife.com",
    "meta.com",
    "micron.com",
    "microsoft.com",
    "molinahealthcare.com",
    "monsanto.com",
    "morganstanley.com",
    "motorolasolutions.com",
    "netflix.com",
    "newmont.com",
    "nike.com",
    "nordstrom.com",
    "nvidia.com",
    "occidental.com",
    "omnicomgroup.com",
    "oracle.com",
    "oshkoshcorp.com",
    "outlook.com",
    "paccar.com",
    "pandora.com",
    "paramount.com",
    "paychex.com",
    "paycom.com",
    "paypal.com",
    "pbfenergy.com",
    "pepsico.com",
    "pfizer.com",
    "pg.com",
    "pinterest.com",
    "pnc.com",
    "prologis.com",
    "prudential.com",
    "publix.com",
    "qualcomm.com",
    "questdiagnostics.com",
    "raytheon.com",
    "regeneron.com",
    "republicservices.com",
    "rheem.com",
    "riteaid.com",
    "roku.com",
    "rossstores.com",
    "salesforce.com",
    "samsclub.com",
    "sandisk.com",
    "schlumberger.com",
    "servicenow.com",
    "sherwin.com",
    "shopify.com",
    "slb.com",
    "snap.com",
    "sony.com",
    "southwest.com",
    "spotify.com",
    "squareup.com",
    "starbucks.com",
    "statefarm.com",
    "stryker.com",
    "symantec.com",
    "target.com",
    "tesla.com",
    "texas instruments.com",
    "t-mobile.com",
    "tjx.com",
    "travelers.com",
    "truist.com",
    "tysonfoods.com",
    "uber.com",
    "united.com",
    "unitedhealthgroup.com",
    "ups.com",
    "usbank.com",
    "verizon.com",
    "visa.com",
    "volkswagen.com",
    "walmart.com",
    "wellsfargo.com",
    "westernunion.com",
    "wework.com",
    "whirlpoolcorp.com",
    "workday.com",
    "xfinity.com",
    "xpo.com",
    "yahoo.com",
    "yelp.com",
    "zoom.us",
]


def _normalize_domain(line: str) -> Optional[str]:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    s = s.split()[0].strip()
    s = s.replace("https://", "").replace("http://", "")
    s = s.split("/")[0]
    s = s.strip(".").lower()
    if not s:
        return None
    return s


def read_domains(path: str) -> List[str]:
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = _normalize_domain(line)
            if d:
                out.append(d)
    return out


def _as_str_set(v: Any) -> Set[str]:
    if v is None:
        return set()
    if isinstance(v, (list, tuple, set)):
        vals = v
    else:
        vals = [v]
    out: Set[str] = set()
    for item in vals:
        if item is None:
            continue
        try:
            s = str(item).strip()
        except Exception:
            continue
        if not s:
            continue
        out.add(s)
    return out


def _normalize_email(s: str) -> Optional[str]:
    s = s.strip().strip("<>").strip().lower()
    if not s or "@" not in s:
        return None
    # handle "Name <email@domain>"
    if "<" in s and ">" in s:
        inner = s.split("<", 1)[1].split(">", 1)[0].strip()
        if "@" in inner:
            s = inner
    if s.count("@") != 1:
        return None
    local, dom = s.split("@", 1)
    local = local.strip()
    dom = dom.strip().strip(".")
    if not local or not dom:
        return None
    return f"{local}@{dom}"


def aggregate_emails(w_clean: Dict[str, Any]) -> Dict[str, Any]:
    """
    Group related fields like emails into higher-signal baselining features.
    Currently:
      - whois_emails_domains: unique set of email domains from whois_emails
      - whois_emails_grouped: { email_domain: [emails...] }
    """
    raw = w_clean.get("emails")
    emails: List[str] = []
    if isinstance(raw, str):
        ne = _normalize_email(raw)
        if ne:
            emails = [ne]
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if not isinstance(item, str):
                continue
            ne = _normalize_email(item)
            if ne:
                emails.append(ne)

    grouped: Dict[str, List[str]] = {}
    for e in sorted(set(emails)):
        dom = e.split("@", 1)[1]
        grouped.setdefault(dom, []).append(e)

    if not grouped:
        return {}

    return {
        "emails_domains": sorted(grouped.keys()),
        "emails_grouped": grouped,
    }


@dataclass(frozen=True)
class WhoisSignals:
    registrar: Set[str]
    org: Set[str]
    name: Set[str]
    emails: Set[str]
    name_servers: Set[str]


def extract_signals(w: Dict[str, Any]) -> WhoisSignals:
    return WhoisSignals(
        registrar=_as_str_set(w.get("registrar")),
        org=_as_str_set(w.get("org")),
        name=_as_str_set(w.get("name")),
        emails=_as_str_set(w.get("emails")),
        name_servers=_as_str_set(w.get("name_servers") or w.get("name_server")),
    )


_RESOLVER: Optional[Resolver] = None


def resolver(**kwargs: Any) -> Resolver:
    """The process-wide resolver, so the cache and rate limiter are shared."""
    global _RESOLVER
    if _RESOLVER is None:
        _RESOLVER = Resolver(keep_raw=False, **kwargs)
    return _RESOLVER


def whois_lookup(domain: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Flat WHOIS dict for one domain, or (None, error)."""
    return _flatten(resolver().lookup(domain))


def whois_lookup_many(
    domains: Sequence[str], workers: int = 8
) -> List[Tuple[str, Optional[Dict[str, Any]], Optional[str]]]:
    """Concurrent lookups. Rate limiting is per server, so this is safe."""
    out = []
    for reg in resolver().lookup_many(domains, workers=workers):
        flat, err = _flatten(reg)
        out.append((reg.domain, flat, err))
    return out


def _flatten(reg: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Registration -> python-whois-shaped dict, or an error string.

    An unregistered domain is an error here rather than an empty record: there
    is nothing to compare, and reporting it as "no match" would imply the
    comparison ran.
    """
    if not reg.has_registration_evidence():
        return None, "; ".join(reg.errors) or "no registration data returned"
    return reg.to_flat(), None


# The noise filters live in reverse_whois.noise, which carries a far larger list
# of privacy proxies, registrar abuse mailboxes and shared nameservers than the
# handful this file used to hard-code. The old names are kept as aliases because
# a selector like ``withheldforprivacy.com`` matching across the baseline would
# otherwise drag in millions of unrelated domains.
_is_redacted = noise.is_redacted
_is_default_registrar_email = noise.is_default_registrar_email
_is_default_registrar_nameserver = noise.is_default_registrar_nameserver
_normalize_ns = noise.normalize_nameserver


def clean_whois_dict(w: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for k, v in w.items():
        if v is None:
            continue

        if isinstance(v, (list, tuple, set)):
            items: List[Any] = []
            for item in v:
                if item is None:
                    continue
                if isinstance(item, str) and _is_redacted(item):
                    continue
                if k == "emails" and isinstance(item, str) and _is_default_registrar_email(item):
                    continue
                if k in ("name_servers", "name_server") and isinstance(item, str) and _is_default_registrar_nameserver(item):
                    continue
                items.append(item)
            if not items:
                continue
            cleaned[k] = items
            continue

        if isinstance(v, str) and _is_redacted(v):
            continue
        if k == "emails" and isinstance(v, str) and _is_default_registrar_email(v):
            continue
        if k in ("name_servers", "name_server") and isinstance(v, str) and _is_default_registrar_nameserver(v):
            continue

        cleaned[k] = v
    return cleaned


def output(outfile: str, line: str) -> None:
    if not outfile:
        print(line)
        return
    with open(outfile, "a+", encoding="utf-8") as f:
        f.write(line)
        f.write("\n")


def _emit_match(
    *,
    greppable: bool,
    outfile: str,
    test_domain: str,
    field: str,
    value: str,
    known_domain: Optional[str] = None,
) -> None:
    if greppable:
        if known_domain:
            output(outfile, f"{test_domain} : match_{field} : {value} : {known_domain}")
        else:
            output(outfile, f"{test_domain} : match_{field} : {value}")
    else:
        if known_domain:
            output(outfile, f"{test_domain}\n  match {field}: {value}\n  known: {known_domain}")
        else:
            output(outfile, f"{test_domain}\n  match {field}: {value}")


# Only fields at least this relevant are compared. Below 4 a shared value is
# evidence of nothing: every domain at the same registrar would match, and a
# third of the internet lists the same country.
MIN_INDEX_RELEVANCE = 4

# WHOIS_FIELD_RELEVANCE grades how identifying a field is, and by that measure
# `registrar` deserves its 4 — it tells you a lot about a domain. But as a
# *match* between two domains it means almost nothing, because a single registrar
# holds millions of unrelated domains. It stays indexed so the match is still
# reported as evidence; the weight override just stops it driving a tier.
FIELD_WEIGHT_OVERRIDES: Dict[str, float] = {"registrar": 1.0}

# Diminishing returns: five middling matches on one record should not outrank a
# single shared registrant email. Same reasoning as reverse_whois.scoring.
SCORE_DECAY = 0.6

TIER_HIGH = "high"
TIER_MEDIUM = "medium"
TIER_LOW = "low"

# 5.0 is one exact email/nameserver match plus a little; 3.5 sits just below a
# single organization match (4.0), so an org hit alone lands in medium.
HIGH_SCORE = 5.0
MEDIUM_SCORE = 3.5

EMAIL_FIELDS = ("emails",)
DOMAIN_FIELDS = ("emails_domains",)
NAMESERVER_FIELDS = ("name_servers", "name_server")


def field_weight(field: str) -> float:
    """How much a match on this field is worth."""
    if field in FIELD_WEIGHT_OVERRIDES:
        return FIELD_WEIGHT_OVERRIDES[field]
    return float(WHOIS_FIELD_RELEVANCE.get(f"whois_{field}", 0))


def is_comparable_field(field: str) -> bool:
    if field in ("emails_grouped",):     # a dict; its contents are indexed already
        return False
    return WHOIS_FIELD_RELEVANCE.get(f"whois_{field}", 0) >= MIN_INDEX_RELEVANCE


def normalize_signal(field: str, value: Any) -> Optional[str]:
    """Comparable form of one field value, or None if it is noise.

    This is where privacy proxies and shared infrastructure are dropped. Without
    it a baseline of MarkMonitor-registered brands would match every other
    MarkMonitor domain on earth through `abusecomplaints@markmonitor.com`.
    """
    text = str(value).strip()
    if not text:
        return None

    if field.endswith("_email") or field in EMAIL_FIELDS:
        addr = noise.normalize_email(text)
        if not addr or noise.is_registrar_email(addr):
            return None
        if noise.is_freemail_domain(addr.split("@", 1)[1]):
            return None            # a gmail address is a person, not an estate
        return addr

    if field in DOMAIN_FIELDS:
        dom = noise.normalize(text).lstrip("@").rstrip(".")
        if not dom or noise.is_registrar_domain(dom) or noise.is_freemail_domain(dom):
            return None
        return dom

    if field in NAMESERVER_FIELDS:
        ns = noise.normalize_nameserver(text)
        if not ns or noise.is_shared_nameserver(ns):
            return None
        return ns

    norm = noise.normalize(text)
    if not norm or noise.is_placeholder(norm) or noise.is_geo_only(norm):
        return None
    return norm


def signal_values(flat: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(field, comparable value) for every field worth matching on."""
    out: List[Tuple[str, str]] = []
    for field, raw in flat.items():
        if not is_comparable_field(field):
            continue
        for item in _as_str_set(raw):
            normalized = normalize_signal(field, item)
            if normalized:
                out.append((field, normalized))
    return out


def prepare(flat: Dict[str, Any]) -> Dict[str, Any]:
    """Cleaned record plus the derived email-domain fields.

    Both sides of the comparison go through this, so both have the derived keys.
    """
    cleaned = clean_whois_dict(flat)
    cleaned.update(aggregate_emails(cleaned))
    return cleaned


@dataclass(frozen=True)
class Match:
    field: str
    value: str
    weight: float
    known_domains: Tuple[str, ...]


@dataclass
class ScoredCandidate:
    domain: str
    score: float
    tier: str
    matches: List[Match]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "score": round(self.score, 2),
            "tier": self.tier,
            "matched_known_domains": sorted(
                {kd for m in self.matches for kd in m.known_domains}
            ),
            "evidence": [
                {"field": m.field, "value": m.value, "weight": m.weight,
                 "known_domains": list(m.known_domains)}
                for m in self.matches
            ],
        }


# to_flat() emits python-whois compatibility aliases alongside the per-role
# fields, so the same organization arrives as both `org` and
# `registrant_organization`. Scoring them separately would double every match.
FIELD_ALIASES: Dict[str, str] = {
    "org": "registrant_organization",
    "name": "registrant_name",
    "address": "registrant_street",
    "zipcode": "registrant_postal_code",
    "city": "registrant_city",
    "state": "registrant_state",
    "country": "registrant_country",
}


def fact_key(field: str, value: str) -> str:
    """What distinct thing this match tells us.

    Nameservers collapse to one key: an estate runs its hosts as a set, and
    matching three of them is one fact — "these domains share DNS" — not three.
    Email addresses stay distinct from each other but collapse across contact
    roles, because the same address on registrant and admin is one mailbox.
    """
    if field in NAMESERVER_FIELDS:
        return "nameservers"
    if field.endswith("_email") or field in EMAIL_FIELDS:
        return f"email|{value}"
    if field in DOMAIN_FIELDS:
        return f"email_domain|{value}"
    return f"{FIELD_ALIASES.get(field, field)}|{value}"


def score_matches(domain: str, matches: Sequence[Match]) -> ScoredCandidate:
    """Weighted score with diminishing returns, plus a tier."""
    ordered = sorted(matches, key=lambda m: (-m.weight, m.field, m.value))

    # Strongest weight per distinct fact, then decayed.
    facts: Dict[str, float] = {}
    for match in ordered:
        key = fact_key(match.field, match.value)
        facts[key] = max(facts.get(key, 0.0), match.weight)
    score = sum(weight * (SCORE_DECAY ** i)
                for i, weight in enumerate(sorted(facts.values(), reverse=True)))

    if any(m.weight >= 5.0 for m in ordered):
        # An exact registrant email, email domain or self-hosted nameserver in
        # common is not something unrelated organizations have by accident.
        tier = TIER_HIGH
    elif score >= HIGH_SCORE:
        tier = TIER_HIGH
    elif score >= MEDIUM_SCORE:
        tier = TIER_MEDIUM
    else:
        tier = TIER_LOW
    return ScoredCandidate(domain=domain, score=score, tier=tier, matches=list(ordered))


def build_baseline(
    known_domains: Sequence[str],
    workers: int = 8,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, WhoisSignals], Dict[str, Dict[str, Set[str]]]]:
    whois_by_domain: Dict[str, Dict[str, Any]] = {}
    per_domain: Dict[str, WhoisSignals] = {}
    index: Dict[str, Dict[str, Set[str]]] = {}

    for domain, flat, err in whois_lookup_many(known_domains, workers=workers):
        if err or flat is None:
            continue
        cleaned = prepare(flat)
        whois_by_domain[domain] = cleaned
        # Signals come from the cleaned record, not the raw one: indexing the raw
        # values would put every privacy-proxy address into the baseline.
        per_domain[domain] = extract_signals(cleaned)
        for field, value in signal_values(cleaned):
            index.setdefault(field, {}).setdefault(value, set()).add(domain)
    return whois_by_domain, per_domain, index


def output_known_valids(
    *,
    whois_by_domain: Dict[str, Dict[str, Any]],
    greppable: bool,
    outfile: str,
) -> None:
    for domain in sorted(whois_by_domain.keys()):
        w = whois_by_domain[domain]
        if greppable:
            for k in sorted(w.keys()):
                output(outfile, f"{domain} : whois_{k} : {w[k]}")
            output(outfile, f"{domain} : result : VALID_WHOIS_OK")
        else:
            output(outfile, f"{domain}:")
            for k in sorted(w.keys()):
                output(outfile, f"  {k}: {w[k]}")
            output(outfile, "")


def compare_domains(
    *,
    known_index: Dict[str, Dict[str, Set[str]]],
    test_domains: Sequence[str],
    greppable: bool,
    outfile: str,
    workers: int = 8,
    min_score: float = 0.0,
    report_file: str = "",
) -> List[ScoredCandidate]:
    """Score each test domain against the baseline index.

    Returns the scored candidates, highest confidence first. Every match is
    emitted as evidence even when the total falls below --min-score, so a
    filtered-out domain is visibly filtered rather than missing.
    """
    scored: List[ScoredCandidate] = []

    for domain, flat, err in whois_lookup_many(test_domains, workers=workers):
        if err or flat is None:
            if greppable:
                output(outfile, f"{domain} : error : {err}")
            else:
                output(outfile, f"{domain}\n  error: {err}")
            continue

        matches: List[Match] = []
        for field, value in signal_values(prepare(flat)):
            knowns = known_index.get(field, {}).get(value)
            if not knowns:
                continue
            matches.append(Match(field=field, value=value,
                                 weight=field_weight(field),
                                 known_domains=tuple(sorted(knowns))))

        if not matches:
            if greppable:
                output(outfile, f"{domain} : result : NO_MATCH")
            else:
                output(outfile, f"{domain}\n  result: NO_MATCH")
            continue

        candidate = score_matches(domain, matches)
        scored.append(candidate)

        if candidate.score < min_score:
            if greppable:
                output(outfile, f"{domain} : result : BELOW_MIN_SCORE : "
                                f"{candidate.score:.2f} < {min_score}")
            else:
                output(outfile, f"{domain}\n  result: below --min-score "
                                f"({candidate.score:.2f} < {min_score})")
            continue

        for match in candidate.matches:
            # One line per known domain, for grepping.
            for known in match.known_domains:
                _emit_match(greppable=greppable, outfile=outfile,
                            test_domain=domain, field=match.field,
                            value=match.value, known_domain=known)

        if greppable:
            output(outfile, f"{domain} : score : {candidate.score:.2f} : "
                            f"{candidate.tier}")
        else:
            output(outfile, f"{domain}\n  score: {candidate.score:.2f} "
                            f"({candidate.tier} confidence)")

    scored.sort(key=lambda c: (-c.score, c.domain))

    if report_file:
        with open(report_file, "a+", encoding="utf-8") as handle:
            for candidate in scored:
                handle.write(json.dumps(candidate.to_dict(), sort_keys=True) + "\n")

    return scored


def _add_bool_arg(parser: argparse.ArgumentParser, name: str, default: bool, help_text: str) -> None:
    try:
        parser.add_argument(name, default=default, action=argparse.BooleanOptionalAction, help=help_text)
    except AttributeError:
        # Python < 3.9 fallback
        dest = name.lstrip("-").replace("-", "_")
        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument(name, dest=dest, action="store_true", help=help_text)
        group.add_argument(f"--no-{dest.replace('_','-')}", dest=dest, action="store_false", help=f"disable: {help_text}")
        parser.set_defaults(**{dest: default})


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare WHOIS signals of test domains against a known-valid baseline",
        epilog="Scores are weighted by WHOIS_FIELD_RELEVANCE with diminishing "
               "returns, so one shared registrant email outranks a pile of weak "
               "matches. Tiers: high >= %.1f, medium >= %.1f."
               % (HIGH_SCORE, MEDIUM_SCORE),
    )

    parser.add_argument("--know_valids", required=True, help="file containing known valid domains (one per line)")
    parser.add_argument("--test_file", required=True, help="file containing domains to test (one per line)")
    _add_bool_arg(parser, "--greppable", default=True, help_text="emit greppable output (default: true)")
    parser.add_argument("-o", "--outfile", default="", required=False, help="output filename, else stdout")
    parser.add_argument("--baseline", action="store_true",
                        help="also dump the cleaned WHOIS records of the baseline domains")
    parser.add_argument("--score", action="store_true",
                        help="print a ranked score summary at the end")
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="suppress evidence for candidates scoring below this "
                             "(they are still reported as BELOW_MIN_SCORE, never dropped silently)")
    parser.add_argument("--report", default="",
                        help="write one JSON object per scored candidate to this file")
    parser.add_argument("--workers", type=int, default=8,
                        help="concurrent WHOIS lookups (default: 8; rate limiting is per server)")

    options = parser.parse_args()

    known_domains = read_domains(options.know_valids)
    test_domains = read_domains(options.test_file)

    whois_by_domain, _, known_index = build_baseline(known_domains, workers=options.workers)
    if not whois_by_domain:
        sys.stderr.write("no baseline domain returned usable WHOIS data; "
                         "nothing to compare against\n")
        raise SystemExit(1)
    if len(whois_by_domain) < len(known_domains):
        sys.stderr.write(
            f"warning: {len(known_domains) - len(whois_by_domain)} of "
            f"{len(known_domains)} baseline domains returned no usable WHOIS "
            "data and are not part of the baseline\n"
        )

    if options.baseline:
        output_known_valids(
            whois_by_domain=whois_by_domain,
            greppable=bool(options.greppable),
            outfile=options.outfile,
        )

    scored = compare_domains(
        known_index=known_index,
        test_domains=test_domains,
        greppable=bool(options.greppable),
        outfile=options.outfile,
        workers=options.workers,
        min_score=options.min_score,
        report_file=options.report,
    )

    if options.score:
        for candidate in scored:
            if candidate.score < options.min_score:
                continue
            top = ", ".join(f"{m.field}={m.value}" for m in candidate.matches[:3])
            output(options.outfile,
                   f"{candidate.domain} : {candidate.tier} : "
                   f"{candidate.score:.2f} : {top}")


if __name__ == "__main__":
    main()

