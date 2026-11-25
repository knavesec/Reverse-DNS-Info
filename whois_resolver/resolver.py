"""Resolver — picks a transport, chases referrals, decides registration state.

Order of attempts for ``transport="auto"``:

1. **RDAP**, if the TLD is in IANA's bootstrap registry. Structured JSON, no
   parsing ambiguity, and it is the only protocol ICANN still requires of gTLD
   registries — port 43 became optional for them on 2025-01-28.
2. **Port 43**, with the server discovered from ``whois.iana.org``. Required for
   the ~240 TLDs with no RDAP service, .pt among them.

Referrals are followed in both directions: thin gTLD registries (.com, .net)
return only a ``Registrar WHOIS Server`` pointer, so without chasing it you
never see contact data at all.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional

from . import aliases, parse_rdap, parse_text
from .bootstrap import DEFAULT_CACHE_DIR, Bootstrap
from .model import Registration
from .overrides import get_override
from .transport import RateLimiter, ResponseCache, Transport

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def normalize_domain(value: str) -> str:
    """Reduce user input to a bare, lowercase, A-label domain."""
    s = value.strip()
    if not s:
        return ""
    s = _SCHEME_RE.sub("", s)
    s = s.split("/", 1)[0].split("?", 1)[0]
    s = s.split("@")[-1]          # tolerate an email address
    s = s.split()[0] if s.split() else s
    s = s.strip().strip(".").lower()
    if not s:
        return ""

    if any(ord(ch) > 127 for ch in s):
        try:
            s = s.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass
    return s


def tld_of(domain: str) -> str:
    """The delegated TLD, i.e. the last label.

    IANA delegates ``uk``, not ``co.uk``; the registry server for the last label
    answers for everything beneath it, so the last label is the right key for
    both discovery sources.
    """
    return domain.rsplit(".", 1)[-1] if "." in domain else domain


class Resolver:
    def __init__(
        self,
        transport: str = "auto",              # "auto" | "rdap" | "whois"
        timeout: float = 25.0,
        cache_dir: Optional[str] = DEFAULT_CACHE_DIR,
        cache_ttl: float = 86400.0,
        follow_referrals: bool = True,
        max_referrals: int = 2,
        rate_limit: Optional[float] = None,
        offline: bool = False,
        keep_raw: bool = True,
    ):
        if transport not in ("auto", "rdap", "whois"):
            raise ValueError(f"unknown transport: {transport!r}")
        self.mode = transport
        self.follow_referrals = follow_referrals
        self.max_referrals = max_referrals
        self.keep_raw = keep_raw

        limiter = RateLimiter(
            default_interval=aliases.DEFAULT_RATE_LIMIT if rate_limit is None else rate_limit
        )
        self.bootstrap = Bootstrap(
            cache_dir=cache_dir or DEFAULT_CACHE_DIR, timeout=timeout, offline=offline
        )
        self.transport = Transport(
            rate_limiter=limiter,
            cache=ResponseCache(cache_dir, cache_ttl),
            timeout=timeout,
        )

    # -- public API -------------------------------------------------------
    def lookup(self, domain: str) -> Registration:
        normalized = normalize_domain(domain)
        if not normalized or "." not in normalized:
            reg = Registration(domain=domain.strip())
            reg.errors.append("not a valid domain name")
            return reg

        tld = tld_of(normalized)
        reg = Registration(domain=normalized, tld=tld)

        tried_rdap = False
        if self.mode in ("auto", "rdap"):
            urls = self.bootstrap.rdap_base_urls(tld)
            if urls:
                tried_rdap = True
                if self._try_rdap(reg, urls, normalized):
                    return self._finalize(reg)
            elif self.mode == "rdap":
                reg.errors.append(f".{tld} has no RDAP service in the IANA bootstrap")
                return self._finalize(reg)

        if self.mode in ("auto", "whois"):
            if tried_rdap:
                reg.notes.append("RDAP unavailable, fell back to port 43")
            self._try_whois(reg, normalized, tld)
        return self._finalize(reg)

    def lookup_many(self, domains: Iterable[str], workers: int = 8) -> List[Registration]:
        """Concurrent lookups. Safe because rate limiting is per server."""
        items = list(domains)
        if not items:
            return []
        if workers <= 1:
            return [self.lookup(d) for d in items]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(self.lookup, items))

    # -- RDAP -------------------------------------------------------------
    def _try_rdap(self, reg: Registration, base_urls: List[str], domain: str) -> bool:
        last_status = None
        for base in base_urls:
            url = f"{base}/domain/{domain}"
            try:
                status, data, raw, cached = self.transport.rdap(url)
            except Exception as exc:
                reg.notes.append(f"rdap {url}: {exc}")
                continue

            reg.servers_queried.append(url)
            last_status = status

            if status == 404:
                reg.registered = False
                reg.source = "rdap"
                reg.source_server = url
                return True

            if status == 200 and data:
                parse_rdap.parse_rdap(data, domain, reg.tld, reg=reg)
                reg.source = "rdap"
                reg.source_server = url
                if self.keep_raw:
                    reg.raw = raw
                if cached:
                    reg.notes.append("served from cache")
                self._follow_rdap_referrals(reg, data, domain, depth=0)
                reg.registered = True
                return True

            if status == 429:
                reg.notes.append(f"rdap {url}: rate limited (429)")
            elif status:
                reg.notes.append(f"rdap {url}: HTTP {status}")

        if last_status is not None and self.mode == "rdap":
            reg.errors.append(f"rdap failed (last status {last_status})")
        return False

    def _follow_rdap_referrals(self, reg, data, domain: str, depth: int) -> None:
        if not self.follow_referrals or depth >= self.max_referrals:
            return
        for href in parse_rdap.related_rdap_links(data):
            if href in reg.servers_queried:
                continue
            try:
                status, nested, _raw, _cached = self.transport.rdap(href)
            except Exception as exc:
                reg.notes.append(f"rdap referral {href}: {exc}")
                continue
            reg.servers_queried.append(href)
            if status == 200 and nested:
                parse_rdap.parse_rdap(nested, domain, reg.tld, reg=reg)
                reg.notes.append(f"followed RDAP referral to {href}")
                self._follow_rdap_referrals(reg, nested, domain, depth + 1)

    # -- port 43 ----------------------------------------------------------
    def _try_whois(self, reg: Registration, domain: str, tld: str) -> None:
        server = self.bootstrap.whois_server_for_tld(tld)
        if not server:
            reg.errors.append(f"no whois server found for .{tld}")
            reg.errors.extend(self.bootstrap.errors[-1:])
            return

        text = self._query_and_parse(reg, server, domain, tld, primary=True)
        if text is None:
            return

        depth = 0
        seen = {server}
        while (
            self.follow_referrals
            and depth < self.max_referrals
            and reg.whois_server
            and reg.whois_server.lower() not in seen
        ):
            referral = reg.whois_server
            seen.add(referral.lower())
            depth += 1
            reg.notes.append(f"followed whois referral to {referral}")
            self._query_and_parse(reg, referral, domain, tld, primary=False)

    def _query_and_parse(
        self, reg: Registration, server: str, domain: str, tld: str, primary: bool
    ) -> Optional[str]:
        try:
            text, cached = self.transport.whois(server, domain)
        except Exception as exc:
            reg.errors.append(f"{server}: {type(exc).__name__}: {exc}")
            return None

        reg.servers_queried.append(server)
        if primary:
            reg.source = "whois"
            reg.source_server = server
            if self.keep_raw:
                reg.raw = text
            if cached:
                reg.notes.append("served from cache")

        return text if self._apply_response(reg, text, domain, tld, server) else None

    @staticmethod
    def _apply_response(
        reg: Registration, text: str, domain: str, tld: str, server: str
    ) -> bool:
        """Parse a port-43 response, then classify it. False means unusable.

        Parsing comes first deliberately. Scanning for refusal phrases up front
        looks safer but is not: DENIC ends every successful response with "The
        use for other purposes, in particular for advertising, is not permitted",
        so phrase-matching before parsing discarded every .de record. A genuine
        refusal carries no registration data, which is the reliable signal.
        """
        emails_before = len(reg.emails)

        override = get_override(tld)
        if override:
            override(text, domain, tld, reg)
        else:
            parse_text.parse_text(text, domain, tld, reg=reg)

        if reg.has_registration_evidence():
            return True

        # An explicit "does not exist" outranks a generic refusal phrase, which
        # may just be boilerplate riding along.
        if parse_text.detect_not_found(text):
            reg.not_found_response = True
            return True

        refusal = parse_text.detect_refusal(text)
        if refusal:
            # Drop addresses harvested out of the refusal notice itself; they
            # belong to the registry, not to the domain.
            del reg.emails[emails_before:]
            reg.errors.append(f"{server} refused the query: {refusal[:160]}")
            return False
        return True

    # -- registration state ----------------------------------------------
    def _finalize(self, reg: Registration) -> Registration:
        if reg.registered is None:
            reg.registered = self._determine_registered(reg)
        # Nothing at all came back and nothing explained why.
        if reg.registered is None and not reg.errors:
            reg.errors.append("no usable response from any server")
        return reg

    @staticmethod
    def _determine_registered(reg: Registration) -> Optional[bool]:
        """Tri-state: True / False / None (undetermined).

        Positive evidence is checked first. Phrase matching alone gets this
        wrong — .be reports a *live* domain as ``Status: NOT AVAILABLE``, and a
        refusal from .ch or .es contains no not-found phrase at all but must
        never be reported as unregistered.
        """
        for status in reg.statuses:
            if " ".join(status.lower().split()) in aliases.FREE_STATUS_VALUES:
                return False

        if reg.has_registration_evidence():
            return True

        if reg.not_found_response:
            return False
        if reg.raw and parse_text.detect_not_found(reg.raw):
            return False

        if reg.domain_name and reg.statuses:
            return True
        if reg.errors:
            return None
        return None


_DEFAULT: Optional[Resolver] = None


def lookup(domain: str, **kwargs) -> Registration:
    """Convenience one-shot lookup using a shared default resolver."""
    global _DEFAULT
    if kwargs:
        return Resolver(**kwargs).lookup(domain)
    if _DEFAULT is None:
        _DEFAULT = Resolver()
    return _DEFAULT.lookup(domain)
