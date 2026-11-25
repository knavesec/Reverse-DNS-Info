#!/usr/bin/env python3
"""reverse_hunt.py — iterative reverse-WHOIS discovery of a domain estate.

The loop this repo was missing. ``whois_resolver`` turns a domain into registrant
details and ``reverse_whois`` turns registrant details back into domains, so:

    seeds -> resolve -> selectors -> reverse search -> new domains -> resolve -> ...

until a round finds nothing new or a ceiling is hit.

Each round runs in strict cost order, which is the whole reason this is safe to
automate:

1. **Resolve** every known-but-unresolved domain (concurrent, cached).
2. **Derive** selectors from the registrant fields, dropping proxy, redacted and
   generic values — one unfiltered selector like ``Domains By Proxy, LLC`` would
   both wreck the results and empty the credit budget.
3. **Free sources, unbounded**: crt.sh, DNS records, the RIRs. crt.sh hands back
   the target's real legal-entity name variants, which become new selectors
   *before* anything is bought.
4. **Preview-gate** every remaining selector against WhoisXMLAPI's free
   ``mode: preview``. Terms matching zero or more than ``--preview-max`` domains
   are rejected on ground truth, and the rejection is written to
   ``selectors.jsonl`` — a silently dropped term and a term that found nothing
   mean opposite things.
5. **Purchase** the survivors, paginating to exhaustion, current and historic as
   separately tagged passes.

Everything is written to ``--out-dir`` as it happens, so a run is auditable and
resumable, and every scored domain carries the chain of evidence that produced
its score.

Examples
--------
Free sources only, costs nothing::

    python3 reverse_hunt.py -s navistar.com -o ./hunt --providers crtsh,dns,rir

Price the paid terms without buying any of them::

    export WHOISXMLAPI_KEY=...
    python3 reverse_hunt.py -s navistar.com -o ./hunt --providers whoisxmlapi --dry-run

A bounded paid run, then feed the strong hits back into whois.py::

    python3 reverse_hunt.py -s navistar.com -kf keywords.txt -o ./hunt \\
        --search-type both --max-rounds 4 --max-credits 200
    python3 whois.py -f ./hunt/high.txt -g
"""
import argparse
import json
import os
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from whois_resolver import Registration, Resolver
from whois_resolver.bootstrap import DEFAULT_CACHE_DIR
from whois_resolver.resolver import normalize_domain
from whois_resolver.transport import RateLimiter, ResponseCache

from whois import Writer, read_domains

from reverse_whois import noise, providers as provider_registry, scoring
from reverse_whois.budget import Budget, BudgetExhausted
from reverse_whois.domains import registrable_domain
from reverse_whois.http import Http
from reverse_whois.model import (
    KIND_DOMAIN,
    KIND_EMAIL_DOMAIN,
    KIND_NAMESERVER,
    SEARCH_CURRENT,
    SEARCH_FREE,
    Finding,
    ScoredDomain,
    Selector,
    SelectorVerdict,
)
from reverse_whois.scoring import ScoreConfig, SeedProfile
from reverse_whois.selectors import derive_selectors, keyword_selectors, rank, specificity

# Selectors weaker than this are not worth a request even when free: a bare
# postal code or a two-token generic phrase matches unrelated organizations.
DEFAULT_MIN_SPECIFICITY = 0.15

# crt.sh returns megabytes of JSON for a broad organization; the RIRs and DNS are
# fast. One shared limiter with per-host overrides keeps all of them polite.
RATE_OVERRIDES = {
    "crt.sh": 2.0,
    "whois.arin.net": 1.0,
    "rdap.db.ripe.net": 1.0,
    "viewdns.info": 3.0,
}


class Hunt:
    """One run: state, the round loop, and the output files."""

    def __init__(self, options: argparse.Namespace):
        self.opt = options
        self.round = 0

        cache = ResponseCache(
            None if options.no_cache else options.cache_dir,
            ttl=options.cache_ttl,
        )
        self.http = Http(
            rate_limiter=RateLimiter(default_interval=options.rate_limit,
                                     overrides=RATE_OVERRIDES),
            cache=cache,
            timeout=options.timeout,
        )
        self.budget = Budget(
            max_credits=options.max_credits,
            max_rounds=options.max_rounds,
            max_seconds=options.max_seconds,
            preview_max=options.preview_max,
            preview_min=options.preview_min,
            dry_run=options.dry_run,
        )
        self.resolver = Resolver(
            cache_dir=None if options.no_cache else options.cache_dir,
            cache_ttl=options.cache_ttl,
            timeout=options.timeout,
            rate_limit=options.whois_rate_limit,
        )
        self.providers = provider_registry.build(
            options.provider_names, self.http, self.budget,
            search_type=options.search_type,
            page_limit=options.page_limit,
            extra={
                "crtsh": {"max_certs": options.crtsh_max_certs},
                "dns": {"dns_transport": options.dns_transport},
                "rir": {"sweep_ptr": options.rir_ptr, "max_ptr": options.rir_max_ptr,
                        "dns_transport": options.dns_transport},
            },
        )
        # Only WhoisXMLAPI can price a term for free, so it is the gate for every
        # paid provider — including the ones that cannot preview at all.
        self.previewer = next(
            (p for p in self.providers if p.name == "whoisxmlapi" and p.available),
            None,
        )

        # -- state ---------------------------------------------------------
        self.seeds: Set[str] = set()
        self.known: Dict[str, int] = {}          # domain -> round first seen
        self.registrations: Dict[str, Registration] = {}
        self.findings: Dict[str, Finding] = {}   # Finding.key() -> Finding
        self.tried: Set[Tuple[str, str]] = set()  # (provider, selector key)
        self.pending: Dict[str, Selector] = {}   # selector key -> Selector
        self.rejected: Set[str] = set()          # selector keys the gate refused
        self.profile = SeedProfile()
        self.emitted_netblocks: Set[str] = set()
        self.warnings: List[str] = []
        self.reported_warnings: Set[str] = set()

        os.makedirs(options.out_dir, exist_ok=True)
        self._writers: Dict[str, Writer] = {}

    # -- output ------------------------------------------------------------
    def _writer(self, filename: str) -> Writer:
        if filename not in self._writers:
            self._writers[filename] = Writer(os.path.join(self.opt.out_dir, filename))
        return self._writers[filename]

    def _emit(self, filename: str, payload: Dict) -> None:
        writer = self._writer(filename)
        writer.write(json.dumps(payload, sort_keys=True, default=str))
        # Flushed per line on purpose. A hunt can run for hours behind rate
        # limits, and these files are the evidence trail: they should be
        # tailable while the run is in flight and survive a Ctrl-C. The volume
        # here is thousands of lines, not millions, so the cost is irrelevant.
        writer.flush()

    def log(self, message: str) -> None:
        if not self.opt.quiet:
            sys.stderr.write(f"{message}\n")
            sys.stderr.flush()

    def warn(self, message: str) -> None:
        """Record a warning once, and show it: truncation must never be silent."""
        if message in self.reported_warnings:
            return
        self.reported_warnings.add(message)
        self.warnings.append(message)
        writer = self._writer("warnings.txt")
        writer.write(message)
        writer.flush()
        self.log(f"  ! {message}")

    def _drain_provider_errors(self) -> None:
        for provider in self.providers:
            for error in provider.errors:
                self.warn(f"[{provider.name}] {error}")
            provider.errors.clear()

    # -- seeding -----------------------------------------------------------
    def add_domain(self, domain: str, round_found: int) -> bool:
        """Register a domain as known. True if it is new."""
        apex = registrable_domain(domain)
        if not apex or apex in self.known:
            return False
        self.known[apex] = round_found
        self._emit("domains.jsonl", {"domain": apex, "round": round_found})
        return True

    def add_seeds(self, domains: Iterable[str]) -> None:
        for raw in domains:
            apex = registrable_domain(raw) or normalize_domain(raw)
            if not apex:
                continue
            self.seeds.add(apex)
            self.add_domain(apex, 0)

    def add_keywords(self, keywords: Sequence[str]) -> None:
        for selector in keyword_selectors(keywords):
            self._queue(selector)

    def _queue(self, selector: Selector) -> bool:
        """Add a selector to the pending pool unless it is noise or already known."""
        key = selector.key()
        if key in self.pending or key in self.rejected:
            return False
        if not self._usable_selector(selector):
            return False
        self.pending[key] = selector
        return True

    def _usable_selector(self, selector: Selector) -> bool:
        value = selector.value.strip()
        if not value:
            return False
        if noise.is_placeholder(value) or noise.is_geo_only(value):
            self._verdict(selector, "-", "filtered", reason="placeholder or geographic value")
            return False
        if selector.kind in (KIND_EMAIL_DOMAIN, KIND_NAMESERVER, KIND_DOMAIN) \
                and noise.is_registrar_domain(value):
            self._verdict(selector, "-", "filtered",
                          reason="registrar, reseller or privacy-proxy domain")
            return False
        if selector.kind == KIND_NAMESERVER and noise.is_shared_nameserver(value):
            self._verdict(selector, "-", "filtered", reason="shared or parked nameserver")
            return False
        spec = specificity(selector)
        if spec < self.opt.min_specificity:
            self._verdict(selector, "-", "filtered",
                          reason=f"specificity {spec:.2f} below --min-specificity "
                                 f"{self.opt.min_specificity}")
            return False
        return True

    def _verdict(self, selector: Selector, provider: str, decision: str,
                 preview_count: Optional[int] = None, reason: str = "",
                 found: int = 0) -> None:
        self._emit("selectors.jsonl", SelectorVerdict(
            selector=selector, provider=provider, decision=decision,
            preview_count=preview_count, reason=reason,
            round_seen=self.round, found=found,
        ).to_dict())

    # -- round steps -------------------------------------------------------
    def resolve_unresolved(self) -> List[Registration]:
        """Resolve known domains we have not looked up yet."""
        todo = [d for d in self.known if d not in self.registrations]
        if self.opt.max_resolve and len(todo) > self.opt.max_resolve:
            self.warn(
                f"{len(todo)} domains awaiting WHOIS resolution; only "
                f"{self.opt.max_resolve} were resolved this round "
                "(--max-resolve). Selectors from the rest were not derived."
            )
            todo = todo[: self.opt.max_resolve]
        if not todo:
            return []

        self.log(f"  resolving {len(todo)} domain(s)")
        out: List[Registration] = []
        for reg in self.resolver.lookup_many(todo, workers=self.opt.workers):
            apex = registrable_domain(reg.domain) or reg.domain
            self.registrations[apex] = reg
            self._emit("registrations.jsonl", reg.to_dict(include_raw=False))
            out.append(reg)
            for error in reg.errors:
                self.warn(f"[whois {reg.domain}] {error}")
        return out

    def harvest(self, registrations: Sequence[Registration]) -> None:
        """Selectors and free sibling domains from freshly resolved records."""
        queued = 0
        for reg in registrations:
            apex = registrable_domain(reg.domain) or reg.domain
            is_seed = apex in self.seeds

            # The seed profile is the yardstick for corroboration, so only
            # domains already believed to belong to the target contribute to it.
            # Letting candidates in would let one false positive redefine the
            # target and drag the rest of the run with it.
            if is_seed:
                self.profile.add_registration(reg)

            # Only seeds and corroborated domains generate new selectors.
            # Snowballing off an unverified candidate is how a run drifts from
            # "Navistar" to "every domain at a shared hosting provider".
            if not (is_seed or self.opt.expand_all):
                continue

            for selector in derive_selectors(reg, include_keyword=not self.opt.no_keywords):
                if self._queue(selector):
                    queued += 1

            # Domains named by the record itself — a nameserver or email domain
            # under a different apex — need no search at all.
            for finding in self._sibling_findings(reg):
                self._record(finding)

            self._queue(Selector(kind=KIND_DOMAIN, value=apex, source_domain=apex,
                                 source_field="known_domain"))
        if queued:
            self.log(f"  {queued} new selector(s) queued")

    def _sibling_findings(self, reg: Registration) -> List[Finding]:
        """Domains implied directly by a registration, with no request at all.

        A nameserver or contact email under a *different* registrable domain
        names a sibling for free — ``navistar.com`` running
        ``brknspn2.navistar.com`` is unremarkable, but a nameserver at another
        apex is a genuine pivot.
        """
        own = registrable_domain(reg.domain) or reg.domain
        out: List[Finding] = []

        for ns in reg.name_servers:
            host = noise.normalize_nameserver(ns)
            if not host or noise.is_shared_nameserver(host):
                continue
            apex = registrable_domain(host)
            if not apex or apex == own:
                continue
            out.append(Finding(
                domain=apex, provider="whois",
                selector=Selector(kind=KIND_NAMESERVER, value=host,
                                  source_domain=own, source_field="name_servers"),
                search_type=SEARCH_CURRENT, round_found=self.round,
                detail={"via": "nameserver under a different registrable domain"},
            ))

        for raw in list(reg.emails) + [reg.contact(r).email or ""
                                       for r in ("registrant", "admin", "tech", "billing")]:
            if noise.is_registrar_email(raw):
                continue
            email_domain = noise.email_domain_of(raw)
            if not email_domain or noise.is_freemail_domain(email_domain):
                continue
            apex = registrable_domain(email_domain)
            if not apex or apex == own:
                continue
            out.append(Finding(
                domain=apex, provider="whois",
                selector=Selector(kind=KIND_EMAIL_DOMAIN, value=email_domain,
                                  source_domain=own, source_field="contact_email"),
                search_type=SEARCH_CURRENT, round_found=self.round,
                detail={"via": "contact email at a different registrable domain"},
            ))
        return out

    def run_free(self) -> None:
        """Free providers, unbounded, and the selectors they discover."""
        for provider in [p for p in self.providers if p.is_free and p.available]:
            for selector in self._selectors_for(provider):
                found = self._search(provider, selector)
                self._verdict(selector, provider.name, "searched",
                              reason="free source", found=found)

            # crt.sh's legal-entity variants and self-hosted nameservers become
            # selectors now, so the paid stage in this same round can use them.
            promoted = 0
            if hasattr(provider, "org_selectors"):
                for selector in provider.org_selectors():
                    promoted += 1 if self._queue(selector) else 0
            if hasattr(provider, "nameserver_selectors"):
                for selector in provider.nameserver_selectors():
                    promoted += 1 if self._queue(selector) else 0
            if promoted:
                self.log(f"  {provider.name} promoted {promoted} new selector(s)")

            # Providers accumulate netblocks for the whole run, so only the ones
            # not already written are emitted.
            for block in getattr(provider, "netblocks", None) or []:
                key = f"{block.get('rir')}|{block.get('cidr')}|{block.get('net_handle')}"
                if key in self.emitted_netblocks:
                    continue
                self.emitted_netblocks.add(key)
                self._emit("netblocks.jsonl", dict(block, round=self.round))
        self._drain_provider_errors()

    def run_paid(self) -> None:
        """Paid providers, each selector priced by the free preview first."""
        paid = [p for p in self.providers if not p.is_free and p.available]
        if not paid:
            return

        for selector in self._ranked_pending():
            if self.budget.out_of_time():
                return
            allow, decision, reason, count = self._gate(selector)
            if not allow:
                self.rejected.add(selector.key())
                for provider in paid:
                    if provider.supports(selector):
                        self._verdict(selector, provider.name, decision,
                                      preview_count=count, reason=reason)
                continue

            priced = selector.with_preview(count)
            self.pending[selector.key()] = priced
            for provider in paid:
                if not provider.supports(selector):
                    self._verdict(priced, provider.name, "unsupported",
                                  preview_count=count,
                                  reason=f"{provider.name} cannot search {selector.kind}")
                    continue
                if (provider.name, selector.key()) in self.tried:
                    continue
                if not self.budget.can_spend(provider.credits_per_search):
                    self._verdict(priced, provider.name, "budget", preview_count=count,
                                  reason="credit ceiling reached before this selector")
                    continue
                found = self._search(provider, priced)
                self._verdict(priced, provider.name, "searched", preview_count=count,
                              reason=reason, found=found)
        self._drain_provider_errors()

    def _gate(self, selector: Selector) -> Tuple[bool, str, str, Optional[int]]:
        """Price a selector for free, then judge it. Returns (allow, decision, reason, count)."""
        count = selector.preview_count
        if count is None and self.previewer is not None \
                and self.previewer.supports(selector):
            count = self.previewer.preview(selector)
        allow, decision, reason = self.budget.gate(count)
        if count is not None and self.previewer is not None:
            reason = f"{reason} (WhoisXMLAPI preview)"
        return allow, decision, reason, count

    def _selectors_for(self, provider) -> List[Selector]:
        return [s for s in self._ranked_pending()
                if provider.supports(s)
                and (provider.name, s.key()) not in self.tried]

    def _ranked_pending(self) -> List[Selector]:
        """Strongest selectors first, so a credit ceiling truncates the weak tail."""
        ranked = rank(self.pending.values())
        if self.opt.max_selectors and len(ranked) > self.opt.max_selectors:
            self.warn(
                f"{len(ranked)} selectors pending in round {self.round}; only the "
                f"{self.opt.max_selectors} strongest were used "
                "(--max-selectors-per-round)"
            )
            ranked = ranked[: self.opt.max_selectors]
        return ranked

    def _search(self, provider, selector: Selector) -> int:
        """Run one search, record its findings. Returns how many domains it added."""
        self.tried.add((provider.name, selector.key()))
        before = len(self.findings)
        new_domains = 0
        try:
            for finding in provider.search(selector):
                if self._record(finding):
                    new_domains += 1
        except BudgetExhausted as exc:
            self.warn(f"[{provider.name}] {exc}")
        except Exception as exc:                       # a provider must not kill a run
            self.warn(f"[{provider.name}] {selector} failed: {type(exc).__name__}: {exc}")

        added = len(self.findings) - before
        if added:
            self.log(f"  {provider.name} {selector.kind}={selector.value!r}: "
                     f"{added} finding(s), {new_domains} new domain(s)")
        return added

    def _record(self, finding: Optional[Finding]) -> bool:
        """Store a finding. True if its domain had not been seen before."""
        if finding is None or not finding.domain:
            return False
        key = finding.key()
        if key in self.findings:
            return False
        finding.round_found = self.round
        self.findings[key] = finding
        self._emit("findings.jsonl", finding.to_dict())
        return self.add_domain(finding.domain, self.round)

    # -- the loop ----------------------------------------------------------
    def run(self) -> int:
        self.log(f"providers: {', '.join(p.name for p in self.providers) or 'none'}")
        missing = provider_registry.missing_keys(self.opt.provider_names)
        for name, env_vars in missing.items():
            self.warn(f"provider {name} was requested but has no API key; set "
                      f"{' or '.join(env_vars)}. It did not run.")

        for round_number in range(1, self.opt.max_rounds + 1):
            self.round = round_number
            before_domains = len(self.known)
            self.log(f"round {round_number}/{self.opt.max_rounds} "
                     f"({before_domains} domains known, "
                     f"{self.budget.credits_spent} credits spent)")

            registrations = self.resolve_unresolved()
            self.harvest(registrations)
            self.run_free()
            self.run_paid()

            added = len(self.known) - before_domains
            self.log(f"  round {round_number} added {added} domain(s)")

            if self.budget.out_of_time():
                self.warn(f"stopped after round {round_number}: --max-seconds reached. "
                          "The result is incomplete.")
                break
            if self.opt.max_credits is not None and self.budget.remaining() == 0:
                self.warn(f"stopped after round {round_number}: credit ceiling "
                          f"{self.opt.max_credits} reached. The result is incomplete.")
                break
            if added == 0:
                self.log(f"  converged: round {round_number} found nothing new")
                break
        else:
            if len(self.known) > len(self.seeds):
                self.warn(f"stopped at --max-rounds {self.opt.max_rounds} while still "
                          "finding new domains; more rounds would likely find more.")

        return self.report()

    # -- reporting ---------------------------------------------------------
    def report(self) -> int:
        config = ScoreConfig(
            high_score=self.opt.high_score,
            medium_score=self.opt.medium_score,
            preview_max=self.opt.preview_max,
        )
        scored = scoring.score_findings(self.findings.values(), seeds=self.seeds,
                                       config=config)
        scored = self._corroborate(scored, config)
        scored = scoring.sort_scored(scored)

        tiers = scoring.by_tier(scored)
        for tier, filename in ((scoring.TIER_HIGH, "high.txt"),
                               (scoring.TIER_MEDIUM, "medium.txt"),
                               (scoring.TIER_LOW, "low.txt")):
            writer = self._writer(filename)
            for item in tiers.get(tier, []):
                if item.score < self.opt.min_score:
                    continue
                if self.opt.exclude_seeds and item.domain in self.seeds:
                    continue
                writer.write(item.domain)

        for item in scored:
            self._emit("report.jsonl", item.to_dict())

        self.budget.save(os.path.join(self.opt.out_dir, "budget.json"))
        # Rewritten rather than appended: this is the run's final view of what
        # "the target" looks like, not a log of how it got there.
        with open(os.path.join(self.opt.out_dir, "profile.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(self.profile.to_dict(), handle, indent=2, sort_keys=True)

        self._summarize(scored, tiers)
        self.close()
        return 0

    def _corroborate(self, scored: List[ScoredDomain],
                     config: ScoreConfig) -> List[ScoredDomain]:
        """Verify candidates against their own WHOIS records.

        This is the only check in the pipeline that does not rely on trusting a
        third-party index, so it is worth the extra lookups: a candidate whose own
        record carries a seed's registrant email is confirmed rather than merely
        suggested.
        """
        if self.profile.is_empty():
            self.warn("no seed registrant details were readable (redacted or "
                      "unresolvable), so no candidate could be corroborated against "
                      "its own record. Scores rest on provider claims alone.")
            return scored
        if self.opt.corroborate_max == 0:
            return scored

        candidates = [s for s in scored
                      if s.domain not in self.seeds and s.score >= self.opt.min_score]
        if len(candidates) > self.opt.corroborate_max:
            self.warn(
                f"{len(candidates)} candidates qualified for corroboration; only the "
                f"{self.opt.corroborate_max} highest-scoring were checked against "
                "their own WHOIS records (--corroborate-max). The rest keep their "
                "provider-only scores."
            )
            candidates = candidates[: self.opt.corroborate_max]

        todo = [c.domain for c in candidates if c.domain not in self.registrations]
        if todo:
            self.log(f"corroborating {len(candidates)} candidate(s) "
                     f"({len(todo)} new lookups)")
            for reg in self.resolver.lookup_many(todo, workers=self.opt.workers):
                apex = registrable_domain(reg.domain) or reg.domain
                self.registrations[apex] = reg
                self._emit("registrations.jsonl", reg.to_dict(include_raw=False))

        for candidate in candidates:
            reg = self.registrations.get(candidate.domain)
            if reg is not None:
                scoring.corroborate(candidate, reg, self.profile, config)
        return scored

    def _summarize(self, scored: Sequence[ScoredDomain],
                   tiers: Dict[str, List[ScoredDomain]]) -> None:
        confirmed = sum(1 for s in scored if s.corroboration)
        lines = [
            "",
            f"seeds:            {len(self.seeds)}",
            f"domains found:    {len(self.known) - len(self.seeds)} new "
            f"({len(self.known)} total)",
            f"findings:         {len(self.findings)}",
            f"selectors tried:  {len(self.tried)} "
            f"({len(self.rejected)} rejected by the preview gate)",
            f"credits spent:    {self.budget.credits_spent}"
            + (f" / {self.opt.max_credits}" if self.opt.max_credits is not None else ""),
            f"high / medium / low: {len(tiers.get(scoring.TIER_HIGH, []))} / "
            f"{len(tiers.get(scoring.TIER_MEDIUM, []))} / "
            f"{len(tiers.get(scoring.TIER_LOW, []))}",
            f"confirmed on their own record: {confirmed}",
            f"warnings:         {len(self.warnings)}",
            f"output:           {self.opt.out_dir}",
        ]
        if self.opt.dry_run:
            lines.insert(1, "DRY RUN: no paid request was issued")
        self.log("\n".join(lines))

        top = [s for s in scored if s.domain not in self.seeds][: self.opt.show]
        if top:
            self.log("\ntop results:")
            for item in top:
                self.log(f"  {scoring.explain(item)}")

    def close(self) -> None:
        for writer in self._writers.values():
            writer.close()
        self._writers.clear()


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse_hunt.py",
        description="Iterative reverse-WHOIS discovery of a domain estate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "API keys are read from the environment, never the command line:\n"
            "  WHOISXMLAPI_KEY, WHOISFREAKS_KEY, WHOXY_KEY, VIEWDNS_API_KEY\n\n"
            "Providers:\n" + "\n".join(
                f"  {name:12} {'free' if entry.free else 'paid'}  {entry.description}"
                for name, entry in provider_registry.REGISTRY.items()
            )
        ),
    )

    group = parser.add_argument_group("input")
    group.add_argument("-s", "--seed", action="append", default=[], metavar="DOMAIN",
                       help="seed domain; repeatable")
    group.add_argument("-f", "--seeds", metavar="FILE",
                       help="file of seed domains, one per line ('-' for stdin)")
    group.add_argument("-kf", "--keyword-file", metavar="FILE",
                       help="file of extra search terms (e.g. keywords.txt)")
    group.add_argument("-k", "--keyword", action="append", default=[], metavar="TERM",
                       help="extra search term; repeatable")

    group = parser.add_argument_group("providers")
    group.add_argument("--providers", metavar="LIST",
                       help="comma-separated provider names (default: the free "
                            "sources plus any paid provider whose key is set)")
    group.add_argument("--search-type", choices=("current", "historic", "both"),
                       default="both",
                       help="which records to search; historic defeats GDPR "
                            "redaction (default: both)")
    group.add_argument("--page-limit", type=int, default=20, metavar="N",
                       help="max pages per search before reporting truncation "
                            "(default: 20)")
    group.add_argument("--crtsh-max-certs", type=int, default=20000, metavar="N",
                       help="max certificates parsed per crt.sh query (default: 20000)")
    group.add_argument("--rir-ptr", action="store_true",
                       help="reverse-DNS sweep the netblocks found at the RIRs "
                            "(slow; off by default)")
    group.add_argument("--rir-max-ptr", type=int, default=256, metavar="N",
                       help="max addresses per PTR sweep (default: 256)")
    group.add_argument("--dns-transport", choices=("auto", "local", "doh"),
                       default="auto",
                       help="how to query DNS: the local resolver (dnspython or "
                            "dig), DNS-over-HTTPS, or auto — local first, DoH if "
                            "no local resolver is usable (default: auto). Public "
                            "DoH endpoints are blocked on some networks.")

    group = parser.add_argument_group("ceilings")
    group.add_argument("--max-rounds", type=int, default=4, metavar="N",
                       help="snowball rounds (default: 4)")
    group.add_argument("--max-credits", type=int, default=None, metavar="N",
                       help="hard ceiling on paid requests (default: unlimited)")
    group.add_argument("--max-seconds", type=float, default=None, metavar="S",
                       help="wall-clock ceiling (default: unlimited)")
    group.add_argument("--preview-max", type=int, default=5000, metavar="N",
                       help="reject a term matching more than this many domains "
                            "(default: 5000)")
    group.add_argument("--preview-min", type=int, default=1, metavar="N",
                       help="reject a term matching fewer than this (default: 1)")
    group.add_argument("--max-selectors-per-round", type=int, default=200, metavar="N",
                       dest="max_selectors",
                       help="cap on selectors used per round, strongest first "
                            "(default: 200; 0 for no cap)")
    group.add_argument("--max-resolve", type=int, default=500, metavar="N",
                       help="cap on WHOIS lookups per round (default: 500; 0 for no cap)")
    group.add_argument("--corroborate-max", type=int, default=250, metavar="N",
                       help="candidates verified against their own WHOIS record "
                            "(default: 250; 0 to skip)")
    group.add_argument("--dry-run", action="store_true",
                       help="price every term via the free preview but buy nothing")

    group = parser.add_argument_group("scoring and output")
    group.add_argument("-o", "--out-dir", default="./hunt", metavar="DIR",
                       help="output directory (default: ./hunt)")
    group.add_argument("--min-score", type=float, default=0.0, metavar="F",
                       help="omit domains scoring below this from the tier files "
                            "(default: 0, keep everything)")
    group.add_argument("--high-score", type=float, default=scoring.DEFAULT_HIGH_SCORE,
                       metavar="F", help="score needed for the high tier "
                                         f"(default: {scoring.DEFAULT_HIGH_SCORE})")
    group.add_argument("--medium-score", type=float, default=scoring.DEFAULT_MEDIUM_SCORE,
                       metavar="F", help="score needed for the medium tier "
                                         f"(default: {scoring.DEFAULT_MEDIUM_SCORE})")
    group.add_argument("--min-specificity", type=float, default=DEFAULT_MIN_SPECIFICITY,
                       metavar="F",
                       help="drop selectors less discriminating than this "
                            f"(default: {DEFAULT_MIN_SPECIFICITY})")
    group.add_argument("--exclude-seeds", action="store_true",
                       help="leave the seed domains out of the tier files")
    group.add_argument("--no-keywords", action="store_true",
                       help="do not derive keyword selectors from domain names")
    group.add_argument("--expand-all", action="store_true",
                       help="derive selectors from every discovered domain, not just "
                            "the seeds. Finds more and drifts further off-target.")
    group.add_argument("--show", type=int, default=15, metavar="N",
                       help="results explained on stderr at the end (default: 15)")
    group.add_argument("-q", "--quiet", action="store_true",
                       help="suppress progress output")

    group = parser.add_argument_group("network")
    group.add_argument("--timeout", type=float, default=30.0, metavar="S",
                       help="per-request timeout (default: 30)")
    group.add_argument("--rate-limit", type=float, default=1.0, metavar="S",
                       help="minimum seconds between requests to one host "
                            "(default: 1.0)")
    group.add_argument("--whois-rate-limit", type=float, default=1.0, metavar="S",
                       help="minimum seconds between WHOIS/RDAP requests to one "
                            "server (default: 1.0)")
    group.add_argument("--workers", type=int, default=8, metavar="N",
                       help="concurrent WHOIS lookups (default: 8)")
    group.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, metavar="DIR",
                       help=f"response cache (default: {DEFAULT_CACHE_DIR})")
    group.add_argument("--cache-ttl", type=float, default=86400.0, metavar="S",
                       help="cache lifetime in seconds (default: 86400)")
    group.add_argument("--no-cache", action="store_true",
                       help="disable the response cache; paid queries will be "
                            "re-billed on a repeat run")
    return parser


def resolve_provider_names(raw: Optional[str]) -> List[str]:
    """Explicit list, or the free sources plus whichever paid keys are present."""
    if raw:
        names = [n.strip().lower() for n in raw.split(",") if n.strip()]
        unknown = [n for n in names if n not in provider_registry.REGISTRY]
        if unknown:
            raise SystemExit(
                f"unknown provider(s): {', '.join(unknown)}\n"
                f"known: {', '.join(provider_registry.REGISTRY)}"
            )
        return names

    names = list(provider_registry.DEFAULT_FREE)
    names += [n for n in provider_registry.PAID_PROVIDERS if provider_registry.key_for(n)]
    return names


def main() -> int:
    parser = build_parser()
    options = parser.parse_args()

    seeds: List[str] = list(options.seed)
    if options.seeds:
        seeds.extend(read_domains(options.seeds, unique=True))
    if not seeds:
        parser.error("no seeds given; use -s DOMAIN or -f FILE")

    keywords: List[str] = list(options.keyword)
    if options.keyword_file:
        with open(options.keyword_file, "r", encoding="utf-8", errors="ignore") as handle:
            keywords.extend(line.strip() for line in handle if line.strip())

    options.provider_names = resolve_provider_names(options.providers)
    if not options.provider_names:
        parser.error("no providers available; the free sources are always usable, "
                     "so pass --providers crtsh,dns,rir explicitly if this is "
                     "unexpected")

    hunt = Hunt(options)
    try:
        hunt.add_seeds(seeds)
        if keywords:
            hunt.add_keywords(keywords)
        return hunt.run()
    except KeyboardInterrupt:
        hunt.warn("interrupted; the output reflects the work completed so far")
        hunt.budget.save(os.path.join(options.out_dir, "budget.json"))
        hunt.close()
        return 130


if __name__ == "__main__":
    sys.exit(main())
