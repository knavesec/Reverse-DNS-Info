#!/usr/bin/env python3
"""Mass WHOIS/RDAP lookups for a list of domains.

Built on the whois_resolver package, which discovers each TLD's server from IANA
at runtime instead of carrying a hardcoded map, and prefers RDAP where the
registry offers it. That is what makes ccTLDs like .pt work — they use different
field names ("Owner Name" rather than "Registrant Name") and day-first dates,
which the previous python-whois-based version could not read.

Output field names match python-whois where an equivalent exists, so existing
greppable pipelines and whois_comparer.py keep working unchanged.

    python3 whois.py -f domains.txt -g -o whois.log
    python3 whois.py -d dns.pt
    python3 whois.py -f domains.txt --json -o whois.jsonl
"""
import argparse
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional, TextIO

from whois_resolver import Registration, Resolver
from whois_resolver.bootstrap import DEFAULT_CACHE_DIR
from whois_resolver.resolver import normalize_domain

FIELD_PREFIX = "whois_"


class Writer:
    """Thread-safe output sink; keeps the file open instead of reopening per line."""

    def __init__(self, path: str = ""):
        self._lock = threading.Lock()
        self._handle: Optional[TextIO] = None
        if path:
            self._handle = open(path, "a+", encoding="utf-8")

    def write(self, line: str) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.write(line + "\n")
            else:
                sys.stdout.write(line + "\n")

    def flush(self) -> None:
        """For callers whose output is an audit trail that must survive a kill."""
        with self._lock:
            handle = self._handle if self._handle is not None else sys.stdout
            handle.flush()

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            else:
                sys.stdout.flush()


def read_domains(path: str, unique: bool = False) -> List[str]:
    """Read one domain per line; ignores blanks and ``#`` comments."""
    stream = sys.stdin if path == "-" else open(path, "r", encoding="utf-8", errors="ignore")
    try:
        out: List[str] = []
        seen = set()
        for line in stream:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = normalize_domain(line)
            if not domain:
                continue
            if unique:
                if domain in seen:
                    continue
                seen.add(domain)
            out.append(domain)
        return out
    finally:
        if stream is not sys.stdin:
            stream.close()


def _values(value) -> List[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def emit(
    reg: Registration,
    writer: Writer,
    *,
    greppable: bool,
    as_json: bool,
    include_raw: bool,
    fields: Optional[List[str]],
    report_unmapped: bool,
) -> None:
    domain = reg.domain

    if as_json:
        payload = reg.to_dict(include_raw=include_raw)
        payload["registered"] = reg.registered
        writer.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return

    flat = reg.to_flat(include_raw=include_raw)
    if fields:
        wanted = set(fields)
        flat = {k: v for k, v in flat.items() if k in wanted}

    if greppable:
        if reg.registered is False:
            writer.write(f"{domain} : result : UNREGISTERED")
        elif reg.registered is None:
            writer.write(f"{domain} : result : UNDETERMINED")
        for key in flat:
            for value in _values(flat[key]):
                if value:
                    writer.write(f"{domain} : {FIELD_PREFIX}{key} : {value}")
        for err in reg.errors:
            writer.write(f"{domain} : error : {err}")
        if report_unmapped:
            for key, values in reg.unmapped.items():
                for value in values:
                    writer.write(f"{domain} : unmapped_{key} : {value}")
        return

    # Human-readable.
    if reg.registered is False:
        writer.write(f"{domain}: UNREGISTERED")
        writer.write("")
        return
    writer.write(f"{domain}:")
    if reg.registered is None:
        writer.write("\tresult: UNDETERMINED")
    for key, value in flat.items():
        if isinstance(value, (list, tuple)):
            writer.write(f"\t{key}: {', '.join(str(v) for v in value)}")
        else:
            writer.write(f"\t{key}: {value}")
    for err in reg.errors:
        writer.write(f"\terror: {err}")
    if report_unmapped:
        for key, values in reg.unmapped.items():
            writer.write(f"\tunmapped {key}: {', '.join(values)}")
    writer.write("")


def lookup_domains(domains: Iterable[str], options) -> int:
    resolver = Resolver(
        transport=options.transport,
        timeout=options.timeout,
        cache_dir=None if options.no_cache else options.cache_dir,
        cache_ttl=options.cache_ttl,
        follow_referrals=not options.no_referrals,
        rate_limit=options.rate_limit,
        offline=options.offline,
        keep_raw=options.raw,
    )
    writer = Writer(options.outfile)
    fields = [f.strip() for f in options.fields.split(",") if f.strip()] if options.fields else None

    items = list(domains)
    total = len(items)
    done = 0
    failures = 0
    progress_lock = threading.Lock()

    def report(reg: Registration) -> None:
        nonlocal done, failures
        with progress_lock:
            done += 1
            if reg.errors:
                failures += 1
            if not options.quiet:
                state = (
                    "unregistered" if reg.registered is False
                    else "undetermined" if reg.registered is None
                    else reg.source or "ok"
                )
                suffix = f" ({reg.errors[0]})" if reg.errors else ""
                print(f"[{done}/{total}] {reg.domain} : {state}{suffix}",
                      file=sys.stderr, flush=True)

    try:
        # executor.map keeps output in input order while still running lookups
        # concurrently; rate limiting inside the transport is per server, so
        # different registries never block each other.
        with ThreadPoolExecutor(max_workers=max(1, options.threads)) as pool:
            for reg in pool.map(resolver.lookup, items):
                report(reg)
                emit(
                    reg,
                    writer,
                    greppable=options.greppable,
                    as_json=options.json,
                    include_raw=options.raw,
                    fields=fields,
                    report_unmapped=options.report_unmapped,
                )
    finally:
        writer.close()

    if not options.quiet:
        print(f"Done: {total} domains, {failures} with errors", file=sys.stderr)
    return failures


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Perform WHOIS/RDAP lookups for a list of domains, across any TLD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Field names match python-whois where possible (org, emails,\n"
            "name_servers, creation_date, ...), with per-role fields such as\n"
            "registrant_name and admin_email added alongside."
        ),
    )

    source = parser.add_argument_group("input")
    source.add_argument("-f", "--file", default="",
                        help="input filename, one domain per line ('-' for stdin)")
    source.add_argument("-d", "--domain", default=[], action="append", dest="domains",
                        help="a single domain to query (repeatable)")
    source.add_argument("--unique", action="store_true",
                        help="drop duplicate domains from the input")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--outfile", default="",
                     help="output filename, else stdout")
    out.add_argument("-g", "--greppable", action="store_true",
                     help="output as 'domain : whois_field : value'")
    out.add_argument("--json", action="store_true",
                     help="output one JSON object per domain (JSONL)")
    out.add_argument("--fields", default="",
                     help="comma-separated list of fields to keep, e.g. "
                          "'emails,name_servers,registrar'")
    out.add_argument("--raw", action="store_true",
                     help="include the raw registry response in the output")
    out.add_argument("--report-unmapped", action="store_true",
                     help="also report response keys with no alias yet — use this "
                          "to find fields worth adding to whois_resolver/aliases.py")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="suppress per-domain progress on stderr")

    net = parser.add_argument_group("lookup behaviour")
    net.add_argument("--transport", default="auto", choices=("auto", "rdap", "whois"),
                     help="auto (RDAP then port 43), or force one (default: auto)")
    net.add_argument("-t", "--threads", type=int, default=8,
                     help="concurrent lookups (default: 8); rate limiting is "
                          "per registry server, so this is safe to raise")
    net.add_argument("--timeout", type=float, default=25.0,
                     help="per-request timeout in seconds (default: 25)")
    net.add_argument("--rate-limit", type=float, default=None,
                     help="minimum seconds between queries to the same server "
                          "(default: 1.0, with higher per-registry overrides)")
    net.add_argument("--no-referrals", action="store_true",
                     help="do not follow registrar referrals (thin registries "
                          "like .com return only a pointer, so this loses data)")
    net.add_argument("--offline", action="store_true",
                     help="use only cached bootstrap data, never query IANA")

    cache = parser.add_argument_group("caching")
    cache.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR,
                       help=f"response cache directory (default: {DEFAULT_CACHE_DIR})")
    cache.add_argument("--cache-ttl", type=float, default=86400.0,
                       help="cache lifetime in seconds (default: 86400)")
    cache.add_argument("--no-cache", action="store_true",
                       help="do not read or write the response cache")

    return parser


def main() -> int:
    parser = build_parser()
    options = parser.parse_args()

    if options.json and options.greppable:
        parser.error("--json and --greppable are mutually exclusive")

    domains: List[str] = []
    if options.domains:
        for entry in options.domains:
            normalized = normalize_domain(entry)
            if normalized:
                domains.append(normalized)
    if options.file:
        domains.extend(read_domains(options.file, unique=False))
    if options.unique:
        seen = set()
        domains = [d for d in domains if not (d in seen or seen.add(d))]

    if not domains:
        parser.error("must provide --domain or --file")

    failures = lookup_domains(domains, options)
    return 1 if failures == len(domains) else 0


if __name__ == "__main__":
    sys.exit(main())
