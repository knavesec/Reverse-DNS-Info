#!/usr/bin/env python3
"""ASN lookup tool - retrieve registrant information and CIDR ranges for ASNs.

Queries the five Regional Internet Registries (RIRs) via RDAP to fetch ASN details:
- ARIN (North America)
- RIPE NCC (Europe, Middle East, Central Asia)
- APNIC (Asia-Pacific)
- LACNIC (Latin America and Caribbean)
- AFRINIC (Africa)

Automatically determines which RIR to query based on the ASN number range.

Examples:
    python3 asn_lookup.py -a AS15169
    python3 asn_lookup.py -a 15169 -a 13335 --json
    python3 asn_lookup.py -f asns.txt -o output.json --json
"""
import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


# RIR RDAP endpoints - these return structured JSON data
RIR_ENDPOINTS = {
    "arin": "https://rdap.arin.net/registry/autnum/",
    "ripe": "https://rdap.db.ripe.net/autnum/",
    "apnic": "https://rdap.apnic.net/autnum/",
    "lacnic": "https://rdap.lacnic.net/rdap/autnum/",
    "afrinic": "https://rdap.afrinic.net/rdap/autnum/",
}

# ASN allocation ranges by RIR (approximate, as of 2024)
# These help us guess which RIR to try first
ASN_RANGES = [
    (1, 23455, "arin"),
    (23456, 23456, "iana"),  # Reserved for documentation
    (23457, 64534, "arin"),
    (64512, 65534, "reserved"),  # Private use
    (65535, 65535, "reserved"),
    (65536, 131071, "apnic"),
    (131072, 196607, "apnic"),
    (196608, 262143, "arin"),
    (262144, 327679, "lacnic"),
    (327680, 393215, "arin"),
    (393216, 4294967295, "mixed"),  # 4-byte ASNs are distributed
]


class AsnInfo:
    """Structured ASN information."""

    def __init__(self, asn: int):
        self.asn = asn
        self.name: Optional[str] = None
        self.description: Optional[str] = None
        self.country: Optional[str] = None
        self.registrant: Optional[str] = None
        self.registration_date: Optional[str] = None
        self.last_updated: Optional[str] = None
        self.ipv4_ranges: List[str] = []
        self.ipv6_ranges: List[str] = []
        self.rir: Optional[str] = None
        self.errors: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "asn": self.asn,
            "name": self.name,
            "description": self.description,
            "country": self.country,
            "registrant": self.registrant,
            "registration_date": self.registration_date,
            "last_updated": self.last_updated,
            "ipv4_ranges": self.ipv4_ranges,
            "ipv6_ranges": self.ipv6_ranges,
            "rir": self.rir,
            "errors": self.errors if self.errors else None,
        }


def normalize_asn(asn_str: str) -> Optional[int]:
    """Parse ASN string, handling 'AS' prefix."""
    asn_str = asn_str.strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]
    try:
        asn = int(asn_str)
        if asn < 0 or asn > 4294967295:  # Max 32-bit ASN
            return None
        return asn
    except ValueError:
        return None


def guess_rir(asn: int) -> str:
    """Guess which RIR owns this ASN based on allocation ranges."""
    for start, end, rir in ASN_RANGES:
        if start <= asn <= end:
            return rir
    return "unknown"


def fetch_rdap(url: str, timeout: float = 15.0) -> Tuple[int, Optional[Dict], Optional[str]]:
    """Fetch RDAP JSON response. Returns (status_code, parsed_json, error_message)."""
    try:
        req = Request(url)
        req.add_header("Accept", "application/rdap+json, application/json")
        req.add_header("User-Agent", "asn-lookup/1.0")

        with urlopen(req, timeout=timeout) as response:
            status = response.status
            data = response.read()
            if data:
                return status, json.loads(data.decode("utf-8")), None
            return status, None, None
    except HTTPError as e:
        return e.code, None, f"HTTP {e.code}"
    except URLError as e:
        return 0, None, f"URL error: {e.reason}"
    except json.JSONDecodeError as e:
        return 0, None, f"JSON decode error: {e}"
    except Exception as e:
        return 0, None, f"Error: {type(e).__name__}: {e}"


def parse_rdap_response(data: Dict, asn: int, rir: str) -> AsnInfo:
    """Parse RDAP JSON response into AsnInfo."""
    info = AsnInfo(asn)
    info.rir = rir

    # Basic ASN info
    info.name = data.get("name")
    info.country = data.get("country")

    # Dates
    events = data.get("events", [])
    for event in events:
        event_action = event.get("eventAction", "")
        event_date = event.get("eventDate", "")
        if event_action == "registration":
            info.registration_date = event_date
        elif event_action == "last changed":
            info.last_updated = event_date

    # Registrant/entity information
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrant" in roles or "holder" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4:
                        if field[0] == "fn":  # Full name
                            info.registrant = field[3]
                            break
            # Fallback to entity handle or name
            if not info.registrant:
                info.registrant = entity.get("handle") or entity.get("name")

    # Remarks often contain description
    remarks = data.get("remarks", [])
    descriptions = []
    for remark in remarks:
        if remark.get("title") == "description" or remark.get("type") == "object":
            desc_parts = remark.get("description", [])
            descriptions.extend(desc_parts)
    if descriptions:
        info.description = " ".join(descriptions)

    return info


def lookup_asn_rdap(asn: int, timeout: float = 15.0) -> AsnInfo:
    """Look up ASN via RDAP, trying all RIRs if needed."""
    info = AsnInfo(asn)

    # Guess which RIR to try first
    primary_rir = guess_rir(asn)

    # Order: try guessed RIR first, then others
    rir_order = []
    if primary_rir in RIR_ENDPOINTS:
        rir_order.append(primary_rir)
    for rir_name in RIR_ENDPOINTS:
        if rir_name not in rir_order:
            rir_order.append(rir_name)

    # Try each RIR until we get a successful response
    for rir_name in rir_order:
        url = f"{RIR_ENDPOINTS[rir_name]}{asn}"
        status, data, error = fetch_rdap(url, timeout)

        if status == 200 and data:
            info = parse_rdap_response(data, asn, rir_name)
            break
        elif status == 404:
            continue  # Try next RIR
        elif error and status != 0:
            info.errors.append(f"{rir_name}: {error}")

    if not info.rir:
        info.errors.append("ASN not found in any RIR")
    else:
        # Look up announced prefixes via RIPE Stat (needs longer timeout for large ASNs)
        # Use max of 60 seconds or user's timeout to handle large ASNs like Cloudflare
        prefix_timeout = max(60.0, timeout)
        info.ipv4_ranges, info.ipv6_ranges = lookup_asn_prefixes(asn, timeout=prefix_timeout)

    return info


def lookup_asn_prefixes(asn: int, timeout: float = 30.0) -> Tuple[List[str], List[str]]:
    """Look up IP prefixes announced by this ASN via RIPE Stat API.

    Uses RIPE Stat's announced-prefixes data call, which aggregates BGP data
    from multiple sources (RIS, RouteViews) and works for ASNs globally.
    """
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

    try:
        req = Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "asn-lookup/1.0")

        # Open connection and read all data at once (simpler, more reliable)
        response = urlopen(req, timeout=timeout)
        # Read all data - for large ASNs this can be 500KB+
        raw_data = b''
        while True:
            chunk = response.read(16384)  # 16KB chunks
            if not chunk:
                break
            raw_data += chunk
        response.close()

        # Parse JSON
        data = json.loads(raw_data.decode("utf-8"))

        if data.get("status") != "ok":
            return [], []

        prefixes = data.get("data", {}).get("prefixes", [])

        ipv4_ranges = []
        ipv6_ranges = []

        for item in prefixes:
            prefix = item.get("prefix", "")
            if not prefix:
                continue

            # Separate IPv4 and IPv6 by presence of ':'
            if ":" in prefix:
                ipv6_ranges.append(prefix)
            else:
                ipv4_ranges.append(prefix)

        return sorted(ipv4_ranges), sorted(ipv6_ranges)

    except (HTTPError, URLError, json.JSONDecodeError) as e:
        # If RIPE Stat fails, return empty lists
        # Silently fail - this is optional data
        return [], []
    except Exception as e:
        # Unexpected errors - log them
        import sys as _sys
        print(f"WARNING: Prefix lookup error: {type(e).__name__}: {e}", file=_sys.stderr)
        return [], []


def format_text(info: AsnInfo) -> str:
    """Format ASN info as human-readable text."""
    lines = [f"AS{info.asn}:"]

    if info.errors and not info.rir:
        lines.append(f"  Errors: {', '.join(info.errors)}")
        return "\n".join(lines)

    if info.name:
        lines.append(f"  Name: {info.name}")
    if info.description:
        lines.append(f"  Description: {info.description}")
    if info.registrant:
        lines.append(f"  Registrant: {info.registrant}")
    if info.country:
        lines.append(f"  Country: {info.country}")
    if info.registration_date:
        lines.append(f"  Registered: {info.registration_date}")
    if info.last_updated:
        lines.append(f"  Last Updated: {info.last_updated}")
    if info.rir:
        lines.append(f"  RIR: {info.rir.upper()}")

    if info.ipv4_ranges:
        lines.append(f"  IPv4 Ranges ({len(info.ipv4_ranges)}):")
        for prefix in info.ipv4_ranges:
            lines.append(f"    {prefix}")
    else:
        lines.append("  IPv4 Ranges: none announced")

    if info.ipv6_ranges:
        lines.append(f"  IPv6 Ranges ({len(info.ipv6_ranges)}):")
        for prefix in info.ipv6_ranges:
            lines.append(f"    {prefix}")
    else:
        lines.append("  IPv6 Ranges: none announced")

    if info.errors:
        lines.append(f"  Warnings: {', '.join(info.errors)}")

    return "\n".join(lines)


def read_asns(path: str) -> List[int]:
    """Read ASN numbers from a file, one per line."""
    asns = []
    stream = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        for line in stream:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            asn = normalize_asn(line)
            if asn is not None:
                asns.append(asn)
            else:
                print(f"! Invalid ASN: {line}", file=sys.stderr)
    finally:
        if stream is not sys.stdin:
            stream.close()
    return asns


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Perform ASN lookups via RDAP to retrieve registrant info and prefixes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "ASN numbers can be provided with or without 'AS' prefix.\n"
            "Queries all five RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC) via RDAP\n"
            "for registration data, then fetches announced prefixes from RIPE Stat\n"
            "(which aggregates global BGP data from RIS and RouteViews)."
        ),
    )

    input_group = parser.add_argument_group("input")
    input_group.add_argument("-a", "--asn", action="append", dest="asns", default=[],
                            help="ASN to query (repeatable), e.g. AS15169 or 15169")
    input_group.add_argument("-f", "--file", default="",
                            help="file of ASN numbers, one per line ('-' for stdin)")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-o", "--outfile", default="",
                             help="output filename, else stdout")
    output_group.add_argument("--json", action="store_true",
                             help="output as JSON (one object per ASN)")
    output_group.add_argument("-q", "--quiet", action="store_true",
                             help="suppress progress messages")

    net_group = parser.add_argument_group("network")
    net_group.add_argument("--timeout", type=float, default=30.0,
                          help="request timeout in seconds (default: 30, min 60 for prefixes)")

    options = parser.parse_args()

    # Collect ASNs from all sources
    asns: List[int] = []
    for asn_str in options.asns:
        asn = normalize_asn(asn_str)
        if asn is not None:
            asns.append(asn)
        else:
            print(f"! Invalid ASN: {asn_str}", file=sys.stderr)

    if options.file:
        asns.extend(read_asns(options.file))

    if not asns:
        parser.error("must provide --asn or --file")

    # Deduplicate while preserving order
    seen = set()
    asns = [a for a in asns if not (a in seen or seen.add(a))]

    # Open output file if specified
    outfile = None
    if options.outfile:
        outfile = open(options.outfile, "w", encoding="utf-8")

    try:
        total = len(asns)
        for idx, asn in enumerate(asns, 1):
            if not options.quiet:
                print(f"[{idx}/{total}] Querying AS{asn}...", file=sys.stderr)

            info = lookup_asn_rdap(asn, timeout=options.timeout)

            if options.json:
                line = json.dumps(info.to_dict(), ensure_ascii=False, sort_keys=True)
                if outfile:
                    outfile.write(line + "\n")
                else:
                    print(line)
            else:
                text = format_text(info)
                if outfile:
                    outfile.write(text + "\n\n")
                else:
                    print(text)
                    if idx < total:
                        print()  # Blank line between entries
    finally:
        if outfile:
            outfile.close()

    if not options.quiet:
        print(f"Done: {total} ASN(s) queried", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
