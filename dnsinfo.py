#!/usr/bin/env python3
"""Keyword-based reverse WHOIS via viewdns.info.

A thin wrapper over ``reverse_whois.providers.viewdns``. The CLI is unchanged;
what changed is underneath:

* no ``requests``/``bs4`` requirement — the provider uses the standard library
  and falls back to a regex when the page restyles, instead of matching one exact
  Tailwind class string and silently returning nothing;
* the free tier's 500-result cap is reported when it is hit, so a truncated
  result can no longer be mistaken for a complete one;
* responses are cached and rate-limited, shared with the rest of the toolkit;
* ``--apikey`` uses the JSON API, which is neither capped nor brittle.

For a full snowball hunt across several providers with scoring, use
``reverse_hunt.py``.
"""
import argparse
import os
import sys
from typing import List

from reverse_whois import Budget, Http, Selector
from reverse_whois.model import KIND_KEYWORD
from reverse_whois.providers.viewdns import ViewDnsProvider


def read_keywords(options: argparse.Namespace) -> List[str]:
    if options.keyword_file:
        with open(options.keyword_file, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    else:
        lines = [options.keywords]
    out = []
    for line in lines:
        keyword = line.strip()
        if keyword and not keyword.startswith("#"):
            out.append(keyword)
    return out


def output(options: argparse.Namespace, line: str) -> None:
    if not options.outfile:
        print(line)
        return
    with open(options.outfile, "a+", encoding="utf-8") as handle:
        handle.write(line + "\n")


def dnsinfo(options: argparse.Namespace) -> int:
    keywords = read_keywords(options)
    if not keywords:
        print("no keywords given", file=sys.stderr)
        return 2

    provider = ViewDnsProvider(Http(), Budget(),
                               api_key=options.apikey or os.environ.get("VIEWDNS_API_KEY", ""))

    seen = set()
    for keyword in keywords:
        print(f"Searching for: {keyword}", file=sys.stderr)
        found = 0
        for finding in provider.search(Selector(KIND_KEYWORD, keyword)):
            found += 1
            if finding.domain in seen:
                continue
            seen.add(finding.domain)
            output(options, finding.domain)
        print(f"Returned {found} domains", file=sys.stderr)

    # Truncation and layout changes are warnings, not silence.
    for error in provider.errors:
        print(f"! {error}", file=sys.stderr)

    return 0 if seen else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="perform keyword based reverse whois searches via viewdns.info")

    parser.add_argument('-k', '--keywords', default="", required=False, help="words to search for")
    parser.add_argument('-kf', '--keyword-file', default="", required=False, help="file containing words to search for")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('--apikey', default="", required=False,
                        help="viewdns.info API key (or set VIEWDNS_API_KEY); "
                             "lifts the 500-result cap")

    options = parser.parse_args()
    raise SystemExit(dnsinfo(options))


if __name__ == '__main__':
    main()
