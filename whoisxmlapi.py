#!/usr/bin/env python3
"""Keyword-based reverse WHOIS via WhoisXMLAPI.

A thin wrapper over ``reverse_whois.providers.whoisxmlapi``. The CLI is
unchanged; what changed is underneath:

* **pagination**. The old version read one page and dropped
  ``nextPageSearchAfter``, so any estate over 10,000 domains was silently
  truncated. ``navi.log`` (408 domains, one page) is why nobody noticed.
* ``--preview`` asks how many domains a term matches for **zero credits** before
  you spend any — worth doing on every new keyword.
* ``--search-type historic`` searches historical records too, which is the only
  way to see registrant details that GDPR redacted from the current record.
* ``--apikey`` still works, but ``WHOISXMLAPI_KEY`` is preferred: a key passed on
  the command line ends up in your shell history and in the process list.

For a full snowball hunt across several providers with scoring, use
``reverse_hunt.py``.
"""
import argparse
import os
import sys
from typing import List

from reverse_whois import Budget, Http, Selector
from reverse_whois.model import KIND_KEYWORD, SEARCH_CURRENT, SEARCH_HISTORIC
from reverse_whois.providers import REGISTRY
from reverse_whois.providers.whoisxmlapi import WhoisXmlApiProvider

ENV_VARS = REGISTRY["whoisxmlapi"].env_vars


def read_keywords(options: argparse.Namespace) -> List[str]:
    if options.keyword_file:
        with open(options.keyword_file, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    else:
        lines = list(options.keywords)
    out = []
    for line in lines:
        keyword = line.strip()
        if keyword and not keyword.startswith("#"):
            out.append(keyword)
    return out


def api_key(options: argparse.Namespace) -> str:
    if options.apikey:
        return options.apikey
    for name in ENV_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def output(options: argparse.Namespace, line: str) -> None:
    if not options.outfile:
        print(line)
        return
    with open(options.outfile, "a+", encoding="utf-8") as handle:
        handle.write(line + "\n")


def reverse(options: argparse.Namespace) -> int:
    keywords = read_keywords(options)
    if not keywords:
        print("no keywords given", file=sys.stderr)
        return 2

    key = api_key(options)
    if not key:
        print(f"no API key; pass --apikey or set {' or '.join(ENV_VARS)}",
              file=sys.stderr)
        return 2

    budget = Budget(max_credits=options.max_credits or None,
                    dry_run=options.preview)
    provider = WhoisXmlApiProvider(Http(), budget, api_key=key,
                                   search_type=options.search_type,
                                   page_limit=options.page_limit)

    seen = set()
    for keyword in keywords:
        selector = Selector(KIND_KEYWORD, keyword)
        print(f"Searching for: {keyword}", file=sys.stderr)

        count = provider.preview(selector)
        if count is not None:
            print(f"  {count} domains match (preview, 0 credits)", file=sys.stderr)
        if options.preview:
            continue

        found = 0
        for finding in provider.search(selector):
            found += 1
            if finding.domain in seen:
                continue
            seen.add(finding.domain)
            output(options, finding.domain)
        print(f"Returned {found} domains", file=sys.stderr)

    for error in provider.errors:
        print(f"! {error}", file=sys.stderr)
    print(f"credits spent: {budget.credits_spent}", file=sys.stderr)

    return 0 if (seen or options.preview) else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="perform keyword based reverse whois searches via WhoisXMLAPI")

    parser.add_argument('-k', '--keywords', default=[], action='append', required=False, help="words to search for")
    parser.add_argument('-kf', '--keyword-file', default="", required=False, help="file containing words to search for")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('--apikey', default="", required=False,
                        help=f"whoisxml api key; prefer {ENV_VARS[0]} in the "
                             "environment, since a key on the command line lands "
                             "in shell history and the process list")
    parser.add_argument('--preview', action='store_true',
                        help="only report how many domains each term matches; "
                             "costs no credits and issues no purchase")
    parser.add_argument('--search-type', default=SEARCH_CURRENT,
                        choices=(SEARCH_CURRENT, SEARCH_HISTORIC, "both"),
                        help="current records, historical records, or both as "
                             "separate passes (default: current)")
    parser.add_argument('--max-credits', type=int, default=0,
                        help="hard ceiling on credits; one request (one page of "
                             "up to 10,000 domains) costs one credit. 0 = no limit")
    parser.add_argument('--page-limit', type=int, default=20,
                        help="maximum pages per search term (default: 20)")

    options = parser.parse_args()

    if len(options.keywords) > 4:
        print("Limited to 4 or less keywords per search")
        raise SystemExit(1)

    raise SystemExit(reverse(options))


if __name__ == '__main__':
    main()
