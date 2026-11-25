# Reverse-DNS-Info

Enumerate a company's domain estate by pivoting on **who registered it** rather
than by guessing names.

The premise: a target's domains are tied together by their registration details —
one registrant email, one organization string, one set of self-hosted
nameservers. Start from a domain you know, read those details out of its WHOIS
record, search them back through every index you can reach, then repeat with what
comes back. That loop is `reverse_hunt.py`. Everything else here supports it.

```
$ python3 reverse_hunt.py -s ibm.com -o ./hunt --providers crtsh,dns,rir

227 new domains, 456 findings, 76 confirmed against their own WHOIS record,
0 credits spent, converged in 2 rounds.
```

Everything runs on the **standard library**. `requests` and `dnspython` are used
if installed and skipped if not. Python 3.8+.

---

## 1. What's here

| Script | Purpose |
| --- | --- |
| `reverse_hunt.py` | the snowball loop: seeds → registrant details → reverse search → new domains → repeat, with confidence scoring and cost ceilings |
| `whois.py` | WHOIS/RDAP lookups for a list of domains, any TLD, greppable or JSON |
| `whois_comparer.py` | score candidate domains against a known-good baseline of WHOIS records |
| `asn_lookup.py` | ASN lookups via RDAP: registrant information and metadata from all five RIRs |
| `dnsinfo.py` | one-shot keyword reverse WHOIS via viewdns.info |
| `whoisxmlapi.py` | one-shot keyword reverse WHOIS via WhoisXMLAPI |

and two packages behind them:

| Package | Purpose |
| --- | --- |
| `whois_resolver/` | forward lookups: IANA discovery, RDAP + port-43, one normalized `Registration` model. See `ALT_README.md` for its design notes |
| `reverse_whois/` | reverse lookups: one `Provider` interface over seven sources, plus selector derivation, noise filtering, budgets and scoring |

---

## 2. Quick start

No key needed for any of this:

```
# the whole loop against one seed, free sources only
python3 reverse_hunt.py -s ibm.com -o ./hunt --providers crtsh,dns,rir

# look at what it found, best first
cat ./hunt/high.txt
python3 -c "import json,sys; [print(json.loads(l)['domain'], json.loads(l)['score']) for l in open('hunt/report.jsonl')]"

# resolve the results and eyeball the registrant fields
python3 whois.py -f ./hunt/high.txt -g | grep registrant_organization
```

With a paid provider, price every search term for free before spending anything:

```
export WHOISXMLAPI_KEY=...
python3 reverse_hunt.py -s ibm.com -o ./hunt --dry-run       # buys nothing
python3 reverse_hunt.py -s ibm.com -o ./hunt --max-credits 50
```

---

## 3. `reverse_hunt.py`

### The loop

Each round:

1. **Resolve** every known domain that hasn't been looked up yet (concurrent,
   cached, via `whois_resolver`).
2. **Derive selectors** — the searchable facts in those records: registrant
   email, email domain, organization, name, phone, address, nameservers, plus
   keywords from the domain labels. Redaction placeholders, privacy proxies,
   registrar abuse mailboxes and shared nameservers are dropped here; without
   that filter a selector like `withheldforprivacy.com` pulls in millions of
   unrelated domains.
3. **Free sources first**, unbounded. crt.sh's organization-name variants become
   new selectors immediately — the cheap way to broaden before paying.
4. **Preview-gate** the rest: WhoisXMLAPI's `mode: preview` reports the match
   count for **zero credits**. Terms matching nothing or more than
   `--preview-max` are rejected, and the count and verdict are logged either way.
5. **Purchase** the survivors, paginating to exhaustion, `current` and `historic`
   as separate tagged passes.
6. **Corroborate** — look up each candidate's *own* WHOIS record and check it
   against the seed profile. This is what separates "a paid index said so" from
   "verified", and it is scored separately and higher.

Stops when a round adds nothing new, or on the first ceiling reached.

Only seeds generate new selectors, so one false positive can't redefine the
target. `--expand-all` lifts that, finds more, and drifts further off-target.

### Providers

Free, no key, no account:

| Name | Searches on | What it gives you |
| --- | --- | --- |
| `crtsh` | organization | Certificate Transparency: domains, **plus the target's other legal-entity spellings**. One org string from `ibm.com`'s WHOIS record — `International Business Machines Corporation` — returns 228 domains, most of them acquired brands with no textual link to the seed. It also surfaces the spelling variants that appear in the wild (`International Business Machines  Corporation` with a double space, `International Business Machines, Corporation`), which are fed straight back as further selectors |
| `dns` | a domain | SPF `include:`, DMARC `rua=`, MX and NS records. Mail has to work, so an organization that runs its own leaks its estate here. IBM is the counter-example: mail is Proofpoint (`pphosted.com`), DNS is NS1 (`nsone.net`), so every record is shared infrastructure, correctly filtered, and this provider contributes **zero** findings. That's the pivot working as intended — it pays off on self-hosted estates and stays quiet otherwise |
| `rir` | organization | ARIN/RIPE org search → netblocks → reverse DNS. `International Business Machines Corporation` returns **297 netblocks** across handles like `IARC-1` and `GBSI-1`. The only free org-name search that exists; domain registries all refuse RDAP search (Verisign 400, `.cz`/`.br` 501, Norid 401). Netblocks are reported even when the PTR sweep is off, since they're useful on their own |

Paid, behind the preview gate:

| Name | Searches on | Notes |
| --- | --- | --- |
| `whoisxmlapi` | any registrant field, keyword | 1 credit per *request*, and one request returns up to 10,000 domains. `mode: preview` is free |
| `whoisfreaks` | email (incl. `*@company.com`), company, owner, keyword | history back to 1986; 500 free credits to start. The email wildcard is the strongest selector available anywhere |
| `whoxy` | name, email, company, keyword | cheap, and not charged for a search that returns nothing |
| `viewdns` | keyword, company, name | free tier caps at 500 results; a key lifts it |

Keys are read from the environment, never the command line, so they stay out of
shell history and the process list: `WHOISXMLAPI_KEY`, `WHOISFREAKS_KEY`,
`WHOXY_KEY`, `VIEWDNS_API_KEY`. A provider named in `--providers` with no key
warns and is skipped; the run continues on the rest.

### Scoring

Weight by *kind*, because the kinds are not comparable — a shared registrant
email is near-proof, a keyword in a domain name is barely a hint:

```
email 5.0   email_domain 4.0   org 4.0   nameserver 4.0
phone 3.5   name 3.0   domain 3.0   address 2.0   keyword 1.0
```

then adjust each finding by how discriminating the specific value is (breadth
from its preview count, generic-token ratio, geographic-only values), by
`historic` ×0.9 (a relationship that only existed historically is real, but the
domain may have been sold since), and by per-provider trust (a scraped HTML table
with an undisclosed row cap is worth less than a signed CT log).

Sum the **strongest finding per selector** with a decay of 0.55, so the second
piece of evidence is worth just over half the first. That's the property that
keeps tiers meaningful: 30 keyword hits score 0.51, one exact registrant-email
hit scores 4.50. Independent providers agreeing adds a capped bonus; the same
provider repeating itself across pages adds nothing.

Tiers: **high** ≥ 4.0, **medium** ≥ 2.5, and a keyword-only match can never
exceed low no matter how many there are. Corroboration on the candidate's own
record promotes to high outright. A record that turns out to be redacted is
reported as *"corroboration not possible"* rather than as a mismatch — post-GDPR,
absence of corroboration is not evidence against.

### Output

`--out-dir` (default `./hunt`), written line-by-line and flushed, so it's
tailable mid-run and survives a Ctrl-C:

| File | Contents |
| --- | --- |
| `high.txt` / `medium.txt` / `low.txt` | domains by confidence tier, plain lists ready to pipe |
| `report.jsonl` | one object per domain: score, tier, every finding, every corroborated field |
| `selectors.jsonl` | every search term tried, its preview count, and whether it was used, filtered or rejected — and why |
| `findings.jsonl` | one row per (domain, selector, provider), never collapsed |
| `domains.jsonl` | every domain seen, with the round it appeared in |
| `registrations.jsonl` | the full WHOIS record of everything resolved |
| `netblocks.jsonl` | netblocks found at the RIRs, with org handle and CIDR |
| `profile.json` | the run's final view of what "the target" looks like |
| `budget.json` | credits spent, per provider |
| `warnings.txt` | truncation, missing keys, refused selectors, resolver failures |

Nothing is dropped silently. A capped page, a missing API key, a selector below
the specificity floor and a WHOIS server that refused all produce a line
somewhere.

### Options

**Input**

| Flag | Meaning |
| --- | --- |
| `-s`, `--seed` | seed domain, repeatable |
| `-f`, `--seeds` | file of seed domains (`-` for stdin) |
| `-k`, `--keyword` | extra search term, repeatable |
| `-kf`, `--keyword-file` | file of extra search terms |

**Providers**

| Flag | Meaning |
| --- | --- |
| `--providers` | comma-separated names; default is the free sources plus any paid provider whose key is set |
| `--search-type` | `current`, `historic`, or `both` (default). Historic is what defeats GDPR redaction |
| `--page-limit` | max pages per search before truncation is reported (default 20) |
| `--crtsh-max-certs` | max certificates parsed per crt.sh query (default 20000) |
| `--rir-ptr` / `--rir-max-ptr` | reverse-DNS sweep the netblocks found (off by default; a /16 is 65,536 addresses) |
| `--dns-transport` | `auto` (local resolver, then DoH), `local`, or `doh` |

**Ceilings**

| Flag | Meaning |
| --- | --- |
| `--max-rounds` | snowball rounds (default 4) |
| `--max-credits` | hard ceiling on paid requests (default unlimited) |
| `--max-seconds` | wall-clock ceiling |
| `--preview-max` / `--preview-min` | reject terms matching more / fewer domains than this (default 5000 / 1) |
| `--max-selectors-per-round` | cap on selectors used per round, strongest first (default 200) |
| `--max-resolve` | cap on WHOIS lookups per round (default 500) |
| `--corroborate-max` | candidates verified against their own record (default 250) |
| `--dry-run` | price every term via the free preview and buy nothing |

**Scoring and output**

| Flag | Meaning |
| --- | --- |
| `-o`, `--out-dir` | output directory (default `./hunt`) |
| `--min-score` | omit domains below this from the tier files |
| `--high-score` / `--medium-score` | tier thresholds (default 4.0 / 2.5) |
| `--min-specificity` | drop selectors less discriminating than this (default 0.15) |
| `--exclude-seeds` | leave the seeds out of the tier files |
| `--no-keywords` | don't derive keyword selectors from domain names |
| `--expand-all` | derive selectors from every discovered domain, not just seeds |
| `--show` | results explained on stderr at the end (default 15) |
| `-q`, `--quiet` | suppress progress |

**Network**: `--timeout`, `--rate-limit`, `--whois-rate-limit`, `--workers`,
`--cache-dir`, `--cache-ttl`, `--no-cache`. Rate limiting is **per host**, so
concurrency doesn't make you a nuisance to any single registry.

### A real run

```
$ python3 reverse_hunt.py -s ibm.com -o ./hunt --providers crtsh,dns,rir
providers: crtsh, dns, rir
round 1/4 (1 domains known, 0 credits spent)
  resolving 1 domain(s)
  1 new selector(s) queued
  crtsh org='International Business Machines Corporation': 228 finding(s), 227 new domain(s)
  crtsh promoted 3 new selector(s)
  ! [rir] found 297 netblock(s) for 'International Business Machines
    Corporation'; PTR sweep disabled, so no domains were derived from them
    (enable --rir-ptr)
  round 1 added 227 domain(s)
round 2/4 (228 domains known, 0 credits spent)
  resolving 227 domain(s)
  crtsh org='International Business Machines  Corporation': 228 finding(s), 0 new domain(s)
  ! [crtsh] crt.sh 'International Business Machines, Corporation': GET
    https://crt.sh/?O=...: TimeoutError: The read operation timed out
  round 2 added 0 domain(s)
  converged: round 2 found nothing new

seeds:            1
domains found:    227 new (228 total)
findings:         456
selectors tried:  9 (0 rejected by the preview gate)
credits spent:    0
high / medium / low: 228 / 0 / 0
confirmed on their own record: 76
warnings:         11
output:           ./hunt

top results:
  appdomain.cloud score=8.03 tier=high; confirmed on its own record:
    org=international business machines corporation; crtsh/free:
    org='International Business Machines Corporation' from ibm.com
```

The 227 include `softlayer.com`, `bluemix.net`, `asperasoft.com`, `ustream.tv`,
`kenexa.com`, `silverpop.com`, `sterlingcommerce.com`, `truvenhealth.com`,
`blekko.com`, `lotus.com`, `spsscloud.com` and `watsonplatform.net` — real
brands, most of them acquisitions, none of which contain the string "ibm".

Three details in that transcript are worth reading closely, because they're the
design showing through rather than incidental noise:

* **One selector did all the work.** IBM's own WHOIS record is redacted down to
  the organization — no registrant email, no phone, no usable nameservers — so
  round 1 queued exactly one useful selector. It was enough for 227 domains. This
  is the post-GDPR case the tool is built for.
* **No `keyword='ibm'` line.** Keyword selectors derived from a domain label
  require at least 4 characters (`selectors.py:127`), so a three-letter apex is
  never guessed at. Against a substring index, `ibm` would have matched half the
  internet.
* **`dns` and `rir` contributed no domains, and said so.** Both are logged with a
  reason — outsourced mail/DNS in one case, PTR sweep disabled in the other — and
  the netblocks are written to `netblocks.jsonl` regardless. A quiet provider is
  never indistinguishable from a broken one.

---

## 4. `whois.py`

Forward lookups for a list of domains, across any TLD, built on
`whois_resolver/`. RDAP where a registry publishes it, port-43 WHOIS where it
doesn't, both discovered from IANA at runtime.

```
python3 whois.py -d dns.pt
python3 whois.py -f domains.txt -g -o whois_output.log
python3 whois.py -f domains.txt --json -o whois_output.jsonl
sort -u domains.txt | python3 whois.py -f - -g
```

```
dns.pt : whois_creation_date : 1991-10-03T00:00:00
dns.pt : whois_name_servers : b.dns.pt
dns.pt : whois_registrant_name : Associação DNS.PT
dns.pt : whois_registrant_city : Lisboa
dns.pt : whois_name : Associação DNS.PT
```

Field names match `python-whois` where an equivalent exists, with the richer
`registrant_*` / `admin_*` / `tech_*` / `billing_*` set alongside. Unregistered
domains are reported as `UNREGISTERED`, and a lookup that couldn't be completed
as `UNDETERMINED` plus an error — the two are never conflated. Progress goes to
stderr, so it never contaminates a redirected result file.

Flags: `-f`/`-d`/`--unique`, `-o`/`-g`/`--json`/`--fields`/`--raw`/
`--report-unmapped`/`-q`, `--transport`/`-t`/`--timeout`/`--rate-limit`/
`--no-referrals`/`--offline`, `--cache-dir`/`--cache-ttl`/`--no-cache`. Full
detail and design notes in `ALT_README.md`.

---

## 5. `whois_comparer.py`

Given domains you know belong to the target and domains you're unsure about,
score the unsure ones by how much registrant identity they share.

```
$ cat known.txt                 # ibm.com, softlayer.com
$ cat candidates.txt            # bluemix.net, asperasoft.com, example.com
$ python3 whois_comparer.py --know_valids known.txt --test_file candidates.txt \
      --score --min-score 3 --report report.jsonl

bluemix.net : match_org : international business machines corporation : ibm.com
bluemix.net : match_org : international business machines corporation : softlayer.com
bluemix.net : match_registrant_organization : international business machines corporation : ibm.com
bluemix.net : match_registrar : csc corporate domains, inc. : ibm.com
bluemix.net : score : 4.60 : medium
asperasoft.com : score : 4.60 : medium
example.com : result : NO_MATCH
```

That 4.60 is the scoring rules in miniature: `org` at weight 4.0, plus `registrar`
capped at 1.0 and decayed to 0.6 as the second-strongest fact. The four `match_`
rows collapse to two facts — "same organization" and "same registrar" — and being
seen from two baseline domains adds nothing, because it is the same fact twice.

Matches are weighted by the `WHOIS_FIELD_RELEVANCE` table at the top of the file
(0–5 per field) with diminishing returns, so one shared registrant email outranks
a pile of weak matches. Three specifics worth knowing:

* **Distinct facts, not distinct rows.** `to_flat()` emits both `org` and
  `registrant_organization` for the same value, and an estate's nameservers come
  as a set — matching three of them is one fact, "these domains share DNS", not
  three. Both still appear as evidence; neither inflates the score.
* **`registrar` is capped at weight 1.0** despite scoring 4 in the table. It's
  genuinely informative *about* a domain, but as a *match between* domains it
  means almost nothing: one registrar holds millions of unrelated domains.
* **The baseline index is built from the cleaned record.** Indexing the raw one
  puts `abusecomplaints@markmonitor.com` in the email index, at which point every
  MarkMonitor-registered brand on earth "matches" every other.

Tiers: high ≥ 5.0 or any exact email/nameserver match, medium ≥ 3.5. Candidates
below `--min-score` are reported as `BELOW_MIN_SCORE`, never dropped silently.
`--report` writes the full evidence chain as JSONL. `--baseline` also dumps the
cleaned baseline records.

---

## 6. `asn_lookup.py`

Look up Autonomous System Numbers (ASNs) via RDAP to retrieve registrant
information and metadata. Queries all five Regional Internet Registries (ARIN,
RIPE NCC, APNIC, LACNIC, AFRINIC) automatically.

```
python3 asn_lookup.py -a AS15169
python3 asn_lookup.py -a 13335 -a 3333 --json
python3 asn_lookup.py -f asn_list.txt -o results.json --json
```

Output includes:
* ASN name and registration details
* Registrant organization
* Country and registration/update dates
* Which RIR owns the ASN

**Note on IP prefixes:** RDAP ASN records don't typically include comprehensive
lists of announced prefixes. For BGP prefix data, use external sources like:
* `bgp.he.net/AS<number>`
* `stat.ripe.net/AS<number>`
* `api.bgpview.io/asn/<number>/prefixes`

Flags: `-a`/`-f`, `-o`/`--json`/`-q`, `--timeout`. ASN numbers can be provided
with or without the `AS` prefix.

---

## 7. `dnsinfo.py` and `whoisxmlapi.py`

The two original one-shot scripts, now thin wrappers over the corresponding
providers. Same CLIs.

```
python3 dnsinfo.py -k "international business machines" -o outputfile.log

WHOISXMLAPI_KEY=... python3 whoisxmlapi.py -k ibm -k bluemix -o out.log

# ask the price before paying it (illustrative — needs a key)
WHOISXMLAPI_KEY=... python3 whoisxmlapi.py -k ibm --preview
Searching for: ibm
  <N> domains match (preview, 0 credits)
credits spent: 0
```

What changed underneath:

* `whoisxmlapi.py` **paginates**. The old version read `nextPageSearchAfter` and
  dropped it, so any estate over 10,000 domains was silently truncated —
  `navi.log` in this repo is a real 408-domain single-page response, which is why
  nobody noticed. Also gains `--preview` (free), `--search-type historic`,
  `--max-credits` and `--page-limit`.
* `dnsinfo.py` no longer needs `requests` or `bs4`, no longer depends on one exact
  Tailwind class string that a restyle would break, and **says so when it hits the
  free tier's 500-result cap** instead of letting a truncated result look
  complete.
* `--apikey` still works on both, but the environment variable is preferred: a key
  on the command line lands in your shell history and in the process list.

For anything more than a single keyword search, use `reverse_hunt.py` — it does
this plus pagination, scoring, corroboration and cost control.

---

## 8. Layout

```
reverse_hunt.py        826   the snowball orchestrator
whois_comparer.py      973   baseline comparison and weighted scoring
whois.py               305   forward-lookup CLI
asn_lookup.py          386   ASN information via RDAP
dnsinfo.py              94   viewdns wrapper
whoisxmlapi.py         144   WhoisXMLAPI wrapper

reverse_whois/
  model.py             201   Selector, Finding, ScoredDomain, kind weights
  selectors.py         295   Registration -> selectors, specificity scoring
  noise.py             447   privacy proxies, registrar mailboxes, shared NS
  scoring.py           467   confidence, tiers, corroboration, explanations
  budget.py            137   credit / round / time ceilings, preview-gate policy
  http.py              171   rate-limited, cached GET/POST over urllib or requests
  dnsquery.py          230   DNS via dnspython, then dig, then DNS-over-HTTPS
  domains.py           141   public-suffix-aware registrable-domain extraction
  providers/
    base.py            106   the Provider contract: preview() and search()
    crtsh.py           150   free: CT logs, domains + org-name variants
    dnspivot.py        133   free: SPF / DMARC / MX / NS mining
    rir.py             254   free: ARIN + RIPE org search -> netblocks -> PTR
    whoisxmlapi.py     211   paid: preview-first, searchAfter pagination
    whoisfreaks.py     182   paid: email wildcards, history to 1986
    whoxy.py           154   paid: 4 identifiers, micro mode
    viewdns.py         151   free/paid: hardened scrape, cap reported
  fixtures/                  5 captured live responses, used by the tests

whois_resolver/              forward lookups; see ALT_README.md
tests/                       1,678 lines, 126 tests, all offline
```

---

## 9. Tests

```bash
python3 -m unittest discover -s tests -v
```

**Live integration tests** - tests make real network requests to WHOIS/RDAP servers.

### Why Live Tests?

This project uses live tests instead of fixtures because:
* **Failures are informative** - DNS blocks, rate limits, and network issues reveal real-world accessibility
* **No stale data** - Tests validate against current registry behavior
* **Geographic awareness** - Failures indicate location-based blocks or restrictions

### Expected Behavior

Some tests may fail - this is normal and provides valuable information:
* PASS: `.com` domains typically work (Verisign RDAP is reliable)
* WARNING:  ccTLDs may fail due to DNS resolution or geographic blocks
* WARNING:  Rate limiting may occur with repeated runs
* WARNING:  Network connectivity affects results

Failures show:
* DNS resolution issues (`gaierror: nodename nor servname provided`)
* Registry blocks or accessibility problems
* Network/connectivity issues
* When connections succeed: parser correctness is validated

See `tests/README.md` for more details on the live testing approach.

---

## 10. Limitations

* **Registry-level reverse WHOIS does not exist.** RFC 9082 defines
  `/domains?name=` and `/entities?fn=`, but every domain registry tested refuses
  it. Reverse WHOIS requires a third-party index; only the *number* registries
  (ARIN, RIPE) answer an org-name search for free.
* **The paid providers are fixture-tested, not live-tested.** No API keys were
  available in the development environment, so `whoisxmlapi`, `whoisfreaks`,
  `whoxy` and viewdns's keyed path have been exercised only against captured and
  synthetic responses. The free path is verified live.
* **Public DoH is blocked on some networks** — `dns.google` and
  `cloudflare-dns.com` both return 403 through some egress proxies. That's why the
  DNS pivot prefers a local resolver, and why it tells you when it can't resolve
  at all rather than reporting an empty estate.
* **GDPR.** Most gTLD registrant data is redacted, which is what makes the
  historic search and the CT-log pivot valuable — and what makes corroboration
  frequently impossible. "Not corroborated" is reported as such, never as
  disconfirmation.
* **crt.sh org search is a substring match** on the certificate subject, so a
  short or generic organization name pulls in unrelated companies. The
  specificity floor and generic-token filter catch the worst of it; a two-word
  legal name works far better than a bare brand.
* **Scraping is scraping.** viewdns is the least trustworthy source here, is
  weighted accordingly (×0.8), and is not in the default provider set.

## 11. Scope

For authorized reconnaissance — your own estate, a client engagement, or public
research. Every source used here is a public index or a public DNS/WHOIS record,
queried at a polite rate.
