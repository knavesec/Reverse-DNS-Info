# Mass WHOIS — resolver rewrite

`whois.py` performs registration lookups for a list of domains and prints the
results in a greppable, JSON, or human-readable form. It is built on the
`whois_resolver/` package, which discovers each TLD's server from IANA at runtime
and speaks both RDAP and port-43 WHOIS.

The motivating problem: the previous version was a thin wrapper around
`python-whois`, which could not read ccTLD formats. Portuguese domains were the
reported case — `whois.dns.pt` labels the registrant `Owner Name:` rather than
`Registrant Name:` and writes dates day-first — but the same gap affected `.de`,
`.it`, `.at`, `.fr`, `.se`, `.dk`, `.be`, `.ru` and `.jp`.

---

## 1. Usage

### Requirements

The resolver needs **no third-party packages** — it uses only the standard
library. If `requests` happens to be installed it will be used; otherwise the
code falls back to `urllib`. (Verified by running with `requests` import-blocked.)

`requirements.txt` still lists `python-whois` and `bs4`, but those are now only
needed by the other scripts in this repo (`whois_comparer.py`, `mass_whois2.py`,
`dnsinfo.py`), not by `whois.py`.

Python 3.8 or newer.

### Quick start

```
python3 whois.py -d dns.pt
python3 whois.py -f domains_list.txt -g -o whois_output.log
python3 whois.py -f domains_list.txt --json -o whois_output.jsonl
```

Input can also come from stdin:

```
sort -u domains.txt | python3 whois.py -f - -g
```

### Options

**Input**

| Flag | Meaning |
| --- | --- |
| `-f`, `--file` | input file, one domain per line (`-` for stdin); blank lines and `#` comments are skipped |
| `-d`, `--domain` | a single domain, repeatable; can be combined with `-f` |
| `--unique` | drop duplicate domains |

**Output**

| Flag | Meaning |
| --- | --- |
| `-o`, `--outfile` | write to a file instead of stdout |
| `-g`, `--greppable` | `domain : whois_field : value` lines |
| `--json` | one JSON object per domain (JSONL) |
| `--fields` | keep only these fields, e.g. `--fields emails,name_servers,registrar` |
| `--raw` | include the verbatim registry response |
| `--report-unmapped` | also print response keys that have no alias yet |
| `-q`, `--quiet` | suppress the per-domain progress lines on stderr |

**Lookup behaviour**

| Flag | Meaning |
| --- | --- |
| `--transport` | `auto` (default; RDAP then port 43), or force `rdap` / `whois` |
| `-t`, `--threads` | concurrent lookups, default 8 |
| `--timeout` | per-request timeout in seconds, default 25 |
| `--rate-limit` | minimum seconds between queries to the *same* server |
| `--no-referrals` | do not chase registrar referrals |
| `--offline` | never contact IANA; use cached bootstrap data only |

**Caching**

| Flag | Meaning |
| --- | --- |
| `--cache-dir` | default `~/.cache/whois_resolver` |
| `--cache-ttl` | cache lifetime in seconds, default 86400 |
| `--no-cache` | neither read nor write the response cache |

### Output formats

Progress goes to **stderr**, so it never contaminates a redirected result file:

```
$ python3 whois.py -f domains.txt -g -o out.log
[1/3] dns.pt : whois
[2/3] cloudflare.com : rdap
[3/3] nosuchdomain-xyz-98765.pt : unregistered
Done: 3 domains, 0 with errors
```

Greppable output uses the same `domain : whois_field : value` shape as before,
with one line **per value** for multi-valued fields:

```
dns.pt : whois_domain_name : dns.pt
dns.pt : whois_creation_date : 1991-10-03T00:00:00
dns.pt : whois_status : Registered
dns.pt : whois_name_servers : b.dns.pt
dns.pt : whois_name_servers : c.dns.pt
dns.pt : whois_registrant_name : Associação DNS.PT
dns.pt : whois_registrant_city : Lisboa
dns.pt : whois_registrant_postal_code : 1050-095
dns.pt : whois_registrant_country : PT
dns.pt : whois_name : Associação DNS.PT
dns.pt : whois_city : Lisboa
dns.pt : whois_zipcode : 1050-095
dns.pt : whois_country : PT
dns.pt : whois_source : whois
dns.pt : whois_source_server : whois.dns.pt
```

Two notes on that sample:

* `1991-10-03` is 3 October. `.pt` sends `03/10/1991`; reading it month-first
  would silently produce March.
* `whois_name` / `whois_city` / `whois_zipcode` are `python-whois`-compatible
  aliases for the registrant fields, emitted alongside the richer `registrant_*` /
  `admin_*` / `tech_*` / `billing_*` set. Existing greps and
  `whois_comparer.py`'s `WHOIS_FIELD_RELEVANCE` table keep working unchanged.
  (`whois_org` is absent here only because `.pt` publishes no organization field
  for this domain — nothing is emitted for an empty value.)

Domains that do not exist are reported explicitly rather than as an error:

```
nosuchdomain-xyz-98765.pt : result : UNREGISTERED
```

and a lookup that could not be completed is distinguished from both:

```
somedomain.ch : result : UNDETERMINED
somedomain.ch : error : whois.nic.ch refused the query: Requests of this client are not permitted...
```

### Finding fields that aren't mapped yet

`--report-unmapped` prints keys the parser saw but had no alias for. This is the
intended way to extend TLD coverage:

```
$ python3 whois.py -d google.com -g --report-unmapped | grep unmapped
google.com : unmapped_registrar abuse contact : https://corp.markmonitor.com/domain/ui/abuse-report
```

### Tests

```
python3 -m unittest discover -s tests
```

48 tests, all offline — they parse the 16 captured registry responses in
`whois_resolver/fixtures/`, so they need no network and cannot be broken by a
registry rate-limiting the build.

---

## 2. The new code

`whois_resolver/` is a package, not a module, and it is deliberately **not**
named `whois/` — a local `whois/` directory would shadow the `python-whois`
package that `whois_comparer.py` imports on its line 6, breaking that script.

```
whois_resolver/
  __init__.py      34   public exports
  dates.py        101   date parsing with a day-first hint
  overrides.py    178   per-TLD parsers (layer C)
  model.py        211   Contact / Registration dataclasses
  bootstrap.py    228   IANA discovery: RDAP bootstrap + whois.iana.org
  transport.py    238   port-43 sockets, HTTP, rate limiting, response cache
  parse_rdap.py   263   RDAP/jCard parser (layer A)
  resolver.py     318   transport selection, referrals, registration state
  parse_text.py   485   generic port-43 parser (layer B)
  aliases.py      527   field alias tables
  fixtures/             16 verbatim registry responses, used by the tests
```

### Libraries

No new dependencies were added. Everything is standard library:

| Module | Used for |
| --- | --- |
| `socket` | port-43 WHOIS is a raw TCP protocol (RFC 3912) — one line in, text out |
| `urllib.request` | RDAP over HTTPS, and the IANA bootstrap file |
| `json` | RDAP responses, the bootstrap file, the cache, `--json` output |
| `dataclasses` | the `Contact` / `Registration` model |
| `datetime` | normalizing ~20 registry date formats to ISO 8601 |
| `re` | the port-43 tokenizer and key normalization |
| `hashlib` | cache keys |
| `threading` | per-host rate limiter locks, thread-safe output |
| `concurrent.futures` | `ThreadPoolExecutor` for concurrent lookups |

`requests` is imported lazily inside a `try` in `bootstrap.py` and
`transport.py`; if it is missing, `urllib` is used instead.

Three PyPI libraries were evaluated and rejected: `asyncwhois`, `whoisit` and
`whodap`. They are decent, but each solves one half of the problem (`whoisit` and
`whodap` are RDAP-only, so they cannot answer `.pt` at all), and the parsing
rules are the part of this that actually needs to be owned and extended locally.

### Module by module

**`bootstrap.py` — runtime discovery, and the reason arbitrary TLDs work.**
Two sources, both fetched at runtime rather than hardcoded:

* IANA's RDAP bootstrap (`https://data.iana.org/rdap/dns.json`) maps a TLD to its
  RDAP base URL. Cached to disk and revalidated with `ETag` / `If-None-Match`, so
  the ordinary case is a `304` and no download.
* `whois.iana.org` is queried on port 43 with the bare TLD; the reply's
  `whois:` line gives that registry's WHOIS host. The result is persisted to
  `whois-servers.json`.

A small `SEED_WHOIS_SERVERS` map covers common TLDs so a cold, offline start
still works for those.

**`transport.py` — the wire, plus two things that make bulk use practical.**
`RateLimiter` enforces a minimum interval **per host** rather than globally,
because registries rate-limit independently; the per-host lock is held across the
sleep so queries to *other* registries proceed freely. `ResponseCache` keys on a
SHA-1 of `kind|host|query`, writes atomically via `os.replace`, and deliberately
never caches `429` or `5xx` — caching a rate-limit reply would poison the cache
for the TTL. `decode_response()` tries UTF-8, then ISO-8859-1, then replacement,
which is what keeps `Associação DNS.PT` intact.

**`model.py` — one canonical shape for every transport.** `Registration` holds
identity, registrar, dates, statuses, nameservers, four `Contact` roles, and
provenance (`source`, `source_server`, `servers_queried`, `notes`, `errors`,
`unmapped`). Writes go through `set_scalar()` / `add_to_list()` /
`Contact.set()`, which implement *first non-empty wins* for scalars and
*append-unique* for lists — that is what lets a registry response and a referral
response be merged into one object without the second overwriting the first.
`to_flat()` produces the `python-whois`-compatible key names; `to_dict()`
produces the JSON form.

**`aliases.py` — where new TLDs get cheap.** Adding a registry is normally a few
rows in a table here, not a new parser. Keys are matched twice: on a normalized
form (lowercased, whitespace collapsed) and on a "squashed" form with all
non-alphanumerics removed, so `Registrant Name`, `registrant-name` and
`REGISTRANT_NAME` all hit one row. Separate tables cover top-level keys,
keys valid *inside* a contact block, keys inside a registrar block, and section
headers. Every alias in the file was derived from a real captured response.
This module also holds the per-registry `QUERY_FORMATS` (Verisign needs
`domain <d>` or it does a substring search; JPRS needs `<d>/e` for English;
DENIC needs `-T dn <d>`), the per-host `RATE_LIMITS`, and the phrase lists for
not-found, refusal, redaction and free-status detection.

**`dates.py` — deterministic, no `dateutil`.** An explicit ordered format list
rather than a guessing parser, split into unambiguous formats, day-first formats
and month-first formats, tried in an order chosen by a per-TLD `day_first` hint.
It also normalizes `Z` to `+00:00` and truncates over-long fractional seconds,
because AFNIC sends nine digits and `fromisoformat` accepts at most six.

**`parse_rdap.py` — layer A.** RDAP is JSON, so there is nothing to guess:
events map to dates, entity roles map to contacts, and jCard `adr` arrays are
positional (`[pobox, ext, street, locality, region, code, country]`). Two
subtleties handled here: the `last update of RDAP database` event is about the
database, not the domain, and must not become the domain's `updated` date; and
the registrar's abuse contact is a *nested* entity with role `abuse`.

**`parse_text.py` — layer B, one generic parser for all port-43 dialects.** The
tokenizer recognizes four line shapes — `Key: value`, `[Key] value`, section
headers, and indented continuations — which between them cover every fixture
except two. A section's body indentation is *learned from its first content
line*, and a dedent closes the section. That is necessary because `.nl` emits
top-level keys (`DNSSEC:`, `Creation Date:`) **after** its indented `Registrar:`
block, while `.jp`'s `Contact Information:` body is not indented at all — so
neither "sections end at a blank line" nor "sections run to the next header" is
correct alone.

**`overrides.py` — layer C, kept deliberately small.** Only for responses that
are structurally different, not merely differently labelled. `.fr` and `.at`
(and `.re`, `.tf`, `.pm`, `.wf`, `.yt`) reference contacts *by handle*:
`holder-c: ABC123-FRNIC` points at a `nic-hdl: ABC123-FRNIC` block further down
the same response. The override splits the response into blank-line-separated
blocks, reuses the generic `parse_text()` on the domain block, and then resolves
the handle pointers to the contact blocks.

**`resolver.py` — orchestration and the registration verdict.** For
`transport="auto"`: try RDAP if the TLD is in the bootstrap, else port 43.
Referrals are chased on both protocols, which matters because thin registries
(`.com`, `.net`) return only a `Registrar WHOIS Server:` pointer — without
chasing it you never see contact data at all.

---

## 3. Larger-scale changes

### The old design, and why it capped out

```python
w = whois.whois(domain.strip())
for val in w:
    output(...)
```

`python-whois` carries a hardcoded server list and a per-TLD regex set, so a TLD
it does not know is simply unreadable. The old script had four further
structural problems:

* **Unregistered domains were inferred from an exception string** —
  `if "No match for" in str(e)`. Every other failure (timeout, rate limit,
  refusal, unknown TLD) was reported identically as a generic error, and any
  registry not using that exact English phrase was misclassified.
* **The output file was reopened and closed for every single line.**
* **No concurrency.**
* **Progress went to stdout**, mixed in with results.

### What changed

**1. Two transports instead of one, with runtime discovery.** RDAP is preferred
where it exists and port 43 is the fallback. Neither list is hardcoded; both come
from IANA.

Measured against IANA's own data today (2026-09-10): **1200 of the 1438 delegated
TLDs publish RDAP**, leaving 238 that are port-43 only. `.pt` is one of them —
along with `.de`, `.it`, `.at`, `.ch`, `.es`, `.ru`, `.jp`, `.se`, `.dk`, `.be`
and `.ie`. So an RDAP-only rewrite would *not* have fixed the reported problem;
both protocols are required. Conversely, port-43 WHOIS became optional for gTLD
registries on 2025-01-28, so RDAP-first is the right default.

**2. A three-layer parsing strategy, so per-TLD code stays rare.**

* Layer A — RDAP. Structured JSON, no parsing rules at all.
* Layer B — one generic port-43 tokenizer plus the alias tables. This handles 14
  of the 16 captured registry formats.
* Layer C — per-TLD overrides, only for responses that are structurally
  different. Currently just the handle-indirection family (`.fr`, `.at`, +5).

The point is that the common case of "new registry, same shapes, different
labels" is a table edit, not new code.

**3. Tri-state registration instead of a phrase match.** `registered` is
`True` / `False` / `None` (undetermined), and the verdict checks **positive
evidence first**: a domain with a creation date, nameservers, a registrar, an
expiry, or any contact data exists, regardless of what phrases the response
contains. This was necessary because:

* `.be` reports a **live** domain as `Status: NOT AVAILABLE` — so a substring
  search for `"available"` (which `mass_whois2.py:152` still does) marks live
  domains as free.
* `.ch` and `.es` refuse queries from unrecognized clients with a message
  containing no not-found phrase at all. Reporting those as "unregistered" would
  be a silent false negative; they are now `UNDETERMINED` plus an error.

**4. Per-server rate limiting plus real concurrency.** Limits are tracked per
host, so different registries never block each other, and `-t 8` is safe.
`ThreadPoolExecutor.map` preserves input order in the output while running
lookups concurrently. The contrast is with `mass_whois2.py:168`, which sleeps
`5 + random.randint(1, 10)` seconds after *every* lookup regardless of which
registry was queried; here a mixed-TLD list is limited only by its slowest
single registry rather than by the sum of all the waits.

**5. Caching, so re-runs and iteration are nearly free.** Responses are cached
with a TTL; the IANA bootstrap file is ETag-revalidated. `--offline` runs purely
from cache.

**6. Fixture-based offline tests.** 16 verbatim registry responses are committed
under `whois_resolver/fixtures/`, covering every structural dialect encountered:
ICANN gTLD (`.com`), indented sections (`.nl`, `.be`, `.it`), bracketed keys
(`.jp`), RIPE-style flat (`.ru`, `.se`), tab-indented (`.dk`), handle indirection
(`.fr`, `.at`), refusals (`.ch`, `.es`), and both a registered and a free `.pt`
response. All 48 tests run without network access.

**7. Output and ergonomics.** The file handle is opened once and shared behind a
lock; progress moved to stderr; `--json`, `--fields`, `--raw`,
`--report-unmapped`, `-d`, `--unique` and stdin input added; multi-valued fields
emit one line per value instead of a Python list repr, which is what the
greppable format was supposed to be for.

### Defects found during live verification

These were found by running the finished resolver against real registries, and
are worth recording because most of them were invisible to the parser-level
tests:

* **`.de` returned nothing at all.** DENIC ends every *successful* response with
  "The use for other purposes, in particular for advertising, is not permitted",
  and the refusal check ran *before* parsing — so the phrase "not permitted"
  caused every valid `.de` record to be discarded. Fixed by inverting the order:
  parse first, and only conclude a refusal when parsing produced no evidence,
  since a genuine refusal carries no registration data. The classification step
  was extracted into `Resolver._apply_response` specifically so it could be
  tested offline; the existing tests called the parser directly and structurally
  could not reach this code path.
* **`.pt` free domains reported `UNDETERMINED`**, for two independent reasons.
  `whois.dns.pt` answers `<domain> - No Match`, putting the marker *after* the
  domain, which prefix-anchored matching never saw. And the verdict read
  `Registration.raw`, which is only populated when the caller passes `--raw` —
  so registration state depended on an output flag. The signal is now recorded as
  `not_found_response` when the response is read.
* **A registrar web form was being stored as an email address.** MarkMonitor
  returns `Registrant Email: Select Request Email Form at https://...`, which
  landed in `emails` — the highest-signal field for correlating domains, and the
  one `whois_comparer.py` depends on. Storing it would invent a match between
  every domain behind that registrar. Addresses are now validated in both
  transports.
* **Statuses were duplicated after a referral**, because the registry writes the
  EPP URL bare (`clientTransferProhibited https://icann.org/epp#...`) while the
  registrar parenthesizes it. `google.com` reported 12 statuses instead of 6.
* **Redaction placeholders were being stored as real contact data on the RDAP
  path** — `"REDACTED FOR PRIVACY"` was landing in `registrant_name`. The filter
  existed only in the port-43 parser; it is now shared by both. Opaque registry
  handles (e.g. `STI044010-SIDN`) are deliberately *kept*, since those are a real
  correlation signal.

### Verified

* All 48 offline tests pass.
* Live sweep across 12 TLDs — `.pt`, `.de`, `.it`, `.nl`, `.se`, `.fr`, `.at`,
  `.be`, `.com`, `.ru`, `.jp`, `.dk` — resolves with zero errors.
* Unregistered detection correct across both transports: RDAP `404` (`.com`,
  `.nl`) and port-43 not-found (`.pt`, `.de`).
* Port-43 referral chasing end-to-end: `google.com` reports
  `source_server: whois.verisign-grs.com` with `registrant_organization: Google
  LLC` obtained from `whois.markmonitor.com` after following the pointer.
* Zero-dependency claim tested by blocking the `requests` import and confirming
  both transports still work via `urllib`.

### Known limitations

* Alias coverage is derived from the 16 captured responses plus the ICANN gTLD
  standard. An unusual ccTLD may put fields in `unmapped` rather than misparsing
  them — run `--report-unmapped` and add rows to `aliases.py`.
* Some registries (`.ch`, `.es`) refuse port-43 queries from unrecognized
  clients. These are correctly reported as `UNDETERMINED` with an error rather
  than guessed at, but no data is obtained.
* Post-GDPR, most gTLD and several ccTLD registries publish no contact data at
  all. `.de` for instance returns only nameservers, status and a change date.
  That is the registry's behaviour, not a parsing failure — the `notes` field
  records when data was withheld rather than absent.

### Untouched

`mass_whois2.py` is left exactly as-is per instruction. `whois_comparer.py`,
`dnsinfo.py` and `whoisxmlapi.py` are unmodified, and the field names in
`whois.py`'s output were kept `python-whois`-compatible so
`whois_comparer.py` continues to work against it without changes.
