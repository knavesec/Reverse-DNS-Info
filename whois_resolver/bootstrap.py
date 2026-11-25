"""Dynamic server discovery — no hardcoded TLD→server map.

Two IANA-published sources make "support every TLD" a data problem rather than a
code problem:

* ``https://data.iana.org/rdap/dns.json`` — the RDAP bootstrap registry
  (RFC 9224), mapping TLDs to RDAP base URLs. It covered 1200 of the ~1438
  delegated TLDs when this was written; RDAP is mandated for gTLDs but optional
  for ccTLDs, so .pt, .de, .jp, .it and friends are absent.
* ``whois.iana.org`` port 43 — querying a TLD returns a ``whois:`` line naming
  the authoritative registry server. This works for every delegated TLD and is
  the fallback path.

Both are cached on disk. The RDAP file is revalidated with ``If-None-Match`` so
refreshes are cheap.
"""
import json
import os
import time
from typing import Dict, List, Optional

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS_HOST = "whois.iana.org"

DEFAULT_CACHE_DIR = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
    "whois_resolver",
)

#: Refresh the RDAP bootstrap file at most this often.
BOOTSTRAP_TTL = 7 * 24 * 3600

#: A few high-volume servers, so the common case needs no IANA round trip on a
#: cold cache. Everything else is discovered dynamically.
SEED_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "pt": "whois.dns.pt",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
}


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _http_get(url: str, timeout: float, etag: Optional[str] = None):
    """Return (status, body_bytes, etag). Uses requests if available."""
    headers = {
        "User-Agent": "whois_resolver/1.0 (+https://github.com/knavesec/Reverse-DNS-Info)",
        "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.5",
    }
    if etag:
        headers["If-None-Match"] = etag

    try:
        import requests  # noqa: PLC0415

        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return resp.status_code, resp.content, resp.headers.get("ETag")
    except ImportError:
        pass

    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), resp.headers.get("ETag")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if exc.fp else b"", exc.headers.get("ETag")


class Bootstrap:
    """Caching front end over the two IANA discovery sources."""

    def __init__(
        self,
        cache_dir: str = DEFAULT_CACHE_DIR,
        timeout: float = 20.0,
        offline: bool = False,
    ):
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.offline = offline
        self._rdap_map: Optional[Dict[str, List[str]]] = None
        self._whois_servers: Optional[Dict[str, str]] = None
        self.errors: List[str] = []

    # -- paths ------------------------------------------------------------
    @property
    def _rdap_path(self) -> str:
        return os.path.join(self.cache_dir, "rdap-dns.json")

    @property
    def _rdap_meta_path(self) -> str:
        return os.path.join(self.cache_dir, "rdap-dns.meta.json")

    @property
    def _whois_path(self) -> str:
        return os.path.join(self.cache_dir, "whois-servers.json")

    # -- RDAP bootstrap ---------------------------------------------------
    def _load_rdap_bootstrap(self) -> Dict[str, List[str]]:
        if self._rdap_map is not None:
            return self._rdap_map

        raw = self._read_rdap_file()
        mapping: Dict[str, List[str]] = {}
        for service in (raw or {}).get("services", []):
            if not isinstance(service, list) or len(service) < 2:
                continue
            tlds, urls = service[0], service[1]
            clean = [str(u).rstrip("/") for u in urls if str(u).startswith("http")]
            for tld in tlds:
                mapping.setdefault(str(tld).lower().lstrip("."), []).extend(clean)
        self._rdap_map = mapping
        return mapping

    def _read_rdap_file(self) -> Optional[dict]:
        cached: Optional[dict] = None
        fresh = False
        if os.path.exists(self._rdap_path):
            try:
                with open(self._rdap_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                fresh = (time.time() - os.path.getmtime(self._rdap_path)) < BOOTSTRAP_TTL
            except (OSError, ValueError):
                cached = None

        if self.offline or (cached is not None and fresh):
            return cached

        etag = None
        if os.path.exists(self._rdap_meta_path):
            try:
                with open(self._rdap_meta_path, "r", encoding="utf-8") as f:
                    etag = json.load(f).get("etag")
            except (OSError, ValueError):
                etag = None

        try:
            status, body, new_etag = _http_get(RDAP_BOOTSTRAP_URL, self.timeout, etag)
            if status == 304 and cached is not None:
                os.utime(self._rdap_path, None)
                return cached
            if status == 200 and body:
                data = json.loads(body.decode("utf-8"))
                _ensure_dir(self.cache_dir)
                with open(self._rdap_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                with open(self._rdap_meta_path, "w", encoding="utf-8") as f:
                    json.dump({"etag": new_etag}, f)
                return data
            self.errors.append(f"RDAP bootstrap HTTP {status}")
        except Exception as exc:  # network, TLS, JSON — all non-fatal
            self.errors.append(f"RDAP bootstrap fetch failed: {exc}")
        return cached

    def rdap_base_urls(self, tld: str) -> List[str]:
        """RDAP base URLs for a TLD, HTTPS preferred. Empty if not covered."""
        urls = self._load_rdap_bootstrap().get(tld.lower(), [])
        https = [u for u in urls if u.startswith("https://")]
        return https + [u for u in urls if not u.startswith("https://")]

    # -- port 43 discovery -----------------------------------------------
    def _load_whois_servers(self) -> Dict[str, str]:
        if self._whois_servers is not None:
            return self._whois_servers
        servers = dict(SEED_WHOIS_SERVERS)
        if os.path.exists(self._whois_path):
            try:
                with open(self._whois_path, "r", encoding="utf-8") as f:
                    disk = json.load(f)
                if isinstance(disk, dict):
                    servers.update({str(k): str(v) for k, v in disk.items() if v})
            except (OSError, ValueError):
                pass
        self._whois_servers = servers
        return servers

    def _save_whois_servers(self) -> None:
        if self._whois_servers is None:
            return
        try:
            _ensure_dir(self.cache_dir)
            with open(self._whois_path, "w", encoding="utf-8") as f:
                json.dump(self._whois_servers, f, indent=1, sort_keys=True)
        except OSError as exc:
            self.errors.append(f"could not write server cache: {exc}")

    def whois_server_for_tld(self, tld: str) -> Optional[str]:
        """Authoritative port-43 server, discovered via IANA and cached."""
        tld = tld.lower().lstrip(".")
        servers = self._load_whois_servers()
        if tld in servers:
            return servers[tld]
        if self.offline:
            return None

        server = self._query_iana(tld)
        if server:
            servers[tld] = server
            self._save_whois_servers()
        return server

    def _query_iana(self, tld: str) -> Optional[str]:
        from .transport import whois_query  # local import avoids a cycle

        try:
            text = whois_query(IANA_WHOIS_HOST, tld, timeout=self.timeout)
        except OSError as exc:
            self.errors.append(f"IANA lookup for .{tld} failed: {exc}")
            return None

        for line in text.splitlines():
            if line.lower().startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return server
        self.errors.append(f"IANA has no whois server for .{tld}")
        return None
