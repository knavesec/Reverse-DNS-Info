"""Transports: port 43 (RFC 3912) and RDAP over HTTPS.

Rate limiting is **per server**, not global. Registries limit independently, so
querying .pt and .com concurrently is fine while hammering either one is not —
this is what lets a large domain list run with real concurrency instead of the
blanket multi-second sleep a single global limiter would force.
"""
import hashlib
import json
import os
import socket
import threading
import time
from typing import Any, Dict, Optional, Tuple

from . import aliases

RDAP_ACCEPT = "application/rdap+json, application/json;q=0.9"
USER_AGENT = "whois_resolver/1.0 (+https://github.com/knavesec/Reverse-DNS-Info)"


def decode_response(data: bytes) -> str:
    """WHOIS has no encoding negotiation; most servers are UTF-8, some Latin-1."""
    for encoding in ("utf-8", "iso-8859-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def whois_query(host: str, query: str, timeout: float = 25.0, port: int = 43) -> str:
    """Send one port-43 query and read the whole response."""
    chunks = []
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8", errors="replace"))
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    return decode_response(b"".join(chunks))


def format_query(server: str, domain: str) -> str:
    """Apply per-server query quirks.

    Without these, whois.verisign-grs.com does a substring search rather than an
    exact lookup and whois.jprs.jp answers in Japanese.
    """
    return aliases.QUERY_FORMATS.get(server, "{d}").format(d=domain)


class RateLimiter:
    """Per-host minimum interval between requests. Thread-safe."""

    def __init__(self, default_interval: float = aliases.DEFAULT_RATE_LIMIT,
                 overrides: Optional[Dict[str, float]] = None):
        self.default_interval = default_interval
        self.overrides = dict(aliases.RATE_LIMITS)
        if overrides:
            self.overrides.update(overrides)
        self._last: Dict[str, float] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def interval_for(self, host: str) -> float:
        return self.overrides.get(host, self.default_interval)

    def _lock_for(self, host: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(host, threading.Lock())

    def acquire(self, host: str) -> None:
        interval = self.interval_for(host)
        if interval <= 0:
            return
        # Holding the per-host lock across the sleep serializes queries to that
        # host while leaving other hosts free to proceed.
        lock = self._lock_for(host)
        lock.acquire()
        try:
            last = self._last.get(host)
            if last is not None:
                wait = interval - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
            self._last[host] = time.monotonic()
        finally:
            lock.release()


class ResponseCache:
    """On-disk cache of raw responses, so re-runs during analysis are free."""

    def __init__(self, cache_dir: Optional[str], ttl: float = 86400.0):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.cache_dir) and self.ttl > 0

    def _path(self, kind: str, host: str, query: str) -> str:
        digest = hashlib.sha1(f"{kind}|{host}|{query}".encode("utf-8")).hexdigest()
        assert self.cache_dir
        return os.path.join(self.cache_dir, "responses", f"{digest}.json")

    def get(self, kind: str, host: str, query: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        path = self._path(kind, host, query)
        try:
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
        except (OSError, ValueError):
            return None
        if time.time() - float(entry.get("ts", 0)) > self.ttl:
            return None
        return entry

    def put(self, kind: str, host: str, query: str, payload: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        path = self._path(kind, host, query)
        entry = dict(payload)
        entry["ts"] = time.time()
        try:
            with self._lock:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                tmp = f"{path}.tmp{os.getpid()}"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(entry, f)
                os.replace(tmp, path)
        except OSError:
            pass


class Transport:
    """Rate-limited, optionally cached access to both protocols."""

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        cache: Optional[ResponseCache] = None,
        timeout: float = 25.0,
    ):
        self.rate = rate_limiter or RateLimiter()
        self.cache = cache or ResponseCache(None)
        self.timeout = timeout
        self._session = None
        self._session_lock = threading.Lock()

    # -- port 43 ----------------------------------------------------------
    def whois(self, server: str, domain: str) -> Tuple[str, bool]:
        """Return (response_text, from_cache)."""
        query = format_query(server, domain)
        hit = self.cache.get("whois", server, query)
        if hit and "text" in hit:
            return hit["text"], True

        self.rate.acquire(server)
        text = whois_query(server, query, timeout=self.timeout)
        self.cache.put("whois", server, query, {"text": text})
        return text, False

    # -- RDAP -------------------------------------------------------------
    def _requests_session(self):
        if self._session is not None:
            return self._session
        with self._session_lock:
            if self._session is None:
                try:
                    import requests  # noqa: PLC0415

                    session = requests.Session()
                    session.headers.update(
                        {"User-Agent": USER_AGENT, "Accept": RDAP_ACCEPT}
                    )
                    self._session = session
                except ImportError:
                    self._session = False  # type: ignore[assignment]
        return self._session

    def rdap(self, url: str) -> Tuple[int, Optional[Dict[str, Any]], str, bool]:
        """GET an RDAP URL. Returns (status, json_or_None, raw_text, from_cache)."""
        host = _host_of(url)
        hit = self.cache.get("rdap", host, url)
        if hit and "status" in hit:
            raw = hit.get("text") or ""
            return int(hit["status"]), hit.get("json"), raw, True

        self.rate.acquire(host)
        status, raw = self._rdap_fetch(url)

        parsed: Optional[Dict[str, Any]] = None
        if raw:
            try:
                candidate = json.loads(raw)
                if isinstance(candidate, dict):
                    parsed = candidate
            except ValueError:
                parsed = None

        # Never cache a rate-limit or server error as if it were an answer.
        if status in (200, 404):
            self.cache.put("rdap", host, url, {"status": status, "json": parsed, "text": raw})
        return status, parsed, raw, False

    def _rdap_fetch(self, url: str) -> Tuple[int, str]:
        session = self._requests_session()
        if session:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code, resp.text

        import urllib.error  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415

        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": RDAP_ACCEPT}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, decode_response(resp.read())
        except urllib.error.HTTPError as exc:
            body = decode_response(exc.read()) if exc.fp else ""
            return exc.code, body


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc or url
