"""IP enrichment via ipinfo.io, with a simple on-disk cache.

Private/reserved IPs are never looked up (they wouldn't return anything
useful anyway). Results are cached by IP so re-running the report daily
doesn't re-query ipinfo.io for IPs we've already looked up recently.
"""

import ipaddress
import json
import os
import time

import requests

IPINFO_URL = "https://ipinfo.io/{ip}/json"


class IPEnricher:
    def __init__(self, cache_path, token="", ttl_days=30, timeout=10):
        self.cache_path = cache_path
        self.token = token
        self.ttl_sec = ttl_days * 86400
        self.timeout = timeout
        self.cache = self._load_cache()
        self._dirty = False

    def _load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def save(self):
        if not self._dirty:
            return
        tmp_path = self.cache_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(self.cache, f, indent=2, sort_keys=True)
        os.replace(tmp_path, self.cache_path)
        self._dirty = False

    @staticmethod
    def is_public(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        )

    def lookup(self, ip):
        """Return an enrichment dict for a public IP, or None for private/invalid IPs."""
        if not self.is_public(ip):
            return None

        cached = self.cache.get(ip)
        if cached and (time.time() - cached.get("_fetched_at", 0)) < self.ttl_sec:
            return cached

        info = self._fetch(ip)
        info["_fetched_at"] = time.time()
        self.cache[ip] = info
        self._dirty = True
        return info

    def _fetch(self, ip):
        params = {"token": self.token} if self.token else {}
        try:
            resp = requests.get(
                IPINFO_URL.format(ip=ip), params=params, timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": ip,
                    "org": data.get("org", ""),
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "country": data.get("country", ""),
                    "hostname": data.get("hostname", ""),
                    "error": None,
                }
            return {"ip": ip, "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            return {"ip": ip, "error": str(e)}
