"""UniFi Network API client.

Thin wrapper around the UniFi v1 REST and v2 APIs using only stdlib.
Authenticates via API key (X-API-KEY header).
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class UniFiClient:
    """Minimal UniFi Network API client."""

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token

    def _req(self, url: str, method: str = "GET", data: dict | None = None) -> dict | list | None:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("X-API-KEY", self.token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=_CTX) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            short_path = url.split("/default/")[-1] if "/default/" in url else url
            print(f"  ! API {e.code} {method} {short_path}", file=sys.stderr)
            if err_body:
                print(f"    {err_body[:200]}", file=sys.stderr)
            raise

    def v1(self, path: str, method: str = "GET", data: dict | None = None):
        """v1 REST API — returns the 'data' array."""
        result = self._req(f"{self.url}/proxy/network/api/s/default/{path}", method, data)
        return result.get("data", result) if isinstance(result, dict) else result

    def v2(self, path: str, method: str = "GET", data: dict | None = None):
        """v2 API — returns the raw response."""
        return self._req(f"{self.url}/proxy/network/v2/api/site/default/{path}", method, data)
