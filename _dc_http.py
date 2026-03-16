"""
_dc_http.py — stdlib drop-in for the requests API surface used by dig_champs.

Covers:
  requests.get(url, *, auth, timeout, verify, allow_redirects, params, headers)
  requests.post(url, *, json, timeout, headers)
  Response.status_code / .text / .json() / .raise_for_status()

Uses only Python stdlib: urllib.request, urllib.parse, urllib.error, ssl, json, base64.
"""

import base64
import json as _json
import ssl
import urllib.error
import urllib.parse
import urllib.request


# ── Response object ────────────────────────────────────────────────────────────

class Response:
    def __init__(self, status_code: int, body: bytes, headers: dict):
        self.status_code = status_code
        self._body       = body
        self.headers     = headers

    @property
    def text(self) -> str:
        return self._body.decode(errors="replace")

    @property
    def content(self) -> bytes:
        return self._body

    def json(self):
        return _json.loads(self._body)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise urllib.error.HTTPError(
                url=None, code=self.status_code,
                msg=f"HTTP {self.status_code}", hdrs=None, fp=None,
            )


# ── Internal helper ────────────────────────────────────────────────────────────

def _build_ssl_ctx(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _do_request(
    method:         str,
    url:            str,
    *,
    params:         dict | None = None,
    data:           bytes | None = None,
    headers:        dict | None = None,
    auth:           tuple | None = None,
    timeout:        float | None = None,
    verify:         bool = True,
    allow_redirects: bool = True,
) -> Response:
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)

    hdrs = {"User-Agent": "dig_champs/1.0"}
    if headers:
        hdrs.update(headers)
    if auth:
        creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {creds}"
    if data and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/octet-stream"

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    ctx = _build_ssl_ctx(verify)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body        = resp.read()
            status_code = resp.status
            resp_hdrs   = dict(resp.headers)
    except urllib.error.HTTPError as exc:
        # urllib raises HTTPError for 4xx/5xx; capture body if available
        try:
            body = exc.read()
        except Exception:
            body = b""
        status_code = exc.code
        resp_hdrs   = {}

    return Response(status_code, body, resp_hdrs)


# ── Public API ─────────────────────────────────────────────────────────────────

def get(
    url: str,
    *,
    auth:            tuple | None = None,
    timeout:         float | None = None,
    verify:          bool = True,
    allow_redirects: bool = True,
    params:          dict | None = None,
    headers:         dict | None = None,
) -> Response:
    return _do_request(
        "GET", url,
        params=params, headers=headers, auth=auth,
        timeout=timeout, verify=verify, allow_redirects=allow_redirects,
    )


def post(
    url: str,
    *,
    json=None,
    timeout: float | None = None,
    headers: dict | None = None,
) -> Response:
    data  = _json.dumps(json).encode() if json is not None else None
    hdrs  = {"Content-Type": "application/json", **(headers or {})}
    return _do_request("POST", url, data=data, headers=hdrs, timeout=timeout)
