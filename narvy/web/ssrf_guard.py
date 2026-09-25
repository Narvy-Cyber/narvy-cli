"""SSRF protection for the web scanner: URL checks, IP pinning, safe redirects."""

import ipaddress
import os
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


def _allowlisted_hosts() -> Set[str]:
    """Opt-in allowlist of host[:port] entries that bypass the IP blocklist."""
    raw = os.environ.get('SSRF_GUARD_ALLOW_HOSTS', '')
    return {h.strip().lower() for h in raw.split(',') if h.strip()}

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging
    logger = logging.getLogger("ssrf_guard")


# Blocked by name too: split-horizon DNS can point these at a benign IP.
METADATA_HOSTNAMES = {
    'localhost',
    'metadata.google.internal',
    'metadata',
    'instance-data',
    'instance-data.ec2.internal',
}

# IPv4 nets the stdlib does not flag but a scanner must never reach.
_BLOCKED_V4_NETS = (
    ipaddress.ip_network('100.64.0.0/10'),   # CGNAT / carrier-grade NAT range
    ipaddress.ip_network('0.0.0.0/8'),       # "this network"
    ipaddress.ip_network('198.18.0.0/15'),   # benchmarking
    ipaddress.ip_network('192.0.0.0/24'),    # IETF protocol assignments
    ipaddress.ip_network('240.0.0.0/4'),     # future-use / reserved
    ipaddress.ip_network('224.0.0.0/4'),     # multicast
)

# Mostly covered by the stdlib is_* properties; listed explicitly for clarity.
_BLOCKED_V6_NETS = (
    ipaddress.ip_network('fc00::/7'),        # unique-local (ULA)
    ipaddress.ip_network('fe80::/10'),       # link-local (also is_link_local)
)

MAX_URL_LEN = 2048
DEFAULT_MAX_REDIRECTS = 5

# Caps buffered body so a hostile target cannot OOM the process.
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
_READ_CHUNK = 65536


class SSRFBlocked(Exception):
    """Raised when a URL is rejected by the SSRF guard. The message is safe to show."""


class ResponseTooLarge(Exception):
    """Raised when a target's response exceeds MAX_RESPONSE_BYTES."""


def _ip_is_blocked(ip_obj) -> bool:
    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) is unwrapped and re-checked.
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return True

    if isinstance(ip_obj, ipaddress.IPv4Address):
        # Cloud metadata range; already covered by is_link_local, kept explicit.
        if str(ip_obj).startswith('169.254.'):
            return True
        if str(ip_obj) == '255.255.255.255':
            return True
        for net in _BLOCKED_V4_NETS:
            if ip_obj in net:
                return True
    else:
        for net in _BLOCKED_V6_NETS:
            if ip_obj in net:
                return True

    return False


def _resolve_all_ips(hostname: str, port: int) -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []
    try:
        infos = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFBlocked(f"Could not resolve hostname: {hostname}") from e

    for family, _stype, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        # Strip any IPv6 scope id (e.g. fe80::1%eth0).
        if '%' in ip_str:
            ip_str = ip_str.split('%', 1)[0]
        results.append((family, ip_str))

    if not results:
        raise SSRFBlocked(f"Could not resolve hostname: {hostname}")
    return results


def validate_url(url: str) -> Tuple[str, str, int]:
    """Validate a URL, returning (validated_url, pinned_ip, port) or raising."""
    if not url or not isinstance(url, str):
        raise SSRFBlocked("Empty or invalid URL")
    if len(url) > MAX_URL_LEN:
        raise SSRFBlocked(f"URL too long (max {MAX_URL_LEN} characters)")

    # urlparse() and .port raise on a malformed IPv6 bracket or bad port.
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or '').lower()
        hostname = parsed.hostname
        port_value = parsed.port
    except ValueError as e:
        raise SSRFBlocked(f"Invalid URL: {e}")

    if scheme not in ('http', 'https'):
        raise SSRFBlocked("Only HTTP and HTTPS URLs are allowed")

    if not hostname:
        raise SSRFBlocked("Invalid URL - no hostname found")
    hostname = hostname.lower()

    port = port_value or (443 if scheme == 'https' else 80)

    _allow = _allowlisted_hosts()
    if _allow and (hostname in _allow or f"{hostname}:{port}" in _allow):
        try:
            literal = ipaddress.ip_address(hostname)
            return url, str(literal), port
        except ValueError:
            # Allowlisted by name, still resolved so there is an IP to pin.
            try:
                resolved = _resolve_all_ips(hostname, port)
                return url, resolved[0][1], port
            except SSRFBlocked:
                raise

    if hostname in METADATA_HOSTNAMES:
        raise SSRFBlocked("Scanning internal/metadata addresses is not allowed")

    try:
        literal = ipaddress.ip_address(hostname)
        if _ip_is_blocked(literal):
            raise SSRFBlocked("Scanning internal/private/reserved IP addresses is not allowed")
        return url, str(literal), port
    except ValueError:
        pass

    resolved = _resolve_all_ips(hostname, port)

    pinned_ip: Optional[str] = None
    for _family, ip_str in resolved:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFBlocked("Resolved to an unparseable address")
        if _ip_is_blocked(ip_obj):
            # Anti-rebinding: one dangerous record rejects the whole host.
            raise SSRFBlocked(
                "Host resolves to an internal/private/reserved address - blocked"
            )
        if pinned_ip is None:
            pinned_ip = ip_str

    if pinned_ip is None:
        raise SSRFBlocked(f"Could not resolve hostname: {hostname}")

    return url, pinned_ip, port


class SSRFSafeAdapter(HTTPAdapter):
    """Connect to a pre-validated IP while keeping the hostname for Host/SNI."""

    def __init__(self, pinned_host: str, pinned_ip: str, *args, **kwargs):
        self._pinned_host = pinned_host.lower()
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        # Pinning happens in send() via a scoped create_connection swap.
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )

    def _make_pinned_create_connection(self, orig_create_connection):
        pinned_host = self._pinned_host
        pinned_ip = self._pinned_ip

        def _pinned_create_connection(address, *a, **kw):
            host = address[0] if address else None
            if host and host.lower() == pinned_host:
                address = (pinned_ip,) + tuple(address[1:])
            return orig_create_connection(address, *a, **kw)

        return _pinned_create_connection

    def send(self, request, *args, **kwargs):
        import urllib3.util.connection as _u3c
        import urllib3.connection as _u3conn
        _orig_util = _u3c.create_connection
        pinned = self._make_pinned_create_connection(_orig_util)
        _orig_conn = getattr(_u3conn, 'create_connection', None)
        _u3c.create_connection = pinned
        if _orig_conn is not None:
            _u3conn.create_connection = pinned
        try:
            return super().send(request, *args, **kwargs)
        finally:
            _u3c.create_connection = _orig_util
            if _orig_conn is not None:
                _u3conn.create_connection = _orig_conn


def _build_pinned_session(
    validated_url: str,
    pinned_ip: str,
    base_session: Optional[requests.Session] = None,
    user_agent: Optional[str] = None,
) -> requests.Session:
    host = urlparse(validated_url).hostname.lower()
    if base_session is not None:
        sess = base_session
    else:
        sess = requests.Session()
        sess.verify = False
        if user_agent:
            sess.headers.setdefault('User-Agent', user_agent)

    adapter = SSRFSafeAdapter(pinned_host=host, pinned_ip=pinned_ip)
    sess.mount('http://', adapter)
    sess.mount('https://', adapter)
    return sess


def _materialize_capped(resp: requests.Response, url: str) -> None:
    """Buffer a streamed response body into ``resp``, capped at MAX_RESPONSE_BYTES."""
    declared = resp.headers.get('Content-Length')
    if declared is not None:
        try:
            if int(declared) > MAX_RESPONSE_BYTES:
                resp.close()
                raise ResponseTooLarge(
                    f"{url}: declared Content-Length {declared} exceeds the "
                    f"{MAX_RESPONSE_BYTES} byte cap")
        except ValueError:
            pass

    buf = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=_READ_CHUNK):
            if not chunk:
                continue
            buf += chunk
            if len(buf) > MAX_RESPONSE_BYTES:
                resp.close()
                raise ResponseTooLarge(
                    f"{url}: response body exceeded the {MAX_RESPONSE_BYTES} "
                    f"byte cap (streaming)")
    finally:
        resp.close()

    # The two attributes `requests` sets on a cached body, so .content/.text/.json() work.
    resp._content = bytes(buf)
    resp._content_consumed = True


def safe_get(
    url: str,
    *,
    timeout: int = 10,
    headers: Optional[dict] = None,
    session: Optional[requests.Session] = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    verify: bool = False,
    user_agent: Optional[str] = None,
    **kwargs,
) -> requests.Response:
    """GET that re-validates and re-pins every redirect hop."""
    kwargs.pop('allow_redirects', None)

    current_url = url
    # Base session carries cookies; each hop gets a fresh pinned adapter (host/IP may differ).
    base = session if session is not None else None
    if base is None:
        base = requests.Session()
        base.verify = verify
        if user_agent:
            base.headers.setdefault('User-Agent', user_agent)

    last_resp: Optional[requests.Response] = None
    for hop in range(max_redirects + 1):
        validated_url, pinned_ip, _port = validate_url(current_url)
        sess = _build_pinned_session(validated_url, pinned_ip, base_session=base)

        resp = sess.get(
            validated_url,
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
            verify=verify,
            stream=True,
            **kwargs,
        )
        last_resp = resp

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location')
            if not location:
                _materialize_capped(resp, validated_url)
                return resp
            # A hop's body is closed unread, so it cannot smuggle a huge body past the cap.
            next_url = urljoin(validated_url, location)
            logger.debug(f"[ssrf_guard] redirect hop {hop}: {validated_url} -> {next_url}")
            current_url = next_url
            resp.close()
            continue

        _materialize_capped(resp, validated_url)
        return resp

    logger.warning(f"[ssrf_guard] max redirects ({max_redirects}) exceeded for {url}")
    if last_resp is not None:
        _materialize_capped(last_resp, current_url)
    return last_resp


def safe_session(
    url: str,
    *,
    base_session: Optional[requests.Session] = None,
    user_agent: Optional[str] = None,
    verify: bool = False,
) -> Tuple[requests.Session, str]:
    """(session, url) pinned to the url's IP for one request. Use safe_get for redirects."""
    validated_url, pinned_ip, _port = validate_url(url)
    sess = _build_pinned_session(
        validated_url, pinned_ip, base_session=base_session, user_agent=user_agent
    )
    sess.verify = verify
    return sess, validated_url


def is_safe_url(url: str) -> bool:
    try:
        validate_url(url)
        return True
    except SSRFBlocked:
        return False
    except Exception:
        return False
