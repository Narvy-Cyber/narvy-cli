"""Optional web-scan denylist. Nothing refused by default; set SCAN_BLOCKLIST_EXTRA
to refuse domains. Internal/reserved-target protection lives in web/ssrf_guard.py.
_MAJOR_PLATFORMS/_OWN_DOMAINS below are reference only, NOT enforced by default.
"""

import os
from typing import Optional, Set
from urllib.parse import urlparse

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging
    logger = logging.getLogger("scan_blocklist")


REFUSAL_MESSAGE = (
    "This target looks like a property you do not own. Narvy only scans "
    "sites you own or are authorized to test. Point it at your own domain."
)


_OWN_DOMAINS = {
    'narvy.io',
}

# Registrable domains only; subdomains are covered by the suffix match.
_MAJOR_PLATFORMS = {
    'twitter.com', 'x.com', 'facebook.com', 'fb.com', 'instagram.com',
    'linkedin.com', 'tiktok.com', 'snapchat.com', 'pinterest.com',
    'reddit.com', 'whatsapp.com', 'telegram.org', 'discord.com',
    'threads.net', 'mastodon.social', 'tumblr.com', 'twitch.tv',
    'google.com', 'google.co.uk', 'youtube.com', 'gmail.com',
    'googleapis.com', 'gstatic.com',
    'microsoft.com', 'live.com', 'office.com', 'bing.com', 'azure.com',
    'windows.com', 'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com',
    'amazonaws.com',
    'github.com', 'gitlab.com', 'bitbucket.org', 'cloudflare.com',
    'slack.com', 'zoom.us', 'dropbox.com', 'salesforce.com', 'atlassian.com',
    'shopify.com', 'stripe.com', 'paypal.com', 'wordpress.com', 'wix.com',
    'squarespace.com', 'netflix.com', 'spotify.com',
    'yahoo.com', 'outlook.com', 'proton.me', 'protonmail.com',
}


def _env_extra_domains() -> Set[str]:
    """Extra refused domains from the comma-separated SCAN_BLOCKLIST_EXTRA env var."""
    raw = os.environ.get('SCAN_BLOCKLIST_EXTRA', '')
    return {d.strip().lower().lstrip('.') for d in raw.split(',') if d.strip()}


def blocked_domains() -> Set[str]:
    return _env_extra_domains()


class ScanBlocked(Exception):
    """Its message is always REFUSAL_MESSAGE, safe to surface verbatim."""

    def __init__(self, message: str = REFUSAL_MESSAGE):
        super().__init__(message)


def normalize_host(host: Optional[str]) -> str:
    """Lowercase, strip a trailing FQDN dot and a leading ``www.``."""
    if not host:
        return ''
    host = host.strip().lower()
    if host.endswith('.'):
        host = host[:-1]
    if host.startswith('www.'):
        host = host[4:]
    return host


def is_blocked_host(host: Optional[str]) -> bool:
    """True if the normalized host equals a refused domain or is a subdomain of one."""
    norm = normalize_host(host)
    if not norm:
        return False
    for domain in blocked_domains():
        if norm == domain or norm.endswith('.' + domain):
            return True
    return False


def check_blocklist(url: str) -> None:
    """Raise ``ScanBlocked`` if ``url`` targets a refused domain."""
    if not url or not isinstance(url, str):
        return
    try:
        host = urlparse(url).hostname
    except Exception:
        return
    if is_blocked_host(host):
        logger.warning(f"[scan_blocklist] refused target the user is unlikely to own host={host!r}")
        raise ScanBlocked()
