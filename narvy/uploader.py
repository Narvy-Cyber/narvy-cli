import os
from urllib.parse import urlparse

import requests

# NARVY_URL overrides the default API endpoint.
API_BASE = (os.environ.get("NARVY_URL") or "https://narvy.io").rstrip("/")


def server_host():
    """Host the CLI talks to, for messages (narvy.io unless NARVY_URL says otherwise)."""
    return urlparse(API_BASE).netloc or API_BASE


def _network_error(exc):
    """Return the (status, data) shape callers handle; status 0 never matches a real HTTP code."""
    return 0, {
        "error": (
            f"could not reach the Narvy server at {API_BASE} ({exc}). "
            "Check your internet connection, VPN/proxy or firewall, then retry."
        )
    }


def _json_or_error(r):
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"error": f"non-JSON response from server (HTTP {r.status_code})"}


def whoami(token):
    try:
        r = requests.get(
            f"{API_BASE}/api/v1/whoami",
            headers={"X-API-Token": token},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        return _network_error(e)
    return _json_or_error(r)


def upload_scan(apk_path, token, platform="android", analysis_type="sast", confirm_warning=False):
    # confirm_warning proceeds past the API's 409 malware-triage warning.
    data = {"platform": platform, "type": analysis_type}
    if confirm_warning:
        data["confirm_warning"] = "true"
    try:
        with open(apk_path, "rb") as f:
            r = requests.post(
                f"{API_BASE}/api/v1/analyze",
                headers={"X-API-Token": token},
                data=data,
                files={"input_file": f},
                timeout=300,
            )
    except requests.exceptions.RequestException as e:
        return _network_error(e)
    return _json_or_error(r)


def ingest_results(token, app_name, platform, scan_mode, findings, version=None,
                   app=None, git_remote=None, git_branch=None, package_id=None):
    """POST this scan's findings to /api/v1/ingest (no binary leaves this machine).

    The app is matched server-side on ``app`` (--app: name or app ID) if
    given, else the git remote, else ``app_name`` with and without a GitHub
    archive suffix. ``package_id`` (binary scans only: the APK manifest package
    or the IPA CFBundleIdentifier) lets the server join the App a web upload of
    the same binary created. Fields left None are not sent."""
    body = {
        "app_name": app_name,
        "platform": platform,
        "scan_mode": scan_mode,
        "version": version,
        "findings": findings,
    }
    for key, val in (("app", app), ("git_remote", git_remote), ("git_branch", git_branch),
                     ("package_id", package_id)):
        if val:
            body[key] = val
    try:
        r = requests.post(
            f"{API_BASE}/api/v1/ingest",
            headers={"X-API-Token": token, "Content-Type": "application/json"},
            json=body,
            timeout=120,
        )
    except requests.exceptions.RequestException as e:
        return _network_error(e)
    return _json_or_error(r)


def ingest_body(token, body):
    """POST a prepared ingest body (narvy.cloud.upload.build_body) to /api/v1/ingest."""
    try:
        r = requests.post(
            f"{API_BASE}/api/v1/ingest",
            headers={"X-API-Token": token, "Content-Type": "application/json"},
            json=body,
            timeout=120,
        )
    except requests.exceptions.RequestException as e:
        return _network_error(e)
    return _json_or_error(r)


def list_scans(token, limit=20, offset=0, status=None):
    """List recent scans on the caller's account via GET /api/v1/scans."""
    params = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    try:
        r = requests.get(
            f"{API_BASE}/api/v1/scans",
            headers={"X-API-Token": token},
            params=params,
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        return _network_error(e)
    return _json_or_error(r)
