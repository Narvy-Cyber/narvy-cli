"""Nuclei-based web scanner. Passive (GET/HEAD only) by default."""

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional

from .nuclei_binary import resolve_nuclei_binary
from .ssrf_guard import validate_url as _ssrf_validate, SSRFBlocked as _SSRFBlocked

logger = logging.getLogger(__name__)

PASSIVE_TEMPLATES = [
    "http/technologies/",
    "http/misconfiguration/",
    "http/exposures/",
]

REQUEST_TIMEOUT = 7
RETRIES = 1
SUBPROCESS_TIMEOUT = 420

# Timeout budget must scale with template count / rate-limit or a low rate limit
# guarantees a timeout; nuclei's `-jle` writer flushes nothing on a kill.
TIMEOUT_SAFETY_FACTOR = 2.5
TIMEOUT_FIXED_OVERHEAD = 120
SUBPROCESS_TIMEOUT_CAP = 3600
# Rough request count of the full active set (about 10k templates). Sizes its time budget.
ACTIVE_REQUEST_ESTIMATE = 18000
MAX_RATE_LIMIT = 50


def compute_subprocess_timeout(n_templates: int, rate_limit: int) -> int:
    rate = max(int(rate_limit or 1), 1)
    needed = (max(int(n_templates), 0) / rate) * TIMEOUT_SAFETY_FACTOR
    return int(min(max(SUBPROCESS_TIMEOUT, needed + TIMEOUT_FIXED_OVERHEAD),
                   SUBPROCESS_TIMEOUT_CAP))
DEFAULT_SEVERITY = ["critical", "high", "medium", "low", "info"]
EXCLUDE_TAGS = ["dos"]


class NucleiScanner:
    """Passive-only wrapper around the `nuclei` binary."""

    _ACTIVE_TEMPLATE_PREFIXES = (
        "dast/",
        "fuzzing/",
        "http/fuzzing/",
        "http/vulnerabilities/",
    )
    _ACTIVE_CVE_SUBSTRINGS = (
        "-rce", "-sqli", "-xss", "-ssrf", "-lfi", "-rfi",
        "-cmdi", "-ssti", "-injection",
    )

    def __init__(self, nuclei_bin: Optional[str] = None):
        self.nuclei_bin = nuclei_bin or resolve_nuclei_binary()

    @classmethod
    def _is_active_template(cls, template_path: str) -> bool:
        if not template_path:
            return False
        tp = template_path.lower()
        for prefix in cls._ACTIVE_TEMPLATE_PREFIXES:
            if tp.startswith(prefix):
                return True
        if tp.startswith(("cves/", "http/cves/")):
            for sub in cls._ACTIVE_CVE_SUBSTRINGS:
                if sub in tp:
                    return True
        return False

    # Passive safety = GET/HEAD only, no body; an omitted method defaults to GET.
    _SAFE_HTTP_METHODS = ("GET", "HEAD", "")

    @classmethod
    def _template_is_get_only(cls, yaml_path: str) -> bool:
        """True if every request block is a bodyless GET or HEAD. Parse errors return False."""
        try:
            import yaml
            with open(yaml_path, "r") as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict):
                return False
            # A non-HTTP protocol block must not fall through to True.
            _NON_HTTP_PROTOCOL_KEYS = (
                "javascript", "network", "code", "dns", "ssl",
                "websocket", "headless", "file",
            )
            if any(doc.get(k) for k in _NON_HTTP_PROTOCOL_KEYS):
                return False
            blocks = doc.get("http") or doc.get("requests") or []
            if not isinstance(blocks, list):
                return False
            for block in blocks:
                if not isinstance(block, dict):
                    return False
                method = str(block.get("method") or "").upper()
                if method not in cls._SAFE_HTTP_METHODS:
                    return False
                if block.get("body"):
                    return False
                if block.get("raw"):
                    return False
            return True
        except Exception as e:
            logger.warning(f"_template_is_get_only: failed to parse {yaml_path}, excluding from passive set: {e}")
            return False

    _NUCLEI_TEMPLATES_ROOT_CANDIDATES = (
        os.environ.get("NUCLEI_TEMPLATES_DIR") or "",
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/nuclei-templates"),
    )

    @classmethod
    def _resolve_templates_root(cls) -> Optional[str]:
        for candidate in cls._NUCLEI_TEMPLATES_ROOT_CANDIDATES:
            if candidate and os.path.isdir(candidate):
                return candidate
        return None

    @classmethod
    def _filter_get_only_templates(cls, template_paths: List[str]) -> List[str]:
        """Expand directories and drop non-GET/HEAD templates; input unchanged if root unresolved."""
        root = cls._resolve_templates_root()
        if root is None:
            logger.warning(
                "_filter_get_only_templates: could not resolve a nuclei "
                "templates root - passive template set NOT method-filtered "
                "this run (falling back to directory-prefix filtering only)"
            )
            return template_paths

        out: List[str] = []
        dropped = 0
        for t in template_paths:
            abs_path = os.path.join(root, t) if not os.path.isabs(t) else t
            if os.path.isdir(abs_path):
                for dirpath, _dirs, files in os.walk(abs_path):
                    for fname in sorted(files):
                        if not fname.endswith((".yaml", ".yml")):
                            continue
                        fpath = os.path.join(dirpath, fname)
                        if cls._template_is_get_only(fpath):
                            out.append(fpath)
                        else:
                            dropped += 1
            elif os.path.isfile(abs_path):
                if cls._template_is_get_only(abs_path):
                    out.append(abs_path)
                else:
                    dropped += 1
                    logger.warning(f"_filter_get_only_templates: dropped non-GET/HEAD template {abs_path}")
            else:
                out.append(t)
        if dropped:
            logger.info(f"_filter_get_only_templates: dropped {dropped} non-GET/HEAD/body template(s) from the passive set")
        return out

    # Redirects resolved here through ssrf_guard (IP-pins every hop); nuclei runs
    # with `-disable-redirects` and is handed the already-validated final URL.
    _REDIRECT_MAX_HOPS = 5

    @classmethod
    def _normalize_for_compare(cls, url: str) -> str:
        return (url or "").rstrip("/").lower()

    def _resolve_redirect_target(self, target: str) -> Dict:
        """Follow redirects through the SSRF guard. Returns {url, note, final_status}; never raises."""
        from .ssrf_guard import safe_get as _ssrf_safe_get, SSRFBlocked as _Blocked
        out = {"url": target, "note": None, "final_status": None, "coverage_incomplete": False}
        try:
            resp = _ssrf_safe_get(
                target, timeout=10, verify=False,
                max_redirects=self._REDIRECT_MAX_HOPS,
                headers={"User-Agent": self._BROWSER_UA},
            )
        except _Blocked as e:
            location = self._peek_redirect_location(target)
            where = f" to {location}" if location else ""
            out["note"] = (
                f"target redirects{where} which was not scanned (SSRF policy: {e}). "
                f"Only the redirect stub at {target} was scanned - treat these results "
                f"as incomplete."
            )
            out["coverage_incomplete"] = True
            logger.warning(f"_resolve_redirect_target: {out['note']}")
            return out
        except Exception as e:
            out["note"] = (
                f"could not pre-resolve redirects for {target} ({e}); scanned the URL "
                f"as given"
            )
            logger.warning(f"_resolve_redirect_target: {out['note']}")
            return out

        out["final_status"] = getattr(resp, "status_code", None)
        final_url = getattr(resp, "url", None) or target
        if self._normalize_for_compare(final_url) != self._normalize_for_compare(target):
            # Re-assert on the URL handed to an external process.
            try:
                _ssrf_validate(final_url)
            except _SSRFBlocked as e:
                out["note"] = (
                    f"target redirects to {final_url} which was not scanned "
                    f"(SSRF policy: {e}). Only the redirect stub at {target} was "
                    f"scanned - treat these results as incomplete."
                )
                out["coverage_incomplete"] = True
                logger.warning(f"_resolve_redirect_target: {out['note']}")
                return out
            out["url"] = final_url
            out["note"] = (
                f"{target} redirects to {final_url} (HTTP {out['final_status']}); scanned "
                f"the resolved URL instead of the redirect stub"
            )
            logger.info(f"_resolve_redirect_target: {out['note']}")
        return out

    def _peek_redirect_location(self, target: str) -> Optional[str]:
        """Best-effort read of the first hop's Location header for the report."""
        try:
            from urllib.parse import urljoin
            from .ssrf_guard import safe_get as _ssrf_safe_get
            resp = _ssrf_safe_get(
                target, timeout=10, verify=False, max_redirects=0,
                headers={"User-Agent": self._BROWSER_UA},
            )
            loc = resp.headers.get("Location")
            return urljoin(target, loc) if loc else None
        except Exception:
            return None

    # A throttled target yields zero findings, indistinguishable from clean unless probed.
    _RATE_LIMIT_STATUSES = (429, 503)
    _RATE_LIMIT_PROBES = 3
    _RATE_LIMIT_PROBE_DELAY = 1.0

    def _probe_rate_limited(self, target: str) -> Dict:
        """Report whether the target is answering 429/503 (only on a zero-finding scan)."""
        import time as _time
        from .ssrf_guard import safe_get as _ssrf_safe_get
        statuses: List[int] = []
        for i in range(self._RATE_LIMIT_PROBES):
            if i:
                _time.sleep(self._RATE_LIMIT_PROBE_DELAY)
            try:
                resp = _ssrf_safe_get(
                    target, timeout=10, verify=False,
                    headers={"User-Agent": self._BROWSER_UA},
                )
                statuses.append(int(resp.status_code))
            except Exception as e:
                logger.debug(f"_probe_rate_limited: probe {i} failed: {e}")
        blocked = [s for s in statuses if s in self._RATE_LIMIT_STATUSES]
        limited = bool(statuses) and len(blocked) * 2 > len(statuses)
        # No status at all = never answered; `limited` needs a code to compare.
        return {"limited": limited, "statuses": statuses, "blocked": blocked,
                "unreachable": not statuses}

    def scan(
        self,
        target: str,
        rate_limit: int = 50,
        timeout: int = REQUEST_TIMEOUT,
        retries: int = RETRIES,
        severity: Optional[List[str]] = None,
        active: bool = False,
    ) -> Dict:
        """Run a nuclei scan. Active mode sends real payloads: only use it on targets you may test."""
        try:
            _ssrf_validate(target)
        except _SSRFBlocked as e:
            logger.warning(f"SSRF guard blocked target {target}: {e}")
            return {"success": False, "error": f"ssrf-blocked: {e}", "findings": []}

        redirect = self._resolve_redirect_target(target)
        scan_target = redirect["url"]
        redirect_note = redirect["note"]

        if active:
            # No -t: nuclei runs every installed template.
            templates = []
            sev = severity or ["info", "low", "medium", "high", "critical"]
        else:
            templates = [t for t in PASSIVE_TEMPLATES if not self._is_active_template(t)]
            templates = self._filter_get_only_templates(templates)
            sev = severity or DEFAULT_SEVERITY

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f:
            output_file = f.name

        cmd = [
            self.nuclei_bin,
            "-u", scan_target,
            "-jle", output_file,
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout),
            "-retries", str(retries),
            "-c", "25",
            "-silent",
            "-no-interactsh",
            # Never follow a redirect to a new host.
            "-disable-redirects",
            "-severity", ",".join(sev),
            "-exclude-tags", ",".join(EXCLUDE_TAGS + (["fuzzing", "brute-force", "intrusive"] if active else [])),
        ]
        for t in templates:
            cmd.extend(["-t", t])

        # Active passes no -t, so size the timeout off a conservative set estimate, not len(0).
        subprocess_timeout = compute_subprocess_timeout(len(templates) if templates else ACTIVE_REQUEST_ESTIMATE, rate_limit)
        if subprocess_timeout > SUBPROCESS_TIMEOUT:
            logger.info(
                f"Nuclei subprocess budget raised to {subprocess_timeout}s "
                f"({len(templates)} templates at {rate_limit} req/s needs at least "
                f"{len(templates) // max(rate_limit, 1)}s; the {SUBPROCESS_TIMEOUT}s "
                f"default would have guaranteed a timeout)"
            )

        logger.info(f"Nuclei {'active' if active else 'passive'} scan: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=subprocess_timeout
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out after {subprocess_timeout}s")
            self._safe_unlink(output_file)
            return {
                "success": False,
                "error": (
                    f"scan timed out after {subprocess_timeout}s "
                    f"({'full active template set' if active else str(len(templates)) + ' passive templates'} "
                    f"at --rate-limit {rate_limit} req/s)."
                    + (" Raise --rate-limit if the target can take it." if rate_limit < MAX_RATE_LIMIT else "")
                ),
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            self._safe_unlink(output_file)
            return {"success": False, "error": str(e), "findings": []}

        findings = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse nuclei output line: {line[:100]}")
                        continue
                    template_id = (raw.get("template-id") or "").lower()
                    matcher_name = (raw.get("matcher-name") or "").lower()
                    if (template_id == "http-missing-security-headers"
                            and matcher_name in self._IGNORED_HEADER_MATCHERS):
                        continue
                    findings.append(self._parse_nuclei_finding(raw))
        self._safe_unlink(output_file)

        findings = self._validate_missing_header_findings(scan_target, findings)
        findings = self._dedup_findings(findings)
        findings = self._suppress_stale_eol_fp(findings)
        findings = self._suppress_uncorroborated_tech_eol(findings)

        out = {
            "success": True,
            "findings": findings,
            "total_findings": len(findings),
            "stderr": result.stderr,
            "returncode": result.returncode,
            "target": target,
            "scanned_url": scan_target,
            "redirect_note": redirect_note,
            "coverage_incomplete": redirect.get("coverage_incomplete", False),
            "degraded": False,
            "degraded_reason": None,
        }

        # A zero-finding result is the only one a rate-limiter can fake.
        if not findings:
            probe = self._probe_rate_limited(scan_target)
            if probe["limited"]:
                reason = (
                    f"target is rate-limiting/blocking the scanner - {len(probe['blocked'])} "
                    f"of {len(probe['statuses'])} verification requests to {scan_target} came "
                    f"back HTTP {'/'.join(str(s) for s in sorted(set(probe['blocked'])))}. "
                    f"This run could not reach real content, so it is inconclusive. Run it "
                    f"from the Narvy platform (allowlisted egress + the full active engine), "
                    f"or re-run with a lower --rate-limit."
                )
                out["degraded"] = True
                out["degraded_reason"] = reason
                out["success"] = False
                out["error"] = reason
                logger.warning(f"scan: {reason}")
            elif probe["unreachable"]:
                reason = (
                    f"target never answered - all {self._RATE_LIMIT_PROBES} verification "
                    f"requests to {scan_target} failed to get any HTTP response at all "
                    f"(connection refused/timed out/DNS or TLS failure). Nuclei's requests "
                    f"were dropped the same way, so nothing was scanned and this run is "
                    f"inconclusive. Run it from the Narvy platform (different network "
                    f"egress), or check the host is up and reachable from this machine "
                    f"(proxy/firewall/egress rules), and that the scheme and port are right."
                )
                out["degraded"] = True
                out["degraded_reason"] = reason
                out["success"] = False
                out["error"] = reason
                logger.warning(f"scan: {reason}")
        return out

    @staticmethod
    def _safe_unlink(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    _EOL_CURRENT_FLOOR = {
        "nginx": (1, 24),
        "apache": (2, 4),
        "httpd": (2, 4),
        "openssh": (9, 0),
        "php": (8, 1),
        "openssl": (3, 0),
    }

    @staticmethod
    def _suppress_stale_eol_fp(findings: List[Dict]) -> List[Dict]:
        kept: List[Dict] = []
        for f in findings:
            tag_blob = " ".join([
                str(f.get("title", "")), str(f.get("template_id", "")),
                " ".join(f.get("tags", []) or []),
            ]).lower()
            is_eol = ("end of life" in tag_blob or "end-of-life" in tag_blob
                      or "eol" in tag_blob)
            if is_eol and not f.get("cve_id"):
                text = " ".join([
                    str(f.get("title", "")), str(f.get("description", "")),
                    " ".join(str(x) for x in (f.get("evidence") or [])),
                ]).lower()
                soft = next((s for s in NucleiScanner._EOL_CURRENT_FLOOR if s in text), None)
                m = re.search(r"(\d+)\.(\d+)", text)
                if soft and m:
                    ver = (int(m.group(1)), int(m.group(2)))
                    if ver >= NucleiScanner._EOL_CURRENT_FLOOR[soft]:
                        continue
            kept.append(f)
        return kept

    # Require independent evidence of the technology before reporting an EOL finding.
    _EOL_REQUIRES_EVIDENCE = {
        "wordpress-eol": (
            "wp-content", "wp-includes", "wp-json", "/wp-admin",
            'content="wordpress', "content='wordpress",
        ),
    }

    @classmethod
    def _suppress_uncorroborated_tech_eol(cls, findings: List[Dict]) -> List[Dict]:
        """Drop EOL findings when the response shows no evidence the technology is present."""
        kept: List[Dict] = []
        for f in findings:
            required = cls._EOL_REQUIRES_EVIDENCE.get((f.get("template_id") or "").lower())
            if required:
                haystack = " ".join([
                    str(f.get("response_raw", "")), str(f.get("request_raw", "")),
                    str(f.get("description", "")),
                    " ".join(str(x) for x in (f.get("evidence") or [])),
                ]).lower()
                if not any(token in haystack for token in required):
                    continue
            kept.append(f)
        return kept

    @staticmethod
    def _dedup_findings(findings: List[Dict]) -> List[Dict]:
        seen = set()
        deduped: List[Dict] = []
        for f in findings:
            key = (
                (f.get("template_id") or "").lower(),
                (f.get("matcher_name") or "").lower(),
                f.get("url") or "",
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    _IGNORED_HEADER_MATCHERS = {
        "clear-site-data",
        "x-permitted-cross-domain-policies",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "missing-content-type",
        "content-type-charset-specification",
    }

    _MATCHER_TO_HEADER = {
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "permissions-policy": "Permissions-Policy",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }

    _WAF_CHALLENGE_HEADERS = {
        "x-vercel-mitigated", "x-vercel-challenge-token", "cf-mitigated",
        "cf-chl-bypass", "x-amz-cf-id", "x-akamai-edgescape",
        "x-akamai-bot-manager-action", "server-timing",
    }

    _BROWSER_UA = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/16.0 Safari/605.1.15"
    )

    @classmethod
    def _is_waf_challenge(cls, status_code: int, headers: Dict, body: str = "") -> bool:
        try:
            hkeys = {k.lower() for k in headers.keys()}
        except Exception:
            return False
        for marker in ("x-vercel-mitigated", "cf-mitigated", "x-vercel-challenge-token",
                       "cf-chl-bypass", "x-akamai-bot-manager-action"):
            if marker in hkeys:
                return True
        # A 429 is always an edge response, never the origin page; no body heuristic needed.
        if status_code == 429:
            return True
        if status_code in (403, 503):
            body_lc = (body or "").lower()
            if any(token in body_lc for token in (
                    "vercel security checkpoint", "attention required", "just a moment",
                    "cloudflare", "access denied", "cf-browser-verification",
                    "challenge-platform")):
                return True
            if len(body or "") < 200 and ("server" in hkeys):
                return True
        return False

    @staticmethod
    def _parse_raw_http_response(raw: str):
        if not raw or not isinstance(raw, str):
            return None, {}, ""
        sep = "\r\n\r\n" if "\r\n\r\n" in raw else ("\n\n" if "\n\n" in raw else None)
        if sep is None:
            head, body = raw, ""
        else:
            head, _, body = raw.partition(sep)
        head = head.replace("\r\n", "\n")
        lines = head.split("\n")
        if not lines:
            return None, {}, body
        status_line = lines[0]
        status_code = None
        try:
            parts = status_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
        except Exception:
            status_code = None
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
        return status_code, headers, body

    def _validate_missing_header_findings(self, target: str, findings: List[Dict]) -> List[Dict]:
        """Re-check missing-header findings; drop them if the header is there or it's a WAF page."""
        if not findings:
            return findings
        header_findings = [
            f for f in findings
            if (f.get("template_id") or "").lower() == "http-missing-security-headers"
        ]
        if not header_findings:
            return findings

        live_fetch_done = False
        live_status = None
        live_headers: Dict = {}
        live_body = ""
        live_failed = False

        def _do_live_fetch():
            nonlocal live_fetch_done, live_status, live_headers, live_body, live_failed
            if live_fetch_done:
                return
            live_fetch_done = True
            try:
                import urllib3
                # `target` may be re-pointed since scan() entry, so re-guard this fetch.
                from .ssrf_guard import safe_get as _ssrf_safe_get
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = _ssrf_safe_get(
                    target, timeout=10, verify=False,
                    headers={
                        "User-Agent": self._BROWSER_UA,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                )
                live_status = resp.status_code
                live_headers = dict(resp.headers)
                live_body = (resp.text or "")[:4096]
            except Exception as e:
                live_failed = True
                logger.warning(f"Header re-validation live fetch failed for {target}: {e}")

        kept: List[Dict] = []
        for f in findings:
            tid = (f.get("template_id") or "").lower()
            if tid != "http-missing-security-headers":
                kept.append(f)
                continue

            matcher = (f.get("matcher_name") or "").lower()
            header_name = self._MATCHER_TO_HEADER.get(matcher)
            if not header_name:
                kept.append(f)
                continue

            nuclei_resp_raw = f.get("response_raw") or ""
            n_status, n_headers, n_body = self._parse_raw_http_response(nuclei_resp_raw)

            if n_status is not None:
                if self._is_waf_challenge(n_status, n_headers, n_body):
                    continue
                hl = {k.lower(): v for k, v in n_headers.items()}
                if hl.get(header_name.lower(), ""):
                    continue
                kept.append(f)
                continue

            _do_live_fetch()
            if live_failed:
                kept.append(f)
                continue
            if self._is_waf_challenge(live_status or 0, live_headers, live_body):
                continue
            hl_live = {k.lower(): v for k, v in live_headers.items()}
            if hl_live.get(header_name.lower(), ""):
                continue
            kept.append(f)

        return kept

    def _parse_nuclei_finding(self, raw: Dict) -> Dict:
        info = raw.get("info", {})
        matched_at = raw.get("matched-at", raw.get("matched", ""))

        severity_map = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "unknown": "info",
        }
        severity = severity_map.get(info.get("severity", "unknown").lower(), "info")

        title = info.get("name", "").lower()
        template_id = raw.get("template-id", "").lower()
        matcher_name = raw.get("matcher-name", "").lower()
        cwe_id = None
        cve_id = None
        classification = info.get("classification", {})
        if classification:
            cwe_id = classification.get("cwe-id", [None])[0] if classification.get("cwe-id") else None
            cve_id = classification.get("cve-id", [None])[0] if classification.get("cve-id") else None

        tags = info.get("tags", [])
        category = self._determine_category(tags)

        extracted = raw.get("extracted-results") or []
        severity = self._upgrade_severity_if_needed(
            severity,
            title,
            template_id,
            matcher_name,
            tags=tags,
            template_path=str(raw.get("template") or raw.get("template-path") or ""),
            has_evidence=bool(extracted),
        )

        return {
            "source": "nuclei",
            "template_id": raw.get("template-id", "unknown"),
            "template": raw.get("template", "unknown"),
            "title": info.get("name", "Unknown Vulnerability"),
            "description": info.get("description", ""),
            "severity": severity,
            "category": category,
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "url": matched_at,
            "method": raw.get("type", "http").upper(),
            "request_raw": raw.get("request", ""),
            "response_raw": raw.get("response", ""),
            "evidence": raw.get("extracted-results", []),
            "matcher_name": raw.get("matcher-name", ""),
            "references": info.get("reference", []) if isinstance(info.get("reference"), list) else (
                [info.get("reference")] if info.get("reference") else []),
            "tags": tags,
            "remediation": info.get("remediation", ""),
            "metadata": raw.get("meta", {}),
        }

    def _determine_category(self, tags: List[str]) -> str:
        category_map = {
            "injection": ["sqli", "xss", "xxe", "ssti", "idor", "lfi", "rfi", "cmdi"],
            "broken_access_control": ["idor", "traversal", "auth-bypass", "unauth"],
            "cryptographic_failures": ["ssl", "tls", "weak-crypto", "exposed-keys"],
            "security_misconfiguration": ["misconfig", "default-login", "exposure", "config"],
            "vulnerable_components": ["cve", "outdated", "eol"],
            "auth_failures": ["auth", "authentication", "session", "jwt"],
            "ssrf": ["ssrf"],
            "information_disclosure": ["disclosure", "exposure", "sensitive-data", "debug"],
            "api_security": ["api", "graphql", "rest"],
        }
        tags_lower = [t.lower() for t in tags]
        for category, keywords in category_map.items():
            if any(keyword in tag for keyword in keywords for tag in tags_lower):
                return category
        return "other"

    # Secret-finding promotion needs a secret word and is vetoed by a public-identifier word.
    _SECRET_WORDS = (
        "secret", "password", "passwd", "credential",
        "token", "api key", "api-key", "apikey",
        "access key", "access-key", "accesskey",
        "private key", "private-key", "privatekey",
    )
    _PUBLIC_IDENTIFIER_WORDS = (
        "client id", "client-id", "clientid",
        "account id", "account-id", "accountid",
        "public key", "public-key", "publickey",
        "key id", "key-id", "keyid",
    )

    @classmethod
    def _is_credential_exposure(cls, title: str, template_id: str) -> bool:
        """True iff the template reports secret material, not a public identifier (title lowercase)."""
        blob = f"{title} {template_id}".lower().replace("_", "-")
        if any(w in blob for w in cls._PUBLIC_IDENTIFIER_WORDS):
            return False
        return any(w in blob for w in cls._SECRET_WORDS)

    @staticmethod
    def _is_exposure_finding(title: str, tags, template_path: str) -> bool:
        """True iff the finding exposes something not meant to be public (judged on tags/path/title)."""
        if "exposed" in title or "exposure" in title:
            return True
        try:
            tag_blob = " ".join(str(t).lower() for t in (tags or []))
        except Exception:
            tag_blob = ""
        if "exposure" in tag_blob or "disclosure" in tag_blob:
            return True
        return "/exposures/" in (template_path or "").lower()

    def _upgrade_severity_if_needed(
        self,
        severity: str,
        title: str,
        template_id: str,
        matcher_name: str,
        tags=None,
        template_path: str = "",
        has_evidence: bool = False,
    ) -> str:
        """Raise 'info' exposure findings that carry real risk."""
        if severity != "info":
            return severity

        if ("missing" in title and "header" in title) or template_id == "http-missing-security-headers":
            blob = f"{title} {matcher_name} {template_id}"
            if "strict-transport" in blob or "hsts" in blob:
                return "medium"
            if "content-security-policy" in blob or "csp" in blob:
                return "low"
            if "x-frame" in blob or "frame-options" in blob:
                return "low"
            if "content-type-options" in blob or "nosniff" in blob:
                return "low"
            if "referrer-policy" in blob:
                return "low"
            if "permissions-policy" in blob or "feature-policy" in blob:
                return "low"
            return "low"

        is_exposure = self._is_exposure_finding(title, tags, template_path)

        if is_exposure and has_evidence and self._is_credential_exposure(title, template_id):
            return "high"

        if "exposed" in title or "exposure" in title:
            if ".git" in title or "git" in template_id:
                return "high"
            # The dot is required: a bare "env" matches unrelated templates.
            if ".env" in title or ".env" in template_id or "dotenv" in template_id:
                return "critical"
            if "backup" in title or "backup" in template_id:
                return "medium"
            if "config" in title or "phpinfo" in title:
                return "medium"
            return "low"

        # Tag/path-detected exposure whose title never says "exposed".
        if is_exposure:
            if "backup" in title or "backup" in template_id:
                return "medium"
            if "config" in title or "phpinfo" in title:
                return "medium"
            return "low"

        if "default" in title and ("login" in title or "credential" in title or "password" in title):
            return "high"

        if "version" in title or "server" in title:
            return "info"

        if "cookie" in title:
            if "samesite" in title or "secure" in title or "httponly" in title:
                return "low"

        return severity
