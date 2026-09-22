"""Host exposure checks run alongside the Lynis baseline: reachable unauthenticated
data services, cloud metadata, container posture, and secret/VCS disclosure under a
web root. Each fires only on a confirmed exposure; checks take a ``run`` probe callable."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

NARVY_ENGINE = "Narvy"


@dataclass
class Probe:
    rc: int
    out: str


# None means the transport failed; a check treats it as no evidence, never a finding.
RunFn = Callable[[str], Optional[Probe]]


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "[::1]", "localhost"}
_ALL_INTERFACES = {"0.0.0.0", "::", "*", "[::]", ""}


def _stdout(run: RunFn, cmd: str) -> str:
    p = run(cmd)
    if p is None:
        return ""
    return p.out or ""


def _host_port(local: str) -> Optional[tuple]:
    """Split an ``ss``/``netstat`` local-address token into (host, port)."""
    a = (local or "").strip()
    if not a:
        return None
    if a.startswith("["):
        end = a.find("]")
        if end == -1:
            return None
        host = a[: end + 1]
        rest = a[end + 1:]
        port = rest.rsplit(":", 1)[-1] if ":" in rest else ""
    else:
        if ":" not in a:
            return None
        host, port = a.rsplit(":", 1)
    if not port.isdigit():
        return None
    return host, int(port)


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().rstrip("%")
    if h in _LOOPBACK_HOSTS:
        return True
    if h.startswith("127."):
        return True
    if h in ("[::1]", "::1"):
        return True
    return False


def _is_exposed(host: str) -> bool:
    """True when a listener binds anything other than pure loopback."""
    h = (host or "").strip()
    if _is_loopback(h):
        return False
    return True


def parse_listeners(text: str) -> List[Dict[str, object]]:
    """Parse ``ss -H -tlnp`` or ``netstat -tlnp`` into {proto,host,port,process,exposed} rows."""
    rows: List[Dict[str, object]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("state") or low.startswith("active") or low.startswith("proto"):
            continue
        parts = line.split()
        local = None
        proc = ""
        proto = "tcp"
        if low.startswith("tcp") or low.startswith("udp"):
            # netstat: proto recvq sendq local foreign state pid/name
            proto = parts[0]
            if len(parts) >= 4:
                local = parts[3]
            if len(parts) >= 7:
                proc = parts[6]
        else:
            # ss -H: State Recv-Q Send-Q Local Peer [Process]
            if len(parts) >= 4:
                local = parts[3]
            if len(parts) >= 6:
                proc = " ".join(parts[5:])
        hp = _host_port(local) if local else None
        if not hp:
            continue
        host, port = hp
        m = re.search(r'"([^"]+)"', proc) or re.search(r"/([A-Za-z0-9_.-]+)", proc)
        pname = (m.group(1) if m else "").strip()
        rows.append({
            "proto": proto,
            "host": host,
            "port": port,
            "process": pname,
            "exposed": _is_exposed(host),
        })
    return rows


def _f(control_id: str, title: str, severity: str, category: str,
       description: str, remediation: str, *, cwe: str = "", cis: str = "",
       location: str = "", discriminator: str = "",
       confidence: str = "HIGH") -> Dict[str, object]:
    """Build a finding in the shape report.normalize expects."""
    return {
        "engine": NARVY_ENGINE,
        "test_id": control_id,
        "control_id": control_id,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "details": "",
        "remediation": remediation,
        "cwe": cwe or None,
        "cis": cis or None,
        "location": location,
        "confidence": confidence,
        "discriminator": discriminator or f"{control_id}:{location or title[:60]}",
    }


# Names that look secret but are shipped as templates -> never a real secret.
_SECRET_NAME_ALLOW = re.compile(
    r"\.(example|sample|template|dist|def|md)$|(^|/)\.env\.(example|sample|template|dist)$",
    re.I,
)

_SECRET_ROOTS = "/home /root /var/www /srv /opt /etc/secrets /etc/nginx /run/secrets"


def check_secrets_on_disk(run: RunFn) -> List[Dict[str, object]]:
    """Flag world-readable secret material on disk (.env, credentials, private keys, DB dumps)."""
    names = (
        r"-name '.env' -o -name '.env.*' -o -name 'credentials' "
        r"-o -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' "
        r"-o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' "
        r"-o -name '*.p12' -o -name '*.pfx' -o -name '*.sql' -o -name '*.sql.gz' "
        r"-o -name '*.dump' -o -name '*.bak'"
    )
    # No outer `sh -c "..."` wrapper: ssh_exec already hands this to one shell; wrapping would expand $f early.
    cmd = (
        "find " + _SECRET_ROOTS + " -maxdepth 5 -type f -perm /004 "
        "\\( " + names + " \\) 2>/dev/null | while IFS= read -r f; do "
        "case \"$f\" in "
        "*.pem|*.key|*.p12|*.pfx|*id_rsa|*id_dsa|*id_ecdsa|*id_ed25519) "
        "if grep -qi 'PRIVATE KEY' \"$f\" 2>/dev/null; then echo \"KEY $f\"; fi;; "
        "*) echo \"CFG $f\";; esac; done"
    )
    out = _stdout(run, cmd)
    findings: List[Dict[str, object]] = []
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        kind, path = line.split(" ", 1)
        path = path.strip()
        if not path or path in seen:
            continue
        if _SECRET_NAME_ALLOW.search(path):
            continue
        seen.add(path)
        if kind == "KEY":
            title = "Private key is world-readable on disk"
            desc = (
                f"The private key at {path} is readable by every local account "
                "on this host (other-readable permission bits set) and its "
                "contents were confirmed to contain a PRIVATE KEY block. Any "
                "user on the box, or any process running as an unrelated "
                "service account, can copy this key and impersonate whatever it "
                "authenticates (SSH access, TLS server identity, signing)."
            )
            rem = (
                f"Restrict the key to its owner: `chmod 600 {path}` (or 400) and "
                "confirm ownership with `chown`. Store service private keys "
                "outside world-readable trees, and rotate this key -- treat it "
                "as compromised, since you cannot prove no other local user "
                "already read it."
            )
            cwe = "CWE-522"
        else:
            title = "Secret or credential file is world-readable on disk"
            desc = (
                f"The file {path} is readable by every local account on this "
                "host (other-readable). Files with these names routinely hold "
                "plaintext credentials -- API tokens, database passwords, cloud "
                "access keys, or a raw database dump. Any local user or "
                "compromised service on this host can read them directly, with "
                "no further escalation."
            )
            rem = (
                f"Tighten permissions to the owning user only: `chmod 600 {path}` "
                "(directories 700), and verify the owner. Keep application "
                "secrets out of web-served and shared directories, prefer a "
                "secrets manager or environment injection over on-disk files, "
                "and rotate any credential that was exposed."
            )
            cwe = "CWE-732"
        findings.append(_f(
            "narvy.host.secrets_on_disk", title, "high",
            "Secrets Exposure", desc, rem, cwe=cwe,
            location=path, discriminator=f"narvy.host.secrets_on_disk:{path}",
        ))
    return findings


@dataclass
class _Svc:
    port: int
    name: str


_DATA_SERVICES = {
    6379: _Svc(6379, "Redis"),
    27017: _Svc(27017, "MongoDB"),
    9200: _Svc(9200, "Elasticsearch"),
    5432: _Svc(5432, "PostgreSQL"),
    11211: _Svc(11211, "Memcached"),
    5984: _Svc(5984, "CouchDB"),
}


def _listener_text(run: RunFn) -> str:
    out = _stdout(run, "ss -H -tlnp 2>/dev/null")
    if out.strip():
        return out
    return _stdout(run, "netstat -tlnp 2>/dev/null")


def _redis_noauth(run: RunFn, port: int) -> Optional[bool]:
    """True if redis answers PING without auth, False if auth required, None if unknown."""
    resp = _tcp_probe(run, port, "PING\\r\\n")
    if resp is None:
        return None
    low = resp.lower()
    if "noauth" in low or "authentication" in low:
        return False
    if "pong" in low:
        return True
    return None


def _memcached_noauth(run: RunFn, port: int) -> Optional[bool]:
    resp = _tcp_probe(run, port, "version\\r\\n")
    if resp is None:
        return None
    low = resp.lower()
    if low.startswith("version") or "version " in low:
        return True
    if "error" in low or "auth" in low:
        return False
    return None


def _http_json_noauth(run: RunFn, port: int, path: str) -> Optional[bool]:
    """GET path on 127.0.0.1:port; True=200 (open), False=401/403 (secured)."""
    code = _stdout(
        run,
        f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' "
        f"http://127.0.0.1:{port}{path} 2>/dev/null",
    ).strip()
    if not code or not code.isdigit():
        return None
    c = int(code)
    if c == 200:
        return True
    if c in (401, 403):
        return False
    return None


def _tcp_probe(run: RunFn, port: int, payload: str) -> Optional[str]:
    """Send payload to 127.0.0.1:port over bash /dev/tcp; None when /dev/tcp is unavailable."""
    cmd = (
        "bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d 2>/dev/null || exit 7; "
        "printf \"%s\" >&3; head -c 256 <&3; exec 3>&-' 2>/dev/null"
        % (port, payload)
    )
    p = run(cmd)
    if p is None:
        return None
    if p.rc == 7:
        return None
    return p.out or ""


def _mongo_noauth(run: RunFn) -> Optional[bool]:
    """False if mongod.conf enables authorization, True if it is present and disabled."""
    out = _stdout(run, "cat /etc/mongod.conf /etc/mongodb.conf 2>/dev/null")
    if not out.strip():
        return None
    if re.search(r"authorization\s*:\s*enabled", out, re.I):
        return False
    if re.search(r"security\s*:", out, re.I) or "net:" in out:
        return True
    return None


def _postgres_trust(run: RunFn) -> List[str]:
    """Return non-local pg_hba.conf entries using 'trust' (password-less) auth."""
    out = _stdout(
        run,
        "cat /etc/postgresql/*/main/pg_hba.conf "
        "/var/lib/pgsql/data/pg_hba.conf "
        "/var/lib/postgresql/data/pg_hba.conf 2>/dev/null",
    )
    bad = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        conn_type, _db, _user, addr, method = parts[0], parts[1], parts[2], parts[3], parts[4]
        if conn_type not in ("host", "hostssl", "hostnossl"):
            continue
        if method.lower() != "trust":
            continue
        if addr in ("127.0.0.1/32", "::1/128", "localhost"):
            continue
        bad.append(line)
    return bad


def check_unauth_data_services(run: RunFn) -> List[Dict[str, object]]:
    """Flag data stores reachable off loopback AND accepting no-auth access; unknown or secured produces nothing."""
    rows = parse_listeners(_listener_text(run))
    findings: List[Dict[str, object]] = []
    flagged_ports = set()
    for row in rows:
        port = int(row["port"])
        if port not in _DATA_SERVICES or not row["exposed"]:
            continue
        if port in flagged_ports:
            continue
        svc = _DATA_SERVICES[port]
        host = str(row["host"])
        noauth: Optional[bool] = None
        evidence = ""
        if port == 6379:
            noauth = _redis_noauth(run, port)
            evidence = "Redis answered PING with no AUTH"
        elif port == 11211:
            noauth = _memcached_noauth(run, port)
            evidence = "Memcached answered a command with no authentication"
        elif port == 9200:
            noauth = _http_json_noauth(run, port, "/_cluster/health")
            evidence = "Elasticsearch returned cluster data with no credentials"
        elif port == 5984:
            noauth = _http_json_noauth(run, port, "/_all_dbs")
            evidence = "CouchDB returned databases with no credentials (admin party)"
        elif port == 27017:
            noauth = _mongo_noauth(run)
            evidence = "mongod configuration does not enable authorization"
        elif port == 5432:
            trust = _postgres_trust(run)
            if trust:
                noauth = True
                evidence = "pg_hba.conf grants non-local 'trust' (password-less) access"
        if noauth is not True:
            continue
        flagged_ports.add(port)
        bind = "all interfaces" if host in _ALL_INTERFACES else host
        desc = (
            f"{svc.name} is listening on {bind} (port {port}), reachable beyond "
            f"loopback, and accepts access without authentication ({evidence}). "
            "Anyone who can route a packet to this port -- another host on the "
            "network, or an attacker pivoting through any service on this box -- "
            "reads and modifies the entire dataset with no credentials. "
            "Internet-exposed instances of these stores are found and ransomed "
            "by automated scanners within hours."
        )
        rem = (
            f"1. Bind {svc.name} to 127.0.0.1 (or a private, firewalled "
            "interface) instead of a public one.\n"
            "2. Enable authentication and create least-privilege accounts "
            f"(for {svc.name}: a password / auth backend, per-app users).\n"
            "3. Put the port behind a host firewall that permits only the "
            "application hosts.\n"
            "4. Assume the current data is already compromised if this was "
            "reachable from an untrusted network, and rotate anything sensitive."
        )
        findings.append(_f(
            "narvy.host.unauth_data_service",
            f"{svc.name} reachable off loopback with no authentication",
            "critical", "Unauthenticated Service", desc, rem,
            cwe="CWE-306", location=f"{host}:{port}",
            discriminator=f"narvy.host.unauth_data_service:{port}",
        ))
    return findings


def _http_code(run: RunFn, cmd_url: str, headers: str = "") -> Optional[int]:
    code = _stdout(
        run,
        f"curl -s -m 2 -o /dev/null -w '%{{http_code}}' {headers} {cmd_url} 2>/dev/null",
    ).strip()
    if code.isdigit():
        return int(code)
    return None


def check_imds_exposure(run: RunFn) -> List[Dict[str, object]]:
    """Flag a reachable cloud metadata endpoint (AWS IMDSv1 / GCP) serving data without a token; IMDSv2 stays quiet."""
    findings: List[Dict[str, object]] = []
    aws_base = "http://169.254.169.254/latest/meta-data/"
    # Token-less GET: 200 => IMDSv1 open; 401 => IMDSv2 enforced; else absent.
    v1 = _http_code(run, aws_base)
    if v1 == 200:
        role = _stdout(
            run,
            "curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/"
            "security-credentials/ 2>/dev/null",
        ).strip().splitlines()
        role_name = (role[0].strip() if role else "")
        role_line = (
            f" The instance exposes IAM role '{role_name}', so its temporary AWS "
            "credentials are readable token-lessly."
            if role_name and "<" not in role_name and role_name.isprintable()
            and len(role_name) < 128 else ""
        )
        desc = (
            "The AWS instance metadata service answered a request with NO session "
            "token (IMDSv1 is enabled). Any code running on this instance, and "
            "crucially any server-side request forgery in an application hosted "
            "here, can read instance metadata and the attached IAM role's "
            "temporary credentials directly from " + aws_base + "." + role_line
        )
        rem = (
            "Require IMDSv2 (token-bound) and disable IMDSv1. On the instance "
            "metadata options set HttpTokens=required (e.g. "
            "`aws ec2 modify-instance-metadata-options --instance-id <id> "
            "--http-tokens required --http-endpoint enabled`), and lower the "
            "hop limit to 1 so containers cannot reach it. Scope the instance "
            "role to least privilege, and add an egress/host rule blocking "
            "169.254.169.254 for application users that never need it."
        )
        findings.append(_f(
            "narvy.host.imds_exposure",
            "Cloud metadata service (IMDSv1) is reachable without a token",
            "high", "Cloud Metadata Exposure", desc, rem,
            cwe="CWE-441", location="169.254.169.254",
            discriminator="narvy.host.imds_exposure:aws-imdsv1",
        ))
        return findings

    gcp = _http_code(
        run,
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        headers="-H 'Metadata-Flavor: Google'",
    )
    if gcp == 200:
        desc = (
            "The GCP instance metadata server responded. Metadata (and, via "
            "`/service-accounts/`, OAuth tokens for the attached service "
            "account) is reachable from any process on this instance, including "
            "through an application-layer SSRF."
        )
        rem = (
            "GCP requires the `Metadata-Flavor: Google` header, which blocks the "
            "simplest SSRF, but you should still: scope the instance service "
            "account to least privilege, prefer workload identity over instance "
            "credentials, and restrict egress to the metadata IP for app users. "
            "Confirm no application proxies arbitrary user-supplied URLs."
        )
        findings.append(_f(
            "narvy.host.imds_exposure",
            "GCP metadata server reachable from the instance",
            "low", "Cloud Metadata Exposure", desc, rem,
            cwe="CWE-441", location="metadata.google.internal",
            discriminator="narvy.host.imds_exposure:gcp",
            confidence="MEDIUM",
        ))
    return findings


def check_container_posture(run: RunFn) -> List[Dict[str, object]]:
    """Flag Docker exposure: world-accessible socket, TCP daemon off loopback, privileged/host-net containers."""
    findings: List[Dict[str, object]] = []

    # Socket permissions.
    sock = _stdout(
        run,
        "stat -c '%a %U %G' /var/run/docker.sock /run/docker.sock 2>/dev/null",
    ).strip().splitlines()
    for line in sock:
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        mode = parts[0]
        other = int(mode[-1])
        if other & 0o6:
            desc = (
                "The Docker daemon socket /var/run/docker.sock is accessible to "
                f"every local user (permission mode {mode}). The Docker API is "
                "root-equivalent by design: anyone who can talk to this socket "
                "can start a container that mounts the host filesystem and "
                "obtain root on the host. World access to the socket is a direct "
                "local privilege-escalation path."
            )
            rem = (
                "Restore restrictive ownership and permissions: "
                "`chown root:docker /var/run/docker.sock && chmod 660 "
                "/var/run/docker.sock`. Grant Docker access only by adding "
                "trusted operators to the `docker` group (itself root-equivalent, "
                "so keep it small), and never widen the socket to `other`."
            )
            findings.append(_f(
                "narvy.host.container_posture",
                "Docker socket is world-accessible", "high",
                "Container Posture", desc, rem, cwe="CWE-732",
                location="/var/run/docker.sock",
                discriminator="narvy.host.container_posture:socket",
            ))
            break

    # dockerd on TCP off loopback.
    rows = parse_listeners(_listener_text(run))
    for row in rows:
        port = int(row["port"])
        if port not in (2375, 2376) or not row["exposed"]:
            continue
        plaintext = port == 2375
        sev = "critical" if plaintext else "high"
        desc = (
            f"The Docker daemon is listening on TCP port {port} on a "
            "non-loopback interface. The Docker API is root-equivalent; port "
            "2375 is unencrypted and unauthenticated, so a remote attacker who "
            "reaches it gets root on this host with no credentials"
            + (" -- this is the plaintext, unauthenticated Docker port."
               if plaintext else
               " (2376 is TLS but still must be mutually authenticated).")
        )
        rem = (
            "Do not expose the Docker daemon over TCP. Remove the `-H tcp://` "
            "flag / `hosts` entry so dockerd listens only on the local unix "
            "socket. If remote access is genuinely required, use 2376 with "
            "verified mutual TLS (`--tlsverify`), never 2375, and firewall it to "
            "known clients."
        )
        findings.append(_f(
            "narvy.host.container_posture",
            f"Docker daemon exposed over TCP ({port})", sev,
            "Container Posture", desc, rem, cwe="CWE-306",
            location=f"{row['host']}:{port}",
            discriminator=f"narvy.host.container_posture:tcp{port}",
        ))

    # Privileged / host-network containers.
    ids = _stdout(run, "docker ps -q 2>/dev/null").strip().split()
    if ids:
        insp = _stdout(
            run,
            "docker inspect --format "
            "'{{.Name}} priv={{.HostConfig.Privileged}} "
            "net={{.HostConfig.NetworkMode}}' " + " ".join(ids[:50]) +
            " 2>/dev/null",
        )
        privileged = []
        hostnet = []
        for line in insp.splitlines():
            line = line.strip()
            if "priv=true" in line:
                privileged.append(line.split()[0].lstrip("/"))
            if "net=host" in line:
                hostnet.append(line.split()[0].lstrip("/"))
        if privileged:
            names = ", ".join(sorted(set(privileged))[:10])
            desc = (
                f"Running container(s) started with --privileged: {names}. A "
                "privileged container disables the normal container isolation "
                "(all capabilities, access to host devices), so a compromise of "
                "the process inside is effectively a compromise of the host."
            )
            rem = (
                "Remove `--privileged`. Grant only the specific Linux "
                "capabilities the workload needs (`--cap-add`), mount only the "
                "specific devices required, and run as a non-root user inside "
                "the container. Re-create the affected containers without the "
                "privileged flag."
            )
            findings.append(_f(
                "narvy.host.container_posture",
                "Privileged container(s) running", "high",
                "Container Posture", desc, rem, cwe="CWE-250",
                location=names,
                discriminator="narvy.host.container_posture:privileged",
            ))
        if hostnet:
            names = ", ".join(sorted(set(hostnet))[:10])
            desc = (
                f"Container(s) running with host networking (--net=host): "
                f"{names}. The container shares the host network namespace, so "
                "it can bind host ports, sniff host traffic, and reach services "
                "the host reaches on loopback, erasing network isolation."
            )
            rem = (
                "Use a bridged or user-defined network and publish only the "
                "ports the service needs (`-p`). Reserve `--net=host` for "
                "workloads that genuinely require it and treat those containers "
                "as part of the host's trust boundary."
            )
            findings.append(_f(
                "narvy.host.container_posture",
                "Container(s) using host network namespace", "medium",
                "Container Posture", desc, rem, cwe="CWE-668",
                location=names,
                discriminator="narvy.host.container_posture:hostnet",
            ))
    return findings


_WEB_ROOT_CANDIDATES = (
    "/var/www", "/var/www/html", "/srv/www", "/srv/http",
    "/usr/share/nginx/html", "/usr/local/apache2/htdocs", "/var/www/public",
)


def _discover_web_roots(run: RunFn) -> List[str]:
    roots = set()
    # nginx `root` directives.
    ng = _stdout(
        run,
        "grep -rhoE '^[[:space:]]*root[[:space:]]+[^;]+;' /etc/nginx 2>/dev/null",
    )
    for line in ng.splitlines():
        m = re.search(r"root\s+([^;]+);", line)
        if m:
            roots.add(m.group(1).strip().strip('"').strip("'"))
    # apache DocumentRoot.
    ap = _stdout(
        run,
        "grep -rhoiE 'DocumentRoot[[:space:]]+\"?[^\"]+\"?' "
        "/etc/apache2 /etc/httpd 2>/dev/null",
    )
    for line in ap.splitlines():
        m = re.search(r'DocumentRoot\s+"?([^"\s]+)"?', line, re.I)
        if m:
            roots.add(m.group(1).strip())
    for c in _WEB_ROOT_CANDIDATES:
        roots.add(c)
    return [r for r in roots if r.startswith("/") and len(r) > 1]


def check_exposed_vcs_web_root(run: RunFn) -> List[Dict[str, object]]:
    """Flag a ``.git/`` repo (needs ``.git/HEAD``), ``.env``, swap files, ``*.bak`` or SQL dumps under a detected web root."""
    findings: List[Dict[str, object]] = []
    roots = _discover_web_roots(run)
    if not roots:
        return findings
    existing = _stdout(
        run,
        "sh -c 'for d in " + " ".join(_shq(r) for r in roots) +
        "; do [ -d \"$d\" ] && echo \"$d\"; done'",
    ).split()
    seen_git = set()
    seen_file = set()
    for root in existing:
        head = _stdout(
            run, f"sh -c '[ -f {_shq(root)}/.git/HEAD ] && echo YES'",
        ).strip()
        if head == "YES" and root not in seen_git:
            seen_git.add(root)
            desc = (
                f"A Git repository is present in the web root {root} "
                "(.git/HEAD exists). If the web server serves this directory, "
                "the entire source history -- including deleted secrets, "
                "configuration and internal endpoints -- is downloadable over "
                "HTTP by walking /.git/, even when directory listing is off."
            )
            rem = (
                f"Remove the repository from the served tree (deploy build "
                f"artifacts, not the working copy) or move {root}/.git outside "
                "the web root. If it must stay, block it at the web server "
                "(`location ~ /\\.git { deny all; }` / Apache `Require all "
                "denied`), and rotate any secret that was ever committed."
            )
            findings.append(_f(
                "narvy.host.exposed_vcs_web_root",
                "Git repository exposed under a web root", "high",
                "Source Disclosure", desc, rem, cwe="CWE-527",
                location=f"{root}/.git",
                discriminator=f"narvy.host.exposed_vcs_web_root:git:{root}",
            ))
        arts = _stdout(
            run,
            "find " + _shq(root) + " -maxdepth 2 -type f \\( "
            "-name '.env' -o -name '.env.*' -o -name '*.bak' -o -name '*.old' "
            "-o -name '*.sql' -o -name '*.sql.gz' -o -name '*~' "
            "-o -name '.*.swp' -o -name '*.orig' \\) 2>/dev/null",
        )
        for path in arts.splitlines():
            path = path.strip()
            if not path or path in seen_file:
                continue
            if _SECRET_NAME_ALLOW.search(path):
                continue
            seen_file.add(path)
            desc = (
                f"A sensitive or backup file is present under the web root: "
                f"{path}. Environment files, editor swap files (.swp), and "
                "`.bak`/`.old`/`.sql` copies are frequently left in the served "
                "tree and are downloadable directly by URL, disclosing "
                "credentials or source that the running application hides."
            )
            rem = (
                f"Delete {path} from the web root (keep backups and .env files "
                "outside any served directory). Add a web-server rule denying "
                "dotfiles and backup extensions, and rotate any credential that "
                "the file may have exposed."
            )
            findings.append(_f(
                "narvy.host.exposed_vcs_web_root",
                "Secret or backup file exposed under a web root", "high",
                "Source Disclosure", desc, rem, cwe="CWE-538",
                location=path,
                discriminator=f"narvy.host.exposed_vcs_web_root:file:{path}",
            ))
    return findings


def _shq(s: str) -> str:
    """Minimal single-quote shell-quoting for a discovered path."""
    return "'" + str(s).replace("'", "'\\''") + "'"


ALL_CHECKS = (
    check_secrets_on_disk,
    check_unauth_data_services,
    check_imds_exposure,
    check_container_posture,
    check_exposed_vcs_web_root,
)

NARVY_HOST_CHECK_COUNT = len(ALL_CHECKS)


def run_checks(run: RunFn) -> List[Dict[str, object]]:
    """Run every host check; one failing check never sinks the others."""
    findings: List[Dict[str, object]] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check(run) or [])
        except Exception:  # noqa: BLE001
            logger.warning("narvy host check %s failed", getattr(check, "__name__", "?"),
                           exc_info=True)
    return findings


def build_ssh_runner(conn, prefix: str) -> RunFn:
    """Build a probe runner executing commands on `conn` over SSH with `prefix` (e.g. ``sudo -n ``)."""
    from .ssh_exec import ssh_exec, SSHExecError

    def run(cmd: str) -> Optional[Probe]:
        try:
            r = ssh_exec(conn, f"{prefix}{cmd}" if prefix else cmd, timeout=45)
        except SSHExecError:
            return None
        return Probe(r.returncode, r.stdout or "")

    return run


def run_narvy_host_checks(conn, prefix: str) -> List[Dict[str, object]]:
    """Run the host checks against a live host."""
    return run_checks(build_ssh_runner(conn, prefix))
