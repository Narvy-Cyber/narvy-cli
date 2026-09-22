"""Unit coverage for the Narvy-authored host checks (narvy/host/narvy_checks.py)
and the honest-Lynis-attribution changes in narvy/host/lynis_parser.py.

Each check is exercised against a fake probe runner (a mocked filesystem /
netstat / metadata endpoint) so real detection logic is validated with no SSH.
Both a positive (exposed) and a negative (hardened / FP-guard) case are covered.

Exits non-zero on any assertion failure.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.host.narvy_checks import (
    Probe, parse_listeners,
    check_secrets_on_disk, check_unauth_data_services, check_imds_exposure,
    check_container_posture, check_exposed_vcs_web_root, run_checks,
    NARVY_HOST_CHECK_COUNT,
)
from narvy.host import lynis_parser


def _check(label, condition):
    if not condition:
        print(f"  FAIL: {label}")
        return False
    print(f"  ok: {label}")
    return True


class FakeRun:
    """Route a shell command to a canned Probe by substring rules.

    rules: list of (substring, stdout, rc). First match wins. Unmatched
    commands return Probe(rc=1, out="") -- i.e. "no evidence".
    """

    def __init__(self, rules):
        self.rules = rules
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        for sub, out, rc in self.rules:
            if sub in cmd:
                return Probe(rc, out)
        return Probe(1, "")


# --------------------------------------------------------------------------- #
# parse_listeners
# --------------------------------------------------------------------------- #

def test_parse_listeners_ss_and_netstat():
    ok = True
    ss = ('LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1,fd=6))\n'
          'LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))\n'
          'LISTEN 0 128 [::]:9200 [::]:* users:(("java",pid=3,fd=9))\n')
    rows = parse_listeners(ss)
    by_port = {r["port"]: r for r in rows}
    ok &= _check("ss: redis 0.0.0.0 exposed", by_port[6379]["exposed"] is True)
    ok &= _check("ss: postgres loopback not exposed", by_port[5432]["exposed"] is False)
    ok &= _check("ss: es [::] exposed", by_port[9200]["exposed"] is True)
    ok &= _check("ss: process name parsed", by_port[6379]["process"] == "redis-server")

    net = ('Active Internet connections\n'
           'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program\n'
           'tcp 0 0 0.0.0.0:2375 0.0.0.0:* LISTEN 10/dockerd\n'
           'tcp 0 0 127.0.0.1:6379 0.0.0.0:* LISTEN 11/redis-server\n')
    rows = parse_listeners(net)
    by_port = {r["port"]: r for r in rows}
    ok &= _check("netstat: dockerd 2375 exposed", by_port[2375]["exposed"] is True)
    ok &= _check("netstat: redis loopback not exposed", by_port[6379]["exposed"] is False)
    return ok


# --------------------------------------------------------------------------- #
# Check 1: secrets on disk
# --------------------------------------------------------------------------- #

def test_secrets_on_disk_positive_and_fp_guard():
    ok = True
    run = FakeRun([
        ("-perm /004",
         "KEY /home/deploy/.ssh/id_rsa\n"
         "CFG /var/www/app/.env\n"
         "CFG /home/u/project/.env.example\n"     # template -> must be filtered
         "CFG /home/u/db_backup.sql\n", 0),
    ])
    f = check_secrets_on_disk(run)
    locs = {x["location"] for x in f}
    ok &= _check("flags world-readable private key", "/home/deploy/.ssh/id_rsa" in locs)
    ok &= _check("flags world-readable .env", "/var/www/app/.env" in locs)
    ok &= _check("flags world-readable sql dump", "/home/u/db_backup.sql" in locs)
    ok &= _check("FP guard: .env.example excluded", "/home/u/project/.env.example" not in locs)
    ok &= _check("private key finding is high", any(
        x["location"] == "/home/deploy/.ssh/id_rsa" and x["severity"] == "high" for x in f))
    ok &= _check("engine is Narvy", all(x["engine"] == "Narvy" for x in f))
    ok &= _check("control id is narvy.host.secrets_on_disk",
                 all(x["control_id"] == "narvy.host.secrets_on_disk" for x in f))

    # Hardened host: find returns nothing (all files 0600) -> zero findings.
    run2 = FakeRun([("-perm /004", "", 0)])
    ok &= _check("FP guard: no world-readable secrets -> no findings",
                 check_secrets_on_disk(run2) == [])
    return ok


# --------------------------------------------------------------------------- #
# Check 2: unauthenticated data services
# --------------------------------------------------------------------------- #

def test_unauth_data_services_positive():
    ok = True
    ss = ('LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*\n'
          'LISTEN 0 128 0.0.0.0:9200 0.0.0.0:*\n'
          'LISTEN 0 128 0.0.0.0:27017 0.0.0.0:*\n')
    run = FakeRun([
        ("ss -H -tlnp", ss, 0),
        ("/dev/tcp/127.0.0.1/6379", "+PONG\r\n", 0),           # redis no-auth
        ("127.0.0.1:9200/_cluster/health", "200", 0),          # es open
        ("cat /etc/mongod.conf", "net:\n  port: 27017\n", 0),  # mongo no authz
    ])
    f = check_unauth_data_services(run)
    ports = {x["location"].rsplit(":", 1)[-1] for x in f}
    ok &= _check("redis flagged", "6379" in ports)
    ok &= _check("elasticsearch flagged", "9200" in ports)
    ok &= _check("mongodb flagged (config no-auth)", "27017" in ports)
    ok &= _check("severity critical", all(x["severity"] == "critical" for x in f))
    ok &= _check("cwe-306", all(x["cwe"] == "CWE-306" for x in f))
    return ok


def test_unauth_data_services_fp_guards():
    ok = True
    # (a) loopback-only bind -> never probed, never flagged.
    run_lb = FakeRun([
        ("ss -H -tlnp", "LISTEN 0 511 127.0.0.1:6379 0.0.0.0:*\n", 0),
        ("/dev/tcp/127.0.0.1/6379", "+PONG\r\n", 0),
    ])
    ok &= _check("FP guard: loopback redis not flagged",
                 check_unauth_data_services(run_lb) == [])

    # (b) exposed but password-protected -> NOAUTH reply -> not flagged.
    run_auth = FakeRun([
        ("ss -H -tlnp", "LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*\n", 0),
        ("/dev/tcp/127.0.0.1/6379", "-NOAUTH Authentication required.\r\n", 0),
    ])
    ok &= _check("FP guard: authenticated redis not flagged",
                 check_unauth_data_services(run_auth) == [])

    # (c) exposed, secured ES (401) -> not flagged.
    run_es = FakeRun([
        ("ss -H -tlnp", "LISTEN 0 128 0.0.0.0:9200 0.0.0.0:*\n", 0),
        ("127.0.0.1:9200/_cluster/health", "401", 0),
    ])
    ok &= _check("FP guard: secured ES (401) not flagged",
                 check_unauth_data_services(run_es) == [])

    # (d) mongo config WITH authorization enabled -> not flagged.
    run_mongo = FakeRun([
        ("ss -H -tlnp", "LISTEN 0 128 0.0.0.0:27017 0.0.0.0:*\n", 0),
        ("cat /etc/mongod.conf",
         "security:\n  authorization: enabled\nnet:\n  port: 27017\n", 0),
    ])
    ok &= _check("FP guard: mongo authorization enabled not flagged",
                 check_unauth_data_services(run_mongo) == [])
    return ok


def test_postgres_trust_guard():
    ok = True
    ss = "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n"
    # non-local trust rule -> flagged.
    hba_bad = "host all all 0.0.0.0/0 trust\nlocal all all peer\n"
    run = FakeRun([("ss -H -tlnp", ss, 0), ("pg_hba.conf", hba_bad, 0)])
    ok &= _check("postgres non-local trust flagged",
                 len(check_unauth_data_services(run)) == 1)
    # only loopback trust -> not flagged.
    hba_ok = "host all all 127.0.0.1/32 trust\nhost all all 0.0.0.0/0 scram-sha-256\n"
    run2 = FakeRun([("ss -H -tlnp", ss, 0), ("pg_hba.conf", hba_ok, 0)])
    ok &= _check("FP guard: loopback-only trust not flagged",
                 check_unauth_data_services(run2) == [])
    return ok


# --------------------------------------------------------------------------- #
# Check 3: IMDS exposure
# --------------------------------------------------------------------------- #

def test_imds_exposure_positive_and_guard():
    ok = True
    run = FakeRun([
        ("iam/security-credentials", "narvy-app-role\n", 0),
        ("169.254.169.254/latest/meta-data/", "200", 0),
    ])
    f = check_imds_exposure(run)
    ok &= _check("IMDSv1 open -> one finding", len(f) == 1)
    ok &= _check("IMDSv1 finding high", f and f[0]["severity"] == "high")
    ok &= _check("role name surfaced in description",
                 f and "narvy-app-role" in f[0]["description"])

    # IMDSv2 enforced: token-less GET returns 401, GCP absent -> no finding.
    run2 = FakeRun([
        ("169.254.169.254/latest/meta-data/", "401", 0),
        ("metadata.google.internal", "000", 0),
    ])
    ok &= _check("FP guard: IMDSv2 enforced (401) -> no finding",
                 check_imds_exposure(run2) == [])

    # Non-cloud host: endpoint unroutable, curl yields no code -> no finding.
    run3 = FakeRun([])
    ok &= _check("FP guard: non-cloud host -> no finding",
                 check_imds_exposure(run3) == [])
    return ok


# --------------------------------------------------------------------------- #
# Check 4: container posture
# --------------------------------------------------------------------------- #

def test_container_posture_positive():
    ok = True
    run = FakeRun([
        ("stat -c", "666 root root\n", 0),                       # world socket
        ("ss -H -tlnp", "LISTEN 0 128 0.0.0.0:2375 0.0.0.0:*\n", 0),  # tcp dockerd
        ("docker ps -q", "abc123\ndef456\n", 0),
        ("docker inspect", "/web priv=true net=host\n/db priv=false net=bridge\n", 0),
    ])
    f = check_container_posture(run)
    discs = {x["discriminator"] for x in f}
    ok &= _check("world socket flagged",
                 "narvy.host.container_posture:socket" in discs)
    ok &= _check("tcp 2375 flagged",
                 "narvy.host.container_posture:tcp2375" in discs)
    ok &= _check("2375 is critical", any(
        x["discriminator"] == "narvy.host.container_posture:tcp2375"
        and x["severity"] == "critical" for x in f))
    ok &= _check("privileged container flagged",
                 "narvy.host.container_posture:privileged" in discs)
    ok &= _check("host-net container flagged",
                 "narvy.host.container_posture:hostnet" in discs)
    return ok


def test_container_posture_fp_guards():
    ok = True
    # Normal socket 660 root:docker, no tcp daemon, no containers -> nothing.
    run = FakeRun([
        ("stat -c", "660 root docker\n", 0),
        ("ss -H -tlnp", "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n", 0),
        ("docker ps -q", "", 0),
    ])
    ok &= _check("FP guard: socket 660 + no tcp + no containers -> nothing",
                 check_container_posture(run) == [])
    return ok


# --------------------------------------------------------------------------- #
# Check 5: exposed VCS / artifacts in web root
# --------------------------------------------------------------------------- #

def test_exposed_vcs_web_root_positive():
    ok = True
    run = FakeRun([
        ("grep -rhoE '^[[:space:]]*root", "root /var/www/html;\n", 0),
        ("for d in", "/var/www/html\n", 0),
        (".git/HEAD ]", "YES", 0),
        ("-maxdepth 2 -type f",
         "/var/www/html/.env\n/var/www/html/config.php.bak\n"
         "/var/www/html/.env.sample\n", 0),
    ])
    f = check_exposed_vcs_web_root(run)
    locs = {x["location"] for x in f}
    ok &= _check("git repo flagged", "/var/www/html/.git" in locs)
    ok &= _check(".env in web root flagged", "/var/www/html/.env" in locs)
    ok &= _check(".bak in web root flagged", "/var/www/html/config.php.bak" in locs)
    ok &= _check("FP guard: .env.sample excluded",
                 "/var/www/html/.env.sample" not in locs)
    return ok


def test_exposed_vcs_web_root_fp_guards():
    ok = True
    # Web root exists but no git repo and no artifacts -> nothing.
    run = FakeRun([
        ("grep -rhoE '^[[:space:]]*root", "root /var/www/html;\n", 0),
        ("for d in", "/var/www/html\n", 0),
        (".git/HEAD ]", "", 0),          # not a repo
        ("-maxdepth 2 -type f", "", 0),  # no artifacts
    ])
    ok &= _check("FP guard: clean web root -> nothing",
                 check_exposed_vcs_web_root(run) == [])
    return ok


# --------------------------------------------------------------------------- #
# run_checks resilience + count honesty
# --------------------------------------------------------------------------- #

def test_run_checks_isolates_failures():
    ok = True

    class Boom:
        def __call__(self, cmd):
            raise RuntimeError("transport exploded")

    # A runner that raises inside every probe must not raise out of run_checks.
    try:
        out = run_checks(Boom())
        ok &= _check("run_checks swallows per-check failures", out == [])
    except Exception as e:  # noqa: BLE001
        ok &= _check(f"run_checks must not raise (got {e!r})", False)
    ok &= _check("exactly 5 Narvy host checks", NARVY_HOST_CHECK_COUNT == 5)
    return ok


# --------------------------------------------------------------------------- #
# Lynis honest-attribution changes
# --------------------------------------------------------------------------- #

def test_lynis_attribution_is_honest():
    ok = True
    ok &= _check("engine name names Lynis",
                 "Lynis" in lynis_parser.ENGINE_NAME
                 and "GPL-3.0" in lynis_parser.ENGINE_NAME)
    ok &= _check("lynis ref points at cisofy control page",
                 lynis_parser._lynis_ref("SSH-7408")
                 == "https://cisofy.com/lynis/controls/SSH-7408/")
    ok &= _check("solution url is preserved not stripped",
                 lynis_parser._parse_solution("url:https://example/ctl")
                 == ("", "https://example/ctl"))
    ok &= _check("solution text advice preserved",
                 lynis_parser._parse_solution("text:Do the thing")
                 == ("Do the thing", ""))

    dat = (
        "hardening_index=61\n"
        "lynis_version=3.1.7\n"
        "warning[]=SSH-7408|Insecure SSH configuration|-|text:Harden sshd|\n"
        "suggestion[]=CISOFY-1234|Some vendor suggestion|-|url:https://cisofy.com/x|\n"
    )
    parsed = lynis_parser.parse_lynis_report(dat)
    findings = parsed["findings"]
    ok &= _check("parsed some findings", len(findings) >= 1)
    ok &= _check("every finding carries a Lynis reference",
                 all(f.get("reference") for f in findings))
    ok &= _check("CISOFY id NOT remapped to MISC group",
                 all("MISC" not in (f.get("control_id") or "") for f in findings))
    return ok


def main():
    tests = [
        test_parse_listeners_ss_and_netstat,
        test_secrets_on_disk_positive_and_fp_guard,
        test_unauth_data_services_positive,
        test_unauth_data_services_fp_guards,
        test_postgres_trust_guard,
        test_imds_exposure_positive_and_guard,
        test_container_posture_positive,
        test_container_posture_fp_guards,
        test_exposed_vcs_web_root_positive,
        test_exposed_vcs_web_root_fp_guards,
        test_run_checks_isolates_failures,
        test_lynis_attribution_is_honest,
    ]
    all_ok = True
    for t in tests:
        print(f"{t.__name__}:")
        all_ok &= t()
    if not all_ok:
        print("\nREGRESSION: Narvy host checks / Lynis attribution broken. "
              "Do not ship until this passes.")
        sys.exit(1)
    print("\nAll clear.")


if __name__ == "__main__":
    main()
