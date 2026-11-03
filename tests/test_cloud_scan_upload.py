"""narvy cloud-scan: AWS (moto) and GCP (stubbed REST) posture checks, and the
--upload body: findings and metadata only, never a credential."""

import json
import sys

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from narvy import main as cli_main  # noqa: E402
from narvy.cloud import upload as cloud_upload  # noqa: E402
from narvy.cloud.normalize import normalize_report  # noqa: E402

# Canary credentials: an AKIA-shaped id and a distinctive secret. moto accepts
# any value; the tests assert neither ever reaches an upload body.
CANARY_KEY_ID = "AKIAZZCANARY0000TEST"
CANARY_SECRET = "canary-secret-must-never-leave-this-machine-0123456789"
CANARY_TOKEN = "canary-session-token-must-never-leave-0123456789"


@pytest.fixture
def aws_env(monkeypatch, tmp_path):
    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", CANARY_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", CANARY_SECRET)
    monkeypatch.setenv("AWS_SESSION_TOKEN", CANARY_TOKEN)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _seed_misconfigured_account():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="narvy-test-bucket")
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Passw0rd!Passw0rd!")
    return sg


@mock_aws
def test_aws_scan_runs_locally_and_finds_open_ssh(aws_env):
    from narvy.cloud.aws_scan import analyze_aws_security
    sg = _seed_misconfigured_account()
    report = analyze_aws_security(region="us-east-1")
    assert report["account_id"] == "123456789012"
    assert report["coverage"]["status"] in ("complete", "partial")
    findings = normalize_report("aws", report, report["account_id"])
    titles = " | ".join(f["title"] for f in findings)
    assert any(sg in f["discriminator"] and "22" in f["title"] for f in findings), titles
    assert all(f["severity"] in ("Critical", "High", "Medium", "Low", "Info", "Undetermined")
               for f in findings)
    assert all(f["engine"] == "Narvy Cloud Audit" for f in findings)


def test_aws_scan_refuses_explicit_keys():
    from narvy.cloud.aws_scan import analyze_aws_security
    with pytest.raises(ValueError):
        analyze_aws_security({"aws_access_key_id": "x", "aws_secret_access_key": "y"})


@mock_aws
def test_upload_payload_carries_no_credential(aws_env, monkeypatch, tmp_path):
    """End to end through the CLI entry point: the body POSTed to /api/v1/ingest
    holds findings and metadata, and no credential material at all."""
    _seed_misconfigured_account()
    captured = {}

    def fake_ingest(token, body):
        captured["token"] = token
        captured["body"] = body
        return 201, {"scan_id": "abc", "dropped": 0}

    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "narvy-api-token"})
    monkeypatch.setattr(cli_main.uploader, "ingest_body", fake_ingest)
    monkeypatch.setattr(sys, "argv", ["narvy", "cloud-scan", "--region", "us-east-1",
                                      "--upload", "-o", "json", "-f", str(tmp_path / "out.json")])
    try:
        cli_main.cli()
    except SystemExit as e:
        assert e.code in (0, None)

    body = captured["body"]
    text = json.dumps(body)
    for secret in (CANARY_KEY_ID, CANARY_SECRET, CANARY_TOKEN, "AKIA",
                   "aws_secret_access_key", "SecretAccessKey", "aws_session_token",
                   "credentials", "narvy-api-token"):
        assert secret not in text, secret
    assert body["platform"] == "cloud" and body["scan_mode"] == "cloud"
    assert body["cloud"]["provider"] == "aws"
    assert body["cloud"]["account_id"] == "123456789012"
    assert set(body["cloud"]["coverage"]) == {"status", "checks_skipped"}
    assert body["findings"], "the misconfigured account must yield findings"
    for f in body["findings"]:
        assert set(f) == set(cloud_upload.FINDING_FIELDS)
    assert set(body) == {"app_name", "platform", "scan_mode", "version", "findings",
                         "scan_seconds", "cloud"}


def test_build_body_refuses_a_credential_value(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", CANARY_SECRET)
    leaky = {"title": "x", "description": f"oops {CANARY_SECRET}"}
    with pytest.raises(cloud_upload.CredentialInPayload):
        cloud_upload.build_body("aws", "123456789012", [leaky])


@pytest.mark.parametrize("leak", ["AKIAIOSFODNN7EXAMPLE",
                                  "-----BEGIN PRIVATE KEY-----\nMIIE",
                                  "ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxx"])
def test_build_body_refuses_key_shapes(leak, monkeypatch):
    for k in cloud_upload.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(cloud_upload.CredentialInPayload):
        cloud_upload.build_body("aws", "1", [{"title": "t", "remediation": leak}])


def test_build_body_drops_raw_fields(monkeypatch):
    for k in cloud_upload.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    body = cloud_upload.build_body("aws", "1", [{"title": "t", "raw": {"Policy": "x"}}],
                                   coverage={"status": "partial", "checks_skipped": 2,
                                             "errors": ["arn:aws:iam::1:user/x denied"]})
    assert "raw" not in body["findings"][0]
    assert body["cloud"]["coverage"] == {"status": "partial", "checks_skipped": 2}
    assert "arn:aws" not in json.dumps(body)


# ------------------------------------------------------------------ GCP

class _FakeCreds:
    token = "ya29.fake-token-never-uploaded-xxxxxxxxxxxx"

    def refresh(self, _req):
        pass


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


def _gcp_stub(monkeypatch, responder):
    pytest.importorskip("google.auth")
    from narvy.cloud import gcp_scan
    monkeypatch.setattr(gcp_scan.google.auth, "default",
                        lambda scopes=None: (_FakeCreds(), "demo-proj"))
    monkeypatch.setattr(gcp_scan.requests, "get", lambda url, headers=None, timeout=None: responder(url))
    return gcp_scan


def test_gcp_scan_uses_adc_and_keeps_one_finding_per_bucket(monkeypatch):
    def responder(url):
        if "storage.googleapis.com" in url:
            return _Resp(200, {"items": [{"name": "pub-a"}, {"name": "pub-b"}]})
        return _Resp(200, {})
    gcp_scan = _gcp_stub(monkeypatch, responder)
    report = gcp_scan.analyze_gcp_security()
    assert report["project_id"] == "demo-proj"
    findings = normalize_report("gcp", report, "demo-proj")
    buckets = [f for f in findings if f["category"] == "Storage"]
    assert len(buckets) == 2
    assert len({f["discriminator"] for f in buckets}) == 2
    assert {f["file"] for f in buckets} == {"pub-a", "pub-b"}


def test_gcp_denied_apis_are_partial_coverage_not_clean(monkeypatch):
    gcp_scan = _gcp_stub(monkeypatch, lambda url: _Resp(403))
    report = gcp_scan.analyze_gcp_security(project_id="demo-proj")
    cov = cli_main._cloud_coverage("gcp", report)
    assert cov["status"] == "partial" and cov["checks_skipped"] > 0
