"""The --upload guard checks the credentials the scan really used (AWS profile
chain, Google ADC), Google key shapes and nested values; GCP checks that got
no usable answer (429 / 404 / 5xx / network) are coverage gaps, never clean."""

import json
import sys

import pytest

boto3 = pytest.importorskip("boto3")
pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from narvy import main as cli_main  # noqa: E402
from narvy.cloud import upload as U  # noqa: E402

PROFILE_KEY = "AKIAPROFILECANARY001"
PROFILE_SECRET = "profile-secret-canary/with+slash=0123456789"
PROFILE_TOKEN = "profile-session-token-canary-0123456789"


@pytest.fixture
def profile_only(monkeypatch, tmp_path):
    """Credentials only in a named profile of a shared credentials file: no
    credential env var at all."""
    for k in U.CREDENTIAL_ENV_VARS + ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL"):
        monkeypatch.delenv(k, raising=False)
    creds = tmp_path / "credentials"
    creds.write_text(f"[prod]\naws_access_key_id = {PROFILE_KEY}\n"
                     f"aws_secret_access_key = {PROFILE_SECRET}\n"
                     f"aws_session_token = {PROFILE_TOKEN}\n")
    (tmp_path / "config").write_text("[profile prod]\nregion = us-east-1\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def test_profile_secrets_are_resolved_and_refused(profile_only, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "prod")
    secrets = U.provider_secrets("aws")
    assert PROFILE_SECRET in secrets and PROFILE_TOKEN in secrets
    for leak in (PROFILE_SECRET, PROFILE_TOKEN):
        with pytest.raises(U.CredentialInPayload):
            U.build_body("aws", "1", [{"title": "t", "description": f"x {leak} y"}], secrets=secrets)


@mock_aws
def test_profile_scan_upload_carries_no_credential(profile_only, monkeypatch, tmp_path):
    ec2 = boto3.Session(profile_name="prod").client("ec2", region_name="us-east-1")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    captured = {}
    monkeypatch.setenv("AWS_PROFILE", "prod")  # restored after the test (--profile sets it)
    monkeypatch.setattr(cli_main.auth, "load_credentials", lambda: {"token": "t"})
    monkeypatch.setattr(cli_main.uploader, "ingest_body",
                        lambda token, body: (captured.update(body=body), (201, {"scan_id": "x"}))[1])
    monkeypatch.setattr(sys, "argv", ["narvy", "cloud-scan", "--profile", "prod", "--region", "us-east-1",
                                      "--upload", "-o", "json", "-f", str(tmp_path / "o.json")])
    try:
        cli_main.cli()
    except SystemExit as e:
        assert e.code in (0, None)
    text = json.dumps(captured["body"])
    assert captured["body"]["findings"]
    for s in (PROFILE_KEY, PROFILE_SECRET, PROFILE_TOKEN, "AKIA"):
        assert s not in text


class _AdcCreds:
    token = "ya29.adc-access-token-canary-xxxxxxxxxxxxxxxx"
    refresh_token = "1//adc-refresh-token-canary-xxxxxxxxxxxxxxxx"
    client_secret = "GOCSPX-adcclientsecretcanary"

    def refresh(self, _req):
        pass


def test_adc_token_and_refresh_token_are_refused(monkeypatch):
    pytest.importorskip("google.auth")
    from narvy.cloud import gcp_scan
    monkeypatch.setattr(gcp_scan, "last_credentials", _AdcCreds())
    secrets = U.provider_secrets("gcp")
    assert _AdcCreds.token in secrets and _AdcCreds.refresh_token in secrets
    # Strip the shape patterns' prefixes so the test proves the VALUE check.
    for leak in ("adc-access-token-canary-xxxxxxxxxxxxxxxx", "adc-refresh-token-canary-xxxxxxxxxxxxxxxx"):
        val = [s for s in secrets if leak in s][0]
        with pytest.raises(U.CredentialInPayload):
            U.build_body("gcp", "p", [{"title": "t", "remediation": val}], secrets=secrets)


@pytest.mark.parametrize("leak", [
    "GOCSPX-abcdefghijklmnop", "1//0gABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxx", "ASIAIOSFODNN7EXAMPLE",
])
def test_google_and_aws_shapes_refused(leak, monkeypatch):
    for k in U.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(U.CredentialInPayload):
        U.build_body("gcp", "p", [{"title": "t", "description": leak}])


def test_url_paths_are_not_mistaken_for_refresh_tokens(monkeypatch):
    for k in U.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    U.build_body("gcp", "p", [{"title": "t", "location": "https://storage.googleapis.com/b/x"}])


@pytest.mark.parametrize("desc", [
    {"detail": "AKIAIOSFODNN7EXAMPLE"},
    ["ok", {"nested": "-----BEGIN PRIVATE KEY-----"}],
])
def test_dict_and_list_descriptions_are_checked(desc, monkeypatch):
    for k in U.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(U.CredentialInPayload):
        U.build_body("aws", "1", [{"title": "t", "description": desc}])


def test_dict_description_is_uploaded_as_text(monkeypatch):
    for k in U.CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(k, raising=False)
    body = U.build_body("aws", "1", [{"title": "t", "description": {"a": 1}}])
    assert body["findings"][0]["description"] == '{"a": 1}'


def test_secret_that_json_would_escape_is_still_found():
    secret = 'tricky"secret\\with-quote-and-é-0123'
    with pytest.raises(U.CredentialInPayload):
        U.build_body("aws", "1", [{"title": "t", "description": secret}], secrets=[secret])


# ------------------------------------------------------------- GCP gaps

class _Resp:
    def __init__(self, status):
        self.status_code = status
        self.text = ""

    def json(self):
        return {}


class _Creds:
    token = "ya29.fake-token-never-uploaded-xxxxxxxxxxxx"

    def refresh(self, _r):
        pass


@pytest.mark.parametrize("status", [429, 404, 500, 503])
def test_gcp_no_answer_is_partial_never_clean(status, monkeypatch):
    pytest.importorskip("google.auth")
    from narvy.cloud import gcp_scan
    monkeypatch.setattr(gcp_scan.google.auth, "default", lambda scopes=None: (_Creds(), "demo"))
    monkeypatch.setattr(gcp_scan.requests, "get",
                        lambda url, headers=None, timeout=None: _Resp(status if "storage" in url else 200))
    report = gcp_scan.analyze_gcp_security()
    cov = cli_main._cloud_coverage("gcp", report)
    assert cov["status"] == "partial" and cov["checks_skipped"] >= 1
    assert any(f"HTTP {status}" in e for e in cov["errors"])


def test_gcp_network_error_is_partial(monkeypatch):
    pytest.importorskip("google.auth")
    from narvy.cloud import gcp_scan

    def boom(url, headers=None, timeout=None):
        raise gcp_scan.requests.exceptions.ConnectionError("down")
    monkeypatch.setattr(gcp_scan.google.auth, "default", lambda scopes=None: (_Creds(), "demo"))
    monkeypatch.setattr(gcp_scan.requests, "get", boom)
    cov = cli_main._cloud_coverage("gcp", gcp_scan.analyze_gcp_security())
    assert cov["status"] == "partial"


def test_gcp_all_200_is_complete(monkeypatch):
    pytest.importorskip("google.auth")
    from narvy.cloud import gcp_scan
    monkeypatch.setattr(gcp_scan.google.auth, "default", lambda scopes=None: (_Creds(), "demo"))
    monkeypatch.setattr(gcp_scan.requests, "get", lambda url, headers=None, timeout=None: _Resp(200))
    cov = cli_main._cloud_coverage("gcp", gcp_scan.analyze_gcp_security())
    assert cov == {"status": "complete", "checks_skipped": 0, "errors": []}
