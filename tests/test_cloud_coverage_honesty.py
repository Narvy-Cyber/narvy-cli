"""cloud-scan never reports a check that errored as clean (1.3.1).

1.3.0 swallowed every WAF ClientError (regional and global), the per-bucket S3
ACL errors, the per-user CIS 1.2 MFA errors and the CIS 1.3 credential report
errors: the payload said `coverage: complete, checks_skipped: 0` while those
checks had not run. Here WAF answers HTTP 500 through moto and the scan must
say partial, name the WAF checks, and `--fail-on` must exit 2.
"""

import json
import sys

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from narvy import main as cli_main  # noqa: E402
from narvy.cloud import aws_scan  # noqa: E402

_EMPTY_WAF = b'{"WebACLs": []}'


@pytest.fixture
def aws_env(monkeypatch, tmp_path):
    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAZZTEST0000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # One attempt: a 500 is retryable and botocore would back off 5 times.
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(aws_scan.time, "sleep", lambda s: None)


class _Raw:
    def __init__(self, body):
        self._body = body

    def stream(self, **kw):
        yield self._body

    def read(self, *a, **kw):
        return self._body


def _waf_answers(monkeypatch, status, body):
    """Every WAF classic call (regional and global) answers `status` / `body`.
    moto does not implement WAF classic, so the healthy case is stubbed too."""
    from botocore.awsrequest import AWSResponse

    real_client = aws_scan._boto3_client

    def _client(service, endpoint_url=None, **kwargs):
        client = real_client(service, endpoint_url=endpoint_url, **kwargs)
        if service in ("waf", "waf-regional"):
            def _respond(request, **kw):
                return AWSResponse(request.url, status,
                                   {"Content-Type": "application/x-amz-json-1.1"}, _Raw(body))
            client.meta.events.register_first("before-send", _respond)
        return client

    monkeypatch.setattr(aws_scan, "_boto3_client", _client)


def _other_gaps(coverage):
    return [e for e in coverage["errors"] if "waf" not in e]


@mock_aws
def test_waf_answering_500_is_partial_coverage_not_clean(aws_env, monkeypatch):
    _waf_answers(monkeypatch, 500, b'{"__type": "WAFInternalErrorException", "message": "boom"}')
    report = aws_scan.analyze_aws_security(region="us-east-1")
    cov = report["coverage"]
    waf = [e for e in cov["errors"] if "waf" in e]
    assert cov["status"] == "partial", cov
    assert any(e.startswith("us-east-1/waf_regional:") for e in waf), cov
    assert any(e.startswith("waf_global:") for e in waf), cov
    assert all("500" in e or "WAFInternalError" in e for e in waf), waf
    assert cov["checks_skipped"] == len(cov["errors"]) >= 2


@mock_aws
def test_healthy_waf_adds_no_gap(aws_env, monkeypatch):
    """Control: the same account with WAF answering 200 has no WAF gap, so the
    gap above comes from the 500 and nothing else."""
    _waf_answers(monkeypatch, 200, _EMPTY_WAF)
    report = aws_scan.analyze_aws_security(region="us-east-1")
    assert not [e for e in report["coverage"]["errors"] if "waf" in e], report["coverage"]


@mock_aws
def test_global_waf_gap_counts_once_across_regions(aws_env, monkeypatch):
    _waf_answers(monkeypatch, 500, b'{"__type": "WAFInternalErrorException", "message": "boom"}')
    monkeypatch.setattr(aws_scan, "get_all_regions", lambda endpoint_url=None: ["us-east-1", "eu-west-1"])
    report = aws_scan.analyze_aws_security()
    errors = report["coverage"]["errors"]
    assert sum(e.startswith("waf_global:") for e in errors) == 1, errors
    assert {e.split(":")[0] for e in errors if "waf_regional" in e} == {
        "us-east-1/waf_regional", "eu-west-1/waf_regional"}


@mock_aws
def test_fail_on_exits_2_when_waf_did_not_run(aws_env, monkeypatch, tmp_path):
    """End to end through the CLI: nothing breaches --fail-on critical, but WAF
    did not run, so the gate exits 2 (EXIT_COVERAGE), as documented."""
    # A fresh moto account has no AWS Config recorder (a Critical finding).
    boto3.client("config", region_name="us-east-1").put_configuration_recorder(ConfigurationRecorder={
        "name": "default", "roleARN": "arn:aws:iam::123456789012:role/config",
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}})
    _waf_answers(monkeypatch, 500, b'{"__type": "WAFInternalErrorException", "message": "boom"}')
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["narvy", "cloud-scan", "--region", "us-east-1",
                                      "--fail-on", "critical", "-o", "json", "-f", str(out)])
    with pytest.raises(SystemExit) as exc:
        cli_main.cli()
    data = json.loads(out.read_text())
    assert not [f for f in data["findings"] if str(f.get("severity")).lower() == "critical"]
    assert data["coverage"]["status"] == "partial"
    assert data["coverage"]["checks_skipped"] >= 2
    assert exc.value.code == cli_main.EXIT_COVERAGE == 2


def test_swallowed_per_item_errors_are_recorded():
    """S3 ACL, IAM login profile, CIS 1.2 and CIS 1.3 errors go to the sink."""
    from botocore.exceptions import ClientError

    def _err(code="AccessDenied"):
        return ClientError({"Error": {"Code": code, "Message": "denied"}}, "Op")

    class _S3:
        def list_buckets(self):
            return {"Buckets": [{"Name": "b1"}]}

        def get_bucket_acl(self, Bucket):
            raise _err()

    class _IAM:
        def get_account_summary(self):
            return {"SummaryMap": {"AccountAccessKeysPresent": 0}}

        def list_users(self):
            return {"Users": [{"UserName": "u1", "UserId": "x",
                               "CreateDate": __import__("datetime").datetime(2026, 1, 1)}]}

        def get_login_profile(self, UserName):
            raise _err()

        def list_mfa_devices(self, UserName):
            return {"MFADevices": [{"SerialNumber": "s"}]}

        def get_credential_report(self):
            raise _err()

    clients = {"s3": _S3(), "iam": _IAM()}
    sink = []
    token = aws_scan._partial_errors.set(sink)
    real = aws_scan._boto3_client
    aws_scan._boto3_client = lambda service, endpoint_url=None, **kw: clients[service]
    try:
        aws_scan.analyze_s3_buckets()
        aws_scan.analyze_iam_users()
        aws_scan.check_cis_compliance()
    finally:
        aws_scan._boto3_client = real
        aws_scan._partial_errors.reset(token)
    labels = [e.split(":")[0] for e in sink]
    assert "s3_buckets/b1 acl" in labels
    assert "iam_users/u1 login profile" in labels
    assert "cis_compliance/CIS 1.2 u1" in labels
    assert "cis_compliance/CIS 1.3 credential report" in labels
