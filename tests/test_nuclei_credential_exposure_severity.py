"""Nuclei exposure severity: credentials go up, public ids stay low."""
import pytest

from narvy.web.scanner import NucleiScanner


@pytest.fixture(scope="module")
def scanner():
    return NucleiScanner()


def _sev(scanner, title, tid, matcher="", tags=None, path="", evidence=False):
    return scanner._upgrade_severity_if_needed(
        "info", title, tid, matcher,
        tags=tags or [], template_path=path, has_evidence=evidence,
    )


CREDENTIAL_CASES = [
    ("github oauth access token", "github-oauth-access",
     ["github", "oauth", "token", "exposure", "vuln"],
     "http/exposures/tokens/github/github-oauth-access.yaml"),
    ("snyk api token", "snyk-api-token",
     ["snyk", "exposure", "tokens", "vuln"],
     "http/exposures/tokens/synk/snyk-api-token.yaml"),
    ("aws session token", "aws-session-token",
     ["aws", "token", "exposure"],
     "http/exposures/tokens/aws/aws-session-token.yaml"),
    ("aws api key", "aws-api-key",
     ["aws", "token", "exposure"],
     "http/exposures/tokens/aws/aws-api-key.yaml"),
    ("artifactory password disclosure", "artifactory-api-password",
     ["token", "exposure"],
     "http/exposures/tokens/artifactory/artifactory-api-password.yaml"),
    ("paypal braintree access token disclosure", "braintree-access-token",
     ["token", "exposure"],
     "http/exposures/tokens/paypal/braintree-access-token.yaml"),
    ("age identity (x22519 secret key)", "age-secret-key",
     ["token", "exposure"],
     "http/exposures/tokens/age/age-secret-key.yaml"),
]


@pytest.mark.parametrize("title,tid,tags,path", CREDENTIAL_CASES)
def test_extracted_credential_is_high_not_info(scanner, title, tid, tags, path):
    """A template that extracted secret material is a proven credential leak."""
    assert _sev(scanner, title, tid, tags=tags, path=path, evidence=True) == "high"


@pytest.mark.parametrize("title,tid,tags,path", CREDENTIAL_CASES)
def test_credential_template_without_evidence_is_not_high(scanner, title, tid, tags, path):
    """No extracted value: exposure-class (low), never promoted on the id alone."""
    assert _sev(scanner, title, tid, tags=tags, path=path, evidence=False) == "low"


PUBLIC_IDENTIFIER_CASES = [
    ("adobe client id", "adobe-client-id",
     "http/exposures/tokens/adobe/adobe-client-id.yaml"),
    ("bitbucket client id", "bitbucket-clientid",
     "http/exposures/tokens/bitbucket/bitbucket-clientid.yaml"),
    ("aws account id", "aws-account-id",
     "http/exposures/tokens/aws/aws-account-id.yaml"),
    ("age recipient (x25519 public key)", "age-public-key",
     "http/exposures/tokens/age/age-public-key.yaml"),
    ("alibaba access key id", "alibaba-accesskey-id",
     "http/exposures/tokens/alibaba/alibaba-accesskey-id.yaml"),
]


@pytest.mark.parametrize("title,tid,path", PUBLIC_IDENTIFIER_CASES)
def test_public_identifier_stays_low(scanner, title, tid, path):
    """Client IDs, account IDs and public keys are not secret material."""
    assert _sev(scanner, title, tid, tags=["token", "exposure"],
                path=path, evidence=True) == "low"


def test_python_venv_exposure_is_not_critical(scanner):
    """"venv" contains "env", but a virtualenv listing is not a credentials leak."""
    assert _sev(scanner, "python virtual environment  directory exposure",
                "python-venv-exposure", tags=["files", "exposure"],
                path="http/exposures/files/python-venv-exposure.yaml") == "low"


def test_aspnetcore_dev_env_is_not_critical(scanner):
    assert _sev(scanner, "asp.net core development environment - exposure",
                "aspnetcore-dev-env", tags=["misconfig", "exposure"],
                path="http/misconfiguration/microsoft/aspnetcore-dev-env.yaml") == "low"


def test_real_dotenv_exposure_still_critical(scanner):
    """The .env rule must still fire on a real .env file."""
    assert _sev(scanner, "exposed .env file", "dotenv-file",
                tags=["exposure"], path="http/exposures/configs/dotenv.yaml") == "critical"


def test_tag_detected_exposure_is_never_info(scanner):
    """A title with no "exposed"/"exposure" wording but exposure tags."""
    out = _sev(scanner, "web configuration file - detect", "web-config",
               tags=["config", "exposure", "vuln"],
               path="http/exposures/configs/web-config.yaml")
    assert out != "info"
    assert out == "medium"  # config exposure


def test_no_info_severity_exposure_template_remains(scanner):
    """Nothing under http/exposures/ may come out of the upgrade still at info."""
    for title, tid, tags, path in CREDENTIAL_CASES:
        assert _sev(scanner, title, tid, tags=tags, path=path, evidence=True) != "info"
        assert _sev(scanner, title, tid, tags=tags, path=path, evidence=False) != "info"


def test_missing_hsts_still_medium(scanner):
    assert _sev(scanner, "http missing security headers",
                "http-missing-security-headers",
                matcher="strict-transport-security", tags=["misconfig"]) == "medium"


def test_missing_xframe_still_low(scanner):
    assert _sev(scanner, "http missing security headers",
                "http-missing-security-headers",
                matcher="x-frame-options", tags=["misconfig"]) == "low"


def test_git_exposure_still_high(scanner):
    assert _sev(scanner, "git config exposure", "git-config",
                tags=["exposure", "config"],
                path="http/exposures/configs/git-config.yaml") == "high"


def test_tech_fingerprinting_stays_info(scanner):
    """Fingerprinting is not a vulnerability and must stay info."""
    assert _sev(scanner, "wappalyzer technology detection", "tech-detect",
                tags=["tech"], path="http/technologies/tech-detect.yaml") == "info"
    assert _sev(scanner, "apache server version", "apache-detect",
                tags=["tech"], path="http/technologies/apache/apache-detect.yaml") == "info"


def test_non_info_severity_is_passed_through_untouched(scanner):
    for sev in ("critical", "high", "medium", "low"):
        assert scanner._upgrade_severity_if_needed(
            sev, "anything", "any-template", "",
            tags=["exposure"], template_path="http/exposures/x.yaml",
            has_evidence=True,
        ) == sev


def test_upgrade_is_callable_without_the_new_kwargs(scanner):
    """The context args are optional; the 4-arg signature must keep working."""
    assert scanner._upgrade_severity_if_needed(
        "info", "http missing security headers",
        "http-missing-security-headers", "strict-transport-security") == "medium"


def test_parse_nuclei_finding_promotes_extracted_github_token(scanner):
    """A raw nuclei record carrying an extracted token."""
    raw = {
        "template-id": "github-oauth-access",
        "template-path": "/path/to/nuclei-templates/http/exposures/tokens/github/github-oauth-access.yaml",
        "info": {
            "name": "GitHub OAuth Access Token",
            "severity": "info",
            "tags": ["github", "oauth", "token", "exposure", "vuln"],
            "classification": {"cwe-id": ["CWE-522"]},
        },
        "matched-at": "http://127.0.0.1:8099/",
        "extracted-results": ["gho_" + "A" * 36],
    }
    parsed = scanner._parse_nuclei_finding(raw)
    assert parsed["severity"] == "high"
    assert parsed["evidence"] == ["gho_" + "A" * 36]
