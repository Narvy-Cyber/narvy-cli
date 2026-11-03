"""One severity per cloud check, keyed by a stable rule id (decision 2026-11-03).

Every check the AWS and GCP analyzers emit has ONE entry here: a fixed
severity, why, and the published reference it follows. The analyzers stamp
``rule_id`` + ``severity`` from this table at scan time, and every surface
that reads a cloud severity (src/cloud/severity.report_severity) resolves it
through :func:`resolve_severity`, so a report stored before this table existed
reads the same as a new one.

Basis of an entry's severity:

- ``published``: the severity AWS Security Hub gives the matching control
  (AWS Foundational Security Best Practices, "FSBP"). The table wins over any
  severity the analyzer stored (a stored value that differs contradicts the
  reference; :data:`CONTRADICTIONS` lists the ones known in the analyzer).
- ``passes``: the reference treats this configuration as compliant; the check
  is kept for visibility at ``info``. The table wins too.
- ``analog``: a GCP check (Google publishes no per-check severity for these;
  CIS benchmarks carry levels, not severities) takes the FSBP severity of the
  equivalent AWS control. A severity the report gives is kept.
- ``none``: no published control covers the check; the severity is the
  rationale below. A severity the report gives is kept.

Old reports (June 2026 analyzer: no rule id, no severity) map by their EXACT
check title (``Issue``) or, for the four checks that had no title, their exact
recommendation text -- an explicit alias table, never a keyword match. An item
that still maps to nothing stays "undetermined" (src/cloud/severity) and is
logged by :func:`log_unmapped`, so the table can be extended.

Stdlib only: the free CLI imports the AWS analyzer as a top-level module
(cli/titanshield_cloud_scan.py) and reaches this file by path.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, NamedTuple, Optional, Tuple

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low", "info")

PUBLISHED, PASSES, ANALOG, NONE = "published", "passes", "analog", "none"
_TABLE_WINS = (PUBLISHED, PASSES)


class Rule(NamedTuple):
    severity: str
    basis: str
    reference: str
    rationale: str
    # An account-level control AWS evaluates in every region (Config.1...):
    # the list keeps one finding per region, the security score counts the
    # rule once per account (decision 2026-11-03, :func:`score_findings`).
    per_region: bool = False


_FSBP = "AWS Security Hub FSBP"

RULES: Dict[str, Rule] = {
    # ---------------------------------------------------------------- AWS EC2
    "aws.ec2.sg_open_high_risk_port": Rule(
        "critical", PUBLISHED,
        f"{_FSBP} EC2.19 (Critical); CIS AWS v3.0.0 5.2 via EC2.53 for 22/3389",
        "A port on the EC2.19 high-risk list (SSH, RDP, databases, FTP, SMB, "
        "Elasticsearch/Kibana, 8080...) is reachable from 0.0.0.0/0."),
    "aws.ec2.sg_open_all_ports": Rule(
        "critical", PUBLISHED, f"{_FSBP} EC2.19 (Critical)",
        "Every port is reachable from 0.0.0.0/0, the EC2.19 high-risk ports included."),
    "aws.ec2.sg_open_port": Rule(
        "high", PUBLISHED, f"{_FSBP} EC2.18 (High)",
        "A port outside the authorized list (80, 443) is reachable from 0.0.0.0/0."),
    "aws.ec2.sg_open_web_port": Rule(
        "info", PASSES, f"{_FSBP} EC2.18 (default authorizedTcpPorts 80, 443: passes)",
        "80/443 open to the internet is the normal web-server configuration."),
    "aws.vpc.public_igw_route": Rule(
        "info", NONE, "No published control",
        "A 0.0.0.0/0 route to an internet gateway defines a public subnet; it "
        "is not a misconfiguration on its own."),
    # ---------------------------------------------------------------- AWS S3
    "aws.s3.bucket_public_acl": Rule(
        "critical", PUBLISHED, f"{_FSBP} S3.2 (Critical)",
        "The bucket ACL grants AllUsers: anyone on the internet can read it."),
    # ---------------------------------------------------------------- AWS IAM
    "aws.iam.root_access_key": Rule(
        "critical", PUBLISHED, f"{_FSBP} IAM.4 (Critical); CIS AWS v3.0.0 1.4",
        "Root access keys give unrestricted account access and cannot be scoped."),
    "aws.iam.console_user_no_mfa": Rule(
        "medium", PUBLISHED, f"{_FSBP} IAM.5 (Medium); CIS AWS v3.0.0 1.10",
        "An IAM user with a console password has no MFA device."),
    "aws.iam.unused_credentials_90d": Rule(
        "medium", PUBLISHED, f"{_FSBP} IAM.8 (Medium)",
        "IAM user credentials unused for over 90 days are still active."),
    "aws.iam.policy_full_admin": Rule(
        "high", PUBLISHED, f"{_FSBP} IAM.1 (High); CIS AWS v1.4.0 1.16 (not in v3.0.0)",
        'A customer managed policy allows "Action": "*" on "Resource": "*".'),
    "aws.iam.policy_service_wildcard": Rule(
        "low", PUBLISHED, f"{_FSBP} IAM.21 (Low)",
        "A customer managed policy allows a service-wide action wildcard."),
    # ---------------------------------------------------------------- AWS logging / detection
    "aws.cloudtrail.no_trail": Rule(
        "high", PUBLISHED, f"{_FSBP} CloudTrail.1 (High); CIS AWS v3.0.0 3.1",
        "No CloudTrail trail: account API activity is not recorded.", per_region=True),
    "aws.cloudtrail.not_multi_region": Rule(
        "high", PUBLISHED, f"{_FSBP} CloudTrail.1 (High); CIS AWS v3.0.0 3.1",
        "CloudTrail.1 requires at least one multi-Region trail."),
    "aws.cloudtrail.log_validation_disabled": Rule(
        "low", PUBLISHED, f"{_FSBP} CloudTrail.4 (Low); CIS AWS v3.0.0 3.2",
        "CloudTrail log file integrity validation is off."),
    "aws.config.not_enabled": Rule(
        "critical", PUBLISHED, f"{_FSBP} Config.1 (Critical); CIS AWS v3.0.0 3.3",
        "AWS Config is not recording: no resource inventory or change history.",
        per_region=True),
    "aws.config.not_all_resources": Rule(
        "critical", PUBLISHED, f"{_FSBP} Config.1 (Critical); CIS AWS v3.0.0 3.3",
        "Config.1 requires recording the resources the enabled controls need.",
        per_region=True),
    "aws.cloudwatch.no_alarms": Rule(
        "low", PUBLISHED, f"{_FSBP} CloudWatch.1 to CloudWatch.14 (Low)",
        "No CloudWatch alarm: the CIS monitoring alarms (root use, IAM changes...) are absent.",
        per_region=True),
    "aws.cloudwatch.log_group_no_retention": Rule(
        "info", PASSES, f"{_FSBP} CloudWatch.16 (no expiry passes the 365-day minimum)",
        "A log group without retention keeps its logs forever."),
    "aws.guardduty.disabled": Rule(
        "high", PUBLISHED, f"{_FSBP} GuardDuty.1 (High)",
        "GuardDuty threat detection is off.", per_region=True),
    # GuardDuty findings are incidents, not an account control: never folded
    # per region in the score.
    "aws.guardduty.critical_severity_findings": Rule(
        "critical", PUBLISHED, "Amazon GuardDuty finding severity levels (Critical: 9.0 to 10.0)",
        "GuardDuty holds findings of severity 9.0 or more."),
    "aws.guardduty.high_severity_findings": Rule(
        "high", PUBLISHED, "Amazon GuardDuty finding severity levels (High: 7.0 to 8.9)",
        "GuardDuty holds findings of severity 7.0 to 8.9."),
    # ---------------------------------------------------------------- AWS data stores
    "aws.rds.publicly_accessible": Rule(
        "critical", PUBLISHED, f"{_FSBP} RDS.2 (Critical); CIS AWS v3.0.0 2.3.3",
        "The DB instance is publicly accessible."),
    "aws.rds.storage_unencrypted": Rule(
        "medium", PUBLISHED, f"{_FSBP} RDS.3 (Medium); CIS AWS v3.0.0 2.3.1",
        "The DB instance storage is not encrypted at rest."),
    "aws.redshift.publicly_accessible": Rule(
        "critical", PUBLISHED, f"{_FSBP} Redshift.1 (Critical)",
        "The Redshift cluster is publicly accessible."),
    "aws.redshift.unencrypted": Rule(
        "medium", PUBLISHED, f"{_FSBP} Redshift.10 (Medium)",
        "The Redshift cluster is not encrypted at rest."),
    "aws.dynamodb.sse_not_enabled": Rule(
        "low", NONE, "No published control",
        "DynamoDB encrypts every table at rest; the flag means no customer-chosen key."),
    "aws.dynamodb.streams_disabled": Rule(
        "info", NONE, "No published control", "Streams are a feature, not a security control."),
    "aws.secretsmanager.rotation_disabled": Rule(
        "medium", PUBLISHED, f"{_FSBP} SecretsManager.1 (Medium)",
        "The secret has no automatic rotation."),
    "aws.kms.rotation_disabled": Rule(
        "medium", PUBLISHED, f"{_FSBP} KMS.4 (Medium); CIS AWS v3.0.0 3.6",
        "Automatic rotation is off on a customer managed key."),
    "aws.kms.key_disabled": Rule(
        "info", NONE, "No published control (KMS.3 covers keys pending deletion)",
        "A disabled key exposes nothing."),
    # ---------------------------------------------------------------- AWS messaging
    "aws.sqs.public_policy": Rule(
        "critical", PUBLISHED, f"{_FSBP} SQS.3 (Critical)",
        'The queue policy allows Principal "*".'),
    "aws.sns.public_policy": Rule(
        "critical", PUBLISHED, f"{_FSBP} SNS.4 (Critical)",
        'The topic policy allows Principal "*".'),
    # ---------------------------------------------------------------- AWS compute / containers
    "aws.lambda.env_no_cmk": Rule(
        "low", NONE, "No published control",
        "Lambda encrypts environment variables with an AWS managed key by default."),
    "aws.ecs.task_host_network": Rule(
        "medium", PUBLISHED, f"{_FSBP} ECS.17 (Medium)",
        "The task uses host network mode."),
    "aws.eks.public_endpoint": Rule(
        "high", PUBLISHED, f"{_FSBP} EKS.1 (High)",
        "The cluster API endpoint is publicly accessible."),
    "aws.eks.no_public_endpoint": Rule(
        "info", PASSES, f"{_FSBP} EKS.1 (a private endpoint passes)",
        "Reports before 2026-11-03 only: the inverted check fired when the public "
        "endpoint was OFF, the configuration EKS.1 asks for."),
    "aws.eks.secrets_not_encrypted": Rule(
        "medium", NONE, "No published control on the current FSBP list",
        "Kubernetes secrets are not envelope-encrypted with KMS."),
    "aws.elasticbeanstalk.no_security_group": Rule(
        "low", NONE, "No published control",
        "The environment names no security group of its own."),
    "aws.elasticbeanstalk.no_ssl_certificate": Rule(
        "medium", ANALOG, f"{_FSBP} ELB.3 (Medium)",
        "The environment load balancer has no TLS certificate."),
    "aws.glue.no_security_configuration": Rule(
        "low", NONE, "No published control", "The job has no security configuration."),
    "aws.emr.kerberos_disabled": Rule(
        "low", NONE, "No published control", "The cluster has no Kerberos authentication."),
    "aws.emr.shared_security_group": Rule(
        "low", NONE, "No published control",
        "Primary and core nodes share one security group."),
    # ---------------------------------------------------------------- AWS edge / API
    "aws.apigateway.no_client_certificate": Rule(
        "medium", PUBLISHED, f"{_FSBP} APIGateway.2 (Medium)",
        "The stage has no client certificate for backend authentication."),
    "aws.apigateway.data_tracing_disabled": Rule(
        "low", NONE, "No published control (APIGateway.1 covers execution logging)",
        "Data tracing is off on the stage."),
    "aws.cloudfront.no_waf": Rule(
        "medium", PUBLISHED, f"{_FSBP} CloudFront.6 (Medium)",
        "The distribution has no WAF web ACL."),
    "aws.cloudfront.no_ssl_certificate": Rule(
        "low", NONE, "No published control",
        "The distribution uses neither the default nor an ACM certificate."),
    "aws.waf.web_acl_no_rules": Rule(
        "medium", PUBLISHED, f"{_FSBP} WAF.4 / WAF.8 / WAF.10 (Medium)",
        "The web ACL has no rule."),
    # ---------------------------------------------------------------- GCP
    "gcp.iam.admin_named_custom_role": Rule(
        "medium", NONE, "No published control (CIS GCP v3.0 1.5 is the closest)",
        "A custom role named owner/admin; its permissions are not inspected."),
    "gcp.storage.public_access_prevention_off": Rule(
        "high", ANALOG, f"{_FSBP} S3.8 (High); CIS GCP v3.0 5.1",
        "Public access prevention is not enforced on the bucket."),
    "gcp.compute.public_ip": Rule(
        "high", ANALOG, f"{_FSBP} EC2.9 (High); CIS GCP v3.0 4.9",
        "The instance has a public IP address."),
    "gcp.sql.ssl_not_required": Rule(
        "medium", ANALOG, f"{_FSBP} Redshift.2 (Medium); CIS GCP v2.0 6.4",
        "The Cloud SQL instance accepts connections without TLS."),
    "gcp.gke.private_nodes_disabled": Rule(
        "high", ANALOG, f"{_FSBP} EC2.9 (High); SCC PRIVATE_CLUSTER_DISABLED",
        "Cluster nodes are not private."),
    "gcp.functions.http_trigger": Rule(
        "low", NONE, "No published control",
        "The function has an HTTP trigger; its invoker IAM is not inspected."),
    "gcp.bigquery.dataset_all_authenticated": Rule(
        "critical", ANALOG, f"{_FSBP} S3.2 (Critical); CIS GCP v3.0 7.1",
        "allAuthenticatedUsers (any Google account) can read the dataset."),
    "gcp.vpc.auto_mode_network": Rule(
        "low", NONE, "No published severity (CIS GCP v3.0 3.1 covers the default network)",
        "An auto-mode network creates subnets and firewall defaults in every region."),
    "gcp.firestore.not_native_mode": Rule(
        "info", NONE, "No published control", "Database mode is not a security control."),
    "gcp.pubsub.no_cmek": Rule(
        "medium", ANALOG, f"{_FSBP} SNS.1 (Medium)",
        "The topic is not encrypted with a customer-managed key."),
    "gcp.cloud_armor.no_policy": Rule(
        "medium", ANALOG, f"{_FSBP} CloudFront.6 (Medium)",
        "No Cloud Armor security policy exists."),
    "gcp.cdn.disabled": Rule(
        "info", NONE, "No published control", "CDN is a performance feature."),
    "gcp.app_engine.split_health_checks_off": Rule(
        "info", NONE, "No published control", "Health-check mode is not a security control."),
    "gcp.endpoints.unmanaged_api": Rule(
        "low", NONE, "No published control", "The API is not managed by Cloud Endpoints."),
    "gcp.dataflow.disk_size_unset": Rule(
        "info", NONE, "No published control", "Disk sizing is not a security control."),
    "gcp.dataproc.no_cmek": Rule(
        "medium", ANALOG, f"{_FSBP} EMR.3 (Medium); CIS GCP v3.0 8.1",
        "The cluster is not encrypted with a customer-managed key."),
    "gcp.monitoring.no_alert_policies": Rule(
        "low", ANALOG, f"{_FSBP} CloudWatch.1 to CloudWatch.14 (Low); CIS GCP v3.0 2.4 to 2.11",
        "No Cloud Monitoring alert policy."),
    "gcp.logging.no_log_sinks": Rule(
        "medium", ANALOG, f"{_FSBP} CloudTrail.5 (Medium); CIS GCP v3.0 2.2",
        "Audit logs are not exported by any sink."),
    "gcp.scc.not_configured": Rule(
        "high", ANALOG, f"{_FSBP} GuardDuty.1 (High)",
        "Security Command Center has no source."),
    "gcp.secret_manager.automatic_replication": Rule(
        "info", NONE, "No published control",
        "Google-managed replication is the default, not a weakness."),
}

# Severities the analyzer stamped that contradict the reference (2026-11-03
# audit of src/cloud/aws/aws_security_analyzer.py). The table wins; listed so
# the change is reviewable.
CONTRADICTIONS: Dict[str, Tuple[str, str]] = {
    # rule id: (analyzer severity, reference severity)
    "aws.rds.publicly_accessible": ("high", "critical"),
    "aws.iam.policy_service_wildcard": ("medium", "low"),
    "aws.iam.unused_credentials_90d": ("low", "medium"),
    "aws.sqs.public_policy": ("high", "critical"),
    "aws.sns.public_policy": ("high", "critical"),
    "aws.config.not_enabled": ("medium", "critical"),
    "aws.config.not_all_resources": ("low", "critical"),
    "aws.cloudtrail.not_multi_region": ("medium", "high"),
    "aws.cloudwatch.no_alarms": ("info", "low"),
    "aws.apigateway.no_client_certificate": ("low (category default)", "medium"),
    # Port classes: the analyzer graded by its own port list (Redis, MongoDB,
    # Docker API... critical; 8080 info; other ports medium); EC2.19 / EC2.18
    # grade by the published high-risk list.
    "aws.ec2.sg_open_port": ("medium / critical / high by port", "high"),
    "aws.ec2.sg_open_high_risk_port": ("high (21, 5601, 9200, 9300) / info (8080)", "critical"),
}

# EC2.19 high-risk ports (not customizable in Security Hub).
EC2_19_HIGH_RISK_PORTS = frozenset({
    20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333,
    5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300})
EC2_18_AUTHORIZED_PORTS = frozenset({80, 443})


def sg_rule_id(from_port: Any, to_port: Any = None) -> Optional[str]:
    """Rule id of a security-group rule open to 0.0.0.0/0, by its port range.
    ``from_port`` "All" / "-1" / None (with no ``to_port``) means every port."""
    if from_port in (None, "All", "all", "-1", -1) and to_port in (None, "All", "all", "-1", -1):
        return "aws.ec2.sg_open_all_ports"
    try:
        lo = int(from_port)
        hi = int(to_port) if to_port not in (None, "") else lo
    except (TypeError, ValueError):
        return None
    if lo > hi:
        lo, hi = hi, lo
    if lo <= 0 and hi >= 65535:
        return "aws.ec2.sg_open_all_ports"
    if any(lo <= p <= hi for p in EC2_19_HIGH_RISK_PORTS):
        return "aws.ec2.sg_open_high_risk_port"
    if hi - lo <= 64 and set(range(lo, hi + 1)) <= EC2_18_AUTHORIZED_PORTS:
        return "aws.ec2.sg_open_web_port"
    return "aws.ec2.sg_open_port"


def _sg_rule_from_item(item: Dict[str, Any]) -> Optional[str]:
    """``OpenPorts`` as the analyzers store it: "22", "8000-8100", or (June
    2026 analyzer) the rule's FromPort only, "All" for all traffic."""
    raw = item.get("OpenPorts")
    if raw is None:
        return None
    s = str(raw).strip()
    if s.lower() in ("all", "-1"):
        return sg_rule_id("All")
    lo, sep, hi = s.partition("-")
    return sg_rule_id(lo, hi if sep else None)


# (report category, exact Issue title) -> rule id. Titles are the analyzers'
# own static messages, June 2026 and current.
TITLE_ALIASES: Dict[Tuple[str, str], str] = {
    ("s3_buckets", "S3 bucket grants public access to AllUsers"): "aws.s3.bucket_public_acl",
    ("iam_policies", "Over-permissive policy: Action:* on Resource:* (full admin)"):
        "aws.iam.policy_full_admin",
    ("iam_policies", "Over-permissive policy: service-wide Action wildcard on Resource:*"):
        "aws.iam.policy_service_wildcard",
    ("vpc_configuration", "Non-default VPC has a public (IGW) route for 0.0.0.0/0"):
        "aws.vpc.public_igw_route",
    ("rds_instances", "Unencrypted Storage"): "aws.rds.storage_unencrypted",
    ("rds_instances", "Publicly Accessible"): "aws.rds.publicly_accessible",
    ("lambda_functions", "No KMS Key for Environment Variables"): "aws.lambda.env_no_cmk",
    ("lambda_functions", "No customer-managed KMS Key for Environment Variables"):
        "aws.lambda.env_no_cmk",
    ("ecs_clusters", "Task using host network mode"): "aws.ecs.task_host_network",
    ("elastic_beanstalk", "No Security Group Specified"): "aws.elasticbeanstalk.no_security_group",
    ("elastic_beanstalk", "No SSL Certificate"): "aws.elasticbeanstalk.no_ssl_certificate",
    ("api_gateway", "Data Tracing Disabled"): "aws.apigateway.data_tracing_disabled",
    ("api_gateway", "No Client-Side SSL Certificate"): "aws.apigateway.no_client_certificate",
    ("dynamodb", "Server-Side Encryption Not Enabled"): "aws.dynamodb.sse_not_enabled",
    ("dynamodb", "DynamoDB Streams Not Enabled"): "aws.dynamodb.streams_disabled",
    ("eks_clusters", "Cluster endpoint is publicly accessible"): "aws.eks.public_endpoint",
    ("eks_clusters", "No public access endpoint"): "aws.eks.no_public_endpoint",  # pre-fix
    ("eks_clusters", "Encryption not configured"): "aws.eks.secrets_not_encrypted",
    ("redshift_clusters", "Encryption not enabled"): "aws.redshift.unencrypted",
    ("redshift_clusters", "Publicly accessible"): "aws.redshift.publicly_accessible",
    ("secrets_manager", "Rotation not enabled"): "aws.secretsmanager.rotation_disabled",
    ("sqs_queues", "Public access policy"): "aws.sqs.public_policy",
    ("sns_topics", "Public access policy"): "aws.sns.public_policy",
    ("glue_jobs", "No Security Configuration"): "aws.glue.no_security_configuration",
    ("emr_clusters", "Kerberos not enabled"): "aws.emr.kerberos_disabled",
    ("emr_clusters", "Same security group for master and slave nodes"):
        "aws.emr.shared_security_group",
    ("cis_compliance", "Root account has access keys"): "aws.iam.root_access_key",
    ("kms_keys", "Disabled key"): "aws.kms.key_disabled",
    ("kms_keys", "Key rotation not enabled"): "aws.kms.rotation_disabled",
    ("config", "AWS Config not enabled"): "aws.config.not_enabled",
    ("config", "Not recording all supported resource types"): "aws.config.not_all_resources",
    ("cloudtrail", "No CloudTrail trails configured"): "aws.cloudtrail.no_trail",
    ("cloudtrail", "Trail is not multi-region"): "aws.cloudtrail.not_multi_region",
    ("cloudtrail", "Log file validation not enabled"): "aws.cloudtrail.log_validation_disabled",
    ("cloudwatch", "No CloudWatch alarms configured"): "aws.cloudwatch.no_alarms",
    ("cloudwatch", "No retention period set"): "aws.cloudwatch.log_group_no_retention",
    ("waf", "No rules in Web ACL"): "aws.waf.web_acl_no_rules",
    ("cloudfront", "No SSL/TLS Certificate"): "aws.cloudfront.no_ssl_certificate",
    ("cloudfront", "No Web ACL associated"): "aws.cloudfront.no_waf",
    ("guardduty", "GuardDuty Disabled"): "aws.guardduty.disabled",
    # GCP (src/cloud/gcp/gcp_security_analyzer.py).
    ("iam_roles", "Overly permissive role"): "gcp.iam.admin_named_custom_role",
    ("storage_buckets", "Public access not prevented"): "gcp.storage.public_access_prevention_off",
    ("compute_instances", "Public IP assigned"): "gcp.compute.public_ip",
    ("sql_instances", "SSL not required"): "gcp.sql.ssl_not_required",
    ("gke_clusters", "Public cluster"): "gcp.gke.private_nodes_disabled",
    ("cloud_functions", "Public HTTP trigger"): "gcp.functions.http_trigger",
    ("bigquery_datasets", "Publicly accessible to all authenticated users"):
        "gcp.bigquery.dataset_all_authenticated",
    ("vpc_networks", "Auto-mode network enabled"): "gcp.vpc.auto_mode_network",
    ("firestore", "Not using Firestore Native mode"): "gcp.firestore.not_native_mode",
    ("pubsub", "Customer-managed encryption key not used"): "gcp.pubsub.no_cmek",
    ("cloud_armor", "No Cloud Armor security policies found"): "gcp.cloud_armor.no_policy",
    ("cdn", "CDN not enabled"): "gcp.cdn.disabled",
    ("app_engine", "Split health checks not enabled"): "gcp.app_engine.split_health_checks_off",
    ("endpoints", "API not managed by Cloud Endpoints"): "gcp.endpoints.unmanaged_api",
    ("dataflow", "Worker persistent disk size not specified for streaming job"):
        "gcp.dataflow.disk_size_unset",
    ("dataproc", "Customer-managed encryption key not used"): "gcp.dataproc.no_cmek",
    ("monitoring", "No alert policies found"): "gcp.monitoring.no_alert_policies",
    ("audit_logs", "No log sinks found"): "gcp.logging.no_log_sinks",
    ("security_center", "Security Command Center not configured"): "gcp.scc.not_configured",
    ("secret_manager", "Automatic replication used"): "gcp.secret_manager.automatic_replication",
}

# (report category, exact Recommendation) -> rule id, for the June 2026
# analyzer checks that carried no Issue title. Two of them are deliberately
# ABSENT: the June iam_users check flagged every user without MFA, console
# password or not (IAM.5 covers console users only), and the June
# iam_policies check matched '"Allow"' and '"Resource": "*"' anywhere in the
# document (it cannot tell IAM.1 from IAM.21). Both stay undetermined.
RECOMMENDATION_ALIASES: Dict[Tuple[str, str], str] = {
    ("vpc_configuration",
     "This VPC has a route to the internet gateway for all traffic (0.0.0.0/0). "
     "Ensure this is intended and restrict if necessary."): "aws.vpc.public_igw_route",
    ("s3_buckets",
     "Remove public access to this bucket unless it's explicitly required. Use AWS S3 "
     "Block Public Access feature and review bucket policies."): "aws.s3.bucket_public_acl",
    ("iam_users",
     "Enable Multi-Factor Authentication (MFA) for this console user to enhance account "
     "security."): "aws.iam.console_user_no_mfa",
}

# CheckId the analyzer writes -> rule id.
CHECK_ID_ALIASES: Dict[str, str] = {
    "CIS 1.1": "aws.iam.root_access_key",
    "CIS 1.2": "aws.iam.console_user_no_mfa",
    "CIS 1.3": "aws.iam.unused_credentials_90d",
}


def _category(cat: Any) -> str:
    """The analyzer service key of a report category ("vulnerabilities /
    storage_buckets" -> "storage_buckets")."""
    s = str(cat or "")
    return s.rsplit(" / ", 1)[-1].strip()


def rule_id_for(item: Any, category: Any = None) -> Optional[str]:
    """Stable rule id of a raw report item: the one it carries, else its
    CheckId, else the exact-title / exact-recommendation alias, else (a
    security-group rule) its port class. None when nothing maps."""
    if not isinstance(item, dict):
        return None
    rid = item.get("rule_id")
    if isinstance(rid, str) and rid in RULES:
        return rid
    check = item.get("CheckId")
    if isinstance(check, str) and check in CHECK_ID_ALIASES:
        return CHECK_ID_ALIASES[check]
    cat = _category(category)
    issue = item.get("Issue")
    if isinstance(issue, str):
        hit = TITLE_ALIASES.get((cat, issue.strip()))
        if hit:
            return hit
    rec = item.get("Recommendation")
    if isinstance(rec, str):
        hit = RECOMMENDATION_ALIASES.get((cat, rec.strip()))
        if hit:
            return hit
    if cat == "ec2_security_groups":
        return _sg_rule_from_item(item)
    return None


def resolve_severity(reported: Optional[str], rule_id: Optional[str]) -> Optional[str]:
    """The severity a finding states: the table's when the entry follows a
    reference (published / passes) or the report gives none; the report's
    own otherwise. None when neither exists."""
    rule = RULES.get(rule_id) if rule_id else None
    if rule is None:
        return reported
    if reported is None or rule.basis in _TABLE_WINS:
        return rule.severity
    return reported


def stamp_item(item: Dict[str, Any], category: Any) -> Optional[str]:
    """Scan time: write ``rule_id`` and ``severity`` from the table on one
    analyzer item (in place). Returns the rule id, None when unmapped."""
    rid = rule_id_for(item, category)
    if rid is None:
        return None
    item["rule_id"] = rid
    reported = str(item.get("severity") or "").strip().lower() or None
    if reported not in SEVERITIES:
        reported = None
    item["severity"] = resolve_severity(reported, rid)
    return rid


def stamp_items(lists: Iterable[Tuple[str, Any]]) -> list:
    """Stamp every dict item of (category, items) pairs; returns the
    (category, title) of the items left unmapped, logged."""
    unmapped = []
    for cat, items in lists:
        if not isinstance(items, list):
            continue
        for it in items:
            if isinstance(it, dict) and stamp_item(it, cat) is None:
                unmapped.append((_category(cat), str(it.get("Issue") or "")[:80]))
    log_unmapped(unmapped)
    return unmapped


def log_unmapped(unmapped: Iterable[Tuple[str, str]]) -> None:
    """One warning per distinct unmapped (category, title): the cue to extend
    RULES / TITLE_ALIASES. Titles are the analyzer's own messages."""
    seen = sorted(set(unmapped))
    for cat, title in seen:
        logger.warning("cloud rule_severity: no rule for category=%s title=%r", cat, title)


def score_findings(findings: Iterable[Any]) -> list:
    """The findings the security score counts: every finding, except that a
    per-region account control (Rule.per_region) counts once per account. A
    finding carries its table rule as ``cloud_rule_id`` (normalized findings,
    src/cloud/{aws,gcp}/normalize); one without it is always counted."""
    out, seen = [], set()
    for f in findings or []:
        rid = f.get("cloud_rule_id") if isinstance(f, dict) else None
        rule = RULES.get(rid) if isinstance(rid, str) else None
        if rule is not None and rule.per_region:
            if rid in seen:
                continue
            seen.add(rid)
        out.append(f)
    return out
