"""Flatten an AWS or GCP posture report into the findings `--upload` sends.

Same shape and identity as the Narvy platform's normalizers
(src/cloud/aws/normalize.py, src/cloud/gcp/normalize.py in the SaaS repo), so a
CLI upload of an account lands on the same tracked findings as the platform's
earlier scans of it. Only finding text and resource names leave the machine:
no raw API object, no credential.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .rule_severity import rule_id_for
from .severity import UNDETERMINED_TITLE, report_severity_title

ENGINE = "Narvy Cloud Audit"

_AWS_CATEGORY = {
    "ec2_security_groups": "Network Security",
    "s3_buckets": "Storage",
    "iam_users": "Identity & Access",
    "iam_policies": "Identity & Access",
    "vpc_configuration": "Network Security",
    "rds_instances": "Databases",
    "lambda_functions": "Compute",
    "ecs_clusters": "Containers",
    "eks_clusters": "Containers",
    "elastic_beanstalk": "Compute",
    "api_gateway": "API",
    "dynamodb": "Databases",
    "cloudfront": "Edge / CDN",
    "guardduty": "Threat Detection",
    "waf": "Edge / CDN",
    "redshift_clusters": "Databases",
    "secrets_manager": "Secrets",
    "sqs_queues": "Messaging",
    "sns_topics": "Messaging",
    "glue_jobs": "Data",
    "emr_clusters": "Data",
    "kms_keys": "Cryptography",
    "cloudtrail": "Logging & Audit",
    "cloudwatch": "Logging & Audit",
    "config": "Logging & Audit",
    "cis_compliance": "CIS Benchmark",
}

_GCP_CATEGORY = {
    "iam_roles": "Identity & Access",
    "storage_buckets": "Storage",
    "compute_instances": "Compute",
    "sql_instances": "Databases",
    "gke_clusters": "Containers",
    "cloud_functions": "Compute",
    "bigquery_datasets": "Data",
    "vpc_networks": "Network Security",
    "firestore": "Databases",
    "pubsub": "Messaging",
    "cloud_armor": "Edge / CDN",
    "cdn": "Edge / CDN",
    "app_engine": "Compute",
    "endpoints": "API",
    "dataflow": "Data",
    "dataproc": "Data",
    "monitoring": "Logging & Audit",
    "audit_logs": "Logging & Audit",
    "security_center": "Threat Detection",
    "secret_manager": "Secrets",
}

_AWS_SKIP_KEYS = {
    "timestamp", "summary", "severity_summary", "passed_checks",
    "_general_recommendations",
}

# Raw-item fields naming the resource a check fired on: two findings of one
# check on two resources stay two tracked findings (platform rule 2026-11-02).
_IDENT_KEYS = ("GroupId", "OpenPorts", "Protocol", "CidrIp", "UserName", "PolicyName",
               "FunctionName", "BucketName", "DBInstanceIdentifier", "TableName",
               "ApiName", "StageName", "LogGroupName", "VpcId", "RouteTableId",
               "ClusterName", "ClusterIdentifier", "ClusterId", "ClusterArn", "TaskArn",
               "EnvironmentName", "SecretName", "JobName", "KeyId", "WebACLId",
               "DistributionId", "DetectorId", "TopicArn", "QueueUrl", "Region")


# Same rule for GCP: one tracked finding per bucket / instance / role...
_GCP_IDENT_KEYS = ("BucketName", "InstanceName", "ClusterName", "DatabaseName", "DatasetId",
                   "FunctionName", "NetworkName", "RoleName", "SecretName", "ServiceName",
                   "TopicName", "ApiName", "AppId", "JobName")


def _item_ident(it: Dict[str, Any], keys=_IDENT_KEYS) -> str:
    parts = [f"{k}={it[k]}" for k in keys if it.get(k) not in (None, "")]
    return (":" + "|".join(str(p) for p in parts)) if parts else ""


def normalize_aws_report(report: Dict[str, Any], account_id: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    i = 0
    for service, items in (report or {}).items():
        if service in _AWS_SKIP_KEYS or not isinstance(items, list):
            continue
        category = _AWS_CATEGORY.get(service, "Cloud Posture")
        for it in items:
            if not isinstance(it, dict):
                continue
            i += 1
            sev = report_severity_title(it, service)
            check = it.get("CheckId") or it.get("check_id") or ""
            issue = (it.get("Issue") or it.get("issue") or it.get("title")
                     or it.get("description") or "Cloud misconfiguration")
            rem = (it.get("Recommendation") or it.get("recommendation")
                   or it.get("remediation") or "")
            resource = (it.get("resource") or it.get("Resource")
                        or it.get("arn") or it.get("region") or "")
            title = f"{check + ': ' if check else ''}{issue}".strip()
            out.append({
                "id": i,
                "title": title[:200],
                "type": category,
                "rule_id": check or f"AWS-{service.upper()}",
                "cloud_rule_id": rule_id_for(it, service),
                "severity": sev,
                "category": category,
                "description": issue,
                "file": resource or account_id,
                "location": resource or (f"aws:{account_id}" if account_id else "aws"),
                "line": None,
                "cwe": "",
                "cis": check if str(check).upper().startswith("CIS") else "",
                "owasp": "A05:2021 - Security Misconfiguration",
                "remediation": rem,
                "engine": ENGINE,
                "confidence": "HIGH",
                "surface": "cloud",
                "discriminator": (f"aws:{account_id}:{service}:{check}:{resource}:{title[:40]}"
                                  + _item_ident(it)),
            })
    return out


def normalize_gcp_report(report: Dict[str, Any], project_id: str = "") -> List[Dict[str, Any]]:
    vulns_by_service = (report or {}).get("vulnerabilities", {})
    if not isinstance(vulns_by_service, dict):
        return []
    out: List[Dict[str, Any]] = []
    i = 0
    for service, items in vulns_by_service.items():
        if not isinstance(items, list):
            continue
        category = _GCP_CATEGORY.get(service, "Cloud Posture")
        for it in items:
            if not isinstance(it, dict):
                continue
            i += 1
            issue = (it.get("Issue") or it.get("issue") or it.get("title")
                     or it.get("description") or "Cloud misconfiguration")
            rem = (it.get("Recommendation") or it.get("recommendation")
                   or it.get("remediation") or "")
            resource = (it.get("Resource") or it.get("resource") or it.get("name")
                        or next((str(it[k]) for k in _GCP_IDENT_KEYS if it.get(k)), ""))
            sev = report_severity_title(it, service)
            explicit = sev != UNDETERMINED_TITLE
            out.append({
                "id": i,
                "title": str(issue)[:200],
                "type": category,
                "rule_id": f"GCP-{service.upper()}",
                "cloud_rule_id": rule_id_for(it, service),
                "severity": sev,
                "category": category,
                "description": issue,
                "file": resource or project_id,
                "location": resource or (f"gcp:{project_id}" if project_id else "gcp"),
                "line": None,
                "cwe": "",
                "cis": "",
                "owasp": "A05:2021 - Security Misconfiguration",
                "remediation": rem,
                "engine": ENGINE,
                "confidence": "HIGH" if explicit else "MEDIUM",
                "surface": "cloud",
                "discriminator": (f"gcp:{project_id}:{service}:{str(issue)[:40]}"
                                  + _item_ident(it, _GCP_IDENT_KEYS)),
            })
    return out


def normalize_report(provider: str, report: Dict[str, Any], account_id: str) -> List[Dict[str, Any]]:
    if provider == "gcp":
        return normalize_gcp_report(report, account_id)
    return normalize_aws_report(report, account_id)
