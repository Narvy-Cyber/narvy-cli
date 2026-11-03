"""GCP posture checks (IAM, storage, compute, SQL, GKE, logging...) on one project.

Same checks as the Narvy platform's analyzer (src/cloud/gcp/gcp_security_analyzer.py
in the SaaS repo). Credentials come from Google Application Default Credentials
only (gcloud auth application-default login, GOOGLE_APPLICATION_CREDENTIALS,
workload identity, metadata server): the CLI never takes a key as an argument
and never sends one anywhere.
"""
from datetime import datetime
import google.auth
from google.auth.transport.requests import Request
import requests
import logging

from .rule_severity import stamp_items as _stamp_rule_severity

logger = logging.getLogger(__name__)

# Minimum fraction of API calls that must return 403/401 before we flag the
# scan result as incomplete.  0.5 = at least half the checked APIs were denied.
_PERMISSION_DENIED_THRESHOLD = 0.5

#Fonctionne sur un projet et sur la base des creds obtenus à modifier dans credentials_path

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def get_credentials():
    """(credentials, project) from Application Default Credentials, refreshed."""
    credentials, project = google.auth.default(scopes=_SCOPES)
    credentials.refresh(Request())
    return credentials, project

def make_request(url, credentials, _scan_ctx=None):
    """
    Perform a single GCP REST API GET.

    Args:
        url: API endpoint URL.
        credentials: Authenticated GCP credentials.
        _scan_ctx: Optional mutable dict tracking permission failures across the
                   scan.  When provided, 'total_calls' and 'denied_apis' keys
                   are updated so analyze_gcp_security() can decide whether the
                   result is trustworthy.

    Returns:
        Parsed JSON dict on 200, None otherwise.
    """
    if _scan_ctx is not None:
        _scan_ctx['total_calls'] = _scan_ctx.get('total_calls', 0) + 1

    headers = {"Authorization": f"Bearer {credentials.token}"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 200:
        return response.json()

    # 401 / 403 = permission denied or auth failure — track separately so we
    # can surface an "incomplete scan" warning instead of a silent clean result.
    if response.status_code in (401, 403):
        logger.warning(f"Permission denied accessing {url}: HTTP {response.status_code}")
        if _scan_ctx is not None:
            _scan_ctx.setdefault('denied_apis', [])
            _scan_ctx['denied_apis'].append(url)
    else:
        logger.warning(f"Error accessing {url}: HTTP {response.status_code} {response.text[:200]}")

    return None
    
def analyze_iam_policies(credentials, project_id, _scan_ctx=None):
    url = f"https://iam.googleapis.com/v1/projects/{project_id}/roles"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    risky_roles = []
    if data:
        for role in data.get('roles', []):
            if 'owner' in role['name'].lower() or 'admin' in role['name'].lower():
                risky_roles.append({
                    'RoleName': role['name'],
                    'Issue': 'Overly permissive role',
                    'Recommendation': 'Review and limit the permissions of this role if possible.'
                })
    return risky_roles

def analyze_storage_buckets(credentials, project_id, _scan_ctx=None):
    url = f"https://storage.googleapis.com/storage/v1/b?project={project_id}"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_buckets = []
    if data:
        for bucket in data.get('items', []):
            if bucket.get('iamConfiguration', {}).get('publicAccessPrevention') != 'enforced':
                vulnerable_buckets.append({
                    'BucketName': bucket['name'],
                    'Issue': 'Public access not prevented',
                    'Recommendation': 'Enable uniform bucket-level access and enforce public access prevention.'
                })
    return vulnerable_buckets

def analyze_compute_instances(credentials, project_id, _scan_ctx=None):
    url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_instances = []
    if data:
        for zone_instances in data.get('items', {}).values():
            for instance in zone_instances.get('instances', []):
                if any(interface.get('accessConfigs') for interface in instance.get('networkInterfaces', [])):
                    vulnerable_instances.append({
                        'InstanceName': instance['name'],
                        'Zone': instance['zone'].split('/')[-1],
                        'Issue': 'Public IP assigned',
                        'Recommendation': 'Review if public IP is necessary, consider using Cloud NAT for outbound connections.'
                    })
    return vulnerable_instances

def analyze_sql_instances(credentials, project_id, _scan_ctx=None):
    url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/instances"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_sql_instances = []
    if data:
        for instance in data.get('items', []):
            if not instance.get('settings', {}).get('ipConfiguration', {}).get('requireSsl'):
                vulnerable_sql_instances.append({
                    'InstanceName': instance['name'],
                    'Issue': 'SSL not required',
                    'Recommendation': 'Enable SSL/TLS for all database connections.'
                })
    return vulnerable_sql_instances

def analyze_gke_clusters(credentials, project_id, _scan_ctx=None):
    url = f"https://container.googleapis.com/v1/projects/{project_id}/locations/-/clusters"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_clusters = []
    if data:
        for cluster in data.get('clusters', []):
            if not cluster.get('privateClusterConfig', {}).get('enablePrivateNodes'):
                vulnerable_clusters.append({
                    'ClusterName': cluster['name'],
                    'Location': cluster['location'],
                    'Issue': 'Public cluster',
                    'Recommendation': 'Enable private clusters to restrict access to the control plane.'
                })
    return vulnerable_clusters

def analyze_cloud_functions(credentials, project_id, _scan_ctx=None):
    url = f"https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/-/functions"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_functions = []
    if data:
        for function in data.get('functions', []):
            if function.get('httpsTrigger'):
                vulnerable_functions.append({
                    'FunctionName': function['name'],
                    'Issue': 'Public HTTP trigger',
                    'Recommendation': 'Review if the function needs to be publicly accessible. Consider using Cloud Pub/Sub or Cloud Storage triggers instead.'
                })
    return vulnerable_functions

def analyze_bigquery_datasets(credentials, project_id, _scan_ctx=None):
    url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/datasets"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_datasets = []
    if data:
        for dataset in data.get('datasets', []):
            if any(access.get('specialGroup') == 'allAuthenticatedUsers' for access in dataset.get('access', [])):
                vulnerable_datasets.append({
                    'DatasetId': dataset['id'],
                    'Issue': 'Publicly accessible to all authenticated users',
                    'Recommendation': 'Restrict access to specific users or service accounts only.'
                })
    return vulnerable_datasets

def analyze_vpc_networks(credentials, project_id, _scan_ctx=None):
    url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/networks"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_networks = []
    if data:
        for network in data.get('items', []):
            if network.get('autoCreateSubnetworks'):
                vulnerable_networks.append({
                    'NetworkName': network['name'],
                    'Issue': 'Auto-mode network enabled',
                    'Recommendation': 'Use custom mode networks for better control over your network architecture.'
                })
    return vulnerable_networks

def analyze_firestore(credentials, project_id, _scan_ctx=None):
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_databases = []
    if data:
        for database in data.get('databases', []):
            if database.get('type') != 'FIRESTORE_NATIVE':
                vulnerable_databases.append({
                    'DatabaseName': database['name'],
                    'Issue': 'Not using Firestore Native mode',
                    'Recommendation': 'Consider migrating to Firestore Native mode for better scalability and features.'
                })
    return vulnerable_databases

def analyze_pubsub(credentials, project_id, _scan_ctx=None):
    url = f"https://pubsub.googleapis.com/v1/projects/{project_id}/topics"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_topics = []
    if data:
        for topic in data.get('topics', []):
            if not topic.get('kmsKeyName'):
                vulnerable_topics.append({
                    'TopicName': topic['name'],
                    'Issue': 'Customer-managed encryption key not used',
                    'Recommendation': 'Use customer-managed encryption keys for additional control over data encryption.'
                })
    return vulnerable_topics

def analyze_cloud_armor(credentials, project_id, _scan_ctx=None):
    url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/securityPolicies"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_policies = []
    if data:
        if not data.get('items'):
            vulnerable_policies.append({
                'Issue': 'No Cloud Armor security policies found',
                'Recommendation': 'Implement Cloud Armor security policies to protect your applications from DDoS and application-layer attacks.'
            })
    return vulnerable_policies

def analyze_cdn(credentials, project_id, _scan_ctx=None):
    url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/backendServices"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_services = []
    if data:
        for service in data.get('items', []):
            if not service.get('enableCDN'):
                vulnerable_services.append({
                    'ServiceName': service['name'],
                    'Issue': 'CDN not enabled',
                    'Recommendation': 'Enable Cloud CDN to improve performance and reduce latency for your users.'
                })
    return vulnerable_services

def analyze_app_engine(credentials, project_id, _scan_ctx=None):
    url = f"https://appengine.googleapis.com/v1/apps/{project_id}"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_apps = []
    if data:
        if not data.get('featureSettings', {}).get('splitHealthChecks'):
            vulnerable_apps.append({
                'AppId': data['id'],
                'Issue': 'Split health checks not enabled',
                'Recommendation': 'Enable split health checks for more granular control over instance health.'
            })
    return vulnerable_apps

def analyze_endpoints(credentials, project_id, _scan_ctx=None):
    url = f"https://apigateway.googleapis.com/v1/projects/{project_id}/locations/-/apis"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_apis = []
    if data:
        for api in data.get('apis', []):
            if not api.get('managedService'):
                vulnerable_apis.append({
                    'ApiName': api['name'],
                    'Issue': 'API not managed by Cloud Endpoints',
                    'Recommendation': 'Use Cloud Endpoints to manage, secure, and monitor your APIs.'
                })
    return vulnerable_apis

def analyze_dataflow(credentials, project_id, _scan_ctx=None):
    url = f"https://dataflow.googleapis.com/v1b3/projects/{project_id}/jobs"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_jobs = []
    if data:
        for job in data.get('jobs', []):
            if job.get('type') == 'JOB_TYPE_STREAMING' and not job.get('environment', {}).get('workerPools', [{}])[0].get('diskSizeGb'):
                vulnerable_jobs.append({
                    'JobName': job['name'],
                    'Issue': 'Worker persistent disk size not specified for streaming job',
                    'Recommendation': 'Specify worker persistent disk size for better performance in streaming jobs.'
                })
    return vulnerable_jobs

def analyze_dataproc(credentials, project_id, _scan_ctx=None):
    url = f"https://dataproc.googleapis.com/v1/projects/{project_id}/regions/-/clusters"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_clusters = []
    if data:
        for cluster in data.get('clusters', []):
            if not cluster.get('config', {}).get('encryptionConfig', {}).get('gcePdKmsKeyName'):
                vulnerable_clusters.append({
                    'ClusterName': cluster['clusterName'],
                    'Issue': 'Customer-managed encryption key not used',
                    'Recommendation': 'Use customer-managed encryption keys for additional control over data encryption in Dataproc clusters.'
                })
    return vulnerable_clusters

def analyze_monitoring(credentials, project_id, _scan_ctx=None):
    url = f"https://monitoring.googleapis.com/v3/projects/{project_id}/alertPolicies"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    # None = the API did not answer 200 (403 lands in denied_apis, reported as
    # coverage): not assessed, never a finding (2026-11-03).
    if data is not None and not data.get('alertPolicies'):
        return [{
            'Issue': 'No alert policies found',
            'Recommendation': 'Set up Cloud Monitoring alert policies to monitor the health and performance of your resources.'
        }]
    return []

def analyze_audit_logs(credentials, project_id, _scan_ctx=None):
    url = f"https://logging.googleapis.com/v2/projects/{project_id}/sinks"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    # None = not assessed (see analyze_monitoring), never a finding.
    if data is not None and not data.get('sinks'):
        return [{
            'Issue': 'No log sinks found',
            'Recommendation': 'Set up log sinks to export your audit logs to long-term storage or a SIEM system.'
        }]
    return []

def analyze_security_center(credentials, project_id, _scan_ctx=None):
    url = f"https://securitycenter.googleapis.com/v1/projects/{project_id}/sources"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    # None = not assessed (see analyze_monitoring), never a finding.
    if data is not None and not data.get('sources'):
        return [{
            'Issue': 'Security Command Center not configured',
            'Recommendation': 'Enable and configure Security Command Center to get a comprehensive view of your security posture.'
        }]
    return []

def analyze_secret_manager(credentials, project_id, _scan_ctx=None):
    url = f"https://secretmanager.googleapis.com/v1/projects/{project_id}/secrets"
    data = make_request(url, credentials, _scan_ctx=_scan_ctx)
    vulnerable_secrets = []
    if data:
        for secret in data.get('secrets', []):
            if not secret.get('replication', {}).get('userManaged'):
                vulnerable_secrets.append({
                    'SecretName': secret['name'],
                    'Issue': 'Automatic replication used',
                    'Recommendation': 'Use customer-managed replication for better control over secret distribution.'
                })
    return vulnerable_secrets

def generate_report(project_id, all_vulnerabilities):
    # Rule id + severity of every finding from the ONE rule table
    # (src/cloud/rule_severity, 2026-11-03); an unmapped item stays without
    # severity (undetermined) and is logged.
    _stamp_rule_severity(all_vulnerabilities.items())
    report = {
        'timestamp': datetime.now().isoformat(),
        'project_id': project_id,
        'vulnerabilities': all_vulnerabilities,
        'summary': {category: len(vulns) for category, vulns in all_vulnerabilities.items()},
        'general_recommendations': [
            "Regularly review and update your GCP security configurations.",
            "Implement the principle of least privilege for all resources and users.",
            "Enable Cloud Audit Logs for all projects.",
            "Use VPC Service Controls to create security perimeters around resources.",
            "Implement and maintain firewall rules to control network access.",
            "Use Security Command Center for centralized security management.",
            "Encrypt data at rest and in transit for all services.",
            "Regularly update and patch all systems and applications.",
            "Implement multi-factor authentication for all user accounts.",
            "Use Private Google Access for services that don't need public internet.",
            "Implement robust monitoring and alerting for all critical resources.",
            "Regularly perform security assessments and penetration testing.",
            "Use customer-managed encryption keys where possible for additional control.",
            "Implement and regularly review IAM policies and service accounts.",
            "Use Cloud KMS for centralized key management.",
            "Implement network segmentation using subnets and firewall rules.",
            "Use Cloud Identity-Aware Proxy (IAP) for secure access to resources.",
            "Implement and maintain a robust incident response plan.",
        ]
    }
    return report

def analyze_gcp_security(project_id=None):
    """Analyze one GCP project's security configuration with ADC credentials.

    Auth errors propagate. A report may carry 'scan_incomplete: True' and
    'denied_apis' when the identity lacks permissions: never a clean result.
    """
    credentials, adc_project = get_credentials()
    project_id = project_id or adc_project
    if not project_id:
        raise ValueError("no GCP project: pass --project or set one with "
                         "`gcloud config set project`")

    # Shared scan context: tracks total API calls and any permission-denied hits
    # so we can surface an "incomplete" warning instead of a silent clean result.
    _scan_ctx = {'total_calls': 0, 'denied_apis': []}

    all_vulnerabilities = {
        'iam_roles': analyze_iam_policies(credentials, project_id, _scan_ctx=_scan_ctx),
        'storage_buckets': analyze_storage_buckets(credentials, project_id, _scan_ctx=_scan_ctx),
        'compute_instances': analyze_compute_instances(credentials, project_id, _scan_ctx=_scan_ctx),
        'sql_instances': analyze_sql_instances(credentials, project_id, _scan_ctx=_scan_ctx),
        'gke_clusters': analyze_gke_clusters(credentials, project_id, _scan_ctx=_scan_ctx),
        'cloud_functions': analyze_cloud_functions(credentials, project_id, _scan_ctx=_scan_ctx),
        'bigquery_datasets': analyze_bigquery_datasets(credentials, project_id, _scan_ctx=_scan_ctx),
        'vpc_networks': analyze_vpc_networks(credentials, project_id, _scan_ctx=_scan_ctx),
        'firestore': analyze_firestore(credentials, project_id, _scan_ctx=_scan_ctx),
        'pubsub': analyze_pubsub(credentials, project_id, _scan_ctx=_scan_ctx),
        'cloud_armor': analyze_cloud_armor(credentials, project_id, _scan_ctx=_scan_ctx),
        'cdn': analyze_cdn(credentials, project_id, _scan_ctx=_scan_ctx),
        'app_engine': analyze_app_engine(credentials, project_id, _scan_ctx=_scan_ctx),
        'endpoints': analyze_endpoints(credentials, project_id, _scan_ctx=_scan_ctx),
        'dataflow': analyze_dataflow(credentials, project_id, _scan_ctx=_scan_ctx),
        'dataproc': analyze_dataproc(credentials, project_id, _scan_ctx=_scan_ctx),
        'monitoring': analyze_monitoring(credentials, project_id, _scan_ctx=_scan_ctx),
        'audit_logs': analyze_audit_logs(credentials, project_id, _scan_ctx=_scan_ctx),
        'security_center': analyze_security_center(credentials, project_id, _scan_ctx=_scan_ctx),
        'secret_manager': analyze_secret_manager(credentials, project_id, _scan_ctx=_scan_ctx),
    }

    report = generate_report(project_id, all_vulnerabilities)

    # --- Permission-denied incomplete-scan detection ---
    total_calls = _scan_ctx.get('total_calls', 0)
    denied_apis = _scan_ctx.get('denied_apis', [])
    denied_count = len(denied_apis)

    if total_calls > 0 and (denied_count / total_calls) >= _PERMISSION_DENIED_THRESHOLD:
        # Significant fraction of APIs were denied.  The 0-finding result is NOT
        # a clean bill of health — it's an under-permissioned scan.
        report['scan_incomplete'] = True
        report['scan_incomplete_reason'] = (
            f"Service account lacks permissions for {denied_count}/{total_calls} APIs checked. "
            f"Results are INCOMPLETE — this is NOT a clean bill of health. "
            f"Grant the service account the required roles and re-scan."
        )
        report['denied_apis'] = denied_apis
        logger.warning(
            f"GCP scan for project {project_id} is INCOMPLETE: "
            f"{denied_count}/{total_calls} API calls returned permission-denied. "
            f"Denied APIs: {denied_apis}"
        )
    elif denied_count > 0:
        # Some denials but below threshold — surface as a warning, not incomplete
        report['permission_warnings'] = denied_apis
        report['permission_warning_message'] = (
            f"Some APIs returned permission-denied ({denied_count}/{total_calls}). "
            f"Results may be missing coverage for: {', '.join(denied_apis)}"
        )

    return report
