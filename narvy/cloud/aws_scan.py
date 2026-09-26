"""AWS posture checks (security groups, IAM, storage, logging) across enabled regions."""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import json
from datetime import datetime
import time
import os

import logging

logger = logging.getLogger(__name__)

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


SEV_CRITICAL = 'critical'
SEV_HIGH = 'high'
SEV_MEDIUM = 'medium'
SEV_LOW = 'low'
SEV_INFO = 'info'

# Web ports are deliberately absent: world-open is their normal configuration.
SENSITIVE_PORTS = {
    22: ('SSH', SEV_CRITICAL),
    3389: ('RDP', SEV_CRITICAL),
    3306: ('MySQL/MariaDB', SEV_CRITICAL),
    5432: ('PostgreSQL', SEV_CRITICAL),
    6379: ('Redis', SEV_CRITICAL),
    27017: ('MongoDB', SEV_CRITICAL),
    1433: ('MSSQL', SEV_CRITICAL),
    9200: ('Elasticsearch', SEV_HIGH),
    9300: ('Elasticsearch transport', SEV_HIGH),
    5601: ('Kibana', SEV_HIGH),
    11211: ('Memcached', SEV_HIGH),
    23: ('Telnet', SEV_CRITICAL),
    21: ('FTP', SEV_HIGH),
    2375: ('Docker API', SEV_CRITICAL),
    2376: ('Docker API (TLS)', SEV_HIGH),
    5984: ('CouchDB', SEV_HIGH),
    7001: ('WebLogic', SEV_HIGH),
    8020: ('Hadoop', SEV_HIGH),
    9000: ('Misc admin', SEV_MEDIUM),
}

WEB_PORTS = {80, 443, 8080, 8443}

_SEV_ORDER = {SEV_CRITICAL: 4, SEV_HIGH: 3, SEV_MEDIUM: 2, SEV_LOW: 1, SEV_INFO: 0}


def _port_range(rule):
    """Return (from_port, to_port) for an IpPermission rule."""
    proto = rule.get('IpProtocol')
    if proto == '-1':
        return (0, 65535)
    fp = rule.get('FromPort')
    tp = rule.get('ToPort')
    if fp is None and tp is None:
        return (0, 65535)
    if fp is None:
        fp = tp
    if tp is None:
        tp = fp
    return (fp, tp)


def _classify_open_rule(from_port, to_port):
    """Given a port range open to 0.0.0.0/0, return (severity, label)."""
    span = to_port - from_port
    if from_port == 0 and to_port == 65535:
        return (SEV_CRITICAL, 'ALL ports (0-65535)')

    hits = []
    for port, (name, sev) in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            hits.append((sev, f'{name} ({port})'))
    if hits:
        hits.sort(key=lambda h: _SEV_ORDER[h[0]], reverse=True)
        return (hits[0][0], ', '.join(h[1] for h in hits))

    covered = set(range(from_port, to_port + 1)) if span <= 64 else None
    if covered is not None and covered and covered.issubset(WEB_PORTS):
        return (SEV_INFO, 'web port(s)')

    if span > 64:
        return (SEV_MEDIUM, f'wide range {from_port}-{to_port}')

    return (SEV_MEDIUM, f'port {from_port}-{to_port}')

def _boto3_client(service, endpoint_url=None, **kwargs):
    """boto3.client wrapper threading an optional endpoint_url override."""
    if endpoint_url is not None:
        kwargs['endpoint_url'] = endpoint_url
    return boto3.client(service, **kwargs)


def get_all_regions(endpoint_url=None):
    logger.info(f"getting all regions ...")

    ec2 = _boto3_client('ec2', endpoint_url=endpoint_url, region_name='us-east-1')
    response = ec2.describe_regions()
    logger.info(f"all regions got")

    return [region['RegionName'] for region in response['Regions']]

def analyze_security_groups(region, endpoint_url=None):
    """Flag security-group rules exposing ports to 0.0.0.0/0, one finding per rule."""
    ec2 = _boto3_client('ec2', endpoint_url=endpoint_url, region_name=region)
    response = ec2.describe_security_groups()
    vulnerable_groups = []

    for sg in response['SecurityGroups']:
        for rule in sg['IpPermissions']:
            open_cidrs = [r['CidrIp'] for r in rule.get('IpRanges', [])
                          if r.get('CidrIp') == '0.0.0.0/0']
            if not open_cidrs:
                continue

            from_port, to_port = _port_range(rule)
            severity, label = _classify_open_rule(from_port, to_port)
            proto = rule.get('IpProtocol', '-1')
            proto_label = 'all' if proto == '-1' else proto
            if from_port == to_port:
                port_str = str(from_port)
            else:
                port_str = f'{from_port}-{to_port}'

            if severity == SEV_INFO:
                issue = (f"Web port(s) {port_str}/{proto_label} open to 0.0.0.0/0 "
                         f"(expected for an internet-facing web server)")
                rec = ("This is normal for a public web server. Confirm the host is "
                       "intended to be internet-facing; otherwise restrict the CIDR.")
            else:
                issue = (f"Sensitive port(s) {label} ({port_str}/{proto_label}) "
                         f"open to 0.0.0.0/0")
                rec = (f"Restrict {port_str}/{proto_label} to specific CIDRs or a "
                       f"bastion/security-group reference. Exposing {label} to the "
                       f"entire internet is a direct attack surface.")

            vulnerable_groups.append({
                'GroupId': sg['GroupId'],
                'GroupName': sg['GroupName'],
                'VpcId': sg.get('VpcId'),
                'OpenPorts': port_str,
                'Protocol': proto_label,
                'CidrIp': '0.0.0.0/0',
                'Region': region,
                'severity': severity,
                'Issue': issue,
                'Recommendation': rec,
            })

    return vulnerable_groups

def analyze_s3_buckets(endpoint_url=None):
    s3 = _boto3_client('s3', endpoint_url=endpoint_url)
    response = s3.list_buckets()
    vulnerable_buckets = []

    for bucket in response['Buckets']:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    vulnerable_buckets.append({
                        'BucketName': bucket['Name'],
                        'PublicAccess': True,
                        'severity': SEV_CRITICAL,
                        'Issue': 'S3 bucket grants public access to AllUsers',
                        'Recommendation': "Remove public access to this bucket unless it's explicitly required. Use AWS S3 Block Public Access feature and review bucket policies."
                    })
                    break
        except ClientError as e:
            logger.error(f"Error checking ACL for bucket {bucket['Name']}: {str(e)}")
    
    return vulnerable_buckets

def _has_console_access(iam, user_name):
    """True iff the IAM user has a console login profile."""
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return False
        # Any other error: assume console user rather than drop a real human.
        logger.error(f"login-profile check failed for {user_name}: {e}")
        return True


def analyze_iam_users(endpoint_url=None):
    """Flag missing MFA, for console users only: MFA does not apply to API keys."""
    iam = _boto3_client('iam', endpoint_url=endpoint_url)
    response = iam.list_users()
    users_without_mfa = []

    for user in response['Users']:
        if not _has_console_access(iam, user['UserName']):
            continue
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
        if not mfa_devices['MFADevices']:
            users_without_mfa.append({
                'UserName': user['UserName'],
                'UserId': user['UserId'],
                'CreateDate': user['CreateDate'].isoformat(),
                'severity': SEV_MEDIUM,
                'Issue': f"Console user {user['UserName']} has no MFA device",
                'Recommendation': "Enable Multi-Factor Authentication (MFA) for this console user to enhance account security."
            })

    return users_without_mfa

def _as_list(value):
    """IAM policy fields can be a scalar or a list; normalize to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statement_is_wildcard_admin(stmt):
    """Returns (is_admin, has_action_wildcard, has_resource_wildcard)."""
    if not isinstance(stmt, dict):
        return (False, False, False)
    if stmt.get('Effect') != 'Allow':
        return (False, False, False)
    actions = _as_list(stmt.get('Action'))
    resources = _as_list(stmt.get('Resource'))
    action_wild = any(a == '*' or (isinstance(a, str) and a.endswith(':*'))
                      for a in actions)
    full_action_wild = any(a == '*' for a in actions)
    resource_wild = any(r == '*' for r in resources)
    return (full_action_wild and resource_wild, action_wild, resource_wild)


def analyze_iam_policies(endpoint_url=None):
    """Flag customer-managed policies whose statements grant wildcard access."""
    iam = _boto3_client('iam', endpoint_url=endpoint_url)
    policies = iam.list_policies(Scope='Local')['Policies']
    risky_policies = []

    for policy in policies:
        policy_version = iam.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )['PolicyVersion']

        document = policy_version['Document']
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except (ValueError, TypeError):
                continue

        worst = None
        for stmt in _as_list(document.get('Statement')):
            is_admin, action_wild, resource_wild = _statement_is_wildcard_admin(stmt)
            if is_admin:
                worst = (SEV_HIGH, 'Action:* on Resource:* (full admin)')
                break
            if action_wild and resource_wild:
                if worst is None:
                    worst = (SEV_MEDIUM, 'service-wide Action wildcard on Resource:*')

        if worst is not None:
            risky_policies.append({
                'PolicyName': policy['PolicyName'],
                'PolicyId': policy['PolicyId'],
                'Arn': policy['Arn'],
                'severity': worst[0],
                'Issue': f'Over-permissive policy: {worst[1]}',
                'Recommendation': "Restrict this policy: replace Action:*/Resource:* with the specific actions and resource ARNs the workload needs (least privilege)."
            })

    return risky_policies

def analyze_vpc_configuration(region, endpoint_url=None):
    """Report non-default VPCs with an internet-gateway default route, as INFO."""
    ec2 = _boto3_client('ec2', endpoint_url=endpoint_url, region_name=region)
    vpcs = ec2.describe_vpcs()['Vpcs']
    findings = []

    for vpc in vpcs:
        # Every default VPC ships an IGW public route, so it carries no signal.
        if vpc.get('IsDefault'):
            continue
        route_tables = ec2.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])['RouteTables']
        for rt in route_tables:
            for route in rt['Routes']:
                if (route.get('GatewayId', '').startswith('igw-')
                        and route.get('DestinationCidrBlock') == '0.0.0.0/0'):
                    findings.append({
                        'VpcId': vpc['VpcId'],
                        'RouteTableId': rt['RouteTableId'],
                        'Region': region,
                        'severity': SEV_INFO,
                        'Issue': 'Non-default VPC has a public (IGW) route for 0.0.0.0/0',
                        'Recommendation': ("Informational: this subnet is public. "
                                           "Confirm internet-facing workloads belong here.")
                    })
                    break

    return findings

def analyze_rds_instances(region, endpoint_url=None):
    rds = _boto3_client('rds', endpoint_url=endpoint_url, region_name=region)
    instances = rds.describe_db_instances()['DBInstances']
    vulnerable_instances = []

    for instance in instances:
        if not instance['StorageEncrypted']:
            vulnerable_instances.append({
                'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                'Engine': instance['Engine'],
                'severity': SEV_MEDIUM,
                'Issue': 'Unencrypted Storage',
                'Recommendation': 'Enable storage encryption for this RDS instance to protect data at rest.'
            })

        if instance['PubliclyAccessible']:
            vulnerable_instances.append({
                'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                'Engine': instance['Engine'],
                'severity': SEV_HIGH,
                'Issue': 'Publicly Accessible',
                'Recommendation': 'Disable public accessibility unless absolutely necessary. Use VPC and security groups to control access.'
            })

    return vulnerable_instances

def analyze_lambda_functions(region, endpoint_url=None):
    lambda_client = _boto3_client('lambda', endpoint_url=endpoint_url, region_name=region)
    functions = lambda_client.list_functions()['Functions']
    vulnerable_functions = []

    for function in functions:
        if not function.get('KMSKeyArn'):
            vulnerable_functions.append({
                'FunctionName': function['FunctionName'],
                'Region': region,
                'severity': SEV_LOW,
                'Issue': 'No customer-managed KMS Key for Environment Variables',
                'Recommendation': 'Use a customer-managed KMS key to encrypt environment variables (Lambda encrypts at rest with an AWS-managed key by default).'
            })

    return vulnerable_functions

def analyze_ecs_clusters(region, endpoint_url=None):
    ecs = _boto3_client('ecs', endpoint_url=endpoint_url, region_name=region)
    clusters = ecs.list_clusters()['clusterArns']
    vulnerable_clusters = []

    for cluster_arn in clusters:
        tasks = ecs.list_tasks(cluster=cluster_arn)['taskArns']
        for task_arn in tasks:
            task_details = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])['tasks'][0]
            if not task_details.get('containers')[0].get('networkInterfaces'):
                vulnerable_clusters.append({
                    'ClusterArn': cluster_arn,
                    'TaskArn': task_arn,
                    'Issue': 'Task using host network mode',
                    'Recommendation': 'Host network mode gives the task direct access to the host network namespace (host loopback, host-bound ports), bypassing the per-task elastic network interface and security group that awsvpc mode provides. Switch to awsvpc mode so this task gets its own isolated network interface.'
                })

    return vulnerable_clusters

def analyze_elastic_beanstalk(region, endpoint_url=None):
    eb = _boto3_client('elasticbeanstalk', endpoint_url=endpoint_url, region_name=region)
    environments = eb.describe_environments()['Environments']
    vulnerable_environments = []

    for env in environments:
        config = eb.describe_configuration_settings(
            ApplicationName=env['ApplicationName'],
            EnvironmentName=env['EnvironmentName']
        )
        
        for setting in config['ConfigurationSettings'][0]['OptionSettings']:
            if setting['OptionName'] == 'SecurityGroups' and setting['Value'] == '':
                vulnerable_environments.append({
                    'EnvironmentName': env['EnvironmentName'],
                    'ApplicationName': env['ApplicationName'],
                    'Issue': 'No Security Group Specified',
                    'Recommendation': 'With no security group attached, this environment falls back to whatever AWS assigns by default (typically the VPC default security group), not one scoped to this application\'s actual ports. Attach a security group that allows only the ports this environment actually needs.'
                })
            elif setting['OptionName'] == 'SSLCertificateId' and setting['Value'] == '':
                vulnerable_environments.append({
                    'EnvironmentName': env['EnvironmentName'],
                    'ApplicationName': env['ApplicationName'],
                    'Issue': 'No SSL Certificate',
                    'Recommendation': 'Configure an SSL certificate to encrypt data in transit.'
                })

    return vulnerable_environments

def analyze_api_gateway(region, endpoint_url=None):
    apigw = _boto3_client('apigateway', endpoint_url=endpoint_url, region_name=region)
    apis = apigw.get_rest_apis()['items']
    vulnerable_apis = []

    for api in apis:
        stages = apigw.get_stages(restApiId=api['id'])['item']
        for stage in stages:
            if not stage.get('methodSettings') or not stage['methodSettings'].get('*/*', {}).get('dataTraceEnabled'):
                vulnerable_apis.append({
                    'ApiName': api['name'],
                    'StageName': stage['stageName'],
                    'Issue': 'Data Tracing Disabled',
                    'Recommendation': 'Without X-Ray tracing, a misbehaving or compromised backend integration leaves no per-request trace during an incident - there is no way to distinguish normal latency from a request that reached an unexpected downstream resource.'
                })

            if not stage.get('clientCertificateId'):
                vulnerable_apis.append({
                    'ApiName': api['name'],
                    'StageName': stage['stageName'],
                    'Issue': 'No Client-Side SSL Certificate',
                    'Recommendation': 'Without a client-side certificate, the backend integration cannot cryptographically verify a request actually came through this API Gateway stage, rather than a direct call to the backend that bypasses Gateway-level throttling and auth.'
                })

    return vulnerable_apis

def analyze_dynamodb(region, endpoint_url=None):
    dynamodb = _boto3_client('dynamodb', endpoint_url=endpoint_url, region_name=region)
    tables = dynamodb.list_tables()['TableNames']
    vulnerable_tables = []

    for table_name in tables:
        table = dynamodb.describe_table(TableName=table_name)['Table']
        if not table.get('SSEDescription') or table['SSEDescription']['Status'] != 'ENABLED':
            vulnerable_tables.append({
                'TableName': table_name,
                'Issue': 'Server-Side Encryption Not Enabled',
                'Recommendation': 'Enable server-side encryption to protect data at rest.'
            })
        
        if not table.get('StreamSpecification') or not table['StreamSpecification'].get('StreamEnabled'):
            vulnerable_tables.append({
                'TableName': table_name,
                'Issue': 'DynamoDB Streams Not Enabled',
                'Recommendation': 'Without Streams enabled, there is no change-data-capture record of item-level writes - an unauthorized modification or delete leaves no trail to reconstruct after the fact.'
            })

    return vulnerable_tables
def analyze_eks(region, endpoint_url=None):
    eks = _boto3_client('eks', endpoint_url=endpoint_url, region_name=region)
    clusters = eks.list_clusters()['clusters']
    vulnerable_clusters = []

    for cluster_name in clusters:
        cluster = eks.describe_cluster(name=cluster_name)['cluster']
        if not cluster['resourcesVpcConfig'].get('endpointPublicAccess'):
            vulnerable_clusters.append({
                'ClusterName': cluster_name,
                'Issue': 'No public access endpoint',
                'Recommendation': 'Consider enabling public access endpoint with restricted access for better management.'
            })
        if not cluster.get('encryptionConfig'):
            vulnerable_clusters.append({
                'ClusterName': cluster_name,
                'Issue': 'Encryption not configured',
                'Recommendation': 'Enable envelope encryption of Kubernetes secrets using AWS KMS.'
            })

    return vulnerable_clusters

def analyze_redshift(region, endpoint_url=None):
    redshift = _boto3_client('redshift', endpoint_url=endpoint_url, region_name=region)
    clusters = redshift.describe_clusters()['Clusters']
    vulnerable_clusters = []

    for cluster in clusters:
        if not cluster['Encrypted']:
            vulnerable_clusters.append({
                'ClusterIdentifier': cluster['ClusterIdentifier'],
                'Issue': 'Encryption not enabled',
                'Recommendation': 'Enable encryption for the Redshift cluster to protect data at rest.'
            })
        if cluster['PubliclyAccessible']:
            vulnerable_clusters.append({
                'ClusterIdentifier': cluster['ClusterIdentifier'],
                'Issue': 'Publicly accessible',
                'Recommendation': 'Disable public accessibility unless absolutely necessary. Use VPC endpoints for secure access.'
            })

    return vulnerable_clusters

def analyze_secrets_manager(region, endpoint_url=None):
    secrets = _boto3_client('secretsmanager', endpoint_url=endpoint_url, region_name=region)
    secret_list = secrets.list_secrets()['SecretList']
    vulnerable_secrets = []

    for secret in secret_list:
        if not secret.get('RotationEnabled'):
            vulnerable_secrets.append({
                'SecretName': secret['Name'],
                'Issue': 'Rotation not enabled',
                'Recommendation': 'Enable automatic rotation for the secret to enhance security.'
            })

    return vulnerable_secrets

def analyze_sqs(region, endpoint_url=None):
    sqs = _boto3_client('sqs', endpoint_url=endpoint_url, region_name=region)
    queues = sqs.list_queues()
    vulnerable_queues = []

    if 'QueueUrls' in queues:
        for queue_url in queues['QueueUrls']:
            attributes = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
            if 'Policy' in attributes['Attributes']:
                policy = json.loads(attributes['Attributes']['Policy'])
                for statement in policy['Statement']:
                    if statement['Effect'] == 'Allow' and statement['Principal'] == '*':
                        vulnerable_queues.append({
                            'QueueUrl': queue_url,
                            'severity': SEV_HIGH,
                            'Issue': 'Public access policy',
                            'Recommendation': 'Review and restrict the queue policy to prevent public access.'
                        })

    return vulnerable_queues

def analyze_sns(region, endpoint_url=None):
    sns = _boto3_client('sns', endpoint_url=endpoint_url, region_name=region)
    topics = sns.list_topics()['Topics']
    vulnerable_topics = []

    for topic in topics:
        attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
        if 'Policy' in attributes['Attributes']:
            policy = json.loads(attributes['Attributes']['Policy'])
            for statement in policy['Statement']:
                if statement['Effect'] == 'Allow' and statement['Principal'] == '*':
                    vulnerable_topics.append({
                        'TopicArn': topic['TopicArn'],
                        'severity': SEV_HIGH,
                        'Issue': 'Public access policy',
                        'Recommendation': 'Review and restrict the topic policy to prevent public access.'
                    })

    return vulnerable_topics


def analyze_glue(region, endpoint_url=None):
    glue = _boto3_client('glue', endpoint_url=endpoint_url, region_name=region)
    jobs = glue.get_jobs()['Jobs']
    vulnerable_jobs = []

    for job in jobs:
        if not job.get('SecurityConfiguration'):
            vulnerable_jobs.append({
                'JobName': job['Name'],
                'Issue': 'No Security Configuration',
                'Recommendation': 'Attach a security configuration to encrypt data and use job bookmarks.'
            })

    return vulnerable_jobs

def analyze_emr(region, endpoint_url=None):
    emr = _boto3_client('emr', endpoint_url=endpoint_url, region_name=region)
    clusters = emr.list_clusters(ClusterStates=['RUNNING', 'WAITING'])['Clusters']
    vulnerable_clusters = []

    for cluster in clusters:
        cluster_id = cluster['Id']
        cluster_info = emr.describe_cluster(ClusterId=cluster_id)['Cluster']
        
        if not cluster_info.get('KerberosAttributes'):
            vulnerable_clusters.append({
                'ClusterId': cluster_id,
                'Issue': 'Kerberos not enabled',
                'Recommendation': 'Enable Kerberos authentication for stronger security.'
            })
        
        if cluster_info['Ec2InstanceAttributes'].get('EmrManagedMasterSecurityGroup') == cluster_info['Ec2InstanceAttributes'].get('EmrManagedSlaveSecurityGroup'):
            vulnerable_clusters.append({
                'ClusterId': cluster_id,
                'Issue': 'Same security group for master and slave nodes',
                'Recommendation': 'Use separate security groups for master and slave nodes.'
            })

    return vulnerable_clusters

def check_cis_compliance(endpoint_url=None):
    iam = _boto3_client('iam', endpoint_url=endpoint_url)
    compliance_issues = []

    root_user = iam.get_account_summary()
    if root_user['SummaryMap']['AccountAccessKeysPresent'] > 0:
        compliance_issues.append({
            'CheckId': 'CIS 1.1',
            'severity': SEV_CRITICAL,
            'Issue': 'Root account has access keys',
            'Recommendation': ('Delete all access keys associated with the root '
                               'account immediately. Root keys grant unrestricted, '
                               'unrevocable account-wide access and cannot be scoped.')
        })

    users = iam.list_users()['Users']
    for user in users:
        try:
            login_profile = iam.get_login_profile(UserName=user['UserName'])
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            if login_profile and not mfa_devices:
                compliance_issues.append({
                    'CheckId': 'CIS 1.2',
                    'severity': SEV_MEDIUM,
                    'UserName': user['UserName'],
                    'Issue': f"User {user['UserName']} has console access without MFA",
                    'Recommendation': 'Enable MFA for all IAM users with console access.'
                })
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.error(f"Error checking MFA for user {user['UserName']}: {str(e)}")

    try:
        credential_report = None
        for _ in range(5):
            try:
                credential_report = iam.get_credential_report()['Content']
                break
            except ClientError as e:
                if e.response['Error']['Code'] == 'ReportNotPresent':
                    logger.error("Credential report not found. Generating new report...")
                    iam.generate_credential_report()
                    time.sleep(10)
                else:
                    raise

        if credential_report is None:
            logger.error("Failed to generate or retrieve credential report after multiple attempts.")
            return compliance_issues

        credential_report = credential_report.decode('utf-8').split('\n')
        for row in credential_report[1:]:
            user_data = row.split(',')
            if len(user_data) < 5:
                continue
            if user_data[3] == 'true' and user_data[4] != 'N/A' and user_data[4] != 'no_information':
                # Credential-report timestamps come either Z-suffixed or with
                # an explicit +00:00 offset; normalize both.
                _ts = user_data[4].strip().replace('Z', '+00:00')
                try:
                    last_used = datetime.fromisoformat(_ts)
                except ValueError:
                    last_used = datetime.strptime(_ts, "%Y-%m-%dT%H:%M:%S+00:00")
                if last_used.tzinfo is not None:
                    last_used = last_used.replace(tzinfo=None)
                if (datetime.now() - last_used).days > 90:
                    compliance_issues.append({
                        'CheckId': 'CIS 1.3',
                        'severity': SEV_LOW,
                        'Issue': f"User {user_data[0]} has unused credentials for over 90 days",
                        'Recommendation': 'Disable or remove unused credentials.'
                    })

    except Exception as e:
        logger.error(f"Error processing credential report: {str(e)}")

    return compliance_issues

def analyze_kms(region, endpoint_url=None):
    kms = _boto3_client('kms', endpoint_url=endpoint_url, region_name=region)
    keys = kms.list_keys()['Keys']
    vulnerable_keys = []

    for key in keys:
        key_info = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
        if not key_info.get('KeyManager') == 'AWS':
            if not key_info.get('Enabled'):
                vulnerable_keys.append({
                    'KeyId': key['KeyId'],
                    'Issue': 'Disabled key',
                    'Recommendation': 'Review and enable the key if needed, or schedule for deletion.'
                })
            if not kms.get_key_rotation_status(KeyId=key['KeyId'])['KeyRotationEnabled']:
                vulnerable_keys.append({
                    'KeyId': key['KeyId'],
                    'Issue': 'Key rotation not enabled',
                    'Recommendation': 'Without rotation, the same key material stays in use indefinitely - anyone who obtains the key (via a leaked grant, an over-permissioned IAM policy, or a past compromise) retains decrypt capability forever. Automatic rotation limits how much data any single key version protects.'
                })

    return vulnerable_keys

def analyze_config(region, endpoint_url=None):
    config = _boto3_client('config', endpoint_url=endpoint_url, region_name=region)
    recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
    issues = []

    if not recorders:
        issues.append({
            'severity': SEV_MEDIUM,
            'Issue': 'AWS Config not enabled',
            'Recommendation': 'Enable AWS Config to track resource inventory and changes.'
        })
    else:
        for recorder in recorders:
            if not recorder.get('recordingGroup', {}).get('allSupported'):
                issues.append({
                    'RecorderName': recorder['name'],
                    'severity': SEV_LOW,
                    'Issue': 'Not recording all supported resource types',
                    'Recommendation': 'Configure AWS Config to record all supported resource types.'
                })

    return issues

def analyze_cloudtrail(region, endpoint_url=None):
    cloudtrail = _boto3_client('cloudtrail', endpoint_url=endpoint_url, region_name=region)
    trails = cloudtrail.describe_trails()['trailList']
    issues = []

    if not trails:
        issues.append({
            'severity': SEV_HIGH,
            'Issue': 'No CloudTrail trails configured',
            'Recommendation': 'Set up a CloudTrail trail to log AWS account activity.'
        })
    else:
        for trail in trails:
            if not trail.get('IsMultiRegionTrail'):
                issues.append({
                    'TrailName': trail['Name'],
                    'severity': SEV_MEDIUM,
                    'Issue': 'Trail is not multi-region',
                    'Recommendation': 'Configure the trail to log events from all regions for comprehensive auditing.'
                })
            if not trail.get('LogFileValidationEnabled'):
                issues.append({
                    'TrailName': trail['Name'],
                    'severity': SEV_LOW,
                    'Issue': 'Log file validation not enabled',
                    'Recommendation': 'Enable log file validation to ensure the integrity of your logs.'
                })

    return issues

def analyze_cloudwatch(region, endpoint_url=None):
    cloudwatch = _boto3_client('cloudwatch', endpoint_url=endpoint_url, region_name=region)
    logs = _boto3_client('logs', endpoint_url=endpoint_url, region_name=region)
    alarms = cloudwatch.describe_alarms()['MetricAlarms']
    log_groups = logs.describe_log_groups()['logGroups']
    issues = []

    if not alarms:
        issues.append({
            'severity': SEV_INFO,
            'Issue': 'No CloudWatch alarms configured',
            'Recommendation': 'Set up CloudWatch alarms to monitor key metrics and receive notifications.'
        })

    for log_group in log_groups:
        if not log_group.get('retentionInDays'):
            issues.append({
                'LogGroupName': log_group['logGroupName'],
                'severity': SEV_INFO,
                'Issue': 'No retention period set',
                'Recommendation': 'Set a retention period for the log group to manage storage and comply with policies.'
            })

    return issues

def _compute_passed_checks(report_lists):
    """Build the list of account-level controls that produced no finding."""
    passed = []

    def _passed(control, detail):
        passed.append({'control': control, 'status': 'pass', 'detail': detail})

    cis = report_lists.get('cis_compliance') or []
    if not any(c.get('CheckId') == 'CIS 1.1' for c in cis if isinstance(c, dict)):
        _passed('CIS 1.1 - root account has no access keys',
                'No access keys on the root account.')
    if not any(c.get('CheckId') == 'CIS 1.2' for c in cis if isinstance(c, dict)):
        _passed('CIS 1.2 - all console users have MFA',
                'No console user is missing MFA.')

    ct = report_lists.get('cloudtrail') or []
    if not any('No CloudTrail' in str(c.get('Issue', '')) for c in ct if isinstance(c, dict)):
        _passed('CloudTrail enabled', 'At least one CloudTrail trail is configured.')

    cfg = report_lists.get('config') or []
    if not any('not enabled' in str(c.get('Issue', '')).lower() for c in cfg if isinstance(c, dict)):
        _passed('AWS Config enabled', 'A configuration recorder is present.')

    if not (report_lists.get('s3_buckets') or []):
        _passed('No public S3 buckets', 'No bucket grants public AllUsers access.')

    sgs = report_lists.get('ec2_security_groups') or []
    if not any(isinstance(s, dict) and s.get('severity') in (SEV_CRITICAL, SEV_HIGH)
               for s in sgs):
        _passed('No sensitive ports open to 0.0.0.0/0',
                'No SSH/RDP/DB/cache port exposed to the internet.')

    rds = report_lists.get('rds_instances') or []
    if not any('Publicly' in str(r.get('Issue', '')) for r in rds if isinstance(r, dict)):
        _passed('No publicly-accessible RDS instances',
                'No RDS instance is publicly accessible.')

    return passed


def generate_report(vulnerable_groups, vulnerable_buckets, users_without_mfa, risky_policies, vulnerable_vpcs,
                    vulnerable_rds, vulnerable_lambdas, vulnerable_ecs, vulnerable_eb, vulnerable_apis,
                    vulnerable_dynamodb, vulnerable_cf, gd_issues, waf_issues, vulnerable_eks,
                    vulnerable_redshift, vulnerable_secrets, vulnerable_sqs, vulnerable_sns,
                    vulnerable_glue_jobs, vulnerable_emr_clusters, compliance_issues,
                    vulnerable_kms_keys, config_issues, cloudtrail_issues, cloudwatch_issues):
    report = {
        'timestamp': datetime.now().isoformat(),
        'ec2_security_groups': vulnerable_groups,
        's3_buckets': vulnerable_buckets,
        'iam_users': users_without_mfa,
        'iam_policies': risky_policies,
        'vpc_configuration': vulnerable_vpcs,
        'rds_instances': vulnerable_rds,
        'lambda_functions': vulnerable_lambdas,
        'ecs_clusters': vulnerable_ecs,
        'elastic_beanstalk': vulnerable_eb,
        'api_gateway': vulnerable_apis,
        'dynamodb': vulnerable_dynamodb,
        'cloudfront': vulnerable_cf,
        'guardduty': gd_issues,
        'waf': waf_issues,
        'eks_clusters': vulnerable_eks,
        'redshift_clusters': vulnerable_redshift,
        'secrets_manager': vulnerable_secrets,
        'sqs_queues': vulnerable_sqs,
        'sns_topics': vulnerable_sns,
        'glue_jobs': vulnerable_glue_jobs,
        'emr_clusters': vulnerable_emr_clusters,
        'cis_compliance': compliance_issues,
        'kms_keys': vulnerable_kms_keys,
        'config': config_issues,
        'cloudtrail': cloudtrail_issues,
        'cloudwatch': cloudwatch_issues,
        'summary': {
            'vulnerable_security_groups': len(vulnerable_groups),
            'vulnerable_s3_buckets': len(vulnerable_buckets),
            'users_without_mfa': len(users_without_mfa),
            'risky_iam_policies': len(risky_policies),
            'vulnerable_vpcs': len(vulnerable_vpcs),
            'vulnerable_rds_instances': len(vulnerable_rds),
            'vulnerable_lambda_functions': len(vulnerable_lambdas),
            'vulnerable_ecs_clusters': len(vulnerable_ecs),
            'vulnerable_elastic_beanstalk': len(vulnerable_eb),
            'vulnerable_api_gateway': len(vulnerable_apis),
            'vulnerable_dynamodb_tables': len(vulnerable_dynamodb),
            'vulnerable_cloudfront_distributions': len(vulnerable_cf),
            'guardduty_issues': len(gd_issues),
            'waf_issues': len(waf_issues),
            'vulnerable_eks_clusters': len(vulnerable_eks),
            'vulnerable_redshift_clusters': len(vulnerable_redshift),
            'vulnerable_secrets': len(vulnerable_secrets),
            'vulnerable_sqs_queues': len(vulnerable_sqs),
            'vulnerable_sns_topics': len(vulnerable_sns),
            'vulnerable_glue_jobs': len(vulnerable_glue_jobs),
            'vulnerable_emr_clusters': len(vulnerable_emr_clusters),
            'cis_compliance_issues': len(compliance_issues),
            'vulnerable_kms_keys': len(vulnerable_kms_keys),
            'config_issues': len(config_issues),
            'cloudtrail_issues': len(cloudtrail_issues),
            'cloudwatch_issues': len(cloudwatch_issues)
        }
    }

    category_default_sev = {
        'ec2_security_groups': SEV_MEDIUM,
        's3_buckets': SEV_CRITICAL,
        'iam_users': SEV_MEDIUM,
        'iam_policies': SEV_MEDIUM,
        'vpc_configuration': SEV_INFO,
        'rds_instances': SEV_MEDIUM,
        'lambda_functions': SEV_LOW,
        'ecs_clusters': SEV_LOW,
        'elastic_beanstalk': SEV_LOW,
        'api_gateway': SEV_LOW,
        'dynamodb': SEV_LOW,
        'cloudfront': SEV_LOW,
        'guardduty': SEV_HIGH,
        'waf': SEV_LOW,
        'eks_clusters': SEV_MEDIUM,
        'redshift_clusters': SEV_MEDIUM,
        'secrets_manager': SEV_LOW,
        'sqs_queues': SEV_HIGH,
        'sns_topics': SEV_HIGH,
        'glue_jobs': SEV_LOW,
        'emr_clusters': SEV_LOW,
        'cis_compliance': SEV_MEDIUM,
        'kms_keys': SEV_MEDIUM,
        'config': SEV_MEDIUM,
        'cloudtrail': SEV_HIGH,
        'cloudwatch': SEV_INFO,
    }
    severity_counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0,
                       SEV_LOW: 0, SEV_INFO: 0}
    for category, default_sev in category_default_sev.items():
        items = report.get(category) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            sev = str(item.get('severity', '')).lower()
            if sev not in severity_counts:
                sev = default_sev
                item['severity'] = sev
            severity_counts[sev] += 1

    report['severity_summary'] = severity_counts
    report['total_findings'] = sum(severity_counts.values())

    report['passed_checks'] = _compute_passed_checks(report)

    return report

def analyze_waf(region, endpoint_url=None):
    waf_regional = _boto3_client('waf-regional', endpoint_url=endpoint_url, region_name=region)
    waf_global = _boto3_client('waf', endpoint_url=endpoint_url, region_name='us-east-1')  # WAF global lives only in us-east-1
    issues = []

    try:
        regional_web_acls = waf_regional.list_web_acls()['WebACLs']
        for acl in regional_web_acls:
            rules = waf_regional.get_web_acl(WebACLId=acl['WebACLId'])['WebACL']['Rules']
            if not rules:
                issues.append({
                    'WebACLId': acl['WebACLId'],
                    'Name': acl['Name'],
                    'Type': 'Regional',
                    'Region': region,
                    'Issue': 'No rules in Web ACL',
                    'Recommendation': 'Add rules to the regional Web ACL to protect against common web exploits.'
                })
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f"No access to WAF in region {region}. Skipping.")
        else:
            logger.error(f"Error accessing regional WAF in {region}: {str(e)}")

    try:
        global_web_acls = waf_global.list_web_acls()['WebACLs']
        for acl in global_web_acls:
            rules = waf_global.get_web_acl(WebACLId=acl['WebACLId'])['WebACL']['Rules']
            if not rules:
                issues.append({
                    'WebACLId': acl['WebACLId'],
                    'Name': acl['Name'],
                    'Type': 'Global',
                    'Issue': 'No rules in Web ACL',
                    'Recommendation': 'Add rules to the global Web ACL to protect against common web exploits.'
                })
    except ClientError as e:
        logger.error(f"Error accessing global WAF: {str(e)}")

    return issues

def analyze_cloudfront(endpoint_url=None):
    cf = _boto3_client('cloudfront', endpoint_url=endpoint_url)
    distributions = cf.list_distributions()['DistributionList']['Items'] if 'Items' in cf.list_distributions()['DistributionList'] else []
    vulnerable_distributions = []

    for dist in distributions:
        if not dist['ViewerCertificate'].get('CloudFrontDefaultCertificate') and not dist['ViewerCertificate'].get('ACMCertificateArn'):
            vulnerable_distributions.append({
                'DistributionId': dist['Id'],
                'DomainName': dist['DomainName'],
                'Issue': 'No SSL/TLS Certificate',
                'Recommendation': 'Configure a custom SSL/TLS certificate or use the CloudFront default certificate.'
            })
        
        if not dist['WebACLId']:
            vulnerable_distributions.append({
                'DistributionId': dist['Id'],
                'DomainName': dist['DomainName'],
                'Issue': 'No Web ACL associated',
                'Recommendation': 'With no Web ACL, this distribution has no layer-7 filtering in front of it - common exploit patterns (SQLi/XSS payloads, known bad IPs, rate-abuse) reach the origin unfiltered. Associate a WAF Web ACL to filter these before they hit the origin.'
            })

    return vulnerable_distributions

def analyze_guardduty(region, endpoint_url=None):
    gd = _boto3_client('guardduty', endpoint_url=endpoint_url, region_name=region)
    detectors = gd.list_detectors()['DetectorIds']
    issues = []

    for detector_id in detectors:
        detector = gd.get_detector(DetectorId=detector_id)
        if not detector['Status'] == 'ENABLED':
            issues.append({
                'DetectorId': detector_id,
                'Issue': 'GuardDuty Disabled',
                'Recommendation': 'With GuardDuty disabled, this region has no automated detection for compromised credentials, reconnaissance, or known-malicious IP/domain activity against this account - an active intrusion would go unnoticed until it surfaces some other way. Enable GuardDuty in this region.'
            })
        
        findings = gd.list_findings(DetectorId=detector_id, FindingCriteria={'Criterion': {'severity': {'Gte': 7}}})
        if findings['FindingIds']:
            issues.append({
                'DetectorId': detector_id,
                'Issue': f"{len(findings['FindingIds'])} High Severity Findings",
                'Recommendation': 'Investigate and address high severity GuardDuty findings.'
            })

    return issues
def _verify_credentials(endpoint_url=None):
    """Raise immediately if boto3 cannot authenticate at all."""
    sts = _boto3_client('sts', endpoint_url=endpoint_url, region_name='us-east-1')
    try:
        sts.get_caller_identity()
    except NoCredentialsError as e:
        raise RuntimeError(
            "No AWS credentials found (checked ~/.aws/credentials, env vars, "
            "IAM role). Run `aws configure` or set AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY, then re-run."
        ) from e
    except EndpointConnectionError as e:
        raise RuntimeError(f"Could not reach the AWS STS endpoint: {e}") from e
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', 'Unknown')
        raise RuntimeError(
            f"AWS rejected these credentials ({code}: "
            f"{e.response.get('Error', {}).get('Message', str(e))}). "
            f"They may be expired, revoked, or malformed - run `aws sts "
            f"get-caller-identity` yourself to confirm, then re-run."
        ) from e


def analyze_aws_security(credentials, region=None, endpoint_url=None):
    """Run every posture check and return the report; credentials={} or None uses boto3's ambient chain."""
    original_env = {}
    env_keys = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']
    for key in env_keys:
        original_env[key] = os.environ.get(key)

    has_explicit_creds = bool(credentials and credentials.get('aws_access_key_id'))

    try:
        # Only set env vars when credentials are passed explicitly: writing
        # empty strings would clobber an ambient aws configure credential.
        if has_explicit_creds:
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '')
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '')
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials['aws_session_token']

        logger.info("Starting AWS Security Analysis (programmatic)...")

        # Deliberately not wrapped: an auth failure must propagate instead of
        # letting the per-check handlers below report an empty, clean scan.
        _verify_credentials(endpoint_url=endpoint_url)

        # Analyzers that couldn't finish (AccessDenied, throttling), so a blind scan
        # shows up as a coverage gap instead of a clean pass.
        coverage_errors = []

        def _collect(dest, label, fn):
            try:
                dest.extend(fn())
            except Exception as e:
                coverage_errors.append(f"{label}: {e}")
                logger.error(f"Error analyzing {label}: {e}")

        all_vulnerable_groups = []
        all_vulnerable_vpcs = []
        all_vulnerable_rds = []
        all_vulnerable_lambdas = []
        all_vulnerable_ecs = []
        all_vulnerable_eb = []
        all_vulnerable_apis = []
        all_vulnerable_dynamodb = []
        all_gd_issues = []
        all_vulnerable_eks = []
        all_vulnerable_redshift = []
        all_vulnerable_secrets = []
        all_vulnerable_sqs = []
        all_vulnerable_sns = []
        all_vulnerable_glue_jobs = []
        all_vulnerable_emr_clusters = []
        all_vulnerable_kms_keys = []
        all_config_issues = []
        all_cloudtrail_issues = []
        all_cloudwatch_issues = []
        all_waf_issues = []

        try:
            if region:
                regions = [region]
            else:
                regions = get_all_regions(endpoint_url=endpoint_url)
            logger.info(f"Scanning {len(regions)} region(s)")
        except Exception as e:
            logger.error(f"Error getting regions: {str(e)}")
            coverage_errors.append(f"region enumeration (ec2:DescribeRegions): {e}")
            regions = []

        # Each analyzer is isolated: one AccessDenied must not skip its siblings for the region.
        for reg in regions:
            logger.info(f"Analyzing region: {reg}")
            _collect(all_vulnerable_groups, f"{reg}/ec2_security_groups", lambda r=reg: analyze_security_groups(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_vpcs, f"{reg}/vpc_configuration", lambda r=reg: analyze_vpc_configuration(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_rds, f"{reg}/rds_instances", lambda r=reg: analyze_rds_instances(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_lambdas, f"{reg}/lambda_functions", lambda r=reg: analyze_lambda_functions(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_ecs, f"{reg}/ecs_clusters", lambda r=reg: analyze_ecs_clusters(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_eb, f"{reg}/elastic_beanstalk", lambda r=reg: analyze_elastic_beanstalk(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_apis, f"{reg}/api_gateway", lambda r=reg: analyze_api_gateway(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_dynamodb, f"{reg}/dynamodb", lambda r=reg: analyze_dynamodb(r, endpoint_url=endpoint_url))
            _collect(all_gd_issues, f"{reg}/guardduty", lambda r=reg: analyze_guardduty(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_eks, f"{reg}/eks_clusters", lambda r=reg: analyze_eks(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_redshift, f"{reg}/redshift_clusters", lambda r=reg: analyze_redshift(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_secrets, f"{reg}/secrets_manager", lambda r=reg: analyze_secrets_manager(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_sqs, f"{reg}/sqs_queues", lambda r=reg: analyze_sqs(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_sns, f"{reg}/sns_topics", lambda r=reg: analyze_sns(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_glue_jobs, f"{reg}/glue_jobs", lambda r=reg: analyze_glue(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_emr_clusters, f"{reg}/emr_clusters", lambda r=reg: analyze_emr(r, endpoint_url=endpoint_url))
            _collect(all_vulnerable_kms_keys, f"{reg}/kms_keys", lambda r=reg: analyze_kms(r, endpoint_url=endpoint_url))
            _collect(all_waf_issues, f"{reg}/waf", lambda r=reg: analyze_waf(r, endpoint_url=endpoint_url))

        # Account-scoped checks: run once against the primary region only.
        primary_region = regions[0] if regions else (region or 'us-east-1')
        _collect(all_cloudtrail_issues, "cloudtrail", lambda: analyze_cloudtrail(primary_region, endpoint_url=endpoint_url))
        _collect(all_config_issues, "config", lambda: analyze_config(primary_region, endpoint_url=endpoint_url))
        _collect(all_cloudwatch_issues, "cloudwatch", lambda: analyze_cloudwatch(primary_region, endpoint_url=endpoint_url))

        vulnerable_buckets = []
        logger.info("Analyzing S3 Buckets...")
        _collect(vulnerable_buckets, "s3_buckets", lambda: analyze_s3_buckets(endpoint_url=endpoint_url))

        users_without_mfa = []
        logger.info("Analyzing IAM Users for MFA...")
        _collect(users_without_mfa, "iam_users", lambda: analyze_iam_users(endpoint_url=endpoint_url))

        risky_policies = []
        logger.info("Analyzing IAM Policies...")
        _collect(risky_policies, "iam_policies", lambda: analyze_iam_policies(endpoint_url=endpoint_url))

        vulnerable_cf = []
        logger.info("Analyzing CloudFront Distributions...")
        _collect(vulnerable_cf, "cloudfront", lambda: analyze_cloudfront(endpoint_url=endpoint_url))

        compliance_issues = []
        logger.info("Checking CIS Compliance...")
        _collect(compliance_issues, "cis_compliance", lambda: check_cis_compliance(endpoint_url=endpoint_url))

        logger.info("Generating report")
        report = generate_report(
            all_vulnerable_groups, vulnerable_buckets, users_without_mfa, risky_policies,
            all_vulnerable_vpcs, all_vulnerable_rds, all_vulnerable_lambdas, all_vulnerable_ecs,
            all_vulnerable_eb, all_vulnerable_apis, all_vulnerable_dynamodb, vulnerable_cf,
            all_gd_issues, all_waf_issues, all_vulnerable_eks, all_vulnerable_redshift,
            all_vulnerable_secrets, all_vulnerable_sqs, all_vulnerable_sns,
            all_vulnerable_glue_jobs, all_vulnerable_emr_clusters, compliance_issues,
            all_vulnerable_kms_keys, all_config_issues, all_cloudtrail_issues, all_cloudwatch_issues
        )

        # Coverage: a scan that could not read some services/regions is NOT a clean 0.
        report["coverage"] = {
            "status": "partial" if coverage_errors else "complete",
            "regions_scanned": len(regions),
            "checks_skipped": len(coverage_errors),
            "errors": coverage_errors,
        }

        logger.info("AWS security analysis complete")
        return report

    finally:
        for key in env_keys:
            if original_env[key] is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_env[key]


