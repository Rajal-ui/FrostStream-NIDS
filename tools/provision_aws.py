"""AWS provisioning for FrostStream NIDS Phase 1 (S3 landing bucket + IAM).

Role-based (OPTION A) path, idempotent:
  * IAM role ``SnowflakeFlowLogsRole`` with trust policy for Snowflake's IAM user
    (external ID enforced) and inline S3 policy on the landing bucket,
  * the landing S3 bucket with a ``flows/`` prefix,
  * S3 event notification -> Snowpipe's auto-ingest SQS queue.

Access-key (OPTION B) helpers for when cross-account AssumeRole is unavailable:
  * ``--ingest-user`` : dedicated low-priv IAM user ``froststream_ingest``
    (S3 read-only on the landing bucket), creates keys and writes
    ``AWS_INGEST_ACCESS_KEY_ID`` / ``AWS_INGEST_SECRET_ACCESS_KEY`` into .env,
  * ``--notify-only``  : ensure bucket + configure S3 -> pipe SQS notification.

Usage:
    python tools/provision_aws.py                 # role/bucket/notification (OPTION A)
    python tools/provision_aws.py --ingest-user   # create ingest IAM user + keys (OPTION B)
    python tools/provision_aws.py --notify-only   # bucket notification -> pipe (OPTION B)

Requires AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION /
AWS_ACCOUNT_ID in .env (or environment).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

ROLE_NAME = 'SnowflakeFlowLogsRole'
INGEST_USER = 'froststream_ingest'


def snowflake_integration_props(session) -> dict:
    rows = session.sql('DESCRIBE INTEGRATION S3_FLOW_INTEGRATION').collect()
    return {row.as_dict()['property']: row.as_dict()['property_value'] for row in rows}


def pipe_sqs_arn(session) -> str | None:
    rows = session.sql("SHOW PIPES LIKE 'PIPE_RAW_FLOW'").collect()
    for row in rows:
        record = row.as_dict()
        if record.get('name') == 'PIPE_RAW_FLOW':
            return record.get('notification_channel')
    return None


def ingest_read_policy(bucket: str) -> dict:
    return {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Action': ['s3:GetBucketLocation', 's3:ListBucket', 's3:GetObject'],
            'Resource': [f'arn:aws:s3:::{bucket}', f'arn:aws:s3:::{bucket}/flows/*'],
        }],
    }


def ensure_bucket(s3, bucket: str) -> None:
    try:
        s3.create_bucket(Bucket=bucket)
        print(f'Created bucket s3://{bucket}')
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        if code not in {'BucketAlreadyOwnedByYou', 'BucketAlreadyExists'}:
            print(f'!! bucket create/check: {exc}')


def ensure_ingest_user(iam, bucket: str) -> tuple[str, str | None]:
    """Create (or reuse) the low-priv ingest user; returns (access_key_id, secret)."""
    try:
        iam.get_user(UserName=INGEST_USER)
    except ClientError:
        iam.create_user(UserName=INGEST_USER)
        print(f'Created IAM user {INGEST_USER}')

    iam.put_user_policy(UserName=INGEST_USER, PolicyName='FrostStreamFlowIngestRead',
                        PolicyDocument=json.dumps(ingest_read_policy(bucket)))
    print(f'Attached read-only S3 policy to {INGEST_USER} for s3://{bucket}/flows/')

    if os.environ.get('AWS_INGEST_ACCESS_KEY_ID') and os.environ.get('AWS_INGEST_SECRET_ACCESS_KEY'):
        return os.environ['AWS_INGEST_ACCESS_KEY_ID'], None

    keys = iam.list_access_keys(UserName=INGEST_USER)['AccessKeyMetadata']
    active = [k['AccessKeyId'] for k in keys if k['Status'] == 'Active']
    if active:
        print(f'User already has {len(active)} active key(s); reuse existing .env entry or '
              'rotate in the AWS console')
        return active[0], None

    created = iam.create_access_key(UserName=INGEST_USER)['AccessKey']
    print(f'Created new access key {created["AccessKeyId"]} for {INGEST_USER}')
    return created['AccessKeyId'], created['SecretAccessKey']


def write_ingest_keys_to_env(access_key_id: str, secret: str | None) -> None:
    dotenv = REPO_ROOT / '.env'
    lines = dotenv.read_text(encoding='utf-8').splitlines() if dotenv.exists() else []
    if secret is None:
        return
    updates = {
        'AWS_INGEST_ACCESS_KEY_ID': access_key_id,
        'AWS_INGEST_SECRET_ACCESS_KEY': secret,
    }
    existing = {line.split('=', 1)[0] for line in lines if '=' in line and not line.lstrip().startswith('#')}
    for key, value in updates.items():
        if key in existing:
            continue
        lines.append(f'{key}={value}')
    dotenv.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Persisted {len(updates)} ingest key(s) to .env')


def configure_notification(s3, bucket: str, pipe_sqs: str | None) -> None:
    if not pipe_sqs:
        print('!! pipe notification_channel not found; event notification skipped')
        return
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            'QueueConfigurations': [{
                'Id': 'snowpipe-auto-ingest',
                'QueueArn': pipe_sqs,
                'Events': ['s3:ObjectCreated:*'],
                'Filter': {'Key': {'FilterRules': [{'Name': 'Prefix', 'Value': 'flows/'}]}},
            }]
        },
    )
    print(f'Bucket notification -> {pipe_sqs} (prefix flows/)')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-only', action='store_true',
                        help='create the IAM role + trust policy only (skip S3/notification)')
    parser.add_argument('--ingest-user', action='store_true',
                        help='create/reuse the low-priv S3 ingest IAM user + keys (OPTION B) and exit')
    parser.add_argument('--notify-only', action='store_true',
                        help='ensure bucket + SQS event notification for the pipe and exit')
    args = parser.parse_args(argv)

    from deploy_cloud import build_session, load_dotenv  # noqa: PLC0415

    load_dotenv()
    for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION', 'AWS_ACCOUNT_ID'):
        if not os.environ.get(key):
            raise SystemExit(f'Missing required AWS env var: {key}')

    import boto3  # noqa: F401, PLC0415

    region = os.environ['AWS_DEFAULT_REGION']
    aws_account = os.environ['AWS_ACCOUNT_ID']
    bucket = os.environ.get('S3_FLOW_BUCKET')
    role_arn = f'arn:aws:iam::{aws_account}:role/{ROLE_NAME}'

    if args.ingest_user:
        if not bucket:
            raise SystemExit('S3_FLOW_BUCKET not set in .env')
        iam = boto3.client('iam', region_name=region)
        key_id, secret = ensure_ingest_user(iam, bucket)
        write_ingest_keys_to_env(key_id, secret)
        print(f'\nIngest user ready: {INGEST_USER} (keys persisted to .env; not printed)')
        return 0

    iam = boto3.client('iam', region_name=region)
    s3 = boto3.client('s3', region_name=region)

    if args.notify_only:
        if not bucket:
            raise SystemExit('S3_FLOW_BUCKET not set in .env')
        ensure_bucket(s3, bucket)
        session = build_session()
        try:
            pipe_sqs = pipe_sqs_arn(session)
        finally:
            session.close()
        configure_notification(s3, bucket, pipe_sqs)
        print('\nNotification configuration complete.')
        return 0

    # --- OPTION A (role-based) full run ---
    session = build_session()
    try:
        props = snowflake_integration_props(session)
        iam_user_arn = props.get('STORAGE_AWS_IAM_USER_ARN')
        external_id = props.get('STORAGE_AWS_EXTERNAL_ID')
        if not iam_user_arn or not external_id:
            raise SystemExit(
                'DESCRIBE INTEGRATION did not return STORAGE_AWS_IAM_USER_ARN / '
                'STORAGE_AWS_EXTERNAL_ID (integration may need to be (re)created).'
            )
        print(f'Snowflake IAM user : {iam_user_arn}')
        print(f'External ID        : {external_id}')
        print(f'Configured role    : {props.get("STORAGE_AWS_ROLE_ARN", "")}')
        pipe_sqs = None if args.account_only else pipe_sqs_arn(session)
    finally:
        session.close()

    trust_doc = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': iam_user_arn},
            'Action': 'sts:AssumeRole',
            'Condition': {'StringEquals': {'sts:ExternalId': external_id}},
        }],
    }

    try:
        iam.get_role(RoleName=ROLE_NAME)
        created_role = False
    except ClientError:
        iam.create_role(RoleName=ROLE_NAME, AssumeRolePolicyDocument=json.dumps(trust_doc))
        created_role = True
        print(f'Created IAM role {ROLE_NAME}')
    current = iam.get_role(RoleName=ROLE_NAME)['Role']['AssumeRolePolicyDocument']
    current_ext = (
        current.get('Statement', [{}])[0].get('Condition', {}).get('StringEquals', {}).get('sts:ExternalId')
    )
    if current_ext == external_id and current.get('Statement', [{}])[0].get('Principal') == {'AWS': iam_user_arn}:
        print(f'Trust policy already aligned (external id {current_ext})')
    else:
        iam.update_assume_role_policy(RoleName=ROLE_NAME, PolicyDocument=json.dumps(trust_doc))
        print('Updated trust policy (external id mismatch or principal drift)')
    time.sleep(created_role and 5 or 1)

    if bucket:
        ensure_bucket(s3, bucket)
        if not args.account_only:
            inline_policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': ['s3:GetBucketLocation', 's3:ListBucket', 's3:GetObject', 's3:PutObject'],
                    'Resource': [f'arn:aws:s3:::{bucket}', f'arn:aws:s3:::{bucket}/flows/*'],
                }],
            }
            iam.put_role_policy(RoleName=ROLE_NAME, PolicyName='FrostStreamFlowIngestion',
                                PolicyDocument=json.dumps(inline_policy))
            print(f'Attached inline policy to {ROLE_NAME} for s3://{bucket}/flows/')
            configure_notification(s3, bucket, pipe_sqs)
        else:
            print('--account-only: skipped S3 bucket policy (still required for ingestion)')

    print(f'\nAWS provisioning complete. Role ARN: {role_arn}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())