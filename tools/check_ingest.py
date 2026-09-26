"""Quick health-check for the S3 -> Snowpipe ingestion path.

Prints the storage-integration vs IAM-role alignment (external id, principal)
and runs a LIST @CORE.S3_FLOW_STAGE to force an AssumeRole test.

Usage:
    python tools/check_ingest.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

import boto3
from botocore.exceptions import ClientError

from deploy_cloud import build_session, load_dotenv

load_dotenv()

s = build_session()
try:
    rows = s.sql('DESCRIBE INTEGRATION S3_FLOW_INTEGRATION').collect()
    props = {r.as_dict()['property']: r.as_dict()['property_value'] for r in rows}
    sf_ext = props.get('STORAGE_AWS_EXTERNAL_ID')
    sf_user = props.get('STORAGE_AWS_IAM_USER_ARN')
    sf_role = props.get('STORAGE_AWS_ROLE_ARN')
finally:
    s.close()

iam = boto3.client('iam', region_name='us-east-1')
print('integ S3_FLOW_INTEGRATION role     :', sf_role)
print('integ S3_FLOW_INTEGRATION iam_user :', sf_user)
try:
    doc = iam.get_role(RoleName='SnowflakeFlowLogsRole')['Role']['AssumeRolePolicyDocument']
    aws_ext = doc['Statement'][0]['Condition']['StringEquals']['sts:ExternalId']
    aws_user = doc['Statement'][0]['Principal']['AWS']
    print('role  trust ext   :', aws_ext, '(match:', sf_ext == aws_ext, ')')
    print('role  trust user  :', aws_user, '(match:', sf_user == aws_user, ')')
except ClientError as exc:
    print('role missing:', exc)

s = build_session()
try:
    rows = s.sql('LIST @CORE.S3_FLOW_STAGE').collect()
    print('LIST @CORE.S3_FLOW_STAGE OK, entries:', len(rows))
    return_code = 0
except Exception as exc:  # noqa: BLE001
    print('LIST @CORE.S3_FLOW_STAGE FAILED:', str(exc)[:200])
    return_code = 1
finally:
    s.close()

sys.exit(return_code)