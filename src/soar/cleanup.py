"""Cleanup Lambda - scheduled hourly via EventBridge.

Queries the target NACL for FrostStream deny rules, compares the
``FrostStream_TTL_<ip>`` tag against the current UTC time, deletes expired
entries, strips their tags and writes an ``EXPIRED`` status back to the
Snowflake ``CORE.NIDS_ALERTS`` table.
"""

import json
import time

from . import nacl


def list_expired(acl: dict, now: int = None) -> list[tuple[str, int, dict]]:
    return nacl.expired_blocks(acl, int(time.time()) if now is None else now)


def expire_blocks(client, nacl_id: str, *, now: int = None,
                  snowflake_update=None) -> dict:
    acl = nacl.describe_acl(client, nacl_id)
    expired = list_expired(acl, now)
    ips = []
    errors = []
    for ip, epoch, entry in expired:
        try:
            nacl.delete_block(client, nacl_id, ip, entry)
            ips.append(ip)
        except Exception as exc:  # noqa: BLE001
            errors.append({'src_ip': ip, 'error': str(exc)})
    updated = 0
    if ips and snowflake_update is not None:
        updated = snowflake_update(ips)
    elif ips:
        updated = snowflake_update_expired(ips)
    return {'expired': ips, 'count': len(ips), 'snowflake_updated': updated,
            'errors': errors}


def snowflake_update_expired(ips: list[str]) -> int:
    connect = _snowflake_connect()
    if connect is None:
        return 0
    conn = connect()
    try:
        with conn.cursor() as cur:
            placeholders = ', '.join(['%s'] * len(ips))
            details = json.dumps({'status': 'EXPIRED', 'source': 'cleanup-lambda'})
            cur.execute(
                f"UPDATE CORE.NIDS_ALERTS SET MITIGATION_STATUS = 'EXPIRED', "
                f"MITIGATED_AT = CURRENT_TIMESTAMP(), "
                f"MITIGATION_DETAILS = PARSE_JSON('{details}') "
                f"WHERE SRC_IP IN ({placeholders}) AND MITIGATION_STATUS = 'ACTIONED'",
                tuple(ips),
            )
            return int(cur.rowcount)
    finally:
        conn.close()


def _snowflake_connect():
    import os

    try:
        import snowflake.connector
    except ImportError:
        return None
    account = os.environ.get('SNOWFLAKE_ACCOUNT')
    user = os.environ.get('SNOWFLAKE_USER')
    password = os.environ.get('SNOWFLAKE_PASSWORD')
    if not account or not user or not password:
        return None
    params = {
        'account': account,
        'user': user,
        'password': password,
        'role': os.environ.get('SNOWFLAKE_ROLE', 'ACCOUNTADMIN'),
        'database': os.environ.get('SNOWFLAKE_DATABASE', 'FROSTSTREAM_NIDS'),
        'schema': os.environ.get('SNOWFLAKE_SCHEMA', 'CORE'),
        'warehouse': os.environ.get('SNOWFLAKE_WAREHOUSE', 'NIDS_ANALYTICS_WH'),
    }
    private_key_path = os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH')
    if private_key_path:
        from cryptography.hazmat.primitives import serialization

        with open(private_key_path, 'rb') as handle:
            key = serialization.load_pem_private_key(
                handle.read(),
                password=os.environ.get('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE'),
            )
        params['private_key'] = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        params.pop('password', None)

    def connect():
        return snowflake.connector.connect(**params)

    return connect


def lambda_handler(event, context):
    nacl_id = nacl.target_nacl_id()
    if not nacl_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'TARGET_NACL_ID_not_configured'})}
    import boto3

    result = expire_blocks(boto3.client('ec2'), nacl_id, snowflake_update=snowflake_update_expired)
    print(json.dumps(result))
    return {'statusCode': 200, 'body': json.dumps(result)}