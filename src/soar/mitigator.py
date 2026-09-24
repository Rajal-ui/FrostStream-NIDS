"""Mitigator Lambda - invoked by API Gateway on behalf of the Snowflake
external function ``CORE.EXTERNAL_MITIGATE_IP``.

Snowflake payload shape:
    {"data": [[<row_id>, src_ip, alert_id, confidence, attack_type], ...]}

Response shape (per Snowflake external-function protocol, one element per
input row, keyed by the same row_id):
    {"data": [[<row_id>, {"status": "ACTIONED|SUPPRESSED|FAILED", ...}], ...]}

Guardrails (defense in depth - the SQL already filters, this re-validates):
  * confidence must be strictly greater than 0.95,
  * the source IP must be a valid IPv4 address,
  * idempotency: an existing deny entry for the same /32 is never duplicated.
"""

import json

from . import nacl


def _parse_value(row, index):
    try:
        return row[index] if isinstance(row, (list, tuple)) and index < len(row) else None
    except (TypeError, IndexError):
        return None


def process_row(row, *, client=None, nacl_id=None, rule_start=None, rule_end=None,
                ttl=None, confidence_threshold: float = nacl.CONFIDENCE_THRESHOLD) -> dict:
    src_ip = _parse_value(row, 1)
    alert_id = _parse_value(row, 2)
    confidence = _parse_value(row, 3)
    attack_type = _parse_value(row, 4)

    reaction = {'alert_id': alert_id, 'attack_type': attack_type}

    try:
        if confidence is None or float(confidence) <= confidence_threshold:
            return {**reaction, 'status': 'SUPPRESSED', 'src_ip': src_ip,
                    'reason': 'below_confidence_threshold'}
        if src_ip is None or not nacl.is_valid_ipv4(src_ip):
            return {**reaction, 'status': 'FAILED', 'src_ip': src_ip, 'reason': 'invalid_ip'}
        if nacl_id is None:
            nacl_id = nacl.target_nacl_id()
        if not nacl_id:
            return {**reaction, 'status': 'FAILED', 'src_ip': src_ip,
                    'reason': 'TARGET_NACL_ID_not_configured'}
        outcome = nacl.block_ip(
            client, nacl_id, src_ip,
            rule_start=rule_start, rule_end=rule_end, ttl=ttl,
        )
        return {**reaction, **outcome}
    except Exception as exc:  # noqa: BLE001 - one bad row must not kill the batch
        return {**reaction, 'status': 'FAILED', 'src_ip': src_ip, 'reason': str(exc)}


def process_rows(data, *, client=None, nacl_id=None, rule_start=None, rule_end=None,
                 ttl=None) -> list[tuple[int, dict]]:
    if client is None:
        import boto3

        client = boto3.client('ec2')
    responses = []
    for row in data or []:
        if not isinstance(row, (list, tuple)):
            continue
        responses.append((row[0], process_row(
            row, client=client, nacl_id=nacl_id, rule_start=rule_start,
            rule_end=rule_end, ttl=ttl,
        )))
    return responses


def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body') or '{}')
        data = body.get('data', [])
    except (TypeError, ValueError):
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'malformed_request'}),
        }
    try:
        responses = process_rows(data)
    except Exception as exc:  # noqa: BLE001
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': str(exc)}),
        }
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'data': responses}),
    }