"""Shared NACL manipulation + TTL helpers for the Phase 5 SOAR Lambdas.

NACL rules carry no user metadata, so per-IP TTLs are stored as tags on the
target ``AWS::EC2::NetworkAcl`` resource using keys ``FrostStream_TTL_<ip>``
mapped to the UTC expiry epoch. The mitigator writes them; the cleanup Lambda
reads, expires and strips them.
"""

import ipaddress
import os
import time

TTL_TAG_PREFIX = 'FrostStream_TTL_'
DEFAULT_RULE_START = 100
DEFAULT_RULE_END = 199
DEFAULT_TTL_HOURS = 24
CONFIDENCE_THRESHOLD = 0.95


def env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == '':
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def env_float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None or raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def target_nacl_id() -> str | None:
    return os.environ.get('TARGET_NACL_ID')


def rule_range() -> tuple[int, int]:
    start = env_int('NACL_RULE_START', DEFAULT_RULE_START)
    end = env_int('NACL_RULE_END', DEFAULT_RULE_END)
    if end < start:
        end = start
    return start, end


def block_ttl_hours() -> int:
    return max(1, env_int('BLOCK_TTL_HOURS', DEFAULT_TTL_HOURS))


def ttl_epoch(hours: int | None = None) -> int:
    hours = block_ttl_hours() if hours is None else hours
    return int(time.time()) + hours * 3600


def ttl_tag_key(ip: str) -> str:
    return f'{TTL_TAG_PREFIX}{ip}'


def ip_from_ttl_tag(key: str) -> str | None:
    if not key.startswith(TTL_TAG_PREFIX):
        return None
    ip = key[len(TTL_TAG_PREFIX):]
    return ip if is_valid_ipv4(ip) else None


def cidr_for(ip: str) -> str:
    return f'{ip}/32'


def is_valid_ipv4(ip) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).version == 4
    except (ValueError, TypeError):
        return False


def describe_acl(client, nacl_id: str) -> dict:
    response = client.describe_network_acls(NetworkAclIds=[nacl_id])
    acls = response.get('NetworkAcls', [])
    return acls[0] if acls else {}


def _ingress_entries(acl: dict) -> list[dict]:
    return [e for e in acl.get('Entries', []) if not e.get('Egress', False)]


def find_entry_for(acl: dict, ip: str) -> dict | None:
    wanted = cidr_for(ip)
    for entry in _ingress_entries(acl):
        if entry.get('CidrBlock') == wanted:
            return entry
    return None


def next_rule_number(acl: dict, start: int = DEFAULT_RULE_START, end: int = DEFAULT_RULE_END) -> int:
    used = {int(e['RuleNumber']) for e in _ingress_entries(acl) if 'RuleNumber' in e}
    for number in range(start, end + 1):
        if number not in used:
            return number
    raise RuntimeError(f'No free NACL rule number in [{start}, {end}]')


def block_ip(client, nacl_id: str, ip: str, *, rule_start: int = None, rule_end: int = None,
             ttl: int = None) -> dict:
    start, end = (rule_range() if rule_start is None or rule_end is None else (rule_start, rule_end))
    ttl = ttl_epoch() if ttl is None else ttl
    acl = describe_acl(client, nacl_id)
    existing = find_entry_for(acl, ip)
    if existing is not None:
        return {'status': 'SUPPRESSED', 'src_ip': ip, 'reason': 'already_blocked',
                'rule_number': int(existing['RuleNumber'])}

    rule_number = next_rule_number(acl, start, end)
    client.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=rule_number,
        Protocol='-1',
        RuleAction='deny',
        Egress=False,
        CidrBlock=cidr_for(ip),
    )
    client.create_tags(Resources=[nacl_id], Tags=[{'Key': ttl_tag_key(ip), 'Value': str(ttl)}])
    return {'status': 'ACTIONED', 'src_ip': ip, 'rule_number': rule_number,
            'ttl_epoch': ttl, 'nacl_id': nacl_id}


def ttl_tags(acl: dict) -> list[tuple[str, int]]:
    out = []
    for tag in acl.get('Tags', []) or []:
        ip = ip_from_ttl_tag(tag.get('Key', ''))
        if ip is None:
            continue
        try:
            out.append((ip, int(tag.get('Value', '0'))))
        except (TypeError, ValueError):
            continue
    return out


def expired_blocks(acl: dict, now: int) -> list[tuple[str, int, dict]]:
    expired = []
    for ip, epoch in ttl_tags(acl):
        entry = find_entry_for(acl, ip)
        if entry is None:
            continue
        if epoch <= now:
            expired.append((ip, epoch, entry))
    if not expired:
        return expired
    expired.sort(key=lambda item: item[1])
    return expired


def expired_tags(acl: dict, now: int) -> list[tuple[str, int]]:
    """Return all expired TTL tags regardless of whether NACL entry exists."""
    expired = []
    for ip, epoch in ttl_tags(acl):
        if epoch <= now:
            expired.append((ip, epoch))
    expired.sort(key=lambda item: item[1])
    return expired


def delete_tag(client, nacl_id: str, ip: str) -> None:
    client.delete_tags(Resources=[nacl_id], Tags=[{'Key': ttl_tag_key(ip)}])


def delete_block(client, nacl_id: str, ip: str, entry: dict) -> None:
    client.delete_network_acl_entry(NetworkAclId=nacl_id, Egress=False, RuleNumber=int(entry['RuleNumber']))
    client.delete_tags(Resources=[nacl_id], Tags=[{'Key': ttl_tag_key(ip)}])