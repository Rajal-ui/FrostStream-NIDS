"""Unit tests for the Phase 5 SOAR layer (src/soar/).

Covers the mitigator's external-function protocol, confidence gating,
idempotency, TTL tagging, and the cleanup hour's expiry/deletion logic —
all against a stateful fake EC2 client (no AWS involved).
"""

import json

import pytest

from src.soar import cleanup, mitigator, nacl


class FakeEc2:
    def __init__(self, nacl_id='acl-test', entries=None, tags=None):
        self.nacl_id = nacl_id
        self.entries = list(entries or [])
        self.tags = dict(tags or {})
        self.created = []
        self.deleted = []
        self.tag_calls = []
        self.untag_calls = []

    def describe_network_acls(self, NetworkAclIds=None):
        return {'NetworkAcls': [{
            'NetworkAclId': self.nacl_id,
            'Entries': list(self.entries),
            'Tags': [{'Key': k, 'Value': str(v)} for k, v in self.tags.items()],
        }]}

    def create_network_acl_entry(self, **kwargs):
        self.created.append(kwargs)
        self.entries.append({
            'NetworkAclId': kwargs['NetworkAclId'],
            'RuleNumber': kwargs['RuleNumber'],
            'Protocol': kwargs['Protocol'],
            'RuleAction': kwargs['RuleAction'],
            'Egress': kwargs['Egress'],
            'CidrBlock': kwargs['CidrBlock'],
        })

    def create_tags(self, Resources=None, Tags=None):
        self.tag_calls.append((Resources, Tags))
        for tag in Tags:
            self.tags[tag['Key']] = tag['Value']

    def delete_network_acl_entry(self, NetworkAclId=None, Egress=False, RuleNumber=None):
        self.deleted.append({'NetworkAclId': NetworkAclId, 'RuleNumber': RuleNumber})
        self.entries = [e for e in self.entries if e['RuleNumber'] != RuleNumber]

    def delete_tags(self, Resources=None, TagKeys=None, Tags=None):
        self.untag_calls.append((Resources, TagKeys, Tags))
        keys = TagKeys or []
        if Tags:
            keys.extend([t['Key'] for t in Tags])
        for key in keys:
            self.tags.pop(key, None)


def _request(*rows):
    return {'data': rows}


# --------------------------------------------------------------------------- #
# Mitigator - decision logic
# --------------------------------------------------------------------------- #

def test_low_confidence_is_suppressed():
    fake = FakeEc2()
    row = [0, '1.2.3.4', 'alert-1', 0.95, 'DoS']
    outcome = mitigator.process_row(row, client=fake, nacl_id='acl-test')
    assert outcome['status'] == 'SUPPRESSED'
    assert outcome['reason'] == 'below_confidence_threshold'
    assert fake.created == []


def test_actioned_creates_deny_rule_and_ttl_tag():
    fake = FakeEc2()
    row = [0, '1.2.3.4', 'alert-1', 0.98, 'DoS']
    outcome = mitigator.process_row(row, client=fake, nacl_id='acl-test',
                                    rule_start=100, rule_end=199, ttl=9999999999)
    assert outcome['status'] == 'ACTIONED'
    assert outcome['rule_number'] == 100
    call = fake.created[0]
    assert call['NetworkAclId'] == 'acl-test'
    assert call['CidrBlock'] == '1.2.3.4/32'
    assert call['RuleAction'] == 'deny'
    assert call['Egress'] is False
    assert call['Protocol'] == '-1'
    assert fake.tags == {'FrostStream_TTL_1.2.3.4': '9999999999'}


def test_idempotent_suppressed_when_already_blocked():
    fake = FakeEc2(entries=[{'RuleNumber': 111, 'Egress': False, 'CidrBlock': '1.2.3.4/32'}])
    outcome = mitigator.process_row([0, '1.2.3.4', 'alert-2', 0.99, 'Probe'],
                                    client=fake, nacl_id='acl-test')
    assert outcome['status'] == 'SUPPRESSED'
    assert outcome['reason'] == 'already_blocked'
    assert fake.created == []


def test_invalid_ip_fails_but_preserves_row():
    fake = FakeEc2()
    outcome = mitigator.process_row([0, 'not-an-ip', 'alert-3', 0.99, 'DoS'],
                                    client=fake, nacl_id='acl-test')
    assert outcome['status'] == 'FAILED'
    assert outcome['reason'] == 'invalid_ip'
    assert fake.created == []


def test_rule_allocation_skips_used_numbers():
    fake = FakeEc2(entries=[{'RuleNumber': 100, 'Egress': False, 'CidrBlock': '9.9.9.9/32'}])
    outcome = mitigator.process_row([0, '8.8.8.8', 'a', 0.97, 'R2L'],
                                    client=fake, nacl_id='acl-test',
                                    rule_start=100, rule_end=199)
    assert outcome['rule_number'] == 101


def test_external_function_response_protocol():
    fake = FakeEc2()
    rows = [
        [0, '1.1.1.1', 'alert-a', 0.99, 'DoS'],
        [1, '2.2.2.2', 'alert-b', 0.90, 'Probe'],
    ]
    response = mitigator.process_rows(rows, client=fake, nacl_id='acl-test')
    body = {'data': response}
    assert len(body['data']) == 2
    assert body['data'][0][0] == 0
    assert body['data'][0][1]['status'] == 'ACTIONED'
    assert body['data'][1][0] == 1
    assert body['data'][1][1]['status'] == 'SUPPRESSED'


def test_lambda_handler_wraps_protocol():
    event = {
        'headers': {'content-type': 'application/json'},
        'body': json.dumps(_request([0, '1.1.1.1', 'a', 0.99, 'DoS'])),
    }
    with pytest.MonkeyPatch.context() as mp:
        import src.soar.mitigator as mod

        def _fake_rows(_data, **kwargs):
            return [[0, {'status': 'ACTIONED', 'src_ip': '1.1.1.1'}]]

        mp.setattr(mod, 'process_rows', _fake_rows)
        result = mod.lambda_handler(event, None)
    assert result['statusCode'] == 200
    payload = json.loads(result['body'])
    assert 'data' in payload
    assert payload['data'][0][1]['status'] == 'ACTIONED'


def test_lambda_handler_rejects_malformed_body():
    from src.soar.mitigator import lambda_handler

    result = lambda_handler({'body': '{not json'}, None)
    assert result['statusCode'] == 400


# --------------------------------------------------------------------------- #
# NACL helpers
# --------------------------------------------------------------------------- #

def test_next_rule_number_skips_used():
    acl = {'Entries': [{'RuleNumber': 10, 'Egress': False}, {'RuleNumber': 11, 'Egress': False}]}
    assert nacl.next_rule_number(acl, start=10, end=12) == 12
    with pytest.raises(RuntimeError):
        nacl.next_rule_number(acl, start=10, end=11)


def test_next_rule_number_ignores_egress_and_raises_when_full():
    full = {'Entries': [{'RuleNumber': 10, 'Egress': True}]}
    assert nacl.next_rule_number(full, start=10, end=11) == 10
    exhausted = {'Entries': [{'RuleNumber': n, 'Egress': False} for n in (10, 11, 12)]}
    with pytest.raises(RuntimeError):
        nacl.next_rule_number(exhausted, start=10, end=12)


def test_expired_blocks_sorts_and_filters():
    acl = {
        'Entries': [
            {'RuleNumber': 100, 'Egress': False, 'CidrBlock': '1.1.1.1/32'},
            {'RuleNumber': 101, 'Egress': False, 'CidrBlock': '2.2.2.2/32'},
        ],
        'Tags': [
            {'Key': 'FrostStream_TTL_1.1.1.1', 'Value': '100'},
            {'Key': 'FrostStream_TTL_2.2.2.2', 'Value': '9999999999'},
            {'Key': 'FrostStream_TTL_bad-ip', 'Value': '1'},
            {'Key': 'OtherTag', 'Value': 'x'},
        ],
    }
    expired = nacl.expired_blocks(acl, now=500)
    assert [(ip, epoch) for ip, epoch, _ in expired] == [('1.1.1.1', 100)]


def test_ttl_tag_key_roundtrip():
    assert nacl.ip_from_ttl_tag(nacl.ttl_tag_key('203.0.113.9')) == '203.0.113.9'
    assert nacl.ip_from_ttl_tag('FrostStream_TTL_oh-junk') is None
    assert nacl.ip_from_ttl_tag('Other') is None


# --------------------------------------------------------------------------- #
# Cleanup
# --------------------------------------------------------------------------- #

def test_cleanup_deletes_expired_and_strips_tag():
    fake = FakeEc2(
        entries=[{'RuleNumber': 100, 'Egress': False, 'CidrBlock': '1.1.1.1/32'}],
        tags={'FrostStream_TTL_1.1.1.1': '100'},
    )
    updates = []

    def _record(ips):
        updates.append(ips)
        return len(ips)

    result = cleanup.expire_blocks(fake, 'acl-test', now=500, snowflake_update=_record)
    assert result['expired'] == ['1.1.1.1']
    assert result['snowflake_updated'] == 1
    assert fake.deleted[0]['RuleNumber'] == 100
    assert 'FrostStream_TTL_1.1.1.1' not in fake.tags
    assert updates == [['1.1.1.1']]


def test_cleanup_keeps_unexpired_blocks():
    fake = FakeEc2(
        entries=[{'RuleNumber': 100, 'Egress': False, 'CidrBlock': '1.1.1.1/32'}],
        tags={'FrostStream_TTL_1.1.1.1': '9999999999'},
    )
    result = cleanup.expire_blocks(fake, 'acl-test', now=500, snowflake_update=lambda ips: 0)
    assert result['expired'] == []
    assert fake.deleted == []