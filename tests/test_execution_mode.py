"""Unit tests for the dual-mode (LOCAL | CLOUD) execution factory.

Verifies environment-variable mode switching, per-mode sink resolution,
lazy cloud construction (no credentials/boto3 required until use) and
fallback to LOCAL when EXECUTION_MODE is unset.
"""

import json
import os
from pathlib import Path

import joblib
import pytest

from src.common.execution_mode import (
    CloudAlertSink,
    CloudFlowSink,
    CloudMitigationAction,
    CloudModelRepository,
    DualModeFactory,
    LocalAlertSink,
    LocalFlowSink,
    LocalMitigationAction,
    LocalModelRepository,
    get_execution_mode,
    get_factory,
    is_cloud,
)
from src.models.constants import (
    BASELINE_FILENAME,
    ENSEMBLE_FILENAME,
    ISOLATION_FILENAME,
    PREPROCESSOR_FILENAME,
)


class FakeFirehose:
    def __init__(self):
        self.calls = []

    def put_record(self, DeliveryStreamName='', Record=None):
        self.calls.append((DeliveryStreamName, Record['Data']))


class FakeEc2:
    def __init__(self, network_acls):
        self.network_acls = network_acls
        self.created = []

    def describe_network_acls(self, NetworkAclIds=None):
        return {'NetworkAcls': self.network_acls}

    def create_network_acl_entry(self, **kwargs):
        self.created.append(kwargs)


# --------------------------------------------------------------------------- #
# Mode resolution / fallback
# --------------------------------------------------------------------------- #

def test_default_mode_is_local_when_unset(monkeypatch):
    monkeypatch.delenv('EXECUTION_MODE', raising=False)
    assert get_execution_mode() == 'LOCAL'
    assert not is_cloud()
    assert get_factory().mode == 'LOCAL'


def test_mode_switching_is_case_insensitive(monkeypatch):
    monkeypatch.setenv('EXECUTION_MODE', 'local')
    assert get_execution_mode() == 'LOCAL'
    assert not is_cloud()

    monkeypatch.setenv('EXECUTION_MODE', 'cloud')
    assert get_execution_mode() == 'CLOUD'
    assert is_cloud()
    assert get_factory().mode == 'CLOUD'


def test_invalid_mode_raises(monkeypatch):
    monkeypatch.setenv('EXECUTION_MODE', 'HYBRID')
    with pytest.raises(ValueError):
        get_execution_mode()
    with pytest.raises(ValueError):
        DualModeFactory(mode='HYBRID')


# --------------------------------------------------------------------------- #
# FlowSink
# --------------------------------------------------------------------------- #

def test_local_flow_sink_emits_json_lines(tmp_path):
    sink = LocalFlowSink(output_path=tmp_path / 'captured.jsonl')
    sink.emit({'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8', 'count': 2})
    sink.emit({'src_ip': '9.9.9.9', 'dst_ip': '5.6.7.8', 'count': 1})
    lines = (tmp_path / 'captured.jsonl').read_text(encoding='utf-8').splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {'count': 2, 'dst_ip': '5.6.7.8', 'src_ip': '1.2.3.4'}


def test_cloud_flow_sink_uses_firehose_put_record():
    fake = FakeFirehose()
    sink = CloudFlowSink(stream_name='froststream-nids-flows', client=fake)
    sink.emit({'src_ip': '1.2.3.4', 'duration': 0.0})
    sink.emit({'src_ip': '2.3.4.5'})
    assert len(fake.calls) == 2
    name, data = fake.calls[0]
    assert name == 'froststream-nids-flows'
    assert data.endswith(b'\n')
    assert json.loads(data.decode('utf-8'))['src_ip'] == '1.2.3.4'


def test_cloud_flow_sink_requires_stream_name(monkeypatch):
    monkeypatch.delenv('FIREHOSE_DELIVERY_STREAM_NAME', raising=False)
    with pytest.raises(RuntimeError):
        CloudFlowSink(client=FakeFirehose())


def test_flow_sink_resolves_by_mode():
    assert isinstance(get_factory('LOCAL').flow_sink(), LocalFlowSink)
    assert isinstance(
        get_factory('CLOUD').flow_sink(stream_name='s', client=FakeFirehose()),
        CloudFlowSink,
    )


# --------------------------------------------------------------------------- #
# ModelRepository
# --------------------------------------------------------------------------- #

def _write_artifacts(model_dir: Path) -> Path:
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({'kind': 'ensemble'}, model_dir / ENSEMBLE_FILENAME)
    joblib.dump({'kind': 'isolation_forest'}, model_dir / ISOLATION_FILENAME)
    joblib.dump({'kind': 'preprocessor'}, model_dir / PREPROCESSOR_FILENAME)
    baseline = {'protocol_type': {'kind': 'categorical', 'categories': ['tcp']}}
    (model_dir / BASELINE_FILENAME).write_text(json.dumps(baseline), encoding='utf-8')
    return model_dir


def test_local_model_repository_loads_artifacts(tmp_path):
    model_dir = _write_artifacts(tmp_path)
    repo = LocalModelRepository(model_dir=model_dir)
    artifacts = repo.load_all()
    assert set(artifacts) == {'ensemble', 'isolation_forest', 'preprocessor', 'baseline'}
    assert artifacts['ensemble'] == {'kind': 'ensemble'}
    assert repo.load_baseline()['protocol_type']['kind'] == 'categorical'


def test_cloud_model_repository_is_lazy(monkeypatch):
    monkeypatch.delenv('SNOWFLAKE_ACCOUNT', raising=False)
    monkeypatch.delenv('SNOWFLAKE_USER', raising=False)
    repo = get_factory('CLOUD').model_repository()
    assert isinstance(repo, CloudModelRepository)
    with pytest.raises(RuntimeError):
        repo.load_all()


# --------------------------------------------------------------------------- #
# AlertSink
# --------------------------------------------------------------------------- #

def test_local_alert_sink_logs_row(tmp_path):
    sink = LocalAlertSink(db_path=tmp_path / 'alerts.db')
    sink.log_alert({
        'protocol_type': 'tcp',
        'service': 'http',
        'src_bytes': 120,
        'dst_bytes': 4000,
        'predicted_category': 'DoS',
        'confidence': 0.99,
        'severity': 'HIGH',
    })
    from storage.alert_logger import AlertLogger

    logger = AlertLogger(db_path=str(tmp_path / 'alerts.db'))
    rows = logger.get_all_alerts()
    assert len(rows) == 1
    assert rows.iloc[0]['predicted_category'] == 'DoS'
    assert rows.iloc[0]['severity'] == 'HIGH'


def test_cloud_alert_sink_row_select_escapes_safely():
    select = CloudAlertSink._row_select({
        'src_ip': "10.0.0.1'; DROP TABLE NIDS_ALERTS--",
        'attack_type': 'Probe',
        'confidence': 0.97,
        'severity': 'HIGH',
    })
    assert select.startswith('SELECT ')
    assert "10.0.0.1''; DROP TABLE NIDS_ALERTS--" in select
    assert "10.0.0.1'; DROP TABLE NIDS_ALERTS--'" not in select


def test_alert_sink_resolves_by_mode():
    assert isinstance(get_factory('LOCAL').alert_sink(), LocalAlertSink)
    assert isinstance(get_factory('CLOUD').alert_sink(), CloudAlertSink)


# --------------------------------------------------------------------------- #
# MitigationAction
# --------------------------------------------------------------------------- #

def test_local_mitigation_action_records_block(tmp_path):
    action = LocalMitigationAction(db_path=tmp_path / 'fw.db', ttl_hours=2)
    result = action.apply('10.0.0.9', alert_id='abc', confidence=0.99, attack_type='DoS')
    assert result['status'] == 'ACTIONED'
    blocks = action.list_blocks()
    assert len(blocks) == 1
    assert blocks[0]['src_ip'] == '10.0.0.9'
    assert blocks[0]['ttl_epoch'] > 0


def test_cloud_mitigation_action_picks_free_rule_and_denies():
    acl = {
        'NetworkAclId': 'acl-test',
        'Entries': [
            {'RuleNumber': 100, 'Egress': False, 'RuleAction': 'deny'},
            {'RuleNumber': 150, 'Egress': True, 'RuleAction': 'allow'},
        ],
    }
    fake = FakeEc2(network_acls=[acl])
    action = CloudMitigationAction(nacl_id='acl-test', client=fake, rule_start=100, rule_end=199)
    result = action.apply('8.8.8.8', alert_id='a1', confidence=0.99, attack_type='DoS')
    assert result['rule_number'] == 101
    call = fake.created[0]
    assert call['NetworkAclId'] == 'acl-test'
    assert call['RuleNumber'] == 101
    assert call['RuleAction'] == 'deny'
    assert call['Egress'] is False
    assert call['CidrBlock'] == '8.8.8.8/32'


def test_mitigation_action_resolves_by_mode(tmp_path):
    assert isinstance(
        get_factory('LOCAL').mitigation_action(db_path=tmp_path / 'fw.db'),
        LocalMitigationAction,
    )
    action = get_factory('CLOUD').mitigation_action(nacl_id='acl-test', client=FakeEc2([{'Entries': []}]))
    assert isinstance(action, CloudMitigationAction)


# --------------------------------------------------------------------------- #
# Factory caching
# --------------------------------------------------------------------------- #

def test_factory_caches_instances_by_kwargs():
    factory = get_factory('LOCAL')
    assert factory.flow_sink() is factory.flow_sink()
    assert factory.alert_sink() is factory.alert_sink()
    assert factory.model_repository() is factory.model_repository()