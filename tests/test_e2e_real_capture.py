import json

import pytest

from ingestion.flow_processor import FEATURE_COLS, FlowFeatureExtractor, _feed_pcap
from src.common.execution_mode import CloudFlowSink
from src.soar import mitigator
from tests.test_execution_mode import FakeFirehose
from tests.test_soar_mitigator import FakeEc2


def test_scapy_capture_aggregates_and_emits_firehose(monkeypatch):
    scapy = pytest.importorskip('scapy.all')
    packets = [
        scapy.IP(src='192.0.2.10', dst='198.51.100.20') / scapy.TCP(sport=51515, dport=80, flags='S'),
        scapy.IP(src='198.51.100.20', dst='192.0.2.10') / scapy.TCP(sport=80, dport=51515, flags='SA'),
        scapy.IP(src='192.0.2.10', dst='198.51.100.20') / scapy.TCP(sport=51515, dport=80, flags='A'),
        scapy.IP(src='192.0.2.10', dst='198.51.100.20') / scapy.TCP(sport=51515, dport=80, flags='F'),
    ]
    monkeypatch.setattr(scapy, 'rdpcap', lambda _path: packets)

    records = _feed_pcap(FlowFeatureExtractor(), 'mocked-capture.pcap')
    assert len(records) == 1
    assert set(FEATURE_COLS).issubset(records[0])

    fake = FakeFirehose()
    sink = CloudFlowSink(stream_name='froststream-nids-flows', client=fake)
    sink.emit_many(records)

    assert len(fake.calls) == 1
    stream_name, payload = fake.calls[0]
    record = json.loads(payload.decode('utf-8'))
    assert stream_name == 'froststream-nids-flows'
    assert record['src_ip'] == '192.0.2.10'
    assert record['dst_ip'] == '198.51.100.20'
    assert record['src_port'] == 51515
    assert record['dst_port'] == 80
    assert record['protocol_type'] == 'tcp'
    assert record['service'] == 'http'
    assert record['flag'] == 'SF'


def test_high_alert_is_actioned_once_then_repeat_is_suppressed():
    fake = FakeEc2()
    first = mitigator.process_row(
        [0, '203.0.113.10', 'alert-high-1', 0.99, 'DoS'],
        client=fake,
        nacl_id='acl-test',
        rule_start=100,
        rule_end=199,
        ttl=9999999999,
    )
    repeat = mitigator.process_row(
        [1, '203.0.113.10', 'alert-high-2', 0.99, 'DoS'],
        client=fake,
        nacl_id='acl-test',
        rule_start=100,
        rule_end=199,
        ttl=9999999999,
    )

    assert first['status'] == 'ACTIONED'
    assert first['rule_number'] == 100
    assert repeat['status'] == 'SUPPRESSED'
    assert repeat['reason'] == 'already_blocked'
    assert len(fake.created) == 1
    assert fake.tags == {'FrostStream_TTL_203.0.113.10': '9999999999'}
