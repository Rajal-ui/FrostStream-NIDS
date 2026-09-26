import json

import pytest

from ingestion.flow_processor import FEATURE_COLS, FlowFeatureExtractor, _feed_pcap
from src.common.execution_mode import CloudFlowSink
from src.soar import mitigator
from tests.test_execution_mode import FakeFirehose
from tests.test_soar_mitigator import FakeEc2


REAL_CAPTURE_FEATURES = {
    'duration': 3,
    'protocol_type': 'tcp',
    'service': 'private',
    'flag': 'REJ',
    'src_bytes': 11097,
    'dst_bytes': 1977,
    'land': 0,
    'wrong_fragment': 0,
    'urgent': 0,
    'hot': 0,
    'num_failed_logins': 0,
    'logged_in': 0,
    'num_compromised': 0,
    'root_shell': 0,
    'su_attempted': 0,
    'num_root': 0,
    'num_file_creations': 0,
    'num_shells': 0,
    'num_access_files': 0,
    'num_outbound_cmds': 0,
    'is_host_login': 0,
    'is_guest_login': 0,
    'count': 1,
    'srv_count': 1,
    'serror_rate': 1.0,
    'srv_serror_rate': 1.0,
    'rerror_rate': 1.0,
    'srv_rerror_rate': 1.0,
    'same_srv_rate': 1.0,
    'diff_srv_rate': 0.0,
    'srv_diff_host_rate': 0.0,
    'dst_host_count': 1,
    'dst_host_srv_count': 1,
    'dst_host_same_srv_rate': 1.0,
    'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 1.0,
    'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 1.0,
    'dst_host_srv_serror_rate': 1.0,
    'dst_host_rerror_rate': 1.0,
    'dst_host_srv_rerror_rate': 1.0,
}


def _sized_tcp_packet(scapy, src_ip, dst_ip, src_port, dst_port, flags, length):
    packet = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(
        sport=src_port, dport=dst_port, flags=flags
    )
    payload_length = length - len(packet)
    if payload_length < 0:
        raise ValueError(f'packet length {length} is smaller than header {len(packet)}')
    return packet / scapy.Raw(load=b'\0' * payload_length)


def test_scapy_capture_aggregates_and_emits_firehose(monkeypatch):
    scapy = pytest.importorskip('scapy.all')
    target_source = '192.168.1.34'
    target_destination = '162.125.21.2'
    target_source_port = 61067
    target_destination_port = 443
    target_syn = _sized_tcp_packet(
        scapy, target_source, target_destination, target_source_port,
        target_destination_port, 'S', 11097,
    )
    filler = scapy.IP(src='10.0.0.1', dst='10.0.0.2') / scapy.UDP(sport=40000, dport=53)
    target_rst = _sized_tcp_packet(
        scapy, target_destination, target_source, target_destination_port,
        target_source_port, 'R', 1977,
    )
    packets = [target_syn] + [filler] * 600 + [target_rst]
    monkeypatch.setattr(scapy, 'rdpcap', lambda _path: packets)

    records = _feed_pcap(FlowFeatureExtractor(), 'mocked-real-capture.pcap')
    assert len(records) == 2
    assert set(REAL_CAPTURE_FEATURES) == set(FEATURE_COLS)
    record = next(
        item for item in records
        if item['src_ip'] == target_source and item['dst_ip'] == target_destination
    )
    assert record['src_port'] == target_source_port
    assert record['dst_port'] == target_destination_port
    assert record['protocol'] == 'tcp'
    for key, expected in REAL_CAPTURE_FEATURES.items():
        assert record[key] == expected

    fake = FakeFirehose()
    sink = CloudFlowSink(stream_name='froststream-nids-flows', client=fake)
    sink.emit_many([record])

    assert len(fake.calls) == 1
    stream_name, payload = fake.calls[0]
    firehose_record = json.loads(payload.decode('utf-8'))
    assert stream_name == 'froststream-nids-flows'
    assert firehose_record == record


def test_high_alert_is_actioned_once_then_repeats_are_suppressed():
    fake = FakeEc2()
    rows = [
        [0, '192.168.1.34', '834c35288f9d4011afedc50dbd9ecfb2', 0.950285, 'Normal'],
        [1, '192.168.1.34', '2645fd97878b4e7683f814217d95f8c2', 0.953653, 'Normal'],
        [2, '192.168.1.34', '1556436392ad47c497cd3f2bf01469ca', 0.953992, 'Normal'],
    ]
    outcomes = [
        mitigator.process_row(
            row,
            client=fake,
            nacl_id='acl-test',
            rule_start=100,
            rule_end=199,
            ttl=9999999999,
        )
        for row in rows
    ]

    assert [outcome['status'] for outcome in outcomes] == ['ACTIONED', 'SUPPRESSED', 'SUPPRESSED']
    assert outcomes[0]['rule_number'] == 100
    assert [outcome['reason'] for outcome in outcomes[1:]] == ['already_blocked', 'already_blocked']
    assert len(fake.created) == 1
    assert fake.tags == {'FrostStream_TTL_192.168.1.34': '9999999999'}
