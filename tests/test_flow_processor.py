"""Unit tests for the Phase 4 dual-mode flow processor (ingestion/flow_processor.py).

Covers NSL-KDD feature aggregation from raw packets, flow expiry (idle/active
timeouts), flag & service derivation, dual-mode sink routing via the Phase 0
factory, and the emitted PMD record shape consumed by the Snowflake flatten task.
"""

import json

from ingestion.flow_processor import (
    FEATURE_COLS,
    FlowFeatureExtractor,
    build_runner,
    emit_sample_flows,
)


def _tcp_flow(extractor, ts, src='10.0.0.1', dst='192.168.1.10', sport=40000,
              dport=80, sequence=('S', 'SA', 'A', 'F'),
              directions=('src', 'dst', 'src', 'src'), lengths=(60, 40, 60, 60)):
    for i, flags in enumerate(sequence):
        direction = directions[i] if i < len(directions) else 'src'
        if direction == 'src':
            pkt = {
                'src_ip': src, 'dst_ip': dst,
                'src_port': sport, 'dst_port': dport,
            }
        else:
            pkt = {
                'src_ip': dst, 'dst_ip': src,
                'src_port': dport, 'dst_port': sport,
            }
        pkt.update({
            'protocol': 'tcp',
            'flags': flags,
            'length': lengths[i] if i < len(lengths) else 60,
            'time': ts + i * 1.0,
        })
        extractor.ingest(pkt, ts + i * 1.0)


def test_basic_tcp_flow_aggregation():
    extractor = FlowFeatureExtractor()
    _tcp_flow(extractor, ts=0.0)
    records = extractor.expire(now=34.0)
    assert len(records) == 1
    record = records[0]
    assert record['protocol_type'] == 'tcp'
    assert record['service'] == 'http'
    assert record['flag'] == 'SF'
    assert record['src_bytes'] == 180
    assert record['dst_bytes'] == 40
    assert record['duration'] == 3
    assert record['src_ip'] == '10.0.0.1'
    assert record['dst_port'] == 80


def test_record_contains_all_nsl_kdd_features():
    extractor = FlowFeatureExtractor()
    _tcp_flow(extractor, ts=0.0)
    record = extractor.expire(now=34.0)[0]
    for col in FEATURE_COLS:
        assert col in record, f"missing feature {col}"


def test_idle_timeout_expires_flow():
    extractor = FlowFeatureExtractor(idle_timeout=30.0)
    extractor.ingest({'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'src_port': 1234,
                      'dst_port': 80, 'protocol': 'tcp', 'flags': 'S', 'time': 0.0}, 0.0)
    assert len(extractor.expire(now=15.0)) == 0
    records = extractor.expire(now=31.0)
    assert len(records) == 1
    assert records[0]['flag'] == 'S0'


def test_active_timeout_expires_long_flow():
    extractor = FlowFeatureExtractor(active_timeout=120.0)
    _tcp_flow(extractor, ts=0.0, sequence=('S', 'SA'), lengths=(60, 40))
    records = extractor.ingest({'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.10',
                                'src_port': 40000, 'dst_port': 80, 'protocol': 'tcp',
                                'flags': 'A', 'length': 20, 'time': 121.0}, 121.0)
    assert len(records) == 1
    assert records[0]['duration'] == 121


def test_flag_derivation():
    extractor = FlowFeatureExtractor()
    _tcp_flow(extractor, ts=0.0, sequence=('S', 'R'))
    assert extractor.expire(now=31.0)[0]['flag'] == 'REJ'


def test_service_mapping_by_dest_port():
    from ingestion.flow_processor import _service_for

    assert _service_for(80) == 'http'
    assert _service_for(22) == 'ssh'
    assert _service_for(53) == 'domain_u'
    assert _service_for(9999) == 'private'


def test_land_detection():
    extractor = FlowFeatureExtractor()
    _tcp_flow(extractor, ts=0.0, src='10.0.0.1', dst='10.0.0.1')
    record = extractor.expire(now=34.0)[0]
    assert record['land'] == 1


def test_window_count_and_serror_rate():
    extractor = FlowFeatureExtractor()
    _tcp_flow(extractor, ts=0.0, src='10.0.0.1', sport=40000)
    _tcp_flow(extractor, ts=0.6, src='10.0.0.2', sport=40001, sequence=('S',))
    records = extractor.expire(now=34.0)
    by_flag = {r['flag']: r for r in records}
    rejected = by_flag['S0']
    assert rejected['count'] == 2
    assert rejected['srv_count'] == 2
    assert rejected['serror_rate'] == 0.5
    assert rejected['same_srv_rate'] == 1.0
    assert rejected['diff_srv_rate'] == 0.0


def test_local_mode_writes_json_lines(tmp_path):
    out = tmp_path / 'captured.jsonl'
    from src.common.execution_mode import get_factory

    sink = get_factory('LOCAL').flow_sink(output_path=out)
    for record in emit_sample_flows(FlowFeatureExtractor(), num_flows=5):
        sink.emit(record)
    lines = [json.loads(l) for l in out.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(lines) >= 1
    assert set(FEATURE_COLS).issubset(lines[0])


def test_cloud_mode_uses_firehose_put_record():
    from tests.test_execution_mode import FakeFirehose
    from src.common.execution_mode import get_factory

    fake = FakeFirehose()
    sink = get_factory('CLOUD').flow_sink(stream_name='froststream-nids-flows', client=fake)
    record = emit_sample_flows(FlowFeatureExtractor(), num_flows=2)[0]
    sink.emit(record)
    assert len(fake.calls) == 1
    name, data = fake.calls[0]
    assert name == 'froststream-nids-flows'
    assert data.endswith(b'\n')
    assert json.loads(data.decode('utf-8'))['flow_id']


def test_cli_replay_sample_local(tmp_path):
    out = tmp_path / 'out.jsonl'
    rc = build_runner(['--replay-sample', '--flows', '5', '--mode', 'LOCAL', '--out', str(out)])
    assert rc == 0
    lines = [json.loads(l) for l in out.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(lines) >= 1
    for record in lines:
        assert set(FEATURE_COLS).issubset(record)