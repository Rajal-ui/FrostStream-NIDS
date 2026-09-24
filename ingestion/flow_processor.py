"""Network ingestion layer (Docker-free, dual-mode).

Scapy is optional at import time (used lazily for live sniffing / PCAP
replay), so the aggregation engine and routing are fully unit-testable
without it.

Dual-mode routing:
    EXECUTION_MODE=LOCAL   -> JSON-lines sink (factory LocalFlowSink)
    EXECUTION_MODE=CLOUD   -> Kinesis Firehose put_record (factory CloudFlowSink)

Each emitted record uses the exact snake_case field names consumed by the
Snowflake flatten task (snowflake_setup/02_snowpipe.sql), i.e. it lands in
RAW_FLOW_LANDING and is typed into CORE.FLOW_FEATURES unmodified.
"""

import argparse
import hashlib
import os
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from data.dataset_loader import COLUMN_NAMES, generate_nsl_kdd_dataset

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.common.execution_mode import get_factory, get_execution_mode

FEATURE_COLS = [c for c in COLUMN_NAMES if c not in ('label', 'difficulty')]

IDLE_TIMEOUT_SEC = 30.0
ACTIVE_TIMEOUT_SEC = 120.0
CONN_WINDOW_SEC = 2.0
DST_HOST_WINDOW_SIZE = 100

SERVICE_PORT_MAP = {
    20: 'ftp_data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain_u',
    80: 'http',
    110: 'private',
    143: 'private',
    443: 'private',
    445: 'private',
    8080: 'http',
    3306: 'private',
    3389: 'private',
}

SYN_ERROR_FLAGS = ('REJ', 'S0', 'S1', 'S2', 'S3', 'RSTO', 'RSTOS0')

CONTENT_DEFAULTS = {
    'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
    'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
    'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
    'is_host_login': 0, 'is_guest_login': 0, 'srv_diff_host_rate': 0.0,
}


class FlowKey:
    """Direction-agnostic connection key: (endpointA, endpointB, protocol)."""

    __slots__ = ('endpoints', 'protocol')

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        left = (str(src_ip), int(src_port))
        right = (str(dst_ip), int(dst_port))
        self.endpoints = tuple(sorted((left, right)))
        self.protocol = str(protocol)

    def _tuple(self):
        return (self.endpoints, self.protocol)

    def __hash__(self):
        return hash(self._tuple())

    def __eq__(self, other):
        return isinstance(other, FlowKey) and self._tuple() == other._tuple()


def _service_for(dst_port: int) -> str:
    return SERVICE_PORT_MAP.get(int(dst_port), 'private')


def flow_id_for(key: FlowKey, start_epoch: float) -> str:
    material = '|'.join([f"{ip}:{port}" for ip, port in key.endpoints]) + f"|{key.protocol}|{start_epoch:.3f}"
    return hashlib.md5(material.encode('utf-8')).hexdigest()


class FlowAccumulator:
    """Aggregates packets of a single bidirectional connection.

    ``src_*``/``dst_*`` reflect the orientation of the connection's first
    packet (the initiator); packets from the other endpoint count toward the
    ``dst`` side regardless of which header field says 'source'.
    """

    __slots__ = (
        'key', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'service',
        'start_ts', 'last_ts', 'src_bytes', 'dst_bytes', 'packets',
        'saw_syn', 'saw_synack', 'saw_rst', 'saw_fin', 'urgent',
        'wrong_fragment',
    )

    def __init__(self, key: FlowKey, packet: dict, ts: float):
        self.key = key
        self.src_ip = str(packet.get('src_ip', '0.0.0.0'))
        self.dst_ip = str(packet.get('dst_ip', '0.0.0.0'))
        self.src_port = int(packet.get('src_port', 0) or 0)
        self.dst_port = int(packet.get('dst_port', 0) or 0)
        self.service = _service_for(self.dst_port) if key.protocol == 'tcp' else 'other'
        self.start_ts = ts
        self.last_ts = ts
        self.src_bytes = 0
        self.dst_bytes = 0
        self.packets = 0
        self.saw_syn = False
        self.saw_synack = False
        self.saw_rst = False
        self.saw_fin = False
        self.urgent = False
        self.wrong_fragment = 0

    def _is_src(self, packet: dict) -> bool:
        return (
            str(packet.get('src_ip', '')) == self.src_ip
            and int(packet.get('src_port', 0) or 0) == self.src_port
        )

    def update(self, packet: dict, ts: float | None = None) -> None:
        ts = ts if ts is not None else packet.get('time', time.time())
        self.last_ts = ts
        self.packets += 1
        length = int(packet.get('length', 0) or 0)
        if self._is_src(packet):
            self.src_bytes += max(0, length)
        else:
            self.dst_bytes += max(0, length)

        flags = str(packet.get('flags', '') or '').upper()
        if flags:
            self.saw_syn = self.saw_syn or ('S' in flags and 'F' not in flags and 'A' not in flags)
            self.saw_synack = self.saw_synack or ('S' in flags and 'A' in flags)
            self.saw_rst = self.saw_rst or ('R' in flags)
            self.saw_fin = self.saw_fin or ('F' in flags)
            self.urgent = self.urgent or ('U' in flags)
        if int(packet.get('fragment_offset', 0) or 0) > 0:
            self.wrong_fragment += 1

    @property
    def duration(self) -> int:
        return int(max(0.0, self.last_ts - self.start_ts))

    @property
    def syn_error(self) -> bool:
        if self.saw_rst and not self.saw_synack:
            return True
        return self.saw_syn and not self.saw_synack

    @property
    def flag(self) -> str:
        if self.saw_rst and not self.saw_synack:
            return 'REJ'
        if self.saw_syn and not self.saw_synack:
            return 'S0'
        if self.saw_rst:
            return 'RSTO'
        if self.saw_fin:
            return 'SF'
        return 'SF'


class FlowFeatureExtractor:
    def __init__(self, idle_timeout: float = IDLE_TIMEOUT_SEC, active_timeout: float = ACTIVE_TIMEOUT_SEC):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._flows: dict[FlowKey, FlowAccumulator] = {}
        self._window: deque = deque()

    def ingest(self, packet: dict, ts: float | None = None) -> list[dict]:
        """Feed one packet; returns any flows that expired as a result."""
        ts = ts if ts is not None else packet.get('time', time.time())
        src = str(packet.get('src_ip', '0.0.0.0'))
        dst = str(packet.get('dst_ip', '0.0.0.0'))
        protocol = str(packet.get('protocol', 'tcp')).lower()
        src_port = int(packet.get('src_port', 0) or 0)
        dst_port = int(packet.get('dst_port', 0) or 0)

        key = FlowKey(src, dst, src_port, dst_port, protocol)
        acc = self._flows.get(key)
        if acc is None:
            acc = FlowAccumulator(key, packet, ts)
            self._flows[key] = acc
        acc.update(packet, ts)
        return self.expire(now=ts)

    def expire(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        expired = []
        for key, acc in list(self._flows.items()):
            idle = (now - acc.last_ts) >= self.idle_timeout
            active = (now - acc.start_ts) >= self.active_timeout
            if idle or active:
                self._flows.pop(key, None)
                expired.append(acc)
        return [self._emit(acc, now) for acc in expired]

    def flush_all(self) -> list[dict]:
        records = []
        for key, acc in list(self._flows.items()):
            self._flows.pop(key, None)
            records.append(self._emit(acc, acc.last_ts))
        return records

    def _window_rates(self, dst_ip: str, service: str, syn_error: bool, rst: bool, now: float) -> dict:
        cutoff = now - CONN_WINDOW_SEC
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
        self._window.append((now, dst_ip, service, syn_error, rst))

        to_host = [w for w in self._window if w[1] == dst_ip]
        count = len(to_host)
        srv_flows = [w for w in to_host if w[2] == service]
        srv_count = len(srv_flows)

        def rate(pool, key_index):
            if not pool:
                return 0.0
            bad = sum(1 for w in pool if w[key_index])
            return round(bad / len(pool), 6)

        return {
            'count': max(1, count),
            'srv_count': max(1, srv_count),
            'serror_rate': rate(to_host, 3),
            'srv_serror_rate': rate(srv_flows, 3) if srv_flows else 0.0,
            'rerror_rate': rate(to_host, 4),
            'srv_rerror_rate': rate(srv_flows, 4) if srv_flows else 0.0,
            'same_srv_rate': round(srv_count / max(1, count), 6),
            'diff_srv_rate': round(1.0 - (srv_count / max(1, count)), 6),
        }

    def _dst_host_rates(self, dst_ip: str, service: str) -> dict:
        return {
            'dst_host_count': DST_HOST_WINDOW_SIZE,
            'dst_host_srv_count': DST_HOST_WINDOW_SIZE,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
        }

    def _emit(self, acc: FlowAccumulator, now: float) -> dict:
        acc_rates = self._window_rates(
            acc.dst_ip, acc.service, acc.syn_error, acc.saw_rst, now
        )
        record = {
            'flow_id': flow_id_for(acc.key, acc.start_ts),
            'src_ip': acc.src_ip,
            'dst_ip': acc.dst_ip,
            'src_port': acc.src_port,
            'dst_port': acc.dst_port,
            'protocol': acc.key.protocol,
            'flow_start_time': datetime.fromtimestamp(acc.start_ts, tz=timezone.utc).isoformat(),
            'timestamp': datetime.fromtimestamp(acc.last_ts, tz=timezone.utc).isoformat(),
            'duration': acc.duration,
            'protocol_type': acc.key.protocol,
            'service': acc.service,
            'flag': acc.flag,
            'src_bytes': acc.src_bytes,
            'dst_bytes': acc.dst_bytes,
            'land': 1 if acc.src_ip == acc.dst_ip else 0,
            'wrong_fragment': acc.wrong_fragment,
            'urgent': 1 if acc.urgent else 0,
        }
        record.update(acc_rates)
        record.update(CONTENT_DEFAULTS)
        record.update(self._dst_host_rates(acc.dst_ip, acc.service))
        return record


def emit_sample_flows(extractor: FlowFeatureExtractor, num_flows: int = 20, seed: int = 7) -> list[dict]:
    """Replay synthetic packets built from generated NSL-KDD sample rows."""
    df = generate_nsl_kdd_dataset(num_samples=num_flows, random_state=seed)
    records = []
    now = time.time() - 3600.0
    port_by_service = {v: k for k, v in SERVICE_PORT_MAP.items()}
    for row in df.to_dict('records'):
        proto = row['protocol_type']
        service = row['service']
        if proto == 'tcp':
            dst_port = port_by_service.get(service, 0) or (1024 + row['count'] % 60000)
            src_port = 40000 + row['count'] % 20000
        else:
            src_port = dst_port = 0
        src_ip = f"10.{row['count'] % 250}.{(row['count'] * 7) % 250}.{row['count'] % 255}"
        dst_ip = '192.168.1.10'
        packet_flags = {
            'SF': ['S', 'SA', 'A', 'F'],
            'S0': ['S'],
            'REJ': ['S', 'R'],
            'RSTO': ['S', 'SA', 'A', 'R'],
        }.get(str(row['flag']), ['S', 'SA', 'A'])
        lengths = [60, 60, max(1, int(row['src_bytes'])), max(1, int(row['dst_bytes']))]
        for i, flg in enumerate(packet_flags):
            now += 0.2
            pkt = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': proto,
                'flags': flg,
                'length': lengths[i % len(lengths)],
                'time': now,
            }
            records.extend(extractor.ingest(pkt, now))
    records.extend(extractor.flush_all())
    return records


def _feed_pcap(extractor: FlowFeatureExtractor, pcap_path: str) -> list[dict]:
    try:
        from scapy.all import IP, TCP, UDP, ICMP, rdpcap
    except ImportError as exc:
        raise RuntimeError('scapy is required for PCAP replay (pip install -r requirements.txt)') from exc

    records = []
    packets = rdpcap(pcap_path)
    start = time.time() - 30.0
    for packet in packets:
        ip = packet.getlayer(IP)
        if ip is None:
            continue
        proto = 'icmp'
        sport = dport = 0
        flags = ''
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto, sport, dport = 'tcp', tcp.sport, tcp.dport
            flags = str(tcp.flags) if hasattr(tcp.flags, 'value') else str(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            proto, sport, dport = 'udp', udp.sport, udp.dport
        elif not packet.haslayer(ICMP):
            continue
        start = start + 0.005
        records.extend(extractor.ingest({
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'src_port': sport,
            'dst_port': dport,
            'protocol': proto,
            'flags': flags,
            'fragment_offset': int(ip.frag if ip.frag is not None else 0),
            'length': len(packet),
            'time': start,
        }, start))
    records.extend(extractor.flush_all())
    return records


def _sniff(extractor: FlowFeatureExtractor, interface: str | None, seconds: float) -> list[dict]:
    try:
        from scapy.all import Ether, IP, TCP, UDP, ICMP, sniff
    except ImportError as exc:
        raise RuntimeError('scapy is required for live capture (pip install -r requirements.txt)') from exc

    start_wall = time.time()
    records = []

    def handle(packet):
        Ether()
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        proto = 'icmp'
        sport = dport = 0
        flags = ''
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto, sport, dport = 'tcp', tcp.sport, tcp.dport
            flags = str(tcp.flags) if hasattr(tcp.flags, 'value') else str(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            proto, sport, dport = 'udp', udp.sport, udp.dport
        elif not packet.haslayer(ICMP):
            return
        records.extend(extractor.ingest({
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'src_port': sport,
            'dst_port': dport,
            'protocol': proto,
            'flags': flags,
            'fragment_offset': int(ip.frag if ip.frag is not None else 0),
            'length': len(packet),
        }, time.time()))

    sniff(iface=interface, prn=handle, timeout=int(seconds))
    records.extend(extractor.flush_all())
    return records


def build_runner(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='ingestion.flow_processor',
        description='FrostStream NIDS dual-mode flow processor (scapy aggregation -> local JSON-lines / Firehose).',
    )
    parser.add_argument('--mode', choices=['LOCAL', 'CLOUD'], default=None,
                        help='Override EXECUTION_MODE (default: env or LOCAL).')
    parser.add_argument('--sniff', nargs='?', const='', default=None,
                        help='Sniff an interface for --duration seconds (uses SCAPY_INTERFACE env when blank).')
    parser.add_argument('--replay', default=None, help='Replay packets from a PCAP file.')
    parser.add_argument('--replay-sample', action='store_true',
                        help='Replay synthetic NSL-KDD-compatible packets (no scapy needed).')
    parser.add_argument('--flows', type=int, default=20, help='Number of synthetic flows for --replay-sample.')
    parser.add_argument('--duration', type=float, default=10.0, help='Capture window (seconds) for sniff/sample modes.')
    parser.add_argument('--out', default=None, help='LOCAL output file override.')
    args = parser.parse_args(argv)

    sink = get_factory(args.mode).flow_sink(output_path=args.out) if args.out else get_factory(args.mode).flow_sink()
    extractor = FlowFeatureExtractor()

    records = []
    if args.replay:
        records = _feed_pcap(extractor, args.replay)
    elif args.replay_sample:
        records = emit_sample_flows(extractor, num_flows=args.flows)
    elif args.sniff is not None:
        interface = args.sniff or os.environ.get('SCAPY_INTERFACE') or None
        if not interface:
            raise SystemExit('No interface specified: pass --sniff <iface> or set SCAPY_INTERFACE in .env')
        records = _sniff(extractor, interface, args.duration)
    else:
        parser.error('one of --sniff, --replay or --replay-sample is required')

    for record in records:
        sink.emit(record)

    mode = get_factory(args.mode).mode
    print(f'[{mode}] emitted {len(records)} flow record(s) via '
          f'{type(sink).__name__} (execution_mode={get_execution_mode()})')
    return 0


if __name__ == '__main__':
    raise SystemExit(build_runner())