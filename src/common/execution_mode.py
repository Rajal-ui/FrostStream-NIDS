"""Dual-mode (LOCAL | CLOUD) execution factory for FrostStream NIDS.

Everything is selected from the ``EXECUTION_MODE`` environment variable
(``LOCAL`` when unset). Each sink is constructed lazily so importing this
module - and constructing a CLOUD sink - never requires credentials,
``boto3``, or ``snowflake-snowpark``; those are only touched on first use.

    from src.common.execution_mode import get_factory
    sink = get_factory().flow_sink()
    sink.emit(flow_record)
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.models.constants import (
    BASELINE_FILENAME,
    ENSEMBLE_FILENAME,
    ISOLATION_FILENAME,
    PREPROCESSOR_FILENAME,
    default_model_dir,
)

VALID_MODES = ('LOCAL', 'CLOUD')
DEFAULT_MODE = 'LOCAL'
MODEL_STAGE = '@CORE.MODEL_STAGE'


def repo_root() -> Path:
    return Path(str(default_model_dir())).parent.parent


def get_execution_mode() -> str:
    """Resolve ``EXECUTION_MODE`` (defaults to LOCAL, rejects unknown values)."""
    raw = os.environ.get('EXECUTION_MODE') or DEFAULT_MODE
    mode = raw.strip().upper()
    if mode not in VALID_MODES:
        raise ValueError(
            f"Invalid EXECUTION_MODE {raw!r}; expected one of {', '.join(VALID_MODES)}"
        )
    return mode


def is_cloud() -> bool:
    return get_execution_mode() == 'CLOUD'


def _local_flow_output() -> Path:
    raw = os.environ.get('LOCAL_FLOW_OUTPUT')
    path = Path(raw) if raw else repo_root() / 'storage' / 'captured_flows.csv'
    return path if path.is_absolute() else repo_root() / path


def _local_alert_db() -> Path:
    raw = os.environ.get('LOCAL_ALERT_DB')
    path = Path(raw) if raw else repo_root() / 'storage' / 'alerts.db'
    return path if path.is_absolute() else repo_root() / path


def _local_model_dir() -> Path:
    raw = os.environ.get('LOCAL_MODEL_DIR')
    path = Path(raw) if raw else Path(default_model_dir())
    return path if path.is_absolute() else repo_root() / path


def _local_firewall_db() -> Path:
    return repo_root() / 'storage' / 'mock_firewall.db'


def _cloud_session():
    """Build a Snowpark session from env vars (lazy - never on import)."""
    from snowflake.snowpark import Session

    config = {}
    for key, env in {
        'account': 'SNOWFLAKE_ACCOUNT',
        'user': 'SNOWFLAKE_USER',
        'password': 'SNOWFLAKE_PASSWORD',
        'role': 'SNOWFLAKE_ROLE',
        'database': 'SNOWFLAKE_DATABASE',
        'schema': 'SNOWFLAKE_SCHEMA',
        'warehouse': 'SNOWFLAKE_WAREHOUSE',
    }.items():
        value = os.environ.get(env)
        if value:
            config[key] = value
    if config.get('user') and os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH'):
        config.pop('password', None)
    if not config.get('account') or not config.get('user'):
        raise RuntimeError(
            'CLOUD mode requires SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and a '
            'password or SNOWFLAKE_PRIVATE_KEY_PATH in the environment.'
        )
    return Session.builder.configs(config).create()


def _json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return None


def _quote(value) -> str:
    return str(value if value is not None else '').replace("'", "''")


# --------------------------------------------------------------------------- #
# FlowSink
# --------------------------------------------------------------------------- #
class FlowSink(ABC):
    """Destination for structured flow records produced by the ingestion layer."""

    @abstractmethod
    def emit(self, record: dict) -> None:
        raise NotImplementedError

    def emit_many(self, records) -> int:
        count = 0
        for record in records:
            self.emit(record)
            count += 1
        return count

    def close(self) -> None:  # pragma: no cover - default no-op
        return None


class LocalFlowSink(FlowSink):
    """Appends one JSON object per line to the local flow output file."""

    def __init__(self, output_path=None):
        self.path = Path(output_path) if output_path else _local_flow_output()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: dict) -> None:
        line = json.dumps(record, default=_json_safe, sort_keys=True)
        with self.path.open('a', encoding='utf-8') as handle:
            handle.write(line + '\n')


class CloudFlowSink(FlowSink):
    """Pushes each flow record to a Kinesis Data Firehose delivery stream."""

    def __init__(self, stream_name=None, client=None):
        self.stream_name = stream_name or os.environ.get('FIREHOSE_DELIVERY_STREAM_NAME')
        if not self.stream_name:
            raise RuntimeError(
                'CLOUD FlowSink requires FIREHOSE_DELIVERY_STREAM_NAME to be set.'
            )
        self._client = client

    @property
    def client(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - env dependent
                raise RuntimeError('boto3 is required for the CLOUD FlowSink') from exc
            self._client = boto3.client('firehose')
        return self._client

    def emit(self, record: dict) -> None:
        payload = json.dumps(record, default=_json_safe, sort_keys=True) + '\n'
        self.client.put_record(
            DeliveryStreamName=self.stream_name,
            Record={'Data': payload.encode('utf-8')},
        )


# --------------------------------------------------------------------------- #
# ModelRepository
# --------------------------------------------------------------------------- #
class ModelRepository(ABC):
    """Loads trained model artifacts (ensemble, anomaly detector, preprocessor)."""

    @abstractmethod
    def load_all(self) -> dict:
        """Return {'ensemble','isolation_forest','preprocessor','baseline'}."""

    def load_baseline(self) -> dict:
        with open(self.load_all()['baseline'], 'r', encoding='utf-8') as handle:
            return json.load(handle)


class LocalModelRepository(ModelRepository):
    """Reads .joblib artifacts straight from the local storage/models dir."""

    def __init__(self, model_dir=None):
        self.model_dir = Path(model_dir) if model_dir else _local_model_dir()

    def load_all(self) -> dict:
        import joblib

        base = str(self.model_dir)
        return {
            'ensemble': joblib.load(os.path.join(base, ENSEMBLE_FILENAME)),
            'isolation_forest': joblib.load(os.path.join(base, ISOLATION_FILENAME)),
            'preprocessor': joblib.load(os.path.join(base, PREPROCESSOR_FILENAME)),
            'baseline': os.path.join(base, BASELINE_FILENAME),
        }


class CloudModelRepository(ModelRepository):
    """Downloads artifacts from @CORE.MODEL_STAGE on first use, then loads them."""

    def __init__(self, session=None, model_dir=None):
        self.session = session
        self.model_dir = Path(model_dir) if model_dir else Path('/tmp/froststream_models')
        self._local = None

    def _session(self):
        if self.session is None:
            self.session = _cloud_session()
        return self.session

    def _ensure_local(self) -> Path:
        if self._local is not None:
            return self._local
        self.model_dir.mkdir(parents=True, exist_ok=True)
        session = self._session()
        for filename in (
            ENSEMBLE_FILENAME,
            ISOLATION_FILENAME,
            PREPROCESSOR_FILENAME,
            BASELINE_FILENAME,
        ):
            target = self.model_dir / filename
            if not target.exists():
                session.file.get(f'{MODEL_STAGE}/{filename}', str(self.model_dir))
        self._local = self.model_dir
        return self.model_dir

    def load_all(self) -> dict:
        return LocalModelRepository(self._ensure_local()).load_all()


# --------------------------------------------------------------------------- #
# AlertSink
# --------------------------------------------------------------------------- #
class AlertSink(ABC):
    """Destination for scored alerts (severity, confidence, raw features)."""

    @abstractmethod
    def log_alert(self, alert: dict) -> None:
        raise NotImplementedError

    def log_many(self, alerts) -> int:
        count = 0
        for alert in alerts:
            self.log_alert(alert)
            count += 1
        return count


class LocalAlertSink(AlertSink):
    """Writes alerts to the local SQLite alert store (storage/alerts.db)."""

    def __init__(self, db_path=None):
        from storage.alert_logger import AlertLogger

        self._logger = AlertLogger(db_path=str(db_path) if db_path else None)

    @property
    def db_path(self) -> str:
        return self._logger.db_path

    def log_alert(self, alert: dict) -> None:
        summary = alert.get('features_summary')
        if summary is None:
            summary = (
                f"anomaly={alert.get('anomaly_score', 0.0)} "
                f"zero_day={alert.get('is_zero_day_suspect', False)} "
                f"severity={alert.get('severity', 'INFO')}"
            )
        self._logger.log_alert(
            protocol=alert.get('protocol_type', 'tcp'),
            service=alert.get('service', 'other'),
            src_bytes=int(alert.get('src_bytes', 0) or 0),
            dst_bytes=int(alert.get('dst_bytes', 0) or 0),
            predicted_category=alert.get(
                'predicted_category', alert.get('attack_type', 'Normal')
            ),
            confidence=float(alert.get('confidence', 0.0)),
            features_summary=str(summary),
        )


class CloudAlertSink(AlertSink):
    """Inserts alerts into Snowflake CORE.NIDS_ALERTS (INSERT ... SELECT form)."""

    COLUMNS = (
        'ALERT_ID', 'FLOW_ID', 'SRC_IP', 'DST_IP', 'SRC_PORT', 'DST_PORT',
        'ATTACK_TYPE', 'CONFIDENCE', 'ANOMALY_SCORE', 'SEVERITY',
        'IS_ZERO_DAY_SUSPECT', 'MITIGATION_STATUS', 'RAW_FEATURES',
    )

    def __init__(self, session=None):
        self.session = session

    def _session(self):
        if self.session is None:
            self.session = _cloud_session()
        return self.session

    @classmethod
    def _row_select(cls, alert: dict) -> str:
        raw = json.dumps({str(k): _json_safe(v) for k, v in alert.items()})
        raw = raw.replace("'", "''")
        attack = alert.get(
            'predicted_category', alert.get('attack_type', 'Normal')
        )
        return (
            "SELECT "
            f"'{_quote(alert.get('alert_id') or uuid.uuid4().hex)}', "
            f"'{_quote(alert.get('flow_id'))}', "
            f"'{_quote(alert.get('src_ip') or '0.0.0.0')}', "
            f"'{_quote(alert.get('dst_ip') or '0.0.0.0')}', "
            f"{int(alert.get('src_port') or 0)}, "
            f"{int(alert.get('dst_port') or 0)}, "
            f"'{_quote(attack)}', "
            f"{float(alert.get('confidence', 0.0))}, "
            f"{float(alert.get('anomaly_score') or 0.0)}, "
            f"'{_quote(alert.get('severity') or 'INFO')}', "
            f"{'TRUE' if alert.get('is_zero_day_suspect') else 'FALSE'}, "
            f"'{_quote(alert.get('mitigation_status') or 'PENDING')}', "
            f"PARSE_JSON('{raw}')::VARIANT"
        )

    def log_alert(self, alert: dict) -> None:
        columns = ', '.join(cls for cls in self.COLUMNS)
        sql = (
            f"INSERT INTO CORE.NIDS_ALERTS ({columns}) "
            + self._row_select(alert)
        )
        self._session().sql(sql).collect()

    def log_many(self, alerts) -> int:
        selects = [self._row_select(alert) for alert in alerts]
        if not selects:
            return 0
        columns = ', '.join(self.COLUMNS)
        sql = (
            f"INSERT INTO CORE.NIDS_ALERTS ({columns}) "
            + ' UNION ALL '.join(selects)
        )
        self._session().sql(sql).collect()
        return len(selects)


# --------------------------------------------------------------------------- #
# MitigationAction
# --------------------------------------------------------------------------- #
class MitigationAction(ABC):
    """Executes (or mocks) the automated block of a hostile source IP."""

    @abstractmethod
    def apply(self, src_ip: str, alert_id: str = None, confidence: float = None,
              attack_type: str = None) -> dict:
        raise NotImplementedError


class LocalMitigationAction(MitigationAction):
    """Records the mock NACL action in a local SQLite firewall table."""

    def __init__(self, db_path=None, ttl_hours: int = None, verbose: bool = False):
        self.db_path = Path(db_path) if db_path else _local_firewall_db()
        if ttl_hours is None:
            raw = os.environ.get('BLOCK_TTL_HOURS', '24')
            try:
                ttl_hours = int(raw)
            except ValueError:
                ttl_hours = 24
        self.ttl_hours = ttl_hours
        self.verbose = verbose
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mock_nacl_rules (
                    rule_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    alert_id TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    status TEXT,
                    ttl_epoch INTEGER,
                    created_at TEXT
                )
            ''')
            conn.commit()

    def apply(self, src_ip: str, alert_id: str = None, confidence: float = None,
              attack_type: str = None) -> dict:
        rule_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        expires = int((now + timedelta(hours=self.ttl_hours)).timestamp())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO mock_nacl_rules '
                '(rule_id, src_ip, alert_id, attack_type, confidence, status, ttl_epoch, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    rule_id, str(src_ip), alert_id, attack_type,
                    float(confidence) if confidence is not None else None,
                    'ACTIONED', expires, now.strftime('%Y-%m-%d %H:%M:%S'),
                ),
            )
            conn.commit()
        if self.verbose:
            print(
                f'[MOCK] NACL deny {src_ip}/32 rule={rule_id} '
                f'ttl={self.ttl_hours}h status=ACTIONED'
            )
        return {
            'status': 'ACTIONED',
            'src_ip': str(src_ip),
            'rule_id': rule_id,
            'ttl_hours': self.ttl_hours,
            'expires_epoch': expires,
        }

    def list_blocks(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT * FROM mock_nacl_rules ORDER BY created_at'
            ).fetchall()
        return [dict(row) for row in rows]


class CloudMitigationAction(MitigationAction):
    """Creates a deny entry on the target NACL via boto3 (rule in a free range)."""

    def __init__(self, nacl_id: str = None, vpc_id: str = None, client=None,
                 rule_start: int = 100, rule_end: int = 199):
        self.nacl_id = nacl_id or os.environ.get('TARGET_NACL_ID')
        self.vpc_id = vpc_id or os.environ.get('TARGET_VPC_ID')
        self._client = client
        self.rule_start = int(os.environ.get('NACL_RULE_START', rule_start))
        self.rule_end = int(os.environ.get('NACL_RULE_END', rule_end))
        if client is None and not self.nacl_id:
            raise RuntimeError('CLOUD mitigation requires TARGET_NACL_ID to be set.')

    @property
    def client(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - env dependent
                raise RuntimeError('boto3 is required for CLOUD mitigation') from exc
            self._client = boto3.client('ec2')
        return self._client

    def _next_rule_number(self) -> int:
        response = self.client.describe_network_acls(NetworkAclIds=[self.nacl_id])
        acls = response.get('NetworkAcls', [])
        used = {
            int(entry['RuleNumber'])
            for acl in acls
            for entry in acl.get('Entries', [])
            if not entry.get('Egress', False)
        }
        for number in range(self.rule_start, self.rule_end + 1):
            if number not in used:
                return number
        raise RuntimeError(
            f'No free NACL rule number in [{self.rule_start}, {self.rule_end}]'
        )

    def apply(self, src_ip: str, alert_id: str = None, confidence: float = None,
              attack_type: str = None) -> dict:
        rule_number = self._next_rule_number()
        self.client.create_network_acl_entry(
            NetworkAclId=self.nacl_id,
            RuleNumber=rule_number,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f'{src_ip}/32',
        )
        return {
            'status': 'ACTIONED',
            'src_ip': str(src_ip),
            'nacl_id': self.nacl_id,
            'rule_number': rule_number,
            'alert_id': alert_id,
        }


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
class DualModeFactory:
    """Resolves every sink to its LOCAL or CLOUD implementation (cached)."""

    def __init__(self, mode: str = None, session=None):
        raw = mode if mode is not None else get_execution_mode()
        self.mode = raw.strip().upper()
        if self.mode not in VALID_MODES:
            raise ValueError(
                f"Invalid execution mode {raw!r}; expected one of {', '.join(VALID_MODES)}"
            )
        self.session = session
        self._sinks: dict = {}

    def flow_sink(self, **kwargs) -> FlowSink:
        key = ('flow', json.dumps(kwargs, sort_keys=True, default=str))
        if key not in self._sinks:
            self._sinks[key] = (
                CloudFlowSink(**kwargs) if self.is_cloud else LocalFlowSink(**kwargs)
            )
        return self._sinks[key]

    def model_repository(self, **kwargs) -> ModelRepository:
        if self.is_cloud and 'session' not in kwargs and self.session is not None:
            kwargs['session'] = self.session
        key = ('model', json.dumps(kwargs, sort_keys=True, default=str))
        if key not in self._sinks:
            if self.is_cloud:
                self._sinks[key] = CloudModelRepository(**kwargs)
            else:
                self._sinks[key] = LocalModelRepository(**kwargs)
        return self._sinks[key]

    def alert_sink(self, **kwargs) -> AlertSink:
        if self.is_cloud and 'session' not in kwargs and self.session is not None:
            kwargs['session'] = self.session
        key = ('alert', json.dumps(kwargs, sort_keys=True, default=str))
        if key not in self._sinks:
            if self.is_cloud:
                self._sinks[key] = CloudAlertSink(**kwargs)
            else:
                self._sinks[key] = LocalAlertSink(**kwargs)
        return self._sinks[key]

    def mitigation_action(self, **kwargs) -> MitigationAction:
        key = ('mitigation', json.dumps(kwargs, sort_keys=True, default=str))
        if key not in self._sinks:
            self._sinks[key] = (
                CloudMitigationAction(**kwargs) if self.is_cloud
                else LocalMitigationAction(**kwargs)
            )
        return self._sinks[key]

    @property
    def is_cloud(self) -> bool:
        return self.mode == 'CLOUD'

    @property
    def is_local(self) -> bool:
        return self.mode == 'LOCAL'


def get_factory(mode: str = None, session=None) -> DualModeFactory:
    return DualModeFactory(mode=mode, session=session)


def flow_sink(mode: str = None, **kwargs) -> FlowSink:
    return get_factory(mode).flow_sink(**kwargs)


def model_repository(mode: str = None, **kwargs) -> ModelRepository:
    return get_factory(mode).model_repository(**kwargs)


def alert_sink(mode: str = None, **kwargs) -> AlertSink:
    return get_factory(mode).alert_sink(**kwargs)


def mitigation_action(mode: str = None, **kwargs) -> MitigationAction:
    return get_factory(mode).mitigation_action(**kwargs)
