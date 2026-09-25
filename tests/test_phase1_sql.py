"""Offline consistency checks for Phase 1 Snowflake DDL (snowflake_setup/01, 02).

These tests parse the SQL text only - no cloud account required. They guard
against the classic deploy breakers: unsupported CREATE INDEX on standard
tables, a flatten task that explodes JSON objects per-key, and column/table
mismatches between the lander, the flatten task and the inference writer.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TABLES_SQL = (REPO_ROOT / 'snowflake_setup' / '01_tables.sql').read_text(encoding='utf-8')
SNOWPIPE_SQL = (REPO_ROOT / 'snowflake_setup' / '02_snowpipe.sql').read_text(encoding='utf-8')


def _table_columns(content: str, table: str) -> set:
    match = re.search(rf'CREATE TABLE IF NOT EXISTS {table}\s*\((.*?)\)\s*COMMENT', content, re.S)
    assert match, f'could not locate CREATE TABLE {table}'
    block = match.group(1)
    columns = re.findall(r'^\s*([A-Z_][A-Z_0-9]*)\s', block, re.M)
    return {c for c in columns if c != 'PRIMARY'}


def _insert_target_columns(sql: str, table: str) -> list:
    match = re.search(rf'INSERT INTO {table}\s*\((.*?)\)', sql, re.S)
    assert match, f'could not locate INSERT INTO {table} column list'
    return re.findall(r'([A-Z_][A-Z_0-9]*)', match.group(1))


FLOW_FEATURES_COLS = _table_columns(TABLES_SQL, 'FLOW_FEATURES')
NIDS_ALERTS_COLS = _table_columns(TABLES_SQL, 'NIDS_ALERTS')


def test_no_unsupported_create_index() -> None:
    # Assert no actual `CREATE INDEX ...` SQL statement (word appears only in comments)
    assert not re.search(r'CREATE\s+INDEX\s+(IF\s+NOT\s+EXISTS\s+)?[A-Z_]+\s+ON', TABLES_SQL)


def test_clustering_keys_reported_for_hot_tables() -> None:
    assert 'ALTER TABLE FLOW_FEATURES CLUSTER BY (PROCESSED_FLAG, CREATED_AT)' in TABLES_SQL
    assert 'ALTER TABLE NIDS_ALERTS CLUSTER BY (SEVERITY, MITIGATION_STATUS)' in TABLES_SQL
    assert 'ALTER TABLE DRIFT_REPORTS CLUSTER BY (CHECK_TIMESTAMP)' in TABLES_SQL


def test_flatten_task_targets_match_table_columns() -> None:
    targets = _insert_target_columns(SNOWPIPE_SQL, 'FLOW_FEATURES')
    missing = [c for c in targets if c not in FLOW_FEATURES_COLS]
    assert not missing, f'flatten task inserts columns absent from table: {missing}'


def test_flatten_task_selects_produce_every_target_column() -> None:
    select_block = SNOWPIPE_SQL.split('INSERT INTO FLOW_FEATURES', 1)[1]
    aliases = set(re.findall(r'\bAS\s+([A-Z_][A-Z_0-9]*)', select_block))
    targets = set(_insert_target_columns(SNOWPIPE_SQL, 'FLOW_FEATURES'))
    assert aliases == targets, (
        f'SELECT aliases {sorted(aliases)} != INSERT columns {sorted(targets)}'
    )


def test_flatten_handles_object_records_without_per_key_explosion() -> None:
    # The per-key explosion bug: LATERAL FLATTEN directly over a JSON *object*
    assert 'LATERAL FLATTEN(INPUT => RECORD_CONTENT) AS src_record' not in SNOWPIPE_SQL
    assert "PATH => 'records'" in SNOWPIPE_SQL
    assert 'OUTER => TRUE' in SNOWPIPE_SQL


def test_synthetic_marker_and_live_views_are_wired() -> None:
    assert 'IS_SYNTHETIC BOOLEAN NOT NULL DEFAULT FALSE' in TABLES_SQL
    assert "FILE_NAME ILIKE 'flows/smoke_%'" in SNOWPIPE_SQL
    assert "src_record:flow_id::VARCHAR ILIKE 'smoke-%'" in SNOWPIPE_SQL
    assert 'CREATE OR REPLACE VIEW LIVE_FLOW_FEATURES AS' in TABLES_SQL
    assert 'CREATE OR REPLACE VIEW LIVE_NIDS_ALERTS AS' in TABLES_SQL
    assert TABLES_SQL.count('WHERE IS_SYNTHETIC = FALSE') >= 2


def test_inference_alert_columns_exist_in_nids_alerts() -> None:
    inference = (REPO_ROOT / 'src' / 'models' / 'inference.py').read_text(encoding='utf-8')
    match = re.search(
        r"INSERT INTO CORE\.NIDS_ALERTS \(([^)]+)\)", inference, re.S
    )
    assert match, 'could not locate the NIDS_ALERTS INSERT in inference.py'
    written = {c.strip('"\' ,\n\t') for c in match.group(1).split(',') if c.strip('"\' ,\n\t')}
    missing = [c for c in written if c not in NIDS_ALERTS_COLS]
    assert not missing, f'inference writes unknown NIDS_ALERTS columns: {missing}'