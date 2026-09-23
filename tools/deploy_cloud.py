"""Cloud deployment runner for FrostStream NIDS phases 1 and 3.

Loads credentials from the repo ``.env`` (or the environment), connects with
``snowflake-snowpark`` (no ``snow`` CLI required), executes the SQL migration
files statement-by-statement, and (phase 3) packages + uploads the Snowpark
code and registered models.

Usage:
    python tools/deploy_cloud.py --check              # validate connection only
    python tools/deploy_cloud.py --phase 1            # 01 + 02 + verify
    python tools/deploy_cloud.py --phase 3            # code upload + 03 + verify
    python tools/deploy_cloud.py --phase 3 --enable-soar   # include SOAR DDL
    python tools/deploy_cloud.py --phase 3 --skip-verify

Never prints secrets. ``--enable-soar`` is required before Phase 5 infra exists.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SETUP_DIR = REPO_ROOT / 'snowflake_setup'

TOKEN_MAP = {
    '<AWS_ACCOUNT_ID>': 'AWS_ACCOUNT_ID',
    '<S3_BUCKET_NAME>': 'S3_FLOW_BUCKET',
    '<region>': 'AWS_DEFAULT_REGION',
    '<AWS_INGEST_ACCESS_KEY_ID>': 'AWS_INGEST_ACCESS_KEY_ID',
    '<AWS_INGEST_SECRET_ACCESS_KEY>': 'AWS_INGEST_SECRET_ACCESS_KEY',
}

SECRET_ENV_KEYS = (
    'AWS_INGEST_SECRET_ACCESS_KEY',
    'AWS_SECRET_ACCESS_KEY',
    'SNOWFLAKE_PASSWORD',
)


def mask_secrets(text: str) -> str:
    """Replace known secret env values so they never reach the console."""
    for key in SECRET_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            text = text.replace(value, '***')
    return text

SOAR_BLOCK_RE = re.compile(
    r'--\s*\[SOAR_API_START\].*?--\s*\[SOAR_API_END\]|'
    r'--\s*\[SOAR_TASK_START\].*?--\s*\[SOAR_TASK_END\]',
    re.S,
)


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE pairs into os.environ (does not override existing vars).

    Handles blank lines, full-line comments and inline ``# comments`` (outside
    string literals)."""
    dotenv = path or REPO_ROOT / '.env'
    if not dotenv.exists():
        return
    for line in dotenv.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if not key or key in os.environ:
            continue
        in_string = False
        comment_at = len(value)
        for idx, ch in enumerate(value):
            if ch == "'":
                in_string = not in_string
            elif ch == '#' and not in_string and (idx == 0 or value[idx - 1] in ' \t'):
                comment_at = idx
                break
        value = value[:comment_at].strip().strip('"\'')
        os.environ[key] = value


def build_session():
    from snowflake.snowpark import Session

    required = ('SNOWFLAKE_ACCOUNT', 'SNOWFLAKE_USER')
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        raise SystemExit(f'Missing required env vars: {", ".join(missing)} (see .env / .env.example)')

    config = {
        'account': os.environ['SNOWFLAKE_ACCOUNT'],
        'user': os.environ['SNOWFLAKE_USER'],
        'role': os.environ.get('SNOWFLAKE_ROLE'),
        'database': os.environ.get('SNOWFLAKE_DATABASE'),
        'schema': os.environ.get('SNOWFLAKE_SCHEMA'),
        'warehouse': os.environ.get('SNOWFLAKE_WAREHOUSE'),
    }
    config = {k: v for k, v in config.items() if v}

    if os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH'):
        config['private_key_file'] = os.environ['SNOWFLAKE_PRIVATE_KEY_PATH']
        if os.environ.get('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE'):
            config['private_key_file_pwd'] = os.environ['SNOWFLAKE_PRIVATE_KEY_PASSPHRASE']
    else:
        password = os.environ.get('SNOWFLAKE_PASSWORD')
        if not password:
            raise SystemExit('No SNOWFLAKE_PASSWORD or SNOWFLAKE_PRIVATE_KEY_PATH provided.')
        config['password'] = password

    return Session.builder.configs(config).create()


def substitute_tokens(sql: str) -> str:
    for token, env_key in TOKEN_MAP.items():
        value = os.environ.get(env_key)
        if value:
            sql = sql.replace(token, value)
    return sql


def strip_soar_blocks(sql: str, enabled: bool) -> str:
    if enabled:
        return re.sub(r'--\s*\[SOAR_(API|TASK)_(START|END)\]', '', sql)
    return SOAR_BLOCK_RE.sub('', sql)


def split_sql_statements(text: str) -> list[str]:
    """Split on top-level semicolons, ignoring comments and string literals."""
    statements: list[str] = []
    current: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            current.append(ch)
            if ch == "'":
                in_string = False
            elif ch == '\\' and i + 1 < n:  # Snowflake string escape
                current.append(text[i + 1])
                i += 1
            i += 1
            continue

        if ch == "'":
            in_string = True
            current.append(ch)
        elif text.startswith('--', i):
            end = text.find('\n', i)
            i = (end if end != -1 else n)
            continue
        elif ch == ';':
            stmt = ''.join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
        else:
            current.append(ch)
        i += 1

    tail = ''.join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def run_script(session, path: Path, *, fail_fast: bool = True,
               tokens: bool = False, parse_only: bool = False) -> int:
    sql = path.read_text(encoding='utf-8')
    statements = split_sql_statements(sql)
    print(f'\n== {path.name} ({len(statements)} statements)')
    executed = 0
    for stmt in statements:
        if tokens:
            stmt = substitute_tokens(stmt)
        print(f'  > {mask_secrets(stmt)[:80]}{"..." if len(stmt) > 80 else ""}')
        if parse_only:
            executed += 1
            continue
        try:
            rows = session.sql(stmt).collect()
            executed += 1
            for row in rows:
                record = row.as_dict() if hasattr(row, 'as_dict') else dict(row)
                for key, value in record.items():
                    text = str(value)
                    if len(text) > 300:
                        text = text[:300] + '...'
                    print(f'      {key}: {text}')
        except Exception as exc:  # noqa: BLE001
            message = f'ERROR executing statement in {path.name}: {exc}'
            if fail_fast:
                raise SystemExit(message) from exc
            print(f'    ! {message}')
    return executed


def check_connection(session) -> None:
    rows = session.sql(
        'SELECT CURRENT_VERSION() AS V, CURRENT_ROLE() AS R, CURRENT_WAREHOUSE() AS W, '
        'CURRENT_DATABASE() AS D, CURRENT_SCHEMA() AS S'
    ).collect()
    row = rows[0].as_dict()
    print('Connection OK:')
    print(f"  version    : {row['V']}")
    print(f"  role       : {row['R']}")
    print(f"  warehouse  : {row['W']}")
    print(f"  database   : {row['D']}")
    print(f"  schema     : {row['S']}")


def deploy_phase1(session, *, verify: bool) -> None:
    run_script(session, SETUP_DIR / '01_tables.sql', tokens=True)
    run_script(session, SETUP_DIR / '02_snowpipe.sql', tokens=True)
    if verify:
        run_script(session, SETUP_DIR / 'verify_phase1.sql', fail_fast=False)


def deploy_phase3(session, *, verify: bool, enable_soar: bool, skip_upload: bool) -> None:
    if not skip_upload:
        sys.path.insert(0, str(REPO_ROOT / 'tools'))
        from deploy_snowpark_code import build_archive

        archive = build_archive(str(REPO_ROOT / '.cache' / 'snowpark_code.zip'))
        try:
            session.file.put(archive, '@CORE.SNOWPARK_CODE_STAGE', overwrite=True, auto_compress=False)
        except TypeError:
            session.file.put(archive, '@CORE.SNOWPARK_CODE_STAGE', overwrite=True)
        print(f'Uploaded {Path(archive).name} -> @CORE.SNOWPARK_CODE_STAGE')

    sql = (SETUP_DIR / '03_snowpark_integration.sql').read_text(encoding='utf-8')
    sql = strip_soar_blocks(sql, enabled=enable_soar)
    statements = split_sql_statements(sql)
    print(f'\n== 03_snowpark_integration.sql ({len(statements)} statements, '
          f'soar={"ON" if enable_soar else "OFF"})')
    for stmt in statements:
        stmt = substitute_tokens(stmt)
        print(f'  > {mask_secrets(stmt)[:80]}{"..." if len(stmt) > 80 else ""}')
        try:
            rows = session.sql(stmt).collect()
            for row in rows:
                for key, value in (row.as_dict() if hasattr(row, 'as_dict') else dict(row)).items():
                    print(f'      {key}: {str(value)[:300]}')
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f'ERROR executing statement in 03_snowpark_integration.sql: {exc}') from exc

    if verify:
        run_script(session, SETUP_DIR / 'verify_phase3.sql', fail_fast=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', type=int, choices=(1, 3))
    parser.add_argument('--check', action='store_true', help='connect and print session state only')
    parser.add_argument('--enable-soar', action='store_true',
                        help='include SOAR API integration/external function/task DDL (Phase 5)')
    parser.add_argument('--skip-verify', action='store_true')
    parser.add_argument('--skip-upload', action='store_true', help='phase 3: skip code archive upload')
    args = parser.parse_args(argv)

    load_dotenv()

    if args.check:
        session = build_session()
        try:
            check_connection(session)
        finally:
            session.close()
        return 0
    if args.phase not in (1, 3):
        parser.error('--phase 1|3 required (or --check)')

    session = build_session()
    try:
        if args.phase == 1:
            deploy_phase1(session, verify=not args.skip_verify)
        else:
            deploy_phase3(session, verify=not args.skip_verify,
                          enable_soar=args.enable_soar, skip_upload=args.skip_upload)
        print(f'\nPhase {args.phase} deployment complete.')
    finally:
        session.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())