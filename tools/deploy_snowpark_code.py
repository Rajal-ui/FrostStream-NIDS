"""Phase 3 code-packaging helper for the Snowpark stage.

Builds ``snowpark_code.zip`` from the ``src/`` and ``data/`` package trees so the
stored procedures in ``snowflake_setup/03_snowpark_integration.sql`` can import
``src.models.inference`` / ``src.models.drift_monitor`` natively on the
Snowflake Python runtime (handler = ``src.models.*.<entrypoint>``).

``--build`` is fully offline (usable in tests/CI without credentials). ``--upload``
requires `EXECUTION_MODE=CLOUD` environment variables or a ~/.snowflake profile.
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import zipfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ARCHIVE = os.path.join(REPO_ROOT, '.cache', 'snowpark_code.zip')
STAGE_TARGET = '@CORE.SNOWPARK_CODE_STAGE'
INCLUDED_ROOTS = ('src', 'data')
SKIP_DIRS = {'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'}
SKIP_SUFFIXES = ('.pyc', '.pyo')


def build_archive(out_path: str | None = None) -> str:
    """Zip ``src/`` and ``data/`` into a single archive on the D: drive (policy)."""
    out_path = out_path or DEFAULT_ARCHIVE
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root in INCLUDED_ROOTS:
            base = os.path.join(REPO_ROOT, root)
            if not os.path.isdir(base):
                raise FileNotFoundError(f'missing package directory: {base}')
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for filename in sorted(filenames):
                    if filename.endswith(SKIP_SUFFIXES):
                        continue
                    full = os.path.join(dirpath, filename)
                    rel = os.path.relpath(full, REPO_ROOT).replace(os.sep, '/')
                    zf.write(full, rel)

    with open(out_path, 'wb') as fh:
        fh.write(buf.getvalue())

    with zipfile.ZipFile(out_path, 'r') as zf:
        names = zf.namelist()
    required = {
        'src/__init__.py',
        'src/models/__init__.py',
        'src/models/inference.py',
        'src/models/drift_monitor.py',
        'src/models/train.py',
        'src/models/constants.py',
        'data/__init__.py',
        'data/dataset_loader.py',
    }
    missing = required - set(names)
    if missing:
        raise RuntimeError(f'archive missing required members: {sorted(missing)}')
    print(f'Built {out_path} ({os.path.getsize(out_path)} bytes, {len(names)} files)')
    return out_path


def _session_from_env():
    import snowflake.snowpark  # noqa: F401
    from snowflake.snowpark import Session

    keys = {
        'account': 'SNOWFLAKE_ACCOUNT',
        'user': 'SNOWFLAKE_USER',
        'password': 'SNOWFLAKE_PASSWORD',
        'role': 'SNOWFLAKE_ROLE',
        'database': 'SNOWFLAKE_DATABASE',
        'schema': 'SNOWFLAKE_SCHEMA',
        'warehouse': 'SNOWFLAKE_WAREHOUSE',
    }
    config = {k: os.environ[v] for k, v in keys.items() if os.environ.get(v)}
    if config.get('user') and os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH'):
        config.pop('password', None)
    if not config.get('account') or not config.get('user'):
        raise SystemExit(
            'CLOUD mode requires SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and a '
            'password or SNOWFLAKE_PRIVATE_KEY_PATH in the environment.'
        )
    return Session.builder.configs(config).create()


def upload_archive(archive_path: str) -> None:
    """PUT the archive (and any updated handler sources) to the code stage."""
    session = _session_from_env()
    try:
        for local, _remote in [(archive_path, None)]:
            try:
                session.file.put(local, STAGE_TARGET, overwrite=True, auto_compress=False)
            except TypeError:
                session.file.put(local, STAGE_TARGET, overwrite=True)
        print(f'Uploaded {os.path.basename(archive_path)} to {STAGE_TARGET}')
    finally:
        session.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='build the zip archive (offline)')
    parser.add_argument('--upload', action='store_true', help='upload the zip to the Snowpark code stage')
    parser.add_argument('--archive', default=None, help='archive path (default: .cache/snowpark_code.zip)')
    args = parser.parse_args(argv)

    if not (args.build or args.upload):
        parser.error('at least one of --build / --upload is required')

    archive = args.archive or DEFAULT_ARCHIVE
    if args.build:
        archive = build_archive(archive)
    if args.upload:
        if not os.path.exists(archive):
            archive = build_archive(archive)
        upload_archive(archive)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())