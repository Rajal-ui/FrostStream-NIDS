"""Offline consistency checks for Phase 3 Snowpark registration SQL.

Verifies that the stored-procedure handlers declared in
snowflake_setup/03_snowpark_integration.sql map onto real (importable) Python
entrypoints in src/, that the packaging IMPORTS matches the built archive, and
that the orchestration tasks reference the procedures/external functions they
are wired to. No cloud account required.
"""

import re
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PHASE3_SQL = (REPO_ROOT / 'snowflake_setup' / '03_snowpark_integration.sql').read_text(encoding='utf-8')
SRC_ROOT = REPO_ROOT / 'src'

# (proc_name, runtime_version, imports_target, handler)
PROCS = re.findall(
    r"CREATE OR REPLACE PROCEDURE CORE\.(\w+)\(\)\s+"
    r"RETURNS STRING\s+LANGUAGE PYTHON\s+RUNTIME_VERSION = '([^']+)'\s+"
    r"PACKAGES = \([^)]*\)\s+IMPORTS = \('([^']+)'\)\s+"
    r"HANDLER = '([^']+)'",
    PHASE3_SQL,
    re.S,
)


def _handler_to_module_path(handler: str) -> tuple[Path, str]:
    module, _, func = handler.rpartition('.')
    parts = module.split('.')
    if parts[0] == 'src':
        parts = parts[1:]
    file = SRC_ROOT.joinpath(*parts).with_suffix('.py')
    return file, func


def test_two_procedures_registered_with_python_310() -> None:
    names = {name for name, _runtime, _imports, _handler in PROCS}
    assert names == {'SP_RUN_NIDS_INFERENCE', 'SP_RUN_DRIFT_MONITOR'}
    assert {runtime for _n, runtime, _i, _h in PROCS} == {'3.10'}


def test_handlers_point_at_real_importable_entrypoints() -> None:
    assert PROCS, 'no CREATE OR REPLACE PROCEDURE ... HANDLER parsed'
    for _name, _runtime, _imports, handler in PROCS:
        file, func = _handler_to_module_path(handler)
        assert file.exists(), f'handler module does not exist: {file}'
        source = file.read_text(encoding='utf-8')
        assert re.search(rf'^def {func}\(', source, re.M), (
            f'{func} not defined in {file}'
        )


def test_procedures_import_the_packaged_archive() -> None:
    for _name, _runtime, imports, _handler in PROCS:
        assert imports == '@CORE.SNOWPARK_CODE_STAGE/snowpark_code.zip'


def test_archive_contains_required_modules() -> None:
    archive = REPO_ROOT / '.cache' / 'snowpark_code.zip'
    if not archive.exists():
        from tools.deploy_snowpark_code import build_archive

        build_archive(str(archive))
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    modules = {_handler_to_module_path(h)[0] for _n, _r, _i, h in PROCS}
    missing = [m.relative_to(REPO_ROOT).as_posix() for m in modules if m.relative_to(REPO_ROOT).as_posix() not in names]
    assert not missing, f'archive missing handler modules: {missing}'


def test_archive_has_no_package_shadowing() -> None:
    """A module file must not collide with a same-named package directory
    (e.g. src/models.py vs src/models/) or zipimport raises NotADirectoryError."""
    archive = REPO_ROOT / '.cache' / 'snowpark_code.zip'
    if not archive.exists():
        from tools.deploy_snowpark_code import build_archive

        build_archive(str(archive))
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    packages = {
        name for name in names
        if name.endswith('/__init__.py') and not name.startswith('__pycache__')
    }
    for name in names:
        if not name.endswith('.py'):
            continue
        stem, _ext = name.rsplit('.', 1)
        assert stem + '/' not in packages, f'{name} shadows package {stem}/'


def test_packaged_init_does_not_hardload_excluded_legacy_module() -> None:
    """src/models/__init__.py must not unconditionally import the legacy
    top-level src/models.py (excluded from the zip) or the SPROC bootstrap
    fails with NotADirectoryError."""
    archive = REPO_ROOT / '.cache' / 'snowpark_code.zip'
    if not archive.exists():
        from tools.deploy_snowpark_code import build_archive

        build_archive(str(archive))
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        assert 'src/models.py' not in names
        init_source = zf.read('src/models/__init__.py').decode('utf-8')
    assert "'models.py'" in init_source or '"models.py"' in init_source
    assert 'exists()' in init_source


def test_external_function_declared_and_called_in_soar_task() -> None:
    assert re.search(r'EXTERNAL FUNCTION CORE\.EXTERNAL_MITIGATE_IP\(', PHASE3_SQL)
    assert re.search(r"AS 'https://<api-id>\.execute-api\.<region>\.amazonaws\.com/prod/mitigate'", PHASE3_SQL)
    soar_task = PHASE3_SQL.split('CREATE OR REPLACE TASK CORE.SOAR_DISPATCH_TASK', 1)[1]
    assert 'EXTERNAL_MITIGATE_IP(' in soar_task
    assert 'SYSTEM$STREAM_HAS_DATA' in soar_task
    assert "MITIGATION_STATUS = 'PENDING'" in soar_task
    assert 'AND IS_SYNTHETIC = FALSE' in soar_task


def test_orchestration_task_wiring() -> None:
    assert 'CALL CORE.SP_RUN_NIDS_INFERENCE()' in PHASE3_SQL
    assert 'CALL CORE.SP_RUN_DRIFT_MONITOR()' in PHASE3_SQL
    assert re.search(r'CREATE OR REPLACE STREAM CORE\.NIDS_ALERTS_STREAM', PHASE3_SQL)
    assert re.search(r'^\s*ALTER TASK INFERENCE_TASK RESUME', PHASE3_SQL, re.M)
    assert re.search(r'^\s*ALTER TASK DRIFT_MONITOR_TASK RESUME', PHASE3_SQL, re.M)
    # SOAR_DISPATCH_TASK must be created (schedulable) but NOT resumed until Phase 5
    assert not re.search(r'^\s*ALTER TASK SOAR_DISPATCH_TASK RESUME', PHASE3_SQL, re.M)