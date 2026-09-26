import os

ENSEMBLE_FILENAME = 'ensemble_classifier.joblib'
ISOLATION_FILENAME = 'isolation_forest.joblib'
PREPROCESSOR_FILENAME = 'preprocessor.joblib'
BASELINE_FILENAME = 'baseline_distribution.json'
MODEL_MANIFEST_FILENAME = 'manifest.json'

ATTACK_TYPES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']

PSI_EPS = 1e-4


def default_model_dir() -> str:
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(repo_root, 'storage', 'models')


def env_float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None or raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def env_bool(key: str, default: bool = False) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().upper() in ('1', 'TRUE', 'YES', 'ON')


DEFAULT_CONFIDENCE_THRESHOLD = env_float('CONFIDENCE_THRESHOLD', 0.90)
DEFAULT_CRITICAL_CONFIDENCE_THRESHOLD = env_float('CRITICAL_CONFIDENCE_THRESHOLD', 0.95)
DEFAULT_ANOMALY_THRESHOLD = env_float('ANOMALY_THRESHOLD', -0.2)
DEFAULT_PSI_DRIFT_THRESHOLD = env_float('PSI_DRIFT_THRESHOLD', 0.25)