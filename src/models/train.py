import argparse
import json
import os
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from xgboost import XGBClassifier

from data.dataset_loader import CATEGORICAL_COLS, NUMERIC_COLS, load_or_create_dataset
from src.models.constants import (
    BASELINE_FILENAME,
    ENSEMBLE_FILENAME,
    ISOLATION_FILENAME,
    MODEL_MANIFEST_FILENAME,
    PREPROCESSOR_FILENAME,
    PSI_EPS,
    default_model_dir,
)
from src.preprocessing import NetworkDataPreprocessor


def compute_baseline_distribution(df: pd.DataFrame, numeric_bins: int = 10) -> dict:
    features = {}
    for col in NUMERIC_COLS:
        if col not in df.columns:
            continue
        values = pd.to_numeric(df[col], errors='coerce').dropna().to_numpy(dtype=float)
        if values.size < 2:
            continue
        quantiles = np.unique(np.quantile(values, np.linspace(0.0, 1.0, int(numeric_bins) + 1)))
        if quantiles.size < 2:
            quantiles = np.array([float(values.min()) - 1.0, float(values.max()) + 1.0])
        counts, _ = np.histogram(values, bins=quantiles)
        expected = (counts + PSI_EPS) / float(counts.sum() + PSI_EPS * counts.size)
        features[col] = {
            'kind': 'numeric',
            'bins': [float(edge) for edge in quantiles],
            'expected': [float(p) for p in expected],
        }
    for col in CATEGORICAL_COLS:
        if col not in df.columns:
            continue
        value_counts = df[col].value_counts(normalize=True)
        categories = [str(c) for c in value_counts.index.tolist()]
        counts = np.array(value_counts.to_list(), dtype=float)
        expected = (counts + PSI_EPS) / float(counts.sum() + PSI_EPS * counts.size)
        features[col] = {
            'kind': 'categorical',
            'categories': categories,
            'expected': [float(p) for p in expected],
        }
    return features


def train_ensemble_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    class_names: list,
    random_state: int = 42,
    iso_contamination: str = 'auto',
) -> dict:
    xgb = XGBClassifier(
        n_estimators=150,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.8,
        random_state=random_state,
        eval_metric='mlogloss',
        n_jobs=-1,
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight='balanced',
        random_state=random_state,
        n_jobs=-1,
    )
    ensemble = VotingClassifier(
        estimators=[('xgb', xgb), ('rf', rf)],
        voting='soft',
        weights=[1.2, 1.0],
        n_jobs=-1,
    )
    ensemble.fit(X_train, y_train)

    normal_index = None
    if 'Normal' in class_names:
        normal_index = class_names.index('Normal')
    normal_mask = y_train == normal_index if normal_index is not None else np.zeros_like(y_train, dtype=bool)

    iso = IsolationForest(
        n_estimators=200,
        contamination=iso_contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    if normal_mask.sum() >= 2:
        iso.fit(X_train[normal_mask])
    else:
        iso.fit(X_train)

    return {'ensemble': ensemble, 'isolation_forest': iso}


def train_models(df: pd.DataFrame, random_state: int = 42) -> dict:
    preprocessor = NetworkDataPreprocessor(scaler_type='standard')
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)
    class_names = list(preprocessor.classes_)

    trained = train_ensemble_models(X_train, y_train, class_names, random_state=random_state)
    ensemble = trained['ensemble']
    iso = trained['isolation_forest']

    start = time.time()
    y_pred = ensemble.predict(X_test)
    proba = ensemble.predict_proba(X_test)
    infer_seconds = time.time() - start

    pred_indices = np.argmax(proba, axis=1)
    confidences = np.max(proba, axis=1)
    labels = preprocessor.decode_labels(pred_indices)
    per_class_recall = classification_report(
        y_test, y_pred, labels=list(range(len(class_names))), target_names=class_names,
        output_dict=True, zero_division=0,
    )

    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, average='weighted', zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, average='weighted', zero_division=0)),
        'f1': float(f1_score(y_test, y_pred, average='weighted', zero_division=0)),
        'macro_f1': float(f1_score(y_test, y_pred, average='macro', zero_division=0)),
        'per_class_recall': {name: per_class_recall.get(name, {}).get('recall', 0.0) for name in class_names},
        'mean_confidence': float(np.mean(confidences)),
        'inference_seconds': round(infer_seconds, 4),
        'train_samples': int(len(df)),
        'test_samples': int(len(y_test)),
    }

    baseline = compute_baseline_distribution(df)

    return {
        'preprocessor': preprocessor,
        'ensemble': ensemble,
        'isolation_forest': iso,
        'baseline_distribution': baseline,
        'class_names': class_names,
        'metrics': metrics,
        'y_test': y_test,
        'y_pred': y_pred,
        'X_test': X_test,
    }


def save_artifacts(out_dir: str, result: dict, version: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        'ensemble': os.path.join(out_dir, ENSEMBLE_FILENAME),
        'isolation_forest': os.path.join(out_dir, ISOLATION_FILENAME),
        'preprocessor': os.path.join(out_dir, PREPROCESSOR_FILENAME),
        'baseline': os.path.join(out_dir, BASELINE_FILENAME),
    }
    joblib.dump(result['ensemble'], paths['ensemble'])
    joblib.dump(result['isolation_forest'], paths['isolation_forest'])
    joblib.dump(result['preprocessor'], paths['preprocessor'])
    with open(paths['baseline'], 'w', encoding='utf-8') as fh:
        json.dump(result['baseline_distribution'], fh, indent=2)

    manifest = {
        'model_name': 'nids_ensemble',
        'version': version,
        'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'class_names': result['class_names'],
        'training_metrics': result['metrics'],
        'baseline_feature_count': len(result['baseline_distribution']),
        'stage_path': f'@CORE.MODEL_STAGE/{ENSEMBLE_FILENAME}',
        'files': {
            'ensemble_classifier': ENSEMBLE_FILENAME,
            'isolation_forest': ISOLATION_FILENAME,
            'preprocessor': PREPROCESSOR_FILENAME,
            'baseline_distribution': BASELINE_FILENAME,
        },
    }
    with open(os.path.join(out_dir, MODEL_MANIFEST_FILENAME), 'w', encoding='utf-8') as fh:
        json.dump(manifest, fh, indent=2, default=str)

    return manifest


def current_version() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def register_in_snowflake(out_dir: str, manifest: dict, session=None) -> str:
    if session is None:
        try:
            from snowflake.snowpark import Session
        except ImportError as exc:
            raise RuntimeError('snowflake-snowpark-python is required in CLOUD mode') from exc
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
        session = Session.builder.configs(config).create()

    put_result = []
    for remote, local in {
        ENSEMBLE_FILENAME: os.path.join(out_dir, ENSEMBLE_FILENAME),
        ISOLATION_FILENAME: os.path.join(out_dir, ISOLATION_FILENAME),
        PREPROCESSOR_FILENAME: os.path.join(out_dir, PREPROCESSOR_FILENAME),
        BASELINE_FILENAME: os.path.join(out_dir, BASELINE_FILENAME),
    }.items():
        try:
            put_result.append(session.file.put(local, '@CORE.MODEL_STAGE', overwrite=True, auto_compress=False))
        except TypeError:
            put_result.append(session.file.put(local, '@CORE.MODEL_STAGE', overwrite=True))

    metrics_json = json.dumps(manifest['training_metrics'])
    baseline_path = f"@CORE.MODEL_STAGE/{BASELINE_FILENAME}"
    registry_rows = [
        ('nids_ensemble', manifest['version'], f"@CORE.MODEL_STAGE/{ENSEMBLE_FILENAME}", 'ENSEMBLE_CLASSIFIER', metrics_json, 'TRUE'),
        ('isolation_forest', manifest['version'], f"@CORE.MODEL_STAGE/{ISOLATION_FILENAME}", 'ISOLATION_FOREST', 'NULL', 'TRUE'),
        ('preprocessor', manifest['version'], f"@CORE.MODEL_STAGE/{PREPROCESSOR_FILENAME}", 'PREPROCESSOR', 'NULL', 'TRUE'),
        ('baseline_distribution', manifest['version'], baseline_path, 'BASELINE_DISTRIBUTION', 'NULL', 'TRUE'),
    ]
    selects = []
    for model_name, version, stage_path, model_type, metrics, active in registry_rows:
        metrics_sql = f"$${metrics}$$" if metrics != 'NULL' else 'NULL'
        selects.append(
            f"SELECT '{model_name}' AS MODEL_NAME, '{version}' AS VERSION, "
            f"'{stage_path}' AS STAGE_PATH, '{model_type}' AS MODEL_TYPE, "
            f"{metrics_sql}::VARIANT AS TRAINING_METRICS, {active} AS IS_ACTIVE"
        )
    sql = (
        "INSERT INTO CORE.MODEL_REGISTRY (MODEL_NAME, VERSION, STAGE_PATH, MODEL_TYPE, "
        "TRAINING_METRICS, IS_ACTIVE) "
        + ' UNION ALL '.join(selects)
    )
    session.sql(sql).collect()
    return f"uploaded staged artifacts and registered {len(registry_rows)} rows in MODEL_REGISTRY"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='FrostStream NIDS - Phase 2 model layer training')
    parser.add_argument('--mode', default=os.environ.get('EXECUTION_MODE', 'LOCAL'),
                        choices=['LOCAL', 'CLOUD'])
    parser.add_argument('--samples', type=int, default=8000)
    parser.add_argument('--dataset', default=None)
    parser.add_argument('--out-dir', default=None)
    parser.add_argument('--version', default=None)
    parser.add_argument('--random-state', type=int, default=42)
    args = parser.parse_args(argv)

    dataset = load_or_create_dataset(file_path=args.dataset, sample_size=args.samples)
    print(f'Training on {len(dataset)} flows')

    result = train_models(dataset, random_state=args.random_state)
    version = args.version or current_version()
    out_dir = args.out_dir or default_model_dir()
    manifest = save_artifacts(out_dir, result, version)

    print('Training metrics:')
    for key, value in manifest['training_metrics'].items():
        if not isinstance(value, dict):
            print(f'  {key}: {value}')

    if args.mode.upper() == 'CLOUD':
        summary = register_in_snowflake(out_dir, manifest)
        print(summary)

    print(f'Artifacts written to: {out_dir} (version {version})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())