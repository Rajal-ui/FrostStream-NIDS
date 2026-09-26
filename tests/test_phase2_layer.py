import json

import numpy as np
import pandas as pd

from data.dataset_loader import generate_nsl_kdd_dataset
from src.models.constants import (
    BASELINE_FILENAME,
    ENSEMBLE_FILENAME,
    ISOLATION_FILENAME,
    PREPROCESSOR_FILENAME,
)
from src.models.drift_monitor import build_drift_report, compute_psi, run_local_drift_monitor
from src.models.inference import (
    compute_severity,
    is_zero_day_suspect,
    run_local_inference,
    score_flows,
)
from src.models.train import compute_baseline_distribution, train_models


def test_ensemble_training_and_artifacts(tmp_path):
    df = generate_nsl_kdd_dataset(num_samples=300, random_state=42)
    result = train_models(df, random_state=42)
    ensemble = result['ensemble']
    iso = result['isolation_forest']
    preprocessor = result['preprocessor']

    assert preprocessor.is_fitted
    assert result['metrics']['precision'] > 0.5
    assert result['metrics']['recall'] > 0.5
    assert set(result['class_names']) == {'Normal', 'DoS', 'Probe', 'R2L', 'U2R'}

    iso_scores = iso.score_samples(result['X_test'])
    assert iso_scores.shape[0] == result['X_test'].shape[0]

    result['preprocessor'].is_fitted = True
    import joblib

    out_dir = str(tmp_path)
    joblib.dump(ensemble, f'{out_dir}/{ENSEMBLE_FILENAME}')
    joblib.dump(iso, f'{out_dir}/{ISOLATION_FILENAME}')
    joblib.dump(preprocessor, f'{out_dir}/{PREPROCESSOR_FILENAME}')
    with open(f'{out_dir}/{BASELINE_FILENAME}', 'w') as fh:
        json.dump(result['baseline_distribution'], fh)


def test_severity_logic():
    assert compute_severity('Normal', 0.99) == 'INFO'
    assert compute_severity('DoS', 0.91) == 'CRITICAL'
    assert compute_severity('U2R', 0.95) == 'CRITICAL'
    assert compute_severity('Probe', 0.91) == 'HIGH'
    assert compute_severity('R2L', 0.91) == 'HIGH'
    assert compute_severity('Probe', 0.96) == 'CRITICAL'
    assert compute_severity('R2L', 0.80) == 'MEDIUM'


def test_zero_day_suspect_flag():
    assert is_zero_day_suspect('Normal', -0.5) is True
    assert is_zero_day_suspect('Normal', -0.1) is False
    assert is_zero_day_suspect('DoS', -0.5) is False
    assert is_zero_day_suspect('Normal', None) is False


def test_psi_identical_distribution_is_near_zero():
    psi = compute_psi([0.5, 0.3, 0.2], [0.5, 0.3, 0.2])
    assert abs(psi) < 1e-6


def test_psi_detects_shifted_distribution():
    psi = compute_psi([0.95, 0.03, 0.02], [0.05, 0.60, 0.35])
    assert psi > 0.5


def test_drift_report_status(tmp_path):
    baseline_df = generate_nsl_kdd_dataset(num_samples=800, random_state=42)
    baseline = compute_baseline_distribution(baseline_df)

    clean_df = generate_nsl_kdd_dataset(num_samples=400, random_state=7)
    clean_report = build_drift_report(baseline, clean_df, threshold=0.25)
    assert clean_report['status'] == 'OK'

    drifted_df = clean_df.copy()
    mask = np.random.rand(len(drifted_df)) < 0.5
    drifted_df.loc[mask & (drifted_df['protocol_type'] == 'tcp'), 'protocol_type'] = 'icmp'
    drifted_df.loc[mask & (drifted_df['service'] == 'http'), 'service'] = 'private'
    drift_report = build_drift_report(baseline, drifted_df, threshold=0.25)
    assert drift_report['status'] == 'ALERT'
    assert drift_report['max_psi'] > 0.25
    assert len(drift_report['drifted_features']) >= 1


def test_run_local_inference_and_drift(tmp_path):
    import joblib

    df = generate_nsl_kdd_dataset(num_samples=250, random_state=11)
    result = train_models(df, random_state=42)
    model_dir = str(tmp_path)
    joblib.dump(result['ensemble'], f'{model_dir}/{ENSEMBLE_FILENAME}')
    joblib.dump(result['isolation_forest'], f'{model_dir}/{ISOLATION_FILENAME}')
    joblib.dump(result['preprocessor'], f'{model_dir}/{PREPROCESSOR_FILENAME}')

    flows = df.sample(n=80, random_state=5).reset_index(drop=True)
    flows = flows.drop(columns=['label', 'difficulty', 'attack_category'])

    result_str = run_local_inference(flows=flows, model_dir=model_dir, log_alerts=False)
    assert 'alerts_raised=' in result_str
    assert result_str.startswith(f'scored={len(flows)} rows')

    drift_summary = run_local_drift_monitor(model_dir=model_dir)
    assert 'status=' in drift_summary

    drifted_summary = run_local_drift_monitor(model_dir=model_dir, perturb=0.6)
    assert 'status=ALERT' in drifted_summary


def test_score_flows_columns(tmp_path):
    import joblib

    df = generate_nsl_kdd_dataset(num_samples=200, random_state=3)
    result = train_models(df, random_state=42)
    model_dir = str(tmp_path)
    joblib.dump(result['ensemble'], f'{model_dir}/{ENSEMBLE_FILENAME}')
    joblib.dump(result['isolation_forest'], f'{model_dir}/{ISOLATION_FILENAME}')
    joblib.dump(result['preprocessor'], f'{model_dir}/{PREPROCESSOR_FILENAME}')

    flows = df.drop(columns=['label', 'difficulty', 'attack_category'])
    scored = score_flows(flows, model_dir=model_dir)
    assert len(scored) == len(flows)
    for col in ('predicted_category', 'confidence', 'anomaly_score', 'severity', 'is_zero_day_suspect', 'is_alert'):
        assert col in scored.columns
    assert set(scored['predicted_category'].unique()).issubset({'Normal', 'DoS', 'Probe', 'R2L', 'U2R'})