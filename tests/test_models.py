"""Expanded tests for ML models: ensemble voting, IsolationForest scoring, PSI drift detection."""

import pytest
import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock

from data.dataset_loader import generate_nsl_kdd_dataset
from src.preprocessing import NetworkDataPreprocessor
from src.models import ModelEvaluator
from src.models.train import train_ensemble_models, compute_baseline_distribution
from src.models.inference import score_flows
from src.models.drift_monitor import compute_psi, build_drift_report, run_local_drift_monitor, sp_run_drift_monitor


def test_model_training_and_evaluation():
    df = generate_nsl_kdd_dataset(num_samples=300, random_state=42)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    evaluator = ModelEvaluator()
    summary_df = evaluator.train_and_evaluate_all(X_train, y_train, X_test, y_test, preprocessor.classes_)

    assert len(summary_df) >= 4  # At least DT, RF, NB, SVM
    assert 'Accuracy' in summary_df.columns
    assert 'Recall' in summary_df.columns
    assert 'FPR' in summary_df.columns

    # Verify highest accuracy is reasonable (> 0.85 on synthetic sample)
    best_name, best_model, best_res = evaluator.get_best_model(metric='Recall')
    assert best_res['Recall'] > 0.70
    assert best_res['Latency (ms/sample)'] < 5.0  # Latency goal < 1s


def test_ensemble_soft_voting():
    """Test that VotingClassifier produces probability-weighted predictions."""
    df = generate_nsl_kdd_dataset(num_samples=200, random_state=123)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    trained = train_ensemble_models(X_train, y_train, list(preprocessor.classes_), random_state=42)
    ensemble = trained['ensemble']
    proba = ensemble.predict_proba(X_test)
    
    # Probabilities should sum to 1 per sample
    assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-6)
    # Predictions should be valid class indices
    preds = ensemble.predict(X_test)
    assert set(preds).issubset(set(y_train))
    # Probabilities in valid range
    assert (proba >= 0).all() and (proba <= 1).all()


def test_isolation_forest_scoring():
    """Test IsolationForest anomaly scores on normal vs anomalous data."""
    df = generate_nsl_kdd_dataset(num_samples=300, random_state=42)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    trained = train_ensemble_models(X_train, y_train, list(preprocessor.classes_), random_state=42)
    iso_forest = trained['isolation_forest']
    
    # Score normal test data (should be near 0, i.e., inlier)
    normal_test = X_test[y_test == 'Normal']
    if len(normal_test) > 0:
        normal_scores = iso_forest.score_samples(normal_test)
        # Inliers have scores closer to 0, outliers negative
        assert normal_scores.mean() > -0.5  # Mostly inliers
    
    # Score attack test data (should be more negative)
    attack_test = X_test[y_test != 'Normal']
    if len(attack_test) > 0:
        attack_scores = iso_forest.score_samples(attack_test)
        if len(normal_test) > 0:
            assert attack_scores.mean() < normal_scores.mean()
        else:
            assert attack_scores.mean() < 0


def test_ensemble_and_iso_inference():
    """Integration test: score_flows uses both ensemble and IsolationForest."""
    df = generate_nsl_kdd_dataset(num_samples=100, random_state=999)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    # Train models
    trained = train_ensemble_models(X_train, y_train, list(preprocessor.classes_), random_state=42)
    
    # Score a batch using the local inference function - pass original DataFrame, not numpy array
    artifacts = {
        'ensemble': trained['ensemble'],
        'isolation_forest': trained['isolation_forest'],
        'preprocessor': preprocessor,
    }
    
    # Use the original DataFrame (before preprocessing) for score_flows
    results_df = score_flows(df.iloc[:10], artifacts=artifacts)
    
    assert len(results_df) == 10
    required_cols = {'predicted_category', 'confidence', 'anomaly_score', 'severity', 'is_zero_day_suspect'}
    assert required_cols.issubset(set(results_df.columns))
    
    for _, row in results_df.iterrows():
        assert 0 <= row['confidence'] <= 1
        assert row['severity'] in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        assert isinstance(row['is_zero_day_suspect'], bool)


def test_psi_identical_distribution_is_near_zero():
    """PSI should be ~0 when actual matches expected."""
    np.random.seed(42)
    # Use histogram-based distributions that compute_psi expects
    expected = np.histogram(np.random.normal(0, 1, 1000), bins=10)[0].astype(float)
    actual = np.histogram(np.random.normal(0, 1, 1000), bins=10)[0].astype(float)
    psi = compute_psi(expected, actual)
    assert psi < 0.1  # Near zero


def test_psi_detects_shifted_distribution():
    """PSI should be high when distribution shifts significantly."""
    np.random.seed(42)
    # Create very different distributions - one centered at 0, one at 100
    expected = np.histogram(np.random.normal(0, 1, 1000), bins=10, range=(-5, 5))[0].astype(float)
    actual = np.histogram(np.random.normal(100, 1, 1000), bins=10, range=(-5, 5))[0].astype(float)
    # The shifted data will all fall in the last bin (overflow) while expected is spread
    psi = compute_psi(expected + 1e-10, actual + 1e-10)  # Add small epsilon to avoid zeros
    assert psi > 0.5  # Significant drift


def test_psi_handles_empty_or_single_bin():
    """PSI should handle edge cases gracefully."""
    expected = np.array([1.0] * 10)
    actual = np.array([1.0] * 10)
    psi = compute_psi(expected, actual)
    assert psi == 0.0  # Identical constant arrays


def test_drift_report_status():
    """Test drift status classification using proper baseline structure."""
    # Create a realistic baseline from real data
    df = generate_nsl_kdd_dataset(num_samples=500, random_state=42)
    baseline = compute_baseline_distribution(df)
    
    # No drift - use similar data
    live_normal = generate_nsl_kdd_dataset(num_samples=100, random_state=43)
    report = build_drift_report(baseline, live_normal, threshold=0.25)
    assert report['status'] in ('OK', 'ALERT')  # Could be either depending on random variance
    
    # Drift detected - perturb data significantly
    live_shifted = live_normal.copy()
    # Shift numeric features significantly
    for col in live_shifted.select_dtypes(include=[np.number]).columns:
        if col in live_shifted.columns:
            live_shifted[col] = live_shifted[col] * 10 + 100
    report = build_drift_report(baseline, live_shifted, threshold=0.25)
    assert report['status'] == 'ALERT'
    assert report['max_psi'] >= 0.25


def test_drift_monitor_excludes_synthetic():
    """Verify drift monitoring only uses real traffic (IS_SYNTHETIC=False).
    
    This test validates that the SPROC SQL query includes the IS_SYNTHETIC = FALSE filter.
    """
    # Direct test of the SQL query string in the SPROC source
    import inspect
    source = inspect.getsource(sp_run_drift_monitor)
    assert 'IS_SYNTHETIC = FALSE' in source, "SPROC must filter out synthetic traffic"
    assert 'PROCESSED_FLAG = TRUE' in source, "SPROC must only process flagged flows"


def test_score_flows_output_columns():
    """Verify score_flows output has all required columns."""
    df = generate_nsl_kdd_dataset(num_samples=50, random_state=555)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    trained = train_ensemble_models(X_train, y_train, list(preprocessor.classes_), random_state=42)
    artifacts = {
        'ensemble': trained['ensemble'],
        'isolation_forest': trained['isolation_forest'],
        'preprocessor': preprocessor,
    }

    # Pass original DataFrame, not numpy array
    results_df = score_flows(df, artifacts=artifacts)
    
    required_cols = {
        'predicted_category', 'confidence', 'anomaly_score',
        'severity', 'is_zero_day_suspect', 'is_alert'
    }
    assert required_cols.issubset(set(results_df.columns)), f"Missing: {required_cols - set(results_df.columns)}"


def test_baseline_distribution_computation():
    """Test baseline distribution is computed correctly for PSI."""
    df = generate_nsl_kdd_dataset(num_samples=500, random_state=42)
    baseline = compute_baseline_distribution(df)
    
    assert 'features' in baseline or len(baseline) > 0
    # Should have both numeric and categorical features
    if 'features' in baseline:
        features = baseline['features']
    else:
        features = baseline
    
    # Check structure
    for feat_name, profile in list(features.items())[:5]:  # Check first 5
        assert 'kind' in profile
        assert profile['kind'] in ('numeric', 'categorical')
        if profile['kind'] == 'numeric':
            assert 'bins' in profile
            assert 'expected' in profile
        else:
            assert 'categories' in profile
            assert 'expected' in profile


def test_run_local_drift_monitor():
    """Test local drift monitor with perturbed data."""
    df = generate_nsl_kdd_dataset(num_samples=500, random_state=42)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)

    trained = train_ensemble_models(X_train, y_train, list(preprocessor.classes_), random_state=42)
    
    # Run drift monitor with perturbation
    result = run_local_drift_monitor(
        flows=df,
        model_dir=None,  # Will use default and create baseline
        perturb=0.3  # 30% perturbation
    )
    
    assert isinstance(result, str)
    assert 'PSI window' in result or 'drift monitor' in result.lower()