import pytest
import os
import pandas as pd
from data.dataset_loader import generate_nsl_kdd_dataset
from src.preprocessing import NetworkDataPreprocessor
from src.models import ModelEvaluator
from src.pipeline import NetworkIDSPipeline
from storage.alert_logger import AlertLogger

def test_pipeline_single_prediction_and_alert_logging(tmp_path):
    db_file = os.path.join(tmp_path, "test_alerts.db")
    alert_logger = AlertLogger(db_path=db_file)
    
    df = generate_nsl_kdd_dataset(num_samples=300, random_state=42)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)
    
    evaluator = ModelEvaluator()
    evaluator.train_and_evaluate_all(X_train, y_train, X_test, y_test, preprocessor.classes_)
    best_name, best_model, _ = evaluator.get_best_model(metric='Recall')
    
    pipeline = NetworkIDSPipeline(model=best_model, preprocessor=preprocessor, alert_logger=alert_logger)
    
    # Test single flow prediction (DoS sample)
    dos_flow = {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
        'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0,
        'is_guest_login': 0, 'count': 250, 'srv_count': 250, 'serror_rate': 1.0,
        'srv_serror_rate': 1.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': 255, 'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0,
        'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }
    
    cat, conf, expl = pipeline.predict_single_flow(dos_flow)
    assert cat in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    assert conf >= 0.0 and conf <= 1.0
    assert 'primary_reasons' in expl
    
    # Check SQLite alert log
    alerts_df = alert_logger.get_all_alerts()
    if cat != 'Normal':
        assert len(alerts_df) >= 1
