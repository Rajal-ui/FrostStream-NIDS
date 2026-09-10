import pytest
import pandas as pd
import numpy as np
from data.dataset_loader import generate_nsl_kdd_dataset
from src.preprocessing import NetworkDataPreprocessor
from src.models import ModelEvaluator

def test_model_training_and_evaluation():
    df = generate_nsl_kdd_dataset(num_samples=300, random_state=42)
    preprocessor = NetworkDataPreprocessor()
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)
    
    evaluator = ModelEvaluator()
    summary_df = evaluator.train_and_evaluate_all(X_train, y_train, X_test, y_test, preprocessor.classes_)
    
    assert len(summary_df) >= 4 # At least DT, RF, NB, SVM
    assert 'Accuracy' in summary_df.columns
    assert 'Recall' in summary_df.columns
    assert 'FPR' in summary_df.columns
    
    # Verify highest accuracy is reasonable (> 0.85 on synthetic sample)
    best_name, best_model, best_res = evaluator.get_best_model(metric='Recall')
    assert best_res['Recall'] > 0.70
    assert best_res['Latency (ms/sample)'] < 5.0 # Latency goal < 1s
