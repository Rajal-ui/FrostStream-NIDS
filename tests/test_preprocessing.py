import pytest
import pandas as pd
import numpy as np
from data.dataset_loader import generate_nsl_kdd_dataset
from src.preprocessing import NetworkDataPreprocessor

def test_nsl_kdd_dataset_generator():
    df = generate_nsl_kdd_dataset(num_samples=100)
    assert len(df) == 100
    assert 'attack_category' in df.columns
    assert set(df['attack_category'].unique()).issubset({'Normal', 'DoS', 'Probe', 'R2L', 'U2R'})

def test_preprocessor_fit_transform():
    df = generate_nsl_kdd_dataset(num_samples=200)
    preprocessor = NetworkDataPreprocessor()
    
    X, y = preprocessor.prepare_data(df)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y, test_size=0.2)
    
    assert len(X_train) == 160
    assert len(X_test) == 40
    assert X_train.shape[1] > 30 # Number of engineered features
    assert preprocessor.is_fitted

def test_preprocessor_transform_new_data():
    df = generate_nsl_kdd_dataset(num_samples=200)
    preprocessor = NetworkDataPreprocessor()
    
    X, y = preprocessor.prepare_data(df)
    preprocessor.fit_transform(X, y)
    
    new_df = generate_nsl_kdd_dataset(num_samples=10)
    X_new, _ = preprocessor.prepare_data(new_df)
    X_proc_new = preprocessor.transform(X_new)
    
    assert X_proc_new.shape[0] == 10
    assert X_proc_new.shape[1] == len(preprocessor.feature_names)
