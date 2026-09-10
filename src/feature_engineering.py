import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif

def analyze_correlations(df_numeric: pd.DataFrame, threshold: float = 0.95):
    """
    Identify redundant numeric features with correlation higher than threshold.
    Returns correlation matrix and list of collinear features to drop.
    """
    corr_matrix = df_numeric.corr().abs()
    upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    
    to_drop = [column for column in upper_tri.columns if any(upper_tri[column] > threshold)]
    return corr_matrix, to_drop

def get_feature_importances(X_train: np.ndarray, y_train: np.ndarray, feature_names: list):
    """
    Calculate feature importances using Random Forest ensemble.
    Returns DataFrame sorted by importance.
    """
    rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    importances = rf.feature_importances_
    df_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values(by='importance', ascending=False).reset_index(drop=True)
    
    return df_importance

def compute_mutual_information(X_train: np.ndarray, y_train: np.ndarray, feature_names: list):
    """Calculate Mutual Information score for each feature relative to attack labels."""
    mi_scores = mutual_info_classif(X_train, y_train, random_state=42)
    df_mi = pd.DataFrame({
        'feature': feature_names,
        'mi_score': mi_scores
    }).sort_values(by='mi_score', ascending=False).reset_index(drop=True)
    
    return df_mi
