import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

class NetworkDataPreprocessor:
    def __init__(self, scaler_type='standard'):
        self.scaler_type = scaler_type
        self.scaler = StandardScaler() if scaler_type == 'standard' else MinMaxScaler()
        self.one_hot_encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        self.label_encoder = LabelEncoder()
        self.numeric_cols = []
        self.categorical_cols = CATEGORICAL_COLS
        self.feature_names = []
        self.classes_ = []
        self.is_fitted = False

    def prepare_data(self, df: pd.DataFrame, target_col: str = 'attack_category'):
        """Extract features and target label from dataframe."""
        df_clean = df.copy()
        if target_col not in df_clean.columns:
            if 'label' in df_clean.columns:
                target_col = 'label'
            else:
                raise ValueError(f"Target column '{target_col}' not found in dataframe.")
                
        X = df_clean.drop(columns=[target_col, 'label', 'difficulty'], errors='ignore')
        y = df_clean[target_col]
        return X, y

    def fit_transform(self, X: pd.DataFrame, y: pd.Series, test_size: float = 0.2, random_state: int = 42):
        """Fit preprocessor transformers and split data into stratified train and test sets."""
        self.numeric_cols = [c for c in X.columns if c not in self.categorical_cols]
        
        # Encode target variable
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = list(self.label_encoder.classes_)

        # Fit & transform categorical features
        X_cat = self.one_hot_encoder.fit_transform(X[self.categorical_cols])
        cat_feature_names = list(self.one_hot_encoder.get_feature_names_out(self.categorical_cols))

        # Fit & transform numeric features
        X_num = self.scaler.fit_transform(X[self.numeric_cols])

        # Combine processed features
        X_processed = np.hstack([X_num, X_cat])
        self.feature_names = list(self.numeric_cols) + cat_feature_names
        self.is_fitted = True

        # Check if stratify is safe (each class has at least 2 samples)
        unique_classes, counts = np.unique(y_encoded, return_counts=True)
        stratify_target = y_encoded if np.min(counts) >= 2 else None

        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y_encoded, test_size=test_size, random_state=random_state, stratify=stratify_target
        )
        
        return X_train, X_test, y_train, y_test

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform new incoming feature dataframe using fitted transformers."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform.")
        
        # Handle missing numeric columns with 0
        for col in self.numeric_cols:
            if col not in X.columns:
                X[col] = 0
                
        # Handle missing categorical columns
        for col in self.categorical_cols:
            if col not in X.columns:
                X[col] = 'other'

        X_cat = self.one_hot_encoder.transform(X[self.categorical_cols])
        X_num = self.scaler.transform(X[self.numeric_cols])
        return np.hstack([X_num, X_cat])

    def decode_labels(self, y_encoded: np.ndarray) -> np.ndarray:
        """Inverse transform numeric target labels back to attack names."""
        return self.label_encoder.inverse_transform(y_encoded)
