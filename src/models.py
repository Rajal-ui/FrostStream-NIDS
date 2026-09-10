import time
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

class ModelEvaluator:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.trained_models = {}
        self.results_summary = []

    def get_default_models(self, num_classes: int = 5):
        """Return dictionary of models to train and compare."""
        models = {
            'Decision Tree': DecisionTreeClassifier(max_depth=15, random_state=self.random_state),
            'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=20, random_state=self.random_state, n_jobs=-1, class_weight='balanced'),
            'Naive Bayes': GaussianNB(),
            'Linear SVM': LinearSVC(dual='auto', max_iter=2000, random_state=self.random_state, class_weight='balanced')
        }
        
        if HAS_XGBOOST:
            models['XGBoost'] = XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=self.random_state,
                eval_metric='mlogloss',
                n_jobs=-1
            )
        return models

    def train_and_evaluate_all(self, X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray, class_names: list):
        """Train all models, measure train time, predict time, and compute all evaluation metrics."""
        models = self.get_default_models(num_classes=len(class_names))
        self.results_summary = []
        self.trained_models = {}

        for name, model in models.items():
            # Training time
            t0 = time.time()
            model.fit(X_train, y_train)
            train_time = time.time() - t0

            # Prediction & Latency
            t1 = time.time()
            y_pred = model.predict(X_test)
            pred_time = time.time() - t1
            latency_per_sample_ms = (pred_time / len(X_test)) * 1000.0

            # Standard Metrics
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

            # Confusion matrix & False Positive Rate (FPR)
            cm = confusion_matrix(y_test, y_pred)
            
            # Calculate FPR = FP / (FP + TN) overall across classes
            fp = cm.sum(axis=0) - np.diag(cm)
            fn = cm.sum(axis=1) - np.diag(cm)
            tp = np.diag(cm)
            tn = cm.sum() - (fp + fn + tp)
            
            fpr = np.mean(fp / (fp + tn + 1e-9))

            res = {
                'Model': name,
                'Accuracy': acc,
                'Precision': prec,
                'Recall': rec,
                'F1-Score': f1,
                'FPR': fpr,
                'Train Time (s)': round(train_time, 3),
                'Latency (ms/sample)': round(latency_per_sample_ms, 4),
                'Confusion Matrix': cm,
                'Predictions': y_pred
            }

            self.results_summary.append(res)
            self.trained_models[name] = model

        return pd.DataFrame(self.results_summary).drop(columns=['Confusion Matrix', 'Predictions'])

    def get_best_model(self, metric: str = 'Recall'):
        """Retrieve model with highest score for chosen metric (Recall prioritized for IDS)."""
        if not self.results_summary:
            raise RuntimeError("No models trained yet.")
        
        best_res = max(self.results_summary, key=lambda x: x[metric])
        model_name = best_res['Model']
        return model_name, self.trained_models[model_name], best_res
