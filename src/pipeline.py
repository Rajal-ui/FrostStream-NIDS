import time
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
from src.preprocessing import NetworkDataPreprocessor
from src.explainability import explain_flow_prediction
from storage.alert_logger import AlertLogger

class NetworkIDSPipeline:
    def __init__(self, model, preprocessor: NetworkDataPreprocessor, alert_logger: AlertLogger = None):
        self.model = model
        self.preprocessor = preprocessor
        self.alert_logger = alert_logger or AlertLogger()

    def predict_single_flow(self, flow_dict: dict) -> Tuple[str, float, dict]:
        """Classify single network flow dictionary in real-time (<50ms)."""
        df_flow = pd.DataFrame([flow_dict])
        
        # Transform features
        X_proc = self.preprocessor.transform(df_flow)
        
        # Predict class & confidence
        if hasattr(self.model, 'predict_proba'):
            probs = self.model.predict_proba(X_proc)[0]
            pred_idx = np.argmax(probs)
            confidence = float(probs[pred_idx])
        else:
            pred_idx = int(self.model.predict(X_proc)[0])
            confidence = 0.95 # Fallback for models without predict_proba (e.g. LinearSVM)

        predicted_category = self.preprocessor.decode_labels([pred_idx])[0]

        # Generate analyst explanation
        explanation = explain_flow_prediction(flow_dict, predicted_category, confidence)

        # Log alert if attack detected
        if predicted_category != 'Normal':
            summary = "; ".join(explanation['primary_reasons'])
            self.alert_logger.log_alert(
                protocol=flow_dict.get('protocol_type', 'tcp'),
                service=flow_dict.get('service', 'http'),
                src_bytes=flow_dict.get('src_bytes', 0),
                dst_bytes=flow_dict.get('dst_bytes', 0),
                predicted_category=predicted_category,
                confidence=confidence,
                features_summary=summary
            )

        return predicted_category, confidence, explanation

    def predict_batch(self, df_flows: pd.DataFrame) -> pd.DataFrame:
        """Classify batch CSV dataframe of network flows."""
        df_clean = df_flows.copy()
        
        # Drop target columns if present in batch CSV
        X_df = df_clean.drop(columns=['attack_category', 'label', 'difficulty'], errors='ignore')
        
        # Preprocess features
        X_proc = self.preprocessor.transform(X_df)
        
        # Predictions
        if hasattr(self.model, 'predict_proba'):
            probs = self.model.predict_proba(X_proc)
            pred_indices = np.argmax(probs, axis=1)
            confidences = np.max(probs, axis=1)
        else:
            pred_indices = self.model.predict(X_proc)
            confidences = np.ones(len(pred_indices)) * 0.95

        pred_labels = self.preprocessor.decode_labels(pred_indices)

        df_clean['predicted_category'] = pred_labels
        df_clean['confidence'] = confidences

        # Log any detected malicious flows
        for idx, row in df_clean.iterrows():
            if row['predicted_category'] != 'Normal':
                self.alert_logger.log_alert(
                    protocol=row.get('protocol_type', 'tcp'),
                    service=row.get('service', 'http'),
                    src_bytes=row.get('src_bytes', 0),
                    dst_bytes=row.get('dst_bytes', 0),
                    predicted_category=row['predicted_category'],
                    confidence=row['confidence'],
                    features_summary=f"Batch score hit: {row['predicted_category']}"
                )

        return df_clean
