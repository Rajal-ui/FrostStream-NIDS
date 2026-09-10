import os
import sqlite3
import pandas as pd
from datetime import datetime

class AlertLogger:
    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_dir = os.path.join(base_dir, 'storage')
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, 'alerts.db')
            
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Create sqlite database table for network security alerts."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT,
                    service TEXT,
                    src_bytes INTEGER,
                    dst_bytes INTEGER,
                    predicted_category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    features_summary TEXT
                )
            ''')
            conn.commit()

    def log_alert(self, protocol: str, service: str, src_bytes: int, dst_bytes: int, 
                  predicted_category: str, confidence: float, features_summary: str = ""):
        """Insert single alert record into SQLite database."""
        # Calculate severity based on attack category
        if predicted_category == 'Normal':
            severity = 'INFO'
        elif predicted_category in ['U2R', 'R2L']:
            severity = 'CRITICAL'
        elif predicted_category == 'DoS':
            severity = 'HIGH'
        else: # Probe
            severity = 'MEDIUM'

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, protocol, service, src_bytes, dst_bytes, 
                                    predicted_category, confidence, severity, features_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, str(protocol), str(service), int(src_bytes), int(dst_bytes),
                  str(predicted_category), float(confidence), severity, str(features_summary)))
            conn.commit()

    def get_all_alerts(self, limit: int = 500) -> pd.DataFrame:
        """Fetch alert history as DataFrame."""
        with sqlite3.connect(self.db_path) as conn:
            query = f"SELECT * FROM alerts ORDER BY id DESC LIMIT {limit}"
            df = pd.read_csv(conn) if False else pd.read_sql_query(query, conn)
        return df

    def clear_alerts(self):
        """Delete all alerts from table."""
        with sqlite3.connect(self.db_path) as conn:
            conn.cursor().execute("DELETE FROM alerts")
            conn.commit()
