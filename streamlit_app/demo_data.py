"""Demo data generator for FrostStream NIDS Streamlit Cloud deployment.

Provides realistic sample data when Snowflake is not available.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd


ATTACK_TYPES = [
    ("DoS", 0.25, "#F97316"),
    ("Probe", 0.20, "#FBBF24"),
    ("R2L", 0.20, "#F43F5E"),
    ("U2R", 0.15, "#6366F1"),
    ("Normal", 0.10, "#10B981"),
    ("DDoS", 0.10, "#EF4444"),
]

SEVERITY_MAP = {
    "DoS": ["HIGH", "CRITICAL"],
    "Probe": ["MEDIUM", "HIGH"],
    "R2L": ["HIGH", "CRITICAL"],
    "U2R": ["CRITICAL"],
    "Normal": ["INFO", "LOW"],
    "DDoS": ["CRITICAL"],
}

MITIGATION_STATUSES = ["PENDING", "ACTIONED", "SUPPRESSED", "EXPIRED"]
MITIGATION_WEIGHTS = [0.3, 0.5, 0.1, 0.1]

SRC_IPS = [
    "192.168.1.45", "10.0.0.23", "172.16.5.67", "192.168.10.12",
    "203.0.113.45", "198.51.100.78", "203.0.113.12", "198.51.100.200",
    "185.220.101.45", "45.155.205.123", "103.224.182.67", "185.220.100.250",
]

DST_IPS = [
    "192.168.1.100", "192.168.1.200", "10.0.0.1", "172.16.1.10",
    "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9",
]

SERVICES = ["http", "https", "ssh", "ftp", "smtp", "dns", "private", "other"]
PROTOCOLS = ["tcp", "udp", "icmp"]


def generate_demo_kpis() -> dict[str, Any]:
    """Generate demo KPI metrics."""
    return {
        "total_alerts": 1247,
        "critical": 312,
        "high": 428,
        "active_blocks": 23,
        "synthetic_alerts": 0,
        "max_psi": 0.087,
        "drift_status": "OK",
        "drift_ts": datetime.now() - timedelta(hours=2),
        "cloud_live": False,
    }


def generate_demo_alerts_by_classification() -> pd.DataFrame:
    """Generate demo classification distribution."""
    data = []
    remaining = 1247
    for i, (attack_type, weight, _) in enumerate(ATTACK_TYPES):
        if i == len(ATTACK_TYPES) - 1:
            count = remaining
        else:
            count = int(1247 * weight)
            remaining -= count
        data.append({"classification": attack_type, "count": count})
    return pd.DataFrame(data)


def generate_demo_alert_timeline(hours: int = 24) -> pd.DataFrame:
    """Generate demo timeline data."""
    now = datetime.now()
    data = []
    for h in range(hours):
        hour_start = now - timedelta(hours=hours - h)
        for attack_type, weight, _ in ATTACK_TYPES:
            if attack_type == "Normal":
                continue
            base_count = int(50 * weight)
            count = max(0, base_count + random.randint(-10, 15))
            if count > 0:
                data.append({
                    "hour_bucket": hour_start,
                    "classification": attack_type,
                    "count": count,
                })
    return pd.DataFrame(data)


def generate_demo_threat_stream(limit: int = 50) -> pd.DataFrame:
    """Generate demo threat stream."""
    data = []
    now = datetime.now()
    for i in range(limit):
        attack_type, _, _ = random.choices(ATTACK_TYPES, weights=[w for _, w, _ in ATTACK_TYPES])[0]
        severity = random.choice(SEVERITY_MAP[attack_type])
        confidence = random.uniform(0.75, 0.999)
        mitigation = random.choices(MITIGATION_STATUSES, weights=MITIGATION_WEIGHTS)[0]
        alert_ts = now - timedelta(minutes=random.randint(1, 60 * 24))
        
        data.append({
            "alert_id": f"ALT-{alert_ts.strftime('%Y%m%d')}-{random.randint(1000, 9999)}",
            "timestamp": alert_ts,
            "src_ip": random.choice(SRC_IPS),
            "dst_ip": random.choice(DST_IPS),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([22, 23, 25, 53, 80, 443, 3306, 5432, 8080]),
            "attack_type": attack_type,
            "confidence": confidence * 100,
            "anomaly_score": round(random.uniform(-0.6, -0.1), 4),
            "severity": severity,
            "mitigation_status": mitigation,
        })
    
    df = pd.DataFrame(data)
    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    return df


def generate_demo_soar_blocks() -> pd.DataFrame:
    """Generate demo active NACL blocks."""
    now = datetime.now()
    data = []
    blocked_ips = random.sample(SRC_IPS, k=random.randint(15, 25))
    for ip in blocked_ips:
        mitigated_at = now - timedelta(hours=random.randint(1, 20))
        expires_at = mitigated_at + timedelta(hours=24)
        ttl_remaining = expires_at - now
        alert_count = random.randint(1, 8)
        data.append({
            "src_ip": ip,
            "first_alert_ts": mitigated_at - timedelta(minutes=random.randint(5, 120)),
            "mitigated_at": mitigated_at,
            "alert_count": alert_count,
            "expires_at": expires_at,
            "ttl_remaining": ttl_remaining,
        })
    return pd.DataFrame(data)


def generate_demo_drift() -> dict[str, Any]:
    """Generate demo drift report."""
    drifted = {}
    if random.random() < 0.3:
        features = ["dst_host_srv_count", "dst_host_same_srv_rate", "serror_rate", "srv_serror_rate"]
        for f in random.sample(features, k=random.randint(1, 3)):
            drifted[f] = round(random.uniform(0.25, 0.45), 4)
    
    max_psi = max(drifted.values()) if drifted else round(random.uniform(0.02, 0.15), 4)
    status = "OK"
    if max_psi >= 0.25:
        status = "DRIFT_DETECTED"
    elif max_psi >= 0.15:
        status = "WARNING"
    
    return {
        "max_psi": max_psi,
        "status": status,
        "check_ts": datetime.now() - timedelta(hours=1),
        "drifted_features": drifted,
        "feature_psi_details": {f: round(random.uniform(0.01, 0.3), 4) for f in 
                                 ["duration", "src_bytes", "dst_bytes", "dst_host_count", 
                                  "dst_host_srv_count", "serror_rate", "srv_serror_rate"]},
    }


def load_local_sqlite_alerts() -> pd.DataFrame | None:
    """Try to load alerts from local SQLite database."""
    try:
        import sqlite3
        conn = sqlite3.connect("storage/alerts.db")
        query = """
            SELECT 
                id as alert_id,
                timestamp,
                protocol,
                service,
                src_bytes,
                dst_bytes,
                predicted_category as attack_type,
                confidence,
                severity,
                features_summary
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT 100
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            return None
            
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["confidence"] = df["confidence"] * 100
        df["mitigation_status"] = np.random.choice(
            MITIGATION_STATUSES, size=len(df), p=MITIGATION_WEIGHTS
        )
        df["src_ip"] = [random.choice(SRC_IPS) for _ in range(len(df))]
        df["dst_ip"] = [random.choice(DST_IPS) for _ in range(len(df))]
        df["src_port"] = [random.randint(1024, 65535) for _ in range(len(df))]
        df["dst_port"] = [random.choice([22, 23, 25, 53, 80, 443, 3306, 5432, 8080]) for _ in range(len(df))]
        df["anomaly_score"] = [round(random.uniform(-0.6, -0.1), 4) for _ in range(len(df))]
        
        return df
    except Exception:
        return None


def get_demo_or_local_data() -> dict[str, Any]:
    """Get demo data, trying local SQLite first, then generated data."""
    local_df = load_local_sqlite_alerts()
    
    if local_df is not None and not local_df.empty:
        kpis = {
            "total_alerts": len(local_df),
            "critical": len(local_df[local_df["severity"] == "CRITICAL"]),
            "high": len(local_df[local_df["severity"] == "HIGH"]),
            "active_blocks": len(local_df[local_df["mitigation_status"] == "ACTIONED"]["src_ip"].unique()),
            "synthetic_alerts": 0,
            "max_psi": 0.087,
            "drift_status": "OK",
            "drift_ts": datetime.now() - timedelta(hours=2),
            "cloud_live": False,
        }
        
        cat_df = local_df.groupby("attack_type").size().reset_index(name="count")
        cat_df.columns = ["classification", "count"]
        
        tl_df = local_df.copy()
        tl_df["hour_bucket"] = tl_df["timestamp"].dt.floor("h")
        tl_df = tl_df.groupby(["hour_bucket", "attack_type"]).size().reset_index(name="count")
        tl_df.columns = ["hour_bucket", "classification", "count"]
        
        soar_df = local_df[local_df["mitigation_status"] == "ACTIONED"].groupby("src_ip").agg(
            first_alert_ts=("timestamp", "min"),
            mitigated_at=("timestamp", "max"),
            alert_count=("alert_id", "count"),
        ).reset_index()
        now = datetime.now()
        soar_df["expires_at"] = soar_df["mitigated_at"] + pd.Timedelta(hours=24)
        soar_df["ttl_remaining"] = soar_df["expires_at"] - pd.Timestamp.now()
        
        return {
            "kpis": kpis,
            "classification_df": cat_df,
            "timeline_df": tl_df,
            "threat_df": local_df.head(50),
            "soar_df": soar_df,
            "drift": generate_demo_drift(),
        }
    
    return {
        "kpis": generate_demo_kpis(),
        "classification_df": generate_demo_alerts_by_classification(),
        "timeline_df": generate_demo_alert_timeline(24),
        "threat_df": generate_demo_threat_stream(50),
        "soar_df": generate_demo_soar_blocks(),
        "drift": generate_demo_drift(),
    }