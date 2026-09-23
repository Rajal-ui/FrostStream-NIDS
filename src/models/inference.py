import json
import os
import uuid
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from data.dataset_loader import generate_nsl_kdd_dataset
from src.models.constants import (
    BASELINE_FILENAME,
    DEFAULT_ANOMALY_THRESHOLD,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_CRITICAL_CONFIDENCE_THRESHOLD,
    ENSEMBLE_FILENAME,
    ISOLATION_FILENAME,
    PREPROCESSOR_FILENAME,
    default_model_dir,
    env_float,
)


def compute_severity(
    predicted_category: str,
    confidence: float,
    conf_threshold: float | None = None,
    critical_threshold: float | None = None,
    anomaly_score: float | None = None,
    anomaly_threshold: float | None = None,
) -> str:
    conf_threshold = DEFAULT_CONFIDENCE_THRESHOLD if conf_threshold is None else conf_threshold
    critical_threshold = DEFAULT_CRITICAL_CONFIDENCE_THRESHOLD if critical_threshold is None else critical_threshold
    anomaly_threshold = DEFAULT_ANOMALY_THRESHOLD if anomaly_threshold is None else anomaly_threshold
    category = str(predicted_category)
    if category == 'Normal':
        if is_zero_day_suspect(category, anomaly_score, anomaly_threshold=anomaly_threshold):
            return 'HIGH'
        return 'INFO'
    if confidence >= conf_threshold:
        if category in ('DoS', 'U2R'):
            return 'CRITICAL'
        if confidence >= critical_threshold:
            return 'CRITICAL'
        return 'HIGH'
    if confidence >= critical_threshold:
        return 'CRITICAL'
    return 'MEDIUM'


def is_zero_day_suspect(
    predicted_category: str,
    anomaly_score: float | None,
    anomaly_threshold: float | None = None,
) -> bool:
    threshold = DEFAULT_ANOMALY_THRESHOLD if anomaly_threshold is None else anomaly_threshold
    return (
        str(predicted_category) == 'Normal'
        and anomaly_score is not None
        and not np.isnan(float(anomaly_score))
        and float(anomaly_score) < threshold
    )


def load_artifacts(model_dir: str | None = None) -> dict:
    model_dir = model_dir or default_model_dir()
    return {
        'ensemble': joblib.load(os.path.join(model_dir, ENSEMBLE_FILENAME)),
        'isolation_forest': joblib.load(os.path.join(model_dir, ISOLATION_FILENAME)),
        'preprocessor': joblib.load(os.path.join(model_dir, PREPROCESSOR_FILENAME)),
        'baseline': os.path.join(model_dir, BASELINE_FILENAME),
    }


def score_flows(
    df_flows: pd.DataFrame,
    artifacts: dict | None = None,
    model_dir: str | None = None,
    anomaly_threshold: float | None = None,
    conf_threshold: float | None = None,
) -> pd.DataFrame:
    if artifacts is None:
        artifacts = load_artifacts(model_dir)
    ensemble = artifacts['ensemble']
    iso = artifacts['isolation_forest']
    preprocessor = artifacts['preprocessor']

    df = df_flows.copy()
    df.columns = [str(c).lower() for c in df.columns]
    df = df.drop(columns=['attack_category', 'label', 'difficulty'], errors='ignore')

    X_proc = preprocessor.transform(df)

    proba = ensemble.predict_proba(X_proc)
    pred_indices = np.argmax(proba, axis=1)
    confidences = np.max(proba, axis=1)
    predictions = preprocessor.decode_labels(pred_indices)
    anomaly_scores = iso.score_samples(X_proc)

    threshold = DEFAULT_ANOMALY_THRESHOLD if anomaly_threshold is None else anomaly_threshold
    conf = DEFAULT_CONFIDENCE_THRESHOLD if conf_threshold is None else conf_threshold
    severities = [
        compute_severity(p, float(c), conf_threshold=conf, anomaly_score=float(a), anomaly_threshold=threshold)
        for p, c, a in zip(predictions, confidences, anomaly_scores)
    ]
    zero_day = [is_zero_day_suspect(p, float(a), anomaly_threshold=threshold) for p, a in zip(predictions, anomaly_scores)]

    df['predicted_category'] = predictions
    df['confidence'] = confidences
    df['anomaly_score'] = anomaly_scores
    df['severity'] = severities
    df['is_zero_day_suspect'] = zero_day
    df['is_alert'] = [s in ('CRITICAL', 'HIGH', 'MEDIUM') for s in severities]
    return df


def log_alerts_local(scored: pd.DataFrame, db_path: str | None = None) -> int:
    try:
        from storage.alert_logger import AlertLogger

        logger = AlertLogger(db_path=db_path)
        count = 0
        for _, row in scored[scored['is_alert']].iterrows():
            logger.log_alert(
                protocol=row.get('protocol_type', 'tcp'),
                service=row.get('service', 'other'),
                src_bytes=int(row.get('src_bytes', 0) or 0),
                dst_bytes=int(row.get('dst_bytes', 0) or 0),
                predicted_category=str(row['predicted_category']),
                confidence=float(row['confidence']),
                features_summary=(
                    f"anomaly={row['anomaly_score']:.4f} zero_day={row['is_zero_day_suspect']} "
                    f"severity={row['severity']}"
                ),
            )
            count += 1
        return count
    except ImportError:
        return 0


def run_local_inference(
    flows: pd.DataFrame | None = None,
    model_dir: str | None = None,
    anomaly_threshold: float | None = None,
    conf_threshold: float | None = None,
    log_alerts: bool = True,
) -> str:
    if flows is None:
        sample = generate_nsl_kdd_dataset(num_samples=500, random_state=7)
        flows = sample.drop(columns=['label', 'difficulty', 'attack_category'], errors='ignore')

    scored = score_flows(flows, model_dir=model_dir, anomaly_threshold=anomaly_threshold, conf_threshold=conf_threshold)
    alerts = scored[scored['is_alert']]
    critical = int((alerts['severity'] == 'CRITICAL').sum())

    if log_alerts:
        log_alerts_local(scored)

    return f"scored={len(scored)} rows, alerts_raised={len(alerts)}, critical={critical}"


def _stage_files(session, model_dir: str) -> None:
    import snowflake.snowpark  # noqa: F401

    os.makedirs(model_dir, exist_ok=True)
    for filename in (ENSEMBLE_FILENAME, ISOLATION_FILENAME, PREPROCESSOR_FILENAME, BASELINE_FILENAME):
        remote = f"@CORE.MODEL_STAGE/{filename}"
        target = os.path.join(model_dir, filename)
        if not os.path.exists(target):
            session.file.get(remote, model_dir)


def _insert_alerts(session, alerts: pd.DataFrame) -> int:
    rows = []
    for _, row in alerts.iterrows():
        features = row.drop(
            labels=['predicted_category', 'confidence', 'anomaly_score', 'severity', 'is_zero_day_suspect', 'is_alert'],
            errors='ignore',
        ).to_dict()
        raw_features = json.dumps({str(k): (v if v is not None else None) for k, v in features.items()}).replace("'", "''")
        conf = f"{row['confidence']:.6f}"
        anomaly = f"{row['anomaly_score']:.6f}"
        rows.append(
            f"('{uuid.uuid4().hex}', "
            f"'{row.get('flow_id', '')}', "
            f"'{row.get('src_ip', '')}', "
            f"'{row.get('dst_ip', '')}', "
            f"{int(row.get('src_port') or 0)}, "
            f"{int(row.get('dst_port') or 0)}, "
            f"'{row['predicted_category']}', "
            f"{conf}, "
            f"{anomaly}, "
            f"'{row['severity']}', "
            f"{'TRUE' if row['is_zero_day_suspect'] else 'FALSE'}, "
            f"'PENDING', "
            f"PARSE_JSON('{raw_features}')::VARIANT)"
        )
    if rows:
        sql = (
            "INSERT INTO CORE.NIDS_ALERTS (ALERT_ID, FLOW_ID, SRC_IP, DST_IP, SRC_PORT, DST_PORT, "
            "ATTACK_TYPE, CONFIDENCE, ANOMALY_SCORE, SEVERITY, IS_ZERO_DAY_SUSPECT, MITIGATION_STATUS, RAW_FEATURES) "
            f"VALUES {', '.join(rows)}"
        )
        session.sql(sql).collect()
    return len(rows)


def _mark_processed(session, flow_ids: list) -> int:
    if not flow_ids:
        return 0
    quoted = ', '.join([f"'{fid}'" for fid in flow_ids])
    sql = (
        "UPDATE CORE.FLOW_FEATURES SET PROCESSED_FLAG = TRUE, PROCESSED_AT = CURRENT_TIMESTAMP() "
        f"WHERE FLOW_ID IN ({quoted})"
    )
    result = session.sql(sql).collect()
    return int(result[0][0]) if result and result[0] else len(flow_ids)


def sp_run_nids_inference(session) -> str:
    import snowflake.snowpark  # noqa: F401
    from snowflake.snowpark.functions import col

    live = (
        session.table('CORE.FLOW_FEATURES')
        .filter(col('PROCESSED_FLAG') == False)  # noqa: E712
        .limit(5000)
        .to_pandas()
    )
    if live.empty:
        return "scored=0 rows, alerts_raised=0, critical=0"

    model_dir = '/tmp/froststream_models'
    _stage_files(session, model_dir)
    artifacts = load_artifacts(model_dir)

    flow_ids = live['FLOW_ID'].dropna().astype(str).tolist()
    scored = score_flows(live, artifacts=artifacts)
    alerts = scored[scored['is_alert']]
    inserted = _insert_alerts(session, alerts)
    critical = int((alerts['severity'] == 'CRITICAL').sum())
    processed = _mark_processed(session, flow_ids)

    return f"scored={len(scored)} rows, alerts_raised={inserted}, critical={critical}, processed={processed}"


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description='FrostStream NIDS - Phase 2 local inference')
    parser.add_argument('--flows', default=None, help='Path to CSV of flow features to score')
    parser.add_argument('--model-dir', default=None)
    parser.add_argument('--no-log', action='store_true')
    args = parser.parse_args(argv)

    if args.flows and os.path.exists(args.flows):
        flows = pd.read_csv(args.flows)
    else:
        flows = None

    summary = run_local_inference(
        flows=flows,
        model_dir=args.model_dir,
        log_alerts=not args.no_log,
    )
    print(summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())