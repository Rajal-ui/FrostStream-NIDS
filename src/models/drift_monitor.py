import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from data.dataset_loader import generate_nsl_kdd_dataset
from src.models.constants import (
    BASELINE_FILENAME,
    DEFAULT_PSI_DRIFT_THRESHOLD,
    PSI_EPS,
    default_model_dir,
)
from src.models.train import compute_baseline_distribution


def compute_psi(expected, actual, eps: float = PSI_EPS) -> float:
    expected_arr = np.asarray(expected, dtype=float)
    actual_arr = np.asarray(actual, dtype=float)
    expected_arr = np.where(expected_arr <= 0, eps, expected_arr)
    actual_arr = np.where(actual_arr <= 0, eps, actual_arr)
    expected_arr = expected_arr / expected_arr.sum()
    actual_arr = actual_arr / actual_arr.sum()
    return float(np.sum((actual_arr - expected_arr) * np.log(actual_arr / expected_arr)))


def compute_feature_psi(profile: dict, live_values) -> float:
    if profile.get('kind') == 'categorical':
        value_counts = pd.Series(live_values).astype(str).value_counts(normalize=True)
        live_map = {str(k): float(v) for k, v in value_counts.items()}
        categories = list(profile['categories'])
        expected = list(profile['expected'])
        actual_values = [live_map.get(cat, 0.0) for cat in categories]
        unseen = [cat for cat in live_map if cat not in set(categories)]
        if unseen:
            actual_values.append(sum(live_map.get(cat, 0.0) for cat in unseen))
            expected = expected + [PSI_EPS]
        return compute_psi(expected, actual_values)

    values = pd.to_numeric(pd.Series(live_values), errors='coerce').dropna().to_numpy(dtype=float)
    if values.size == 0:
        return 0.0
    counts, _ = np.histogram(values, bins=np.asarray(profile['bins'], dtype=float))
    actual = (counts + PSI_EPS) / float(counts.sum() + PSI_EPS * counts.size)
    return compute_psi(profile['expected'], actual)


def build_drift_report(
    baseline: dict,
    live_df: pd.DataFrame,
    threshold: float | None = None,
    window_start=None,
    window_end=None,
) -> dict:
    threshold = DEFAULT_PSI_DRIFT_THRESHOLD if threshold is None else threshold
    features = baseline.get('features', baseline)
    columns_lower = {str(c).lower(): c for c in live_df.columns}
    details = {}
    drifted = []
    for feature, profile in features.items():
        if feature not in columns_lower:
            continue
        psi = compute_feature_psi(profile, live_df[columns_lower[feature]])
        details[str(feature)] = round(psi, 6)
        if psi > threshold:
            drifted.append({'feature': str(feature), 'psi': round(psi, 6), 'threshold_exceeded': True})

    max_psi = max(details.values(), default=0.0)
    status = 'ALERT' if max_psi > threshold else 'OK'
    now = datetime.now(timezone.utc)
    default_start = (window_start or (now - timedelta(hours=1))).strftime('%Y-%m-%d %H:%M:%S')
    default_end = window_end or now
    if not isinstance(default_end, str):
        default_end = default_end.strftime('%Y-%m-%d %H:%M:%S')
    return {
        'report_id': uuid.uuid4().hex,
        'window_start': window_start if isinstance(window_start, str) else default_start,
        'window_end': window_end if isinstance(window_end, str) else default_end,
        'max_psi': round(float(max_psi), 6),
        'status': status,
        'threshold': threshold,
        'drifted_features': drifted,
        'feature_psi_details': details,
    }


def load_baseline(model_dir: str | None = None, baseline_path: str | None = None) -> dict:
    path = baseline_path or os.path.join(model_dir or default_model_dir(), BASELINE_FILENAME)
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def prepare_baseline_if_missing(model_dir: str | None = None) -> str:
    model_dir = model_dir or default_model_dir()
    path = os.path.join(model_dir, BASELINE_FILENAME)
    if os.path.exists(path):
        return path
    os.makedirs(model_dir, exist_ok=True)
    sample = generate_nsl_kdd_dataset(num_samples=2000, random_state=42)
    baseline = compute_baseline_distribution(sample)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(baseline, fh, indent=2)
    return path


def run_local_drift_monitor(
    flows: pd.DataFrame | None = None,
    model_dir: str | None = None,
    threshold: float | None = None,
    perturb: float = 0.0,
) -> str:
    model_dir = model_dir or default_model_dir()
    baseline_path = prepare_baseline_if_missing(model_dir)
    baseline = load_baseline(model_dir=model_dir, baseline_path=baseline_path)

    if flows is None:
        live = generate_nsl_kdd_dataset(num_samples=1000, random_state=9)
        if perturb > 0:
            mask = np.random.rand(len(live)) < perturb
            live.loc[mask & (live['protocol_type'] == 'tcp'), 'protocol_type'] = 'icmp'
            live.loc[mask & (live['service'] == 'http'), 'service'] = 'private'
    else:
        live = flows.copy()

    report = build_drift_report(baseline, live, threshold=threshold)
    os.makedirs(model_dir, exist_ok=True)
    output_path = os.path.join(model_dir, 'drift_report.json')
    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, indent=2)

    return (
        f"PSI window: max_psi={report['max_psi']:.4f}, status={report['status']}, "
        f"drifted_features={len(report['drifted_features'])} (report: {output_path})"
    )


def _escape_sql(value) -> str:
    return str(value).replace("'", "''")


def sp_run_drift_monitor(session, threshold: float | None = None) -> str:
    import snowflake.snowpark  # noqa: F401

    threshold = DEFAULT_PSI_DRIFT_THRESHOLD if threshold is None else threshold
    model_dir = '/tmp/froststream_models'
    os.makedirs(model_dir, exist_ok=True)
    try:
        session.file.get(f'@CORE.MODEL_STAGE/{BASELINE_FILENAME}', model_dir)
    except Exception as exc:  # noqa: BLE001
        return f"drift monitor failed: baseline unavailable ({exc})"

    baseline = load_baseline(model_dir=model_dir)

    live = session.sql(
        "SELECT * FROM CORE.FLOW_FEATURES "
        "WHERE CREATED_AT >= DATEADD(hour, -1, CURRENT_TIMESTAMP()) AND PROCESSED_FLAG = TRUE "
        "LIMIT 10000"
    ).to_pandas()
    if live.empty:
        return "drift monitor: no live flows in window, status=OK"

    live.columns = [str(c).lower() for c in live.columns]
    window_start = str(live['created_at'].min()) if 'created_at' in live.columns else None
    window_end = str(live['created_at'].max()) if 'created_at' in live.columns else None
    report = build_drift_report(
        baseline, live, threshold=threshold, window_start=window_start, window_end=window_end
    )

    drifted_json = json.dumps(report['drifted_features'])
    details_json = json.dumps(report['feature_psi_details'])
    drifted_json = drifted_json.replace('null', 'NULL')
    details_json = details_json.replace('null', 'NULL')

    sql = (
        "INSERT INTO CORE.DRIFT_REPORTS (REPORT_ID, WINDOW_START, WINDOW_END, MAX_PSI, "
        "DRIFTED_FEATURES, FEATURE_PSI_DETAILS, STATUS) VALUES ("
        f"'{_escape_sql(report['report_id'])}', "
        f"TO_TIMESTAMP_NTZ('{_escape_sql(report['window_start'])}'), "
        f"TO_TIMESTAMP_NTZ('{_escape_sql(report['window_end'])}'), "
        f"{report['max_psi']}, "
        f"PARSE_JSON('{_escape_sql(drifted_json)}')::VARIANT, "
        f"PARSE_JSON('{_escape_sql(details_json)}')::VARIANT, "
        f"'{report['status']}')"
    )
    session.sql(sql).collect()

    if report['status'] == 'ALERT':
        alert_sql = (
            "INSERT INTO CORE.NIDS_ALERTS (ALERT_ID, SRC_IP, DST_IP, ATTACK_TYPE, CONFIDENCE, SEVERITY, "
            "IS_ZERO_DAY_SUSPECT, MITIGATION_STATUS) VALUES ("
            f"'{uuid.uuid4().hex}', '0.0.0.0', '0.0.0.0', 'MODEL_DRIFT_ALERT', 1.0, 'HIGH', FALSE, 'PENDING')"
        )
        session.sql(alert_sql).collect()

    return (
        f"drift monitor: max_psi={report['max_psi']:.4f}, status={report['status']}, "
        f"drifted_features={len(report['drifted_features'])}"
    )


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description='FrostStream NIDS - Phase 2 local drift monitor')
    parser.add_argument('--flows', default=None, help='Path to CSV of live flow features')
    parser.add_argument('--model-dir', default=None)
    parser.add_argument('--perturb', type=float, default=0.0,
                        help='Fraction of live flows to perturb to simulate drift (0-1)')
    args = parser.parse_args(argv)

    flows = pd.read_csv(args.flows) if args.flows and os.path.exists(args.flows) else None
    summary = run_local_drift_monitor(flows=flows, model_dir=args.model_dir, perturb=args.perturb)
    print(summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())