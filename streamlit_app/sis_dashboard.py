"""FrostStream NIDS - SiS Operational Dashboard (Real Data Only)

Live queries against Snowflake CORE.NIDS_ALERTS, CORE.FLOW_FEATURES, CORE.DRIFT_REPORTS.
All queries filtered WHERE IS_SYNTHETIC = FALSE by default.
Dual-mode: Snowflake live + local offline fallback.
"""

from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# =============================================================================
# STREAMLIT PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="FrostStream NIDS - SOC Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# DESIGN TOKENS
# =============================================================================

CYBER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root {
  --bg-app: #0B0D12;
  --bg-card: #13161D;
  --bg-card-hover: #1A1E2A;
  --border: #232836;
  --border-active: #6366F1;
  --text-primary: #E8ECF4;
  --text-secondary: #8B95A9;
  --text-muted: #5A6478;
  --crit: #F43F5E;
  --high: #F97316;
  --med: #FBBF24;
  --low: #10B981;
  --info: #06B6D4;
}
html, body, [class*="css"] {font-family: 'Inter', sans-serif; color: var(--text-primary);}
.stApp {background: var(--bg-app) !important;}
#MainMenu, header, footer {visibility: hidden; height: 0;}
.cyber-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  height: 100%;
  transition: border-color .2s, transform .2s;
}
.cyber-card:hover {border-color: var(--border-active); transform: translateY(-1px);}
.card-label {font-size: 11px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .5px;}
.card-value {font-size: 28px; font-weight: 700; color: var(--text-primary); font-family: 'JetBrains Mono', monospace; line-height: 1;}
.badge-synth {display:inline-block; font-size:10px; font-weight:600; color:#F97316; background:rgba(249,115,22,.12); border:1px solid rgba(249,115,22,.3); padding:2px 8px; border-radius:999px; margin-left:8px;}
.status-pill {display:inline-flex; align-items:center; gap:4px; font-size:10px; font-weight:600; padding:2px 8px; border-radius:999px;}
.status-actioned {background:rgba(16,185,129,.15); color:#34D399; border:1px solid rgba(16,185,129,.3);}
.status-pending {background:rgba(249,115,22,.15); color:#FB923C; border:1px solid rgba(249,115,22,.3);}
.status-suppressed {background:rgba(99,102,241,.15); color:#A5B4FC; border:1px solid rgba(99,102,241,.3);}
.status-expired {background:rgba(107,114,128,.15); color:#9CA3AF; border:1px solid rgba(107,114,128,.3);}
.sidebar .stButton>button {width:100%; justify-content:flex-start;}
</style>
"""

st.markdown(CYBER_CSS, unsafe_allow_html=True)

# =============================================================================
# DATA ACCESS LAYER (Snowflake + Local Fallback)
# =============================================================================

@st.cache_resource(ttl=30, show_spinner=False)
def get_snowflake_session():
    """Return Snowpark Session if credentials available, else None."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from tools.deploy_cloud import build_session, load_dotenv
        load_dotenv()
        return build_session()
    except Exception:
        return None


def _exec_sql(session, sql: str) -> pd.DataFrame:
    """Execute SQL and return DataFrame, or empty DF on error."""
    try:
        rows = session.sql(sql).collect()
        if rows:
            df = pd.DataFrame([r.as_dict() for r in rows])
            df.columns = [str(c).lower() for c in df.columns]
            return df
    except Exception:
        pass
    return pd.DataFrame()


def fetch_kpis() -> Dict[str, Any]:
    """KPI metrics from live tables."""
    session = get_snowflake_session()
    if session:
        try:
            # Total real alerts (non-synthetic)
            total_alerts = session.sql(
                "SELECT COUNT(*) FROM CORE.NIDS_ALERTS WHERE IS_SYNTHETIC = FALSE"
            ).collect()[0][0]

            critical = session.sql(
                "SELECT COUNT(*) FROM CORE.NIDS_ALERTS WHERE SEVERITY = 'CRITICAL' AND IS_SYNTHETIC = FALSE"
            ).collect()[0][0]

            high = session.sql(
                "SELECT COUNT(*) FROM CORE.NIDS_ALERTS WHERE SEVERITY = 'HIGH' AND IS_SYNTHETIC = FALSE"
            ).collect()[0][0]

            # Active NACL blocks: join alerts with current TTL tags from NACL (via cleanup lambda state)
            # Since NACL tags are in AWS, we approximate from alerts with ACTIONED status that aren't EXPIRED
            actioned = session.sql(
                """SELECT COUNT(DISTINCT SRC_IP) FROM CORE.NIDS_ALERTS 
                   WHERE MITIGATION_STATUS = 'ACTIONED' AND IS_SYNTHETIC = FALSE"""
            ).collect()[0][0]

            # Synthetic count for badge
            synth_alerts = session.sql(
                "SELECT COUNT(*) FROM CORE.NIDS_ALERTS WHERE IS_SYNTHETIC = TRUE"
            ).collect()[0][0]

            # Latest drift
            max_psi = 0.0
            drift_status = "OK"
            drift_ts = None
            try:
                psi_row = session.sql(
                    "SELECT MAX_PSI, STATUS, CHECK_TIMESTAMP FROM CORE.DRIFT_REPORTS ORDER BY CHECK_TIMESTAMP DESC LIMIT 1"
                ).collect()
                if psi_row:
                    max_psi = float(psi_row[0][0])
                    drift_status = str(psi_row[0][1])
                    drift_ts = psi_row[0][2]
            except Exception:
                pass

            return {
                "total_alerts": int(total_alerts),
                "critical": int(critical),
                "high": int(high),
                "active_blocks": int(actioned),
                "synthetic_alerts": int(synth_alerts),
                "max_psi": max_psi,
                "drift_status": drift_status,
                "drift_ts": drift_ts,
                "cloud_live": True,
            }
        except Exception:
            pass

    # Local fallback (from SQLite/CSV if available)
    return {
        "total_alerts": 0, "critical": 0, "high": 0, "active_blocks": 0,
        "synthetic_alerts": 0, "max_psi": 0.0, "drift_status": "OK",
        "drift_ts": None, "cloud_live": False,
    }


def fetch_alerts_by_classification() -> pd.DataFrame:
    """Real GROUP BY ATTACK_TYPE on non-synthetic alerts."""
    session = get_snowflake_session()
    if session:
        df = _exec_sql(session, """
            SELECT ATTACK_TYPE as classification, COUNT(*) as count
            FROM CORE.NIDS_ALERTS
            WHERE IS_SYNTHETIC = FALSE
            GROUP BY ATTACK_TYPE
            ORDER BY count DESC
        """)
        if not df.empty:
            return df
    return pd.DataFrame({"classification": [], "count": []})


def fetch_alert_timeline(hours: int = 72) -> pd.DataFrame:
    """Real timeline grouped by hour on ALERT_TS (TIMESTAMP column)."""
    session = get_snowflake_session()
    if session:
        df = _exec_sql(session, f"""
            SELECT 
                DATE_TRUNC('hour', "TIMESTAMP") as hour_bucket,
                ATTACK_TYPE as classification,
                COUNT(*) as count
            FROM CORE.NIDS_ALERTS
            WHERE IS_SYNTHETIC = FALSE
              AND "TIMESTAMP" >= DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
            GROUP BY 1, 2
            ORDER BY 1
        """)
        if not df.empty:
            df["hour_bucket"] = pd.to_datetime(df["hour_bucket"])
            return df
    return pd.DataFrame({"hour_bucket": [], "classification": [], "count": []})


def fetch_threat_stream(limit: int = 100) -> pd.DataFrame:
    """Live threat rows for the table."""
    session = get_snowflake_session()
    if session:
        df = _exec_sql(session, f"""
            SELECT
                ALERT_ID, "TIMESTAMP", SRC_IP, DST_IP, SRC_PORT, DST_PORT,
                ATTACK_TYPE, CONFIDENCE, ANOMALY_SCORE, SEVERITY, MITIGATION_STATUS
            FROM CORE.NIDS_ALERTS
            WHERE IS_SYNTHETIC = FALSE
            ORDER BY "TIMESTAMP" DESC
            LIMIT {limit}
        """)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            # confidence stored as 0-1, convert to 0-100 for display
            if "confidence" in df.columns:
                df["confidence"] = df["confidence"].apply(
                    lambda v: float(v) * 100 if float(v) <= 1.0 else float(v)
                )
            return df
    return pd.DataFrame()


def fetch_soar_active_blocks() -> pd.DataFrame:
    """Currently active NACL blocks with TTL info.
    Since TTL tags live in AWS, we derive from alerts with ACTIONED status
    that haven't been marked EXPIRED. For TTL we use MITIGATED_AT + 24h.
    """
    session = get_snowflake_session()
    if session:
        df = _exec_sql(session, """
            SELECT
                SRC_IP,
                MIN("TIMESTAMP") as first_alert_ts,
                MAX(MITIGATED_AT) as mitigated_at,
                COUNT(*) as alert_count
            FROM CORE.NIDS_ALERTS
            WHERE MITIGATION_STATUS = 'ACTIONED'
              AND IS_SYNTHETIC = FALSE
            GROUP BY SRC_IP
        """)
        if not df.empty:
            df["first_alert_ts"] = pd.to_datetime(df["first_alert_ts"])
            df["mitigated_at"] = pd.to_datetime(df["mitigated_at"])
            # TTL expiry = mitigated_at + 24 hours
            df["expires_at"] = df["mitigated_at"] + pd.Timedelta(hours=24)
            df["ttl_remaining"] = df["expires_at"] - pd.Timestamp.now(tz="UTC")
            return df
    return pd.DataFrame()


def fetch_latest_drift() -> Dict[str, Any]:
    """Latest drift report details."""
    session = get_snowflake_session()
    if session:
        df = _exec_sql(session, """
            SELECT MAX_PSI, STATUS, CHECK_TIMESTAMP, DRIFTED_FEATURES, FEATURE_PSI_DETAILS
            FROM CORE.DRIFT_REPORTS
            ORDER BY CHECK_TIMESTAMP DESC
            LIMIT 1
        """)
        if not df.empty:
            row = df.iloc[0]
            return {
                "max_psi": float(row["max_psi"]),
                "status": str(row["status"]),
                "check_ts": pd.to_datetime(row["check_timestamp"]),
                "drifted_features": row["drifted_features"],
                "feature_psi_details": row["feature_psi_details"],
            }
    return {"max_psi": 0.0, "status": "OK", "check_ts": None, "drifted_features": {}, "feature_psi_details": {}}


def render_risk_bar(confidence: float) -> str:
    """Simple horizontal risk bar for AgGrid."""
    pct = max(0, min(100, confidence))
    color = "#F43F5E" if pct >= 95 else "#F97316" if pct >= 85 else "#10B981"
    return f"""
<div style="display:flex;align-items:center;gap:8px;width:100%;">
  <div style="flex:1;background:#232836;border-radius:3px;height:6px;overflow:hidden;">
    <div style="width:{pct}%;height:100%;background:{color};border-radius:3px;"></div>
  </div>
  <span style="font-size:11px;color:#CBD5E1;font-family:monospace;min-width:40px;text-align:right;">{pct:.1f}%</span>
</div>"""


# =============================================================================
# MAIN RENDER
# =============================================================================

def main():
    kpis = fetch_kpis()
    cloud_live = kpis["cloud_live"]

    # ----- Header -----
    col_title, col_badge, col_status = st.columns([3, 1, 1])
    with col_title:
        st.markdown("## FrostStream NIDS — SOC Command")
    with col_badge:
        if kpis["synthetic_alerts"]:
            st.markdown(f'<span class="badge-synth">Synthetic rows hidden ({kpis["synthetic_alerts"]})</span>', unsafe_allow_html=True)
    with col_status:
        dot = "🟢" if cloud_live else "🟡"
        st.markdown(f"**{dot} {'Snowflake Live' if cloud_live else 'Local Fallback'}**")

    st.markdown("<br>", unsafe_allow_html=True)

    # ----- KPI ROW -----
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
<div class="cyber-card">
  <div class="card-label">Total Alerts (Real)</div>
  <div class="card-value">{kpis['total_alerts']:,}</div>
</div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
<div class="cyber-card">
  <div class="card-label">CRITICAL</div>
  <div class="card-value" style="color:var(--crit);">{kpis['critical']:,}</div>
</div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
<div class="cyber-card">
  <div class="card-label">HIGH</div>
  <div class="card-value" style="color:var(--high);">{kpis['high']:,}</div>
</div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
<div class="cyber-card">
  <div class="card-label">Active NACL Blocks</div>
  <div class="card-value" style="color:var(--low);">{kpis['active_blocks']:,}</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ----- MIDDLE TIER: Donut + Timeline + SOAR -----
    col_donut, col_timeline, col_soar = st.columns([1.2, 1.3, 1.1])

    with col_donut:
        st.markdown("#### Alerts by Classification")
        cat_df = fetch_alerts_by_classification()
        if not cat_df.empty:
            fig = px.pie(cat_df, values="count", names="classification", hole=0.6,
                         color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_traces(textinfo="none", hoverinfo="label+percent+value")
            fig.update_layout(showlegend=True, legend=dict(orientation="h", y=-0.2, x=0.5, xanchor="center"),
                              margin=dict(t=10, b=30, l=10, r=10),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No real alerts yet — run live capture to populate.")

    with col_timeline:
        st.markdown("#### Alert Timeline (Last 24h)")
        tl_df = fetch_alert_timeline(24)
        if not tl_df.empty:
            fig = px.line(tl_df, x="hour_bucket", y="count", color="classification",
                          markers=True, color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_layout(xaxis_title="", yaxis_title="Count",
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"),
                              margin=dict(t=10, b=30, l=10, r=10))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No timeline data in the last 24h.")

    with col_soar:
        st.markdown("#### SOAR — Active Blocks")
        soar_df = fetch_soar_active_blocks()
        if not soar_df.empty:
            for _, row in soar_df.iterrows():
                ttl = row["ttl_remaining"]
                if ttl.total_seconds() > 0:
                    hrs = int(ttl.total_seconds() // 3600)
                    mins = int((ttl.total_seconds() % 3600) // 60)
                    ttl_str = f"{hrs}h {mins}m"
                    ttl_color = "var(--low)"
                else:
                    ttl_str = "EXPIRED"
                    ttl_color = "var(--text-muted)"
                st.markdown(f"""
<div class="cyber-card" style="margin-bottom:8px;">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <code style="font-family:'JetBrains Mono',monospace;">{row['src_ip']}</code>
    <span style="color:{ttl_color}; font-size:11px; font-weight:600;">{ttl_str}</span>
  </div>
  <div style="font-size:11px; color:var(--text-secondary);">
    {row['alert_count']} alert(s) · mitigated {row['mitigated_at'].strftime('%H:%M UTC')}
  </div>
</div>""", unsafe_allow_html=True)
        else:
            st.info("No active NACL blocks.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ----- BOTTOM: Threat Stream Table + Drift Panel -----
    col_table, col_drift = st.columns([2.2, 1])

    with col_table:
        st.markdown("#### Threat Stream")
        threat_df = fetch_threat_stream(50)
        if not threat_df.empty:
            # Build display DF
            display = threat_df[["timestamp", "alert_id", "src_ip", "dst_ip", "attack_type", "confidence", "severity", "mitigation_status"]].copy()
            display["timestamp"] = display["timestamp"].dt.strftime("%b %d, %H:%M")
            display["confidence"] = display["confidence"].apply(lambda v: f"{v:.1f}%")

            # Use st.dataframe for simplicity (no AgGrid dependency)
            st.dataframe(
                display,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "timestamp": st.column_config.TextColumn("Detected", width="small"),
                    "alert_id": st.column_config.TextColumn("Alert ID", width="small"),
                    "src_ip": st.column_config.TextColumn("Attacker IP", width="small"),
                    "dst_ip": st.column_config.TextColumn("Target IP", width="small"),
                    "attack_type": st.column_config.TextColumn("Type", width="small"),
                    "confidence": st.column_config.TextColumn("Confidence", width="small"),
                    "severity": st.column_config.TextColumn("Severity", width="small"),
                    "mitigation_status": st.column_config.TextColumn("SOAR", width="small"),
                }
            )
        else:
            st.info("No real alerts to display.")

    with col_drift:
        st.markdown("#### Drift Monitor")
        drift = fetch_latest_drift()
        psi = drift["max_psi"]
        status = drift["status"]
        ts = drift["check_ts"]
        psi_color = "var(--low)" if psi < 0.1 else "var(--high)" if psi < 0.25 else "var(--crit)"
        status_color = "var(--low)" if status == "OK" else "var(--high)" if status == "WARNING" else "var(--crit)"

        st.markdown(f"""
<div class="cyber-card">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
    <span class="card-label">Population Stability Index</span>
    <span style="color:{psi_color}; font-weight:700; font-family:'JetBrains Mono',monospace;">{psi:.4f}</span>
  </div>
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
    <span class="card-label">Status</span>
    <span style="color:{status_color}; font-weight:600;">{status}</span>
  </div>
  <div style="font-size:11px; color:var(--text-secondary);">
    Last check: {ts.strftime('%Y-%m-%d %H:%M UTC') if ts else 'N/A'}
  </div>
</div>""", unsafe_allow_html=True)

        if drift["drifted_features"]:
            st.markdown("**Drifted Features:**")
            for feat, val in drift["drifted_features"].items():
                st.markdown(f"- `{feat}`: PSI = {val:.4f}")
        else:
            st.caption("No features exceeded threshold (0.25).")


if __name__ == "__main__":
    main()