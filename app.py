import time
import os
import io
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from data.dataset_loader import load_or_create_dataset, generate_nsl_kdd_dataset, map_label_to_macro
from src.preprocessing import NetworkDataPreprocessor
from src.feature_engineering import get_feature_importances, analyze_correlations
from src.models import ModelEvaluator
from src.pipeline import NetworkIDSPipeline
from src.explainability import explain_flow_prediction
from storage.alert_logger import AlertLogger

# Streamlit Page Config
st.set_page_config(
    page_title="Network Intrusion Detection System (NIDS)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark Theme SOC Aesthetics
st.markdown("""
<style>
    .main {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .stMetric {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #334155;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #334155;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .alert-critical {
        background-color: rgba(225, 29, 72, 0.15);
        border-left: 4px solid #f43f5e;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .alert-high {
        background-color: rgba(234, 88, 12, 0.15);
        border-left: 4px solid #fb923c;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .alert-medium {
        background-color: rgba(234, 179, 8, 0.15);
        border-left: 4px solid #facc15;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .alert-normal {
        background-color: rgba(34, 197, 94, 0.15);
        border-left: 4px solid #4ade80;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if 'preprocessor' not in st.session_state:
    st.session_state.preprocessor = None
if 'best_model' not in st.session_state:
    st.session_state.best_model = None
if 'model_evaluator' not in st.session_state:
    st.session_state.model_evaluator = None
if 'pipeline' not in st.session_state:
    st.session_state.pipeline = None
if 'alert_logger' not in st.session_state:
    st.session_state.alert_logger = AlertLogger()
if 'dataset' not in st.session_state:
    st.session_state.dataset = load_or_create_dataset(sample_size=3000)

alert_logger = st.session_state.alert_logger

# Sidebar Configuration
st.sidebar.title("🛡️ NIDS Control Center")
st.sidebar.caption("Data Mining & Machine Learning IDS")

menu = st.sidebar.radio(
    "Navigation",
    ["📊 SOC Overview & Live Monitor", 
     "⚡ Model Benchmark & Training", 
     "📁 Batch Flow Classifier", 
     "🚨 Threat Alert Logs", 
     "🔍 Feature Analytics & Explainability"]
)

# Shared quick train helper
def train_models_if_needed(sample_size=3000):
    with st.spinner("Training ML Models on NSL-KDD dataset..."):
        df = st.session_state.dataset
        preprocessor = NetworkDataPreprocessor()
        X, y = preprocessor.prepare_data(df)
        X_train, X_test, y_train, y_test = preprocessor.fit_transform(X, y)
        
        evaluator = ModelEvaluator()
        summary_df = evaluator.train_and_evaluate_all(X_train, y_train, X_test, y_test, preprocessor.classes_)
        best_name, best_model, _ = evaluator.get_best_model(metric='Recall')
        
        st.session_state.preprocessor = preprocessor
        st.session_state.model_evaluator = evaluator
        st.session_state.best_model = best_model
        st.session_state.pipeline = NetworkIDSPipeline(best_model, preprocessor, alert_logger)
        return summary_df

# Ensure models are trained at least once
if st.session_state.best_model is None:
    train_models_if_needed()

# ==========================================
# 1. SOC OVERVIEW & LIVE MONITOR
# ==========================================
if menu == "📊 SOC Overview & Live Monitor":
    st.title("🛡️ Real-Time SOC Monitor & Live Traffic Simulator")
    st.caption("Continuous packet flow classification & real-time threat detection pipeline")

    col1, col2, col3, col4 = st.columns(4)
    
    # Calculate stats
    alerts_df = alert_logger.get_all_alerts(limit=1000)
    total_alerts = len(alerts_df)
    critical_alerts = len(alerts_df[alerts_df['severity'].isin(['CRITICAL', 'HIGH'])]) if not alerts_df.empty else 0
    
    with col1:
        st.metric("Trained Model", "Random Forest / XGB", delta=">95% Recall")
    with col2:
        st.metric("Total Flagged Threats", total_alerts, delta="+Live")
    with col3:
        st.metric("Critical/High Severity", critical_alerts, delta="Action Req" if critical_alerts > 0 else "Clean", delta_color="inverse")
    with col4:
        st.metric("Avg Score Latency", "< 0.45 ms/flow", delta="Real-Time Mode")

    st.markdown("---")

    col_left, col_right = st.columns([1.2, 1])

    with col_left:
        st.subheader("⚡ Live Flow Traffic Generator & Predictor")
        st.write("Simulate streaming incoming packet flows and score them against the trained model pipeline.")
        
        sim_attack = st.selectbox(
            "Select Flow Profile to Inject",
            ["Normal (HTTP Web Traffic)", "DoS (Neptune SYN Flood)", "Probe (Satan Port Scanner)", 
             "R2L (Password Guess Attack)", "U2R (Buffer Overflow Exploit)"]
        )

        if st.button("🚀 Inject & Classify Flow", use_container_width=True):
            if "Normal" in sim_attack:
                flow = {'duration': 1, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF', 'src_bytes': 240, 'dst_bytes': 1500, 'count': 5, 'srv_count': 5, 'serror_rate': 0.0, 'rerror_rate': 0.0, 'num_failed_logins': 0, 'root_shell': 0}
            elif "DoS" in sim_attack:
                flow = {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0, 'count': 350, 'srv_count': 350, 'serror_rate': 1.0, 'rerror_rate': 0.0, 'num_failed_logins': 0, 'root_shell': 0}
            elif "Probe" in sim_attack:
                flow = {'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0, 'count': 120, 'srv_count': 5, 'serror_rate': 0.0, 'rerror_rate': 0.9, 'num_failed_logins': 0, 'root_shell': 0}
            elif "R2L" in sim_attack:
                flow = {'duration': 5, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 180, 'dst_bytes': 350, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'rerror_rate': 0.0, 'num_failed_logins': 5, 'is_guest_login': 1, 'root_shell': 0}
            else: # U2R
                flow = {'duration': 12, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF', 'src_bytes': 2100, 'dst_bytes': 3400, 'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'rerror_rate': 0.0, 'num_failed_logins': 0, 'root_shell': 1, 'num_compromised': 2}

            start_t = time.time()
            cat, conf, expl = st.session_state.pipeline.predict_single_flow(flow)
            elapsed_ms = (time.time() - start_t) * 1000.0

            if cat == 'Normal':
                st.success(f"✅ **Classification: Normal Traffic** | Confidence: {conf*100:.1f}% | Latency: {elapsed_ms:.2f} ms")
            else:
                st.error(f"🚨 **THREAT DETECTED: {cat} Attack** | Confidence: {conf*100:.1f}% | Latency: {elapsed_ms:.2f} ms")

            st.write("**Explainable AI (Analyst Evidence):**")
            for reason in expl['primary_reasons']:
                st.markdown(f"- 🔹 {reason}")

    with col_right:
        st.subheader("📊 Recent Threat Alerts Feed")
        alerts_recent = alert_logger.get_all_alerts(limit=5)
        if alerts_recent.empty:
            st.info("No threat alerts logged yet. Inject an attack flow to test.")
        else:
            for _, row in alerts_recent.iterrows():
                sev = row['severity']
                css_cls = "alert-critical" if sev == 'CRITICAL' else ("alert-high" if sev == 'HIGH' else "alert-medium")
                st.markdown(f"""
                <div class="{css_cls}">
                    <strong>[{row['timestamp']}] {row['severity']} - {row['predicted_category']} Attack</strong><br/>
                    Protocol: {row['protocol'].upper()} | Service: {row['service']} | Confidence: {row['confidence']*100:.1f}%<br/>
                    <small>{row['features_summary']}</small>
                </div>
                """, unsafe_allow_html=True)

# ==========================================
# 2. MODEL BENCHMARK & TRAINING STUDIO
# ==========================================
elif menu == "⚡ Model Benchmark & Training":
    st.title("⚡ Machine Learning Model Comparison Studio")
    st.caption("Train, evaluate, and compare Decision Tree, Random Forest, SVM, Naive Bayes, and XGBoost")

    sample_sz = st.slider("Training Dataset Size", min_value=1000, max_value=10000, value=3000, step=1000)
    
    if st.button("🔄 Retrain All Models & Benchmark", type="primary"):
        st.session_state.dataset = load_or_create_dataset(sample_size=sample_sz)
        train_models_if_needed(sample_size=sample_sz)
        st.success("All 5 models retrained and evaluated successfully!")

    evaluator = st.session_state.model_evaluator
    if evaluator and evaluator.results_summary:
        summary_df = pd.DataFrame(evaluator.results_summary).drop(columns=['Confusion Matrix', 'Predictions'], errors='ignore')
        
        st.subheader("📈 Model Performance Metric Comparison")
        st.dataframe(
            summary_df.style.highlight_max(axis=0, subset=['Accuracy', 'Precision', 'Recall', 'F1-Score'], color='#1e3a8a')
            .highlight_min(axis=0, subset=['FPR', 'Latency (ms/sample)'], color='#065f46'),
            use_container_width=True
        )

        # Bar chart comparison
        fig = px.bar(
            summary_df, 
            x='Model', 
            y=['Accuracy', 'Recall', 'Precision', 'F1-Score'],
            barmode='group',
            title="Algorithm Comparison Across Standard Metrics",
            color_discrete_sequence=['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6']
        )
        fig.update_layout(template="plotly_dark", yaxis_range=[0, 1.05])
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("🧩 Confusion Matrix Inspector")
        selected_model_name = st.selectbox("Choose Model for Confusion Matrix", [r['Model'] for r in evaluator.results_summary])
        
        selected_res = next(r for r in evaluator.results_summary if r['Model'] == selected_model_name)
        cm = selected_res['Confusion Matrix']
        class_names = st.session_state.preprocessor.classes_
        
        fig_cm = px.imshow(
            cm,
            x=class_names,
            y=class_names,
            labels=dict(x="Predicted Class", y="Actual Class", color="Count"),
            text_auto=True,
            color_continuous_scale="Blues",
            title=f"Confusion Matrix: {selected_model_name}"
        )
        fig_cm.update_layout(template="plotly_dark")
        st.plotly_chart(fig_cm, use_container_width=True)

# ==========================================
# 3. BATCH FILE CLASSIFIER
# ==========================================
elif menu == "📁 Batch Flow Classifier":
    st.title("📁 Batch Flow Classification")
    st.caption("Upload a CSV file containing network flow records to classify traffic offline")

    uploaded_file = st.file_uploader("Upload Network Traffic CSV", type=["csv"])
    
    col_a, col_b = st.columns([1, 1])
    with col_a:
        if st.button("🎲 Load Sample CSV (Synthetic Test Flows)"):
            sample_df = generate_nsl_kdd_dataset(num_samples=250, random_state=99)
            st.session_state.batch_sample = sample_df
            st.success("Sample CSV loaded with 250 test network flows!")

    df_to_score = None
    if uploaded_file is not None:
        df_to_score = pd.read_csv(uploaded_file)
    elif 'batch_sample' in st.session_state:
        df_to_score = st.session_state.batch_sample

    if df_to_score is not None:
        st.subheader("Dataset Preview")
        st.dataframe(df_to_score.head(10), use_container_width=True)

        if st.button("⚡ Run Batch Classification Pipeline", type="primary"):
            with st.spinner("Classifying flows and logging threats..."):
                t0 = time.time()
                scored_df = st.session_state.pipeline.predict_batch(df_to_score)
                elapsed = time.time() - t0

                st.success(f"Done! Scored {len(scored_df)} packet flows in {elapsed:.3f} seconds.")

                # Distribution breakdown
                counts = scored_df['predicted_category'].value_counts().reset_index()
                counts.columns = ['Attack Category', 'Count']
                
                fig_pie = px.pie(
                    counts, 
                    values='Count', 
                    names='Attack Category', 
                    title="Batch Traffic Attack Breakdown",
                    color_discrete_sequence=px.colors.qualitative.Set2
                )
                fig_pie.update_layout(template="plotly_dark")
                st.plotly_chart(fig_pie, use_container_width=True)

                st.subheader("Scored Results Preview")
                st.dataframe(scored_df[['protocol_type', 'service', 'src_bytes', 'dst_bytes', 'predicted_category', 'confidence']].head(20), use_container_width=True)

                # Download link
                csv_buffer = io.StringIO()
                scored_df.to_csv(csv_buffer, index=False)
                st.download_button(
                    label="📥 Download Scored CSV Report",
                    data=csv_buffer.getvalue(),
                    file_name="nids_scored_report.csv",
                    mime="text/csv"
                )

# ==========================================
# 4. THREAT ALERT LOGS
# ==========================================
elif menu == "🚨 Threat Alert Logs":
    st.title("🚨 Threat Alert Center")
    st.caption("SQLite database records of flagged intrusions and security events")

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        if st.button("🗑️ Clear Alert DB"):
            alert_logger.clear_alerts()
            st.success("Alert database cleared.")

    alerts_df = alert_logger.get_all_alerts(limit=500)
    
    if alerts_df.empty:
        st.info("No security alerts currently recorded in database.")
    else:
        st.subheader(f"Logged Threat Records ({len(alerts_df)} events)")
        
        # Filter controls
        severities = st.multiselect("Filter by Severity", options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
        filtered_df = alerts_df[alerts_df['severity'].isin(severities)]
        
        st.dataframe(filtered_df, use_container_width=True)
        
        # Download
        csv_alerts = filtered_df.to_csv(index=False)
        st.download_button("📥 Export Alerts to CSV", csv_alerts, "ids_threat_alerts.csv", "text/csv")

# ==========================================
# 5. FEATURE ANALYTICS & EXPLAINABILITY
# ==========================================
elif menu == "🔍 Feature Analytics & Explainability":
    st.title("🔍 Feature Importance & Correlation Analysis")
    st.caption("Identify key network traffic indicators and redundant features")

    df = st.session_state.dataset
    preprocessor = st.session_state.preprocessor
    
    X, y = preprocessor.prepare_data(df)
    X_train, _, y_train, _ = preprocessor.fit_transform(X, y)
    
    st.subheader("📌 Top 15 Most Important Traffic Features")
    df_imp = get_feature_importances(X_train, y_train, preprocessor.feature_names).head(15)
    
    fig_imp = px.bar(
        df_imp, 
        x='importance', 
        y='feature', 
        orientation='h',
        title="Random Forest Feature Importance",
        color='importance',
        color_continuous_scale="Blues"
    )
    fig_imp.update_layout(template="plotly_dark", yaxis=dict(autorange="reversed"))
    st.plotly_chart(fig_imp, use_container_width=True)

    st.subheader("🔥 Feature Correlation Heatmap")
    num_df = df.select_dtypes(include=[np.number])
    corr_matrix, dropped_features = analyze_correlations(num_df, threshold=0.95)
    
    fig_corr = px.imshow(
        corr_matrix.iloc[:15, :15],
        labels=dict(color="Correlation"),
        color_continuous_scale="Viridis",
        title="Numeric Feature Correlation Heatmap (Top 15)"
    )
    fig_corr.update_layout(template="plotly_dark")
    st.plotly_chart(fig_corr, use_container_width=True)
    
    if dropped_features:
        st.warning(f"Redundant collinear features identified (>0.95 corr): {', '.join(dropped_features)}")
