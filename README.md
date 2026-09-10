# Network Intrusion Detection System (NIDS)

> 📚 **Detailed Documentation:** Read the full [Project Documentation](PROJECT_DOCUMENTATION.md).

A Machine Learning & Data Mining Network Intrusion Detection System (NIDS) designed to classify network traffic flows into **Normal**, **DoS**, **Probe**, **R2L**, and **U2R** categories.

## Features
- **Data Mining Pipeline**: Multi-class classification based on NSL-KDD traffic flow features.
- **5 ML Algorithms**: Decision Tree, Random Forest, Naive Bayes, Linear SVM, and XGBoost with automated benchmark comparison.
- **Preprocessing & Balancing**: Categorical One-Hot Encoding, StandardScaler/MinMaxScaler, and Stratified train/test splitting.
- **Explainable AI (XAI)**: Per-flow evidence breakdown and global feature importance ranking for SOC analyst trust.
- **Real-Time & Batch Ingestion**: Real-time traffic flow injector (<1ms per flow) and CSV batch file processor.
- **SQLite Threat Alert Storage**: Automated alert logger with severity levels (Critical, High, Medium, Low).
- **Interactive SOC Dashboard**: Streamlit web dashboard with interactive Plotly metrics, live monitor, and confusion matrices.

## Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Automated Tests
```bash
pytest tests/
```

### 3. Launch Streamlit Web Dashboard
```bash
streamlit run app.py
```

## Directory Structure
```
network_ids/
├── data/
│   └── dataset_loader.py       # NSL-KDD loader & synthetic flow generator
├── src/
│   ├── preprocessing.py        # Scaler & categorical encoders
│   ├── feature_engineering.py  # Correlation & feature importances
│   ├── models.py               # 5 ML model trainers & metrics evaluator
│   ├── pipeline.py             # Single-flow real-time & batch scoring
│   └── explainability.py       # Analyst evidence breakdown
├── storage/
│   └── alert_logger.py         # SQLite threat alert database
├── tests/                      # Pytest automated unit test suite
├── app.py                      # Streamlit SOC Dashboard
├── requirements.txt
└── README.md
```