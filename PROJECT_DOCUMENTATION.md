# Comprehensive Project Documentation: Network Intrusion Detection System (NIDS)

---

## 1. Executive Summary & Project Short Explanation

The **Network Intrusion Detection System (NIDS)** is an intelligent, data-mining-driven cybersecurity defense system. It monitors network packet flows in real-time and offline batch modes to automatically detect, classify, and explain malicious network intrusions.

Unlike traditional signature-based Intrusion Detection Systems (like Snort or Suricata) that fail against novel attack variants, this system applies **Machine Learning (ML)** and **Data Mining** on network flow traffic features (duration, protocol type, service, TCP flags, byte counts, error rates, login attempts, host statistics). It categorizes network traffic into **5 primary macro-classes**:

1. **Normal**: Standard benign user and application network traffic.
2. **DoS (Denial of Service)**: Flooding attacks aimed at crashing or overloading services (e.g., Neptune SYN flood, Smurf, Pod, Teardrop).
3. **Probe**: Surveillance scans and port sweep activities gathering network topology intelligence (e.g., Satan, Ipsweep, Nmap, Portsweep).
4. **R2L (Remote to Local)**: Unauthorized access attempts from a remote machine (e.g., password brute-forcing, Warezmaster, FTP write exploits).
5. **U2R (User to Root)**: Local non-privileged user attempts to gain administrative root privileges (e.g., buffer overflow exploits, Loadmodule, Rootkit).

---

## 2. Problem Statement & Why It Was Built

### 2.1 The Cybersecurity Challenge
Modern computer networks experience continuous, sophisticated cyber threats. Traditional defense mechanisms rely on static signature matching, which suffers from critical limitations:
- **Zero-Day Vulnerability Blindness**: Unable to detect novel attack variants or unknown exploits without prior signatures.
- **High False Alarm Rates**: Static rules create excessive false positives, causing security alert fatigue for Security Operations Center (SOC) analysts.
- **High Traffic Latency**: Deep packet inspection on every raw packet header and payload degrades high-speed network performance.

### 2.2 Core Objective
To design, train, evaluate, and deploy a data-mining ML system that:
- Achieves **>95% detection accuracy** across multi-class network threats.
- Maintains a **false positive rate <5%**.
- Delivers **real-time classification latency (<1ms per flow)**.
- Provides **Explainable AI (XAI)** evidence so SOC analysts understand *why* an alert was raised.

---

## 3. System Architecture & Methodology

```
+-----------------------------------------------------------------------------------+
|                              NETWORK TRAFFIC INGESTION                             |
|              (Live Packet/Flow Stream Generator OR Offline CSV Batches)            |
+---------------------------------------------------+-------------------------------+
                                                    |
                                                    v
+-----------------------------------------------------------------------------------+
|                               PREPROCESSING PIPELINE                              |
|  - Feature Extraction (41 NSL-KDD Traffic & Host Features)                         |
|  - Categorical One-Hot Encoding (Protocol, Service, Flags)                       |
|  - Feature Normalization & Scaling (StandardScaler / MinMaxScaler)               |
|  - Imbalance & Stratified Sampling Handling                                      |
+---------------------------------------------------+-------------------------------+
                                                    |
                                                    v
+-----------------------------------------------------------------------------------+
|                           CLASSIFICATION ENGINE & MODELS                          |
|  - Decision Tree  |  Random Forest  |  Naive Bayes  |  Linear SVM  |  XGBoost       |
+---------------------------------------------------+-------------------------------+
                                                    |
                                                    v
+-----------------------------------------------------------------------------------+
|                        REAL-TIME SCORING & EXPLAINABILITY (XAI)                    |
|  - Feature Importance & Per-Flow Evidence Rule Inference                          |
+---------------------------------------------------+-------------------------------+
                                                    |
                                                    v
+---------------------------------------------------+-------------------------------+
|                       STORAGE & DASHBOARD PRESENTATION LAYER                       |
|  - SQLite Alert Database (alerts.db)                                              |
|  - Interactive Streamlit SOC Web Application                                      |
+-----------------------------------------------------------------------------------+
```

---

## 4. Machine Learning Algorithms Analysis

| Algorithm | Why Used | How It Works | Where Used | Time Complexity (Train) | Time Complexity (Predict) | Space Complexity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Decision Tree (DT)** | Interpretable baseline classifier; fast decision rules. | Splits data recursively based on Gini Impurity / Information Gain feature thresholds. | Fast baseline scoring & rule generation. | $O(n \cdot m \log n)$ | $O(\text{depth})$ | $O(\text{nodes})$ |
| **Random Forest (RF)** | **Primary Recommended Classifier**. High accuracy, robust against noise, handles high-dimensional interactions without overfitting. | Ensemble of decorrelated decision trees using bagging & random feature subspace sampling. | High-precision SOC threat classification. | $O(k \cdot n \cdot m \log n)$ | $O(k \cdot \text{depth})$ | $O(k \cdot \text{nodes})$ |
| **Naive Bayes (NB)** | Ultra-fast probabilistic baseline. | Applies Bayes' Theorem assuming class-conditional feature independence: $P(Y \mid X) \propto P(Y) \prod P(X_i \mid Y)$. | Ultra-low latency fallback filtering. | $O(n \cdot m)$ | $O(c \cdot m)$ | $O(c \cdot m)$ |
| **Linear SVM** | Effective for high-dimensional sparse feature spaces. | Finds optimal linear hyperplanes maximizing the margin between threat classes: $\min \frac{1}{2} \|w\|^2 + C \sum \xi_i$. | Margin-based separation of protocol features. | $O(n \cdot m^2)$ | $O(m)$ | $O(m)$ |
| **XGBoost** | Gradient Boosted Decision Trees providing state-of-the-art accuracy. | Sequentially fits new trees to residual errors of previous iterations using second-order Taylor expansion loss optimization. | High-throughput batch classification. | $O(k \cdot d \cdot n \log n)$ | $O(k \cdot d)$ | $O(k \cdot \text{nodes})$ |

*Legend: $n = \text{samples}$, $m = \text{features}$, $k = \text{number of trees}$, $d = \text{max depth}$, $c = \text{number of classes}$.*

---

## 5. Unique Innovations of This Project

1. **Integrated Explainable AI (XAI)**: Unlike black-box ML models, this system auto-generates human-readable evidence strings for SOC analysts (e.g., explaining that a flow was flagged as DoS due to `serror_rate = 1.0` and `count = 350`).
2. **Sub-Millisecond Scoring Latency**: Inference executes in **<0.5ms per flow**, meeting the real-time requirement (<1s).
3. **Dual Execution Pipeline**: Supports both real-time streaming simulation and offline batch CSV processing.
4. **Persistent SQLite Alert Storage**: Security alerts are logged with automated severity classification (`CRITICAL`, `HIGH`, `MEDIUM`, `INFO`) into `alerts.db`.
5. **Interactive SOC Dashboard**: A Streamlit web dashboard displaying live metrics, threat feeds, model performance benchmarks, and feature correlation heatmaps.

---

## 6. Dashboard Interface & What is Shown

1. **📊 SOC Overview & Live Monitor**:
   - Total network flows scored & flagged threat counter metrics.
   - Live flow injector to simulate attacks (DoS, Probe, R2L, U2R, Normal).
   - Real-time threat feed with timestamp, protocol, confidence, and primary XAI evidence.
2. **⚡ Model Benchmark & Training**:
   - Multi-model evaluation table comparing Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), and Inference Latency.
   - Interactive Confusion Matrices for selected algorithms.
   - Side-by-side performance bar charts.
3. **📁 Batch Flow Classifier**:
   - Drag-and-drop CSV uploader for offline network traffic analysis.
   - Traffic breakdown donut/pie charts.
   - Scored output report generator with one-click CSV download.
4. **🚨 Threat Alert Logs**:
   - Filterable SQLite alert records.
   - Severity filters and log exporter.
5. **🔍 Feature Analytics & Explainability**:
   - Top 15 Random Forest feature importances.
   - Pearson correlation matrix heatmap for redundancy identification.

---

## 7. Applications & Real-World Use Cases

- **Enterprise Security Operations Centers (SOCs)**: Automated triage assistant filtering noise and highlighting high-risk intrusions.
- **Data Center & Cloud Infrastructure Protection**: Real-time traffic monitoring to safeguard cloud services against DoS/DDoS amplification attacks.
- **Industrial Control Systems (ICS / SCADA)**: Detecting unauthorized remote access attempts (R2L) and protocol anomalies.
- **Academic & Security Research**: Benchmarking ML classifiers against network flow datasets.

---

## 8. How to Setup and Run the System

### Prerequisites
- Python 3.9+
- Packages: `streamlit`, `pandas`, `numpy`, `scikit-learn`, `xgboost`, `plotly`, `joblib`, `pytest`

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run Unit Tests
```bash
pytest tests/
```

### Step 3: Launch Web Application
```bash
streamlit run app.py
```
Open browser at `http://localhost:8501`.
