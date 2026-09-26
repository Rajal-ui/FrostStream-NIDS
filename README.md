# FrostStream NIDS

FrostStream NIDS is a dual-mode network intrusion detection system (NIDS). It turns network packets or existing flow records into 41 NSL-KDD-compatible features, classifies each flow, records security alerts, and can optionally send a qualifying alert to an AWS Network ACL (NACL) mitigation path.

The project has two deliberately separate operating modes:

- **LOCAL** — Scapy capture or offline replay, local model artifacts, JSONL flow output, and a SQLite alert store. This is the best starting point for development and evaluation.
- **CLOUD** — the flow processor sends records to Kinesis Data Firehose, Snowflake loads them through Snowpipe, Snowpark procedures score and monitor them, and an optional SOAR path can call an API Gateway/Lambda function to create a temporary NACL deny rule.

## Documentation

- [Project Documentation](PROJECT_DOCUMENTATION.md) — beginner-friendly technical handbook.
- [Project Master Document](docs/NIDS-SecOps%20Project%20Master%20Document.md) — public architecture, scope, governance, and delivery overview.
- [Testing, Running, AWS, and Snowflake Guide](docs/TESTING_RUNNING_AWS_SNOWFLAKE_GUIDE.md) — practical setup, deployment, verification, and troubleshooting instructions.

## What the system detects

The current model maps labeled NSL-KDD attacks to five macro-classes:

| Class | Meaning | Examples from the dataset |
| --- | --- | --- |
| `Normal` | Benign traffic | Ordinary service connections |
| `DoS` | Denial of service | Neptune, Smurf, Teardrop |
| `Probe` | Reconnaissance or scanning | Satan, Nmap, Portsweep |
| `R2L` | Remote-to-local access attempts | FTP write, password guessing |
| `U2R` | User-to-root privilege escalation | Buffer overflow, rootkit |

The primary cloud model is a soft-voting ensemble of XGBoost and Random Forest, with an Isolation Forest used for anomaly/possible-zero-day detection. The repository also contains an older five-algorithm benchmark module at `src/models.py`; it is not the same thing as the current `src/models/train.py` training path.

## Data flow

```text
Packets or flow records
        |
        v
ingestion/flow_processor.py
  FlowFeatureExtractor
  - aggregates bidirectional packets
  - calculates 41 NSL-KDD-compatible features
        |
        +--> LOCAL: JSONL flow output
        |
        +--> CLOUD: Kinesis Data Firehose
                         |
                         v
                 S3 flows/ prefix
                         |
                S3 event -> SQS -> Snowpipe
                         |
                         v
                 RAW_FLOW_LANDING
                         |
                 stream + flatten task
                         |
                         v
                  FLOW_FEATURES
                         |
                 Snowpark inference
                         |
                         v
                    NIDS_ALERTS
                         |
             optional qualifying SOAR dispatch
                         |
             API Gateway -> Lambda -> AWS NACL
```

The current repository implements the Scapy/flow-record producer and the Firehose sink. A separate VPC Flow Logs exporter or other production traffic source must deliver records to Firehose; that adapter is outside this repository.

## Local quick start

Use Python 3.10 or later. From the repository root:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The cloud deployment helpers load `.env`; the local CLI does not automatically load values from that file. The model commands use their explicit `--out-dir`/`--model-dir` options, while the flow and factory components read the relevant process environment variables:

```powershell
$env:EXECUTION_MODE = "LOCAL"
$env:LOCAL_MODEL_DIR = "storage/models"
$env:LOCAL_FLOW_OUTPUT = "storage/captured_flows.csv"
$env:LOCAL_ALERT_DB = "storage/alerts.db"
```

The current local inference CLI logs alerts to `storage/alerts.db` by default; use the model-directory flags explicitly when artifacts are stored elsewhere. `LOCAL_MODEL_DIR` is used by factory-based consumers, while `LOCAL_ALERT_DB` is used by factory-based local alert sinks.

Train local artifacts, replay a small synthetic sample, and score it:

```powershell
python -m src.models.train --out-dir storage/models --samples 8000
python -m ingestion.flow_processor --replay-sample --flows 20 --mode LOCAL
python -m src.models.inference --model-dir storage/models
```

Replay a packet capture instead of generated packets:

```powershell
python -m ingestion.flow_processor --replay path/to/capture.pcap --mode LOCAL --out storage/replayed_flows.jsonl
```

Live sniffing requires Scapy, a supported capture interface, and the permissions required by the host operating system:

```powershell
python -m ingestion.flow_processor --sniff "<interface>" --duration 30 --mode LOCAL
```

Launch the local Streamlit dashboard after training artifacts exist:

```powershell
streamlit run app.py
```

## Test and validate

Run the complete automated suite from the repository root:

```powershell
pytest tests/ -v
```

The current validation baseline is 71 passing tests. The suite covers preprocessing, flow aggregation, dual-mode factories, model behavior, SQL structure, mitigation idempotency, and mocked real-capture end-to-end paths.

For cloud verification, follow the dedicated guide rather than copying local commands. Cloud checks require an AWS account, a Snowflake account, a configured S3 landing bucket, a Firehose delivery stream, model artifacts, and appropriate IAM permissions.

## Repository map

```text
.
├── app.py                         Local Streamlit dashboard entry point
├── data/dataset_loader.py         NSL-KDD schema, labels, and sample generator
├── ingestion/flow_processor.py   Packet aggregation and local/cloud flow sink
├── src/common/execution_mode.py   LOCAL/CLOUD factory and implementations
├── src/models/                    Current ensemble, inference, and drift code
├── src/soar/                      Optional NACL mitigation and cleanup Lambdas
├── storage/                       Generated local alerts, models, and flow data
├── snowflake_setup/               Snowflake schema, pipe, procedures, and checks
├── infra/template.yaml            AWS SAM template for the SOAR stack
├── tools/                         Provisioning, packaging, smoke, and check scripts
├── tests/                         Automated unit, SQL, SOAR, and E2E tests
├── PROJECT_DOCUMENTATION.md       Technical handbook
└── docs/                          Public PMD and operations guide
```

## Security and data handling

- Never commit `.env`, private keys, access keys, passwords, or real network captures containing sensitive data.
- Use least-privilege AWS and Snowflake roles. The optional SOAR path changes network controls and must be reviewed before it is enabled.
- Synthetic records are explicitly marked with `IS_SYNTHETIC`; use `CORE.LIVE_FLOW_FEATURES` and `CORE.LIVE_NIDS_ALERTS` for real-traffic reporting.
- The default SOAR response creates a `/32` ingress deny rule in the managed rule range and records a TTL tag. Review rule ranges, NACL placement, and emergency rollback procedures before production use.
- This is an engineering and research implementation, not a certified replacement for a production IDS, SIEM, or incident-response process.

## Known boundaries

- The local dashboard is a Streamlit application; cloud UI deployment is environment-specific.
- Snowflake procedures run on a schedule and are not a per-packet intrusion-prevention function.
- The model is trained from NSL-KDD-compatible data; traffic distributions, protocols, and threats change over time. Monitor drift and validate against representative local traffic.
- Firehose provisioning and VPC Flow Logs delivery are deployment prerequisites, not fully automated by the Python package.
- CI/CD, production change automation, and a full SIEM integration are outside the current documented scope.
