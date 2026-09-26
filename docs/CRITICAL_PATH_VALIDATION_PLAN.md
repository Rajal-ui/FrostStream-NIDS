# CRITICAL-Path Validation Plan (Draft — Requires Approval Before Execution)

## Objective
Deliberately generate a CRITICAL-severity alert (DoS/U2R attack pattern) against a controlled target, validate end-to-end path:
1. Flow capture → Firehose → Snowpipe → Feature extraction
2. ML inference → CRITICAL classification (confidence ≥ 0.95, DoS/U2R)
3. SOAR dispatch → NACL deny rule creation with 24h TTL
3. Dashboard reflects CRITICAL alert + active block
4. Cleanup Lambda expiry → NACL rule removal + MITIGATION_STATUS=EXPIRED

## Constraints & Safety
- **Target**: A machine I own/control (isolated test VM or dedicated interface)
- **SOAR initially suspended** (like HIGH test) — manual approval before dispatch
- **No production traffic impact** — synthetic/controlled packets only
- **Rollback**: Manual NACL rule deletion via AWS Console if needed
- **Observers**: At least one other person monitoring during execution

---

## Phase 1: Test Environment Setup

### 1.1 Target Machine
- Dedicated test VM (separate from production host)
- Known IP: e.g., `10.0.100.50` (internal) or dedicated VPC subnet
- No production services running

### 1.2 Traffic Generator
- Use `scapy` script to craft DoS/U2R pattern packets
- **DoS pattern**: High-volume SYN flood to single port (e.g., 1000+ SYN/sec to port 80)
- **U2R pattern**: Privilege escalation payload signatures (if safe) or exploit attempt patterns
- Packets injected via local interface (not replayed PCAP) to exercise live capture

### 1.3 Snowflake Prep
```sql
-- Ensure SOAR task is SUSPENDED
ALTER TASK CORE.SOAR_DISPATCH_TASK SUSPEND;

-- Verify current state
SELECT * FROM CORE.NIDS_ALERTS WHERE IS_SYNTHETIC = FALSE ORDER BY TIMESTAMP DESC LIMIT 5;
```

---

## Phase 2: Controlled Traffic Injection

### 2.1 Baseline Capture (2 min)
```bash
# Start live capture on test interface
python -m ingestion.flow_processor --sniff <test_iface> --duration 120 --mode CLOUD
```

### 2.2 Attack Traffic Injection (30 sec)
```bash
# Run DoS generator against target
python tools/generate_dos_test.py --target-ip 10.0.100.50 --duration 30 --rate 1000
```
*Script to be created: crafts TCP SYN packets at high rate to single destination port*

### 2.3 Observation Window (5 min)
- Wait for Firehose buffer (60s) + Snowpipe (typically <30s) + Inference task (1-min schedule)
- Monitor `CORE.NIDS_ALERTS` for CRITICAL entries

---

## Phase 3: Validation Checkpoints

### 3.1 Ingestion Verification
```sql
-- Raw landing
SELECT COUNT(*) FROM CORE.RAW_FLOW_LANDING WHERE INGESTION_TIMESTAMP >= DATEADD('minute', -10, CURRENT_TIMESTAMP());

-- Flattened features
SELECT COUNT(*) FROM CORE.FLOW_FEATURES WHERE CREATED_AT >= DATEADD('minute', -10, CURRENT_TIMESTAMP()) AND IS_SYNTHETIC = FALSE;
```

### 3.2 Inference Verification
```sql
-- Check for CRITICAL alerts
SELECT ALERT_ID, SRC_IP, ATTACK_TYPE, CONFIDENCE, SEVERITY, MITIGATION_STATUS
FROM CORE.NIDS_ALERTS
WHERE IS_SYNTHETIC = FALSE
  AND TIMESTAMP >= DATEADD('minute', -10, CURRENT_TIMESTAMP())
  AND SEVERITY = 'CRITICAL';
```
**Expected**: 1+ rows with `ATTACK_TYPE IN ('DoS','U2R')`, `CONFIDENCE >= 0.95`, `SEVERITY = 'CRITICAL'`

### 3.3 SOAR Dispatch (Manual Approval)
```sql
-- Resume SOAR task after confirming CRITICAL alert
ALTER TASK CORE.SOAR_DISPATCH_TASK RESUME;

-- Monitor dispatch
SELECT * FROM CORE.NIDS_ALERTS WHERE SEVERITY = 'CRITICAL' AND MITIGATION_STATUS IN ('PENDING','ACTIONED');
```

### 3.4 NACL Verification (AWS)
```bash
# Check NACL deny rule created
aws ec2 describe-network-acls --network-acl-ids acl-0dc50d7f2245eac6f \
  --query 'NetworkAcls[0].Entries[?CidrBlock==`10.0.100.50/32`]'

# Check TTL tag
aws ec2 describe-network-acls --network-acl-ids acl-0dc50d7f2245eac6f \
  --query 'NetworkAcls[0].Tags[?starts_with(Key, `FrostStream_TTL`)]'
```
**Expected**: Deny rule in range 100-199, TTL tag with expiry ~24h from now

### 3.5 Dashboard Verification
- Open SiS dashboard
- Verify CRITICAL KPI increments
- Verify Threat Stream shows CRITICAL row with SOAR pill = ACTIONED
- Verify SOAR panel shows active block with TTL countdown

---

## Phase 4: Expiry Validation (24h + Buffer)

### 4.1 Wait for Cleanup Lambda (hourly schedule)
- Or manually invoke cleanup Lambda:
```bash
aws lambda invoke --function-name froststream-soar-CleanupFunction-Ag0BxwhI9U8a --payload '{}' response.json
```

### 4.2 Post-Expiry Verification
```sql
-- Alert status updated
SELECT MITIGATION_STATUS, MITIGATED_AT, MITIGATION_DETAILS
FROM CORE.NIDS_ALERTS
WHERE ALERT_ID = '<critical_alert_id>';
```
**Expected**: `MITIGATION_STATUS = 'EXPIRED'`, `MITIGATION_DETAILS` contains `{"source":"cleanup-lambda","status":"EXPIRED"}`

```bash
# NACL rule and tag removed
aws ec2 describe-network-acls --network-acl-ids acl-0dc50d7f2245eac6f \
  --query 'NetworkAcls[0].Entries[?CidrBlock==`10.0.100.50/32`]'
aws ec2 describe-network-acls --network-acl-ids acl-0dc50d7f2245eac6f \
  --query 'NetworkAcls[0].Tags[?starts_with(Key, `FrostStream_TTL`)]'
```
**Expected**: No deny rule for test IP, no TTL tag

---

## Phase 5: Cleanup & Reporting

1. Suspend SOAR task again: `ALTER TASK CORE.SOAR_DISPATCH_TASK SUSPEND;`
2. Document all timestamps, alert IDs, NACL rule numbers
3. Compare dashboard screenshots before/during/after
4. Sign off or iterate on thresholds

---

## Approval Required

**Before execution, confirm:**
- [ ] Target machine identified and isolated
- [ ] Traffic generator script reviewed
- [ ] SOAR task will remain SUSPENDED until manual resume
- [ ] Rollback procedure documented (manual NACL delete)
- [ ] Observer assigned

**Approval**: ________________ Date: ________________

---

## Notes
- This plan only — **do not execute** without explicit approval
- The HIGH-alert test (192.168.1.34) validated the SOAR path; this extends to CRITICAL
- If CRITICAL threshold (0.95) proves unreachable with real DoS traffic, threshold tuning may be needed first