import numpy as np
import pandas as pd

def explain_flow_prediction(flow_dict: dict, predicted_category: str, confidence: float) -> dict:
    """
    Generate human-readable explanation and key evidence features for SOC analysts.
    """
    reasons = []

    if predicted_category == 'DoS':
        if flow_dict.get('serror_rate', 0) > 0.5:
            reasons.append(f"High SYN error rate ({flow_dict.get('serror_rate', 0):.2f}) indicating connection floods")
        if flow_dict.get('count', 0) > 100:
            reasons.append(f"Abnormally high connection count ({flow_dict.get('count', 0)}) to same host")
        if flow_dict.get('flag') == 'S0':
            reasons.append("Connection flag S0 (SYN sent, no response acknowledged)")

    elif predicted_category == 'Probe':
        if flow_dict.get('rerror_rate', 0) > 0.5:
            reasons.append(f"High REJ/RST error rate ({flow_dict.get('rerror_rate', 0):.2f}) from rejected port probes")
        if flow_dict.get('dst_host_diff_srv_rate', 0) > 0.3:
            reasons.append(f"Scanning multiple distinct services on target ({flow_dict.get('dst_host_diff_srv_rate', 0):.2f})")
        if flow_dict.get('src_bytes', 0) < 20 and flow_dict.get('dst_bytes', 0) < 20:
            reasons.append("Minimal packet payload bytes sent during port sweep")

    elif predicted_category == 'R2L':
        if flow_dict.get('num_failed_logins', 0) > 2:
            reasons.append(f"Multiple failed authentication attempts ({flow_dict.get('num_failed_logins', 0)})")
        if flow_dict.get('is_guest_login', 0) == 1:
            reasons.append("Unusual guest account privilege escalation attempt")
        if flow_dict.get('service') in ['ftp', 'telnet', 'smtp']:
            reasons.append(f"Targeting remote access service ({flow_dict.get('service')})")

    elif predicted_category == 'U2R':
        if flow_dict.get('root_shell', 0) == 1:
            reasons.append("Root shell access spawned during session")
        if flow_dict.get('num_compromised', 0) > 0:
            reasons.append("System file compromise indicator present")
        if flow_dict.get('src_bytes', 0) > 1000:
            reasons.append(f"Large payload size ({flow_dict.get('src_bytes', 0)} bytes) matching exploit buffer overflow")

    else:
        reasons.append("Traffic characteristics match standard baseline operations")

    if not reasons:
        reasons.append("Multi-feature statistical pattern matching trained decision boundaries")

    return {
        'category': predicted_category,
        'confidence_pct': round(confidence * 100.0, 1),
        'primary_reasons': reasons,
        'key_metrics': {
            'protocol': flow_dict.get('protocol_type', 'tcp'),
            'service': flow_dict.get('service', 'http'),
            'src_bytes': flow_dict.get('src_bytes', 0),
            'dst_bytes': flow_dict.get('dst_bytes', 0),
            'count': flow_dict.get('count', 1)
        }
    }
