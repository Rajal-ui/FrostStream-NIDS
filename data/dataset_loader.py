import os
import pandas as pd
import numpy as np

# NSL-KDD Feature Names (41 traffic features + label + difficulty)
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Standard 5-class categorization mapping for NSL-KDD
ATTACK_MAPPING = {
    'normal': 'Normal',
    
    # DoS Attacks
    'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS', 
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 
    'processtable': 'DoS', 'udpstorm': 'DoS',
    
    # Probe Attacks
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
    'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    
    # R2L (Remote to Local)
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 
    'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 
    'warezmaster': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 
    'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 
    'xsnoop': 'R2L', 'worm': 'R2L',
    
    # U2R (User to Root)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 
    'rootkit': 'U2R', 'httptunnel': 'U2R', 'ps': 'U2R', 
    'sqlattack': 'U2R', 'xterm': 'U2R'
}

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
NUMERIC_COLS = [c for c in COLUMN_NAMES if c not in CATEGORICAL_COLS + ['label', 'difficulty']]

def map_label_to_macro(label: str) -> str:
    """Map raw NSL-KDD sub-attack label to macro class (Normal, DoS, Probe, R2L, U2R)."""
    clean_label = str(label).strip().lower().rstrip('.')
    return ATTACK_MAPPING.get(clean_label, 'Normal')

def generate_nsl_kdd_dataset(num_samples: int = 5000, random_state: int = 42) -> pd.DataFrame:
    """
    Generate realistic synthetic NSL-KDD dataset matching feature distributions,
    protocols, services, flags, and attack category ratios.
    """
    np.random.seed(random_state)
    
    # Target proportions: Normal ~53%, DoS ~30%, Probe ~12%, R2L ~4%, U2R ~1%
    raw_attacks = np.random.choice(
        ['normal', 'neptune', 'satan', 'guess_passwd', 'buffer_overflow'],
        size=num_samples,
        p=[0.53, 0.30, 0.12, 0.04, 0.01]
    )
    
    # Guarantee at least 5 samples per class for small sample sizes
    attack_types = list(raw_attacks)
    guaranteed = ['normal', 'neptune', 'satan', 'guess_passwd', 'buffer_overflow'] * 3
    for i, g in enumerate(guaranteed):
        if i < len(attack_types):
            attack_types[i] = g

    
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'private', 'smtp', 'ftp_data', 'domain_u', 'other', 'dns', 'telnet', 'ftp', 'ecr_i']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'S2']
    
    data = []
    for attack in attack_types:
        if attack == 'normal':
            proto = np.random.choice(protocols, p=[0.8, 0.15, 0.05])
            srv = 'http' if proto == 'tcp' and np.random.rand() > 0.3 else np.random.choice(services)
            flg = 'SF' if np.random.rand() > 0.05 else np.random.choice(flags)
            dur = int(np.random.exponential(scale=2.0))
            src_bytes = int(np.random.normal(loc=250, scale=80))
            dst_bytes = int(np.random.normal(loc=1200, scale=400))
            count = int(np.random.randint(1, 10))
            srv_count = count
            serror_rate = 0.0
            rerror_rate = 0.0
            num_failed_logins = 0
            root_shell = 0
        elif attack == 'neptune': # DoS
            proto = 'tcp'
            srv = np.random.choice(['private', 'http', 'other'])
            flg = 'S0'
            dur = 0
            src_bytes = 0
            dst_bytes = 0
            count = int(np.random.normal(loc=250, scale=50))
            srv_count = count
            serror_rate = float(np.random.uniform(0.9, 1.0))
            rerror_rate = 0.0
            num_failed_logins = 0
            root_shell = 0
        elif attack == 'satan': # Probe
            proto = np.random.choice(['tcp', 'udp', 'icmp'])
            srv = np.random.choice(services)
            flg = np.random.choice(['REJ', 'RSTO', 'S0'])
            dur = 0
            src_bytes = int(np.random.randint(0, 10))
            dst_bytes = int(np.random.randint(0, 10))
            count = int(np.random.normal(loc=120, scale=30))
            srv_count = int(count * 0.1)
            serror_rate = 0.0
            rerror_rate = float(np.random.uniform(0.7, 1.0))
            num_failed_logins = 0
            root_shell = 0
        elif attack == 'guess_passwd': # R2L
            proto = 'tcp'
            srv = np.random.choice(['telnet', 'ftp', 'smtp'])
            flg = 'SF'
            dur = int(np.random.randint(1, 20))
            src_bytes = int(np.random.normal(loc=180, scale=30))
            dst_bytes = int(np.random.normal(loc=300, scale=50))
            count = 1
            srv_count = 1
            serror_rate = 0.0
            rerror_rate = 0.0
            num_failed_logins = int(np.random.randint(3, 10))
            root_shell = 0
        else: # U2R (buffer_overflow)
            proto = 'tcp'
            srv = np.random.choice(['telnet', 'ftp'])
            flg = 'SF'
            dur = int(np.random.randint(5, 50))
            src_bytes = int(np.random.normal(loc=1500, scale=200))
            dst_bytes = int(np.random.normal(loc=2000, scale=300))
            count = 1
            srv_count = 1
            serror_rate = 0.0
            rerror_rate = 0.0
            num_failed_logins = 0
            root_shell = 1

        row = {
            'duration': max(0, dur),
            'protocol_type': proto,
            'service': srv,
            'flag': flg,
            'src_bytes': max(0, src_bytes),
            'dst_bytes': max(0, dst_bytes),
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': int(np.random.choice([0, 1, 2], p=[0.9, 0.08, 0.02])),
            'num_failed_logins': num_failed_logins,
            'logged_in': 1 if attack in ['normal', 'guess_passwd', 'buffer_overflow'] else 0,
            'num_compromised': 1 if attack == 'buffer_overflow' else 0,
            'root_shell': root_shell,
            'su_attempted': 0,
            'num_root': 1 if attack == 'buffer_overflow' else 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 1 if attack == 'guess_passwd' else 0,
            'count': max(1, count),
            'srv_count': max(1, srv_count),
            'serror_rate': np.clip(serror_rate, 0.0, 1.0),
            'srv_serror_rate': np.clip(serror_rate, 0.0, 1.0),
            'rerror_rate': np.clip(rerror_rate, 0.0, 1.0),
            'srv_rerror_rate': np.clip(rerror_rate, 0.0, 1.0),
            'same_srv_rate': np.clip(srv_count / max(1, count), 0.0, 1.0),
            'diff_srv_rate': np.clip(1.0 - (srv_count / max(1, count)), 0.0, 1.0),
            'srv_diff_host_rate': float(np.random.uniform(0, 0.5)),
            'dst_host_count': int(np.random.randint(1, 255)),
            'dst_host_srv_count': int(np.random.randint(1, 255)),
            'dst_host_same_srv_rate': float(np.random.uniform(0.1, 1.0)),
            'dst_host_diff_srv_rate': float(np.random.uniform(0.0, 0.5)),
            'dst_host_same_src_port_rate': float(np.random.uniform(0.0, 1.0)),
            'dst_host_srv_diff_host_rate': float(np.random.uniform(0.0, 0.2)),
            'dst_host_serror_rate': np.clip(serror_rate, 0.0, 1.0),
            'dst_host_srv_serror_rate': np.clip(serror_rate, 0.0, 1.0),
            'dst_host_rerror_rate': np.clip(rerror_rate, 0.0, 1.0),
            'dst_host_srv_rerror_rate': np.clip(rerror_rate, 0.0, 1.0),
            'label': attack,
            'difficulty': 21
        }
        data.append(row)
        
    df = pd.DataFrame(data)
    df['attack_category'] = df['label'].apply(map_label_to_macro)
    return df

def load_or_create_dataset(file_path: str = None, sample_size: int = 5000) -> pd.DataFrame:
    """Load existing NSL-KDD CSV or generate sample dataset if missing."""
    if file_path and os.path.exists(file_path):
        df = pd.read_csv(file_path, names=COLUMN_NAMES if not file_path.endswith('.csv') else None)
        if 'attack_category' not in df.columns:
            if 'label' in df.columns:
                df['attack_category'] = df['label'].apply(map_label_to_macro)
            else:
                df['attack_category'] = 'Normal'
        return df
    
    # Generate high-quality realistic dataset
    return generate_nsl_kdd_dataset(num_samples=sample_size)
