"""FrostStream NIDS - Security Operations Center (SOC) Command Center
Phase 6: Ultra High-Fidelity Cyber Defense Dashboard (Root Application Entrypoint)

Runs the consolidated Fortexa-style cyber SOC Command Center.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import and execute the dashboard module directly
from streamlit_app import sis_dashboard

sis_dashboard.main()
