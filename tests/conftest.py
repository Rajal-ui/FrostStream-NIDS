import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SOAR_PATH = PROJECT_ROOT / "src" / "soar"
if str(SOAR_PATH) not in sys.path:
    sys.path.insert(0, str(SOAR_PATH))
