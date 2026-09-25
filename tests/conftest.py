import sys
from pathlib import Path

SOAR_PATH = Path(__file__).parent.parent / "src" / "soar"
if str(SOAR_PATH) not in sys.path:
    sys.path.insert(0, str(SOAR_PATH))
