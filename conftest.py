# Ensures `lab` and `payloads` are importable when pytest is run from any cwd.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
