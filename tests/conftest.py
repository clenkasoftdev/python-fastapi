import sys
from pathlib import Path

# Ensure project root is on sys.path so tests can import the `src` package.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
