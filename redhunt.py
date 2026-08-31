from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path = [entry for entry in sys.path if Path(entry or ".").resolve() != ROOT]
sys.path.insert(0, str(ROOT / "src"))

from redhunt.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
