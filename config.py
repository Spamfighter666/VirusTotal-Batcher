"""Default data directory for the interactive tools."""

import os
from pathlib import Path

home_path = str(Path(os.environ.get("VTMG_HOME", Path(__file__).resolve().parent)).expanduser())
server_friendly = "yes" if "VTMG_HOME" in os.environ else "no"
