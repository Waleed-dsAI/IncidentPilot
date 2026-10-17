"""Isolated disposable database for each full pytest invocation."""
import os
import tempfile
from pathlib import Path
os.environ['DB_PATH']=str(Path(tempfile.mkdtemp(prefix='incidentpilot-test-'))/'testing.db')
