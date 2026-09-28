"""Spec F §3.3: the chain gate. A malicious verdict stands only when the model quoted a chain the shown code
contains. Pure: it reads the verdict's quotes and `shown` (the lines the model was shown), never package bytes, and
never runs or fetches anything."""

SOURCE_KINDS = ("secret-read", "payload", "fetch", "none")
SINK_KINDS = ("send", "exec", "write-and-run", "none")
QUOTE_MAX = 2_000
