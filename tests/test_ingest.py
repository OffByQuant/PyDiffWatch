from pydiffwatch import ingest
from pydiffwatch.config import Config

class FakeProxy:
    def __init__(self, rows): self._rows = rows
    def changelog_since_serial(self, since): return [r for r in self._rows if r[4] > since]

def test_filters_and_sorts(monkeypatch):
    rows = [
        ("a", "1.0", 0, "new release", 10),
        ("a", "1.0", 0, "add py3 file a-1.0.tar.gz", 11),   # ignored: not "new release"
        ("b", "2.0", 0, "new release", 9),
        ("a", "1.0", 0, "new release", 12),                 # dup (a,1.0) -> keep max serial
    ]
    monkeypatch.setattr(ingest.xmlrpc.client, "ServerProxy", lambda url: FakeProxy(rows))
    out = ingest.changes_since(Config(), since_serial=0)
    assert [(r.package, r.version, r.serial) for r in out] == [("b", "2.0", 9), ("a", "1.0", 12)]

def test_transport_error_returns_empty(monkeypatch):
    def boom(url): raise OSError("blocked")
    monkeypatch.setattr(ingest.xmlrpc.client, "ServerProxy", boom)
    assert ingest.changes_since(Config(), since_serial=5) == []
