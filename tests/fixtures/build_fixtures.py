import io, tarfile

def make_sdist(members: dict[str, bytes], top="pkg-1.0") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(f"{top}/{name}"); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()

def make_raw_member(name: str, data: bytes) -> bytes:   # no top dir; for tar-slip names
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        ti = tarfile.TarInfo(name); ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()
