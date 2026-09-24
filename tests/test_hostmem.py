# tests/test_hostmem.py
import dataclasses
import struct

from pydiffwatch import hostmem
from pydiffwatch.config import Config


def _swap(total_mb, used_mb):
    # struct xsw_usage { u64 total, avail, used; u32 pagesize; i32 encrypted } as sysctlbyname returns it
    mb = 2 ** 20
    return struct.pack("<QQQIi", int(total_mb * mb), int((total_mb - used_mb) * mb), int(used_mb * mb), 16384, 1)


def _darwin(swap, level=1):
    vals = {"vm.swapusage": swap, "kern.memorystatus_vm_pressure_level": struct.pack("<i", level)}
    return hostmem.HostMemory(75, system="Darwin", sysctl=lambda name: vals[name])


def test_macos_swap_over_threshold():
    # the reading at the time of last night's kill
    hm = _darwin(_swap(9216.00, 7672.56))
    assert hm.pressure() == "swap 83% used"


def test_macos_pressure_level():
    assert _darwin(_swap(9216, 100), level=4).pressure() == "OS memory pressure level 4"
    assert _darwin(_swap(9216, 100)).pressure() is None


def test_macos_no_swap_configured():
    assert _darwin(_swap(0, 0)).pressure() is None


def _linux(meminfo, psi=None):
    files = {"/proc/meminfo": meminfo}
    if psi is not None:
        files["/proc/pressure/memory"] = psi

    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]
    return hostmem.HostMemory(75, system="Linux", read=read)


_OK = "MemTotal: 100000 kB\nMemAvailable: 50000 kB\nSwapTotal: 1000 kB\nSwapFree: 900 kB\n"


def test_linux_checks():
    assert _linux(_OK).pressure() is None
    assert _linux("MemTotal: 100000 kB\nMemAvailable: 5000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").pressure() == "available memory 5%"
    assert _linux("MemTotal: 100000 kB\nMemAvailable: 50000 kB\nSwapTotal: 1000 kB\nSwapFree: 100 kB\n").pressure() == "swap 90% used"
    assert _linux(_OK, "some avg10=12.50 avg60=3.00 avg300=1.00 total=1\n").pressure() == "memory pressure (PSI some avg10=12.5)"


def test_unsupported_platform_is_inactive_not_an_error():
    hm = hostmem.HostMemory(75, system="Windows")
    assert hm.pressure() is None and hm.pressure() is None


def test_for_config_auto_only_for_loopback():
    base = Config()

    def at(url, **kw):
        return dataclasses.replace(base, reviewer=dataclasses.replace(base.reviewer, base_url=url, **kw))
    assert hostmem.for_config(at("http://127.0.0.1:8000/v1")) is not None
    assert hostmem.for_config(at("http://localhost:8000/v1")) is not None
    assert hostmem.for_config(at("http://192.0.2.10:8000/v1")) is None
    assert hostmem.for_config(at("http://192.0.2.10:8000/v1", host_memory_guard=True)) is not None
    assert hostmem.for_config(at("http://127.0.0.1:8000/v1", host_memory_guard=False)) is None
