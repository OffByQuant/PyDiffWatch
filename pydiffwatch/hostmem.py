"""Memory pressure on this machine, for a model server running here. Standard library only: a supply-chain
scanner shouldn't take on a dependency (psutil) for this. macOS: sysctlbyname via libc (ctypes; the package
never starts a subprocess). Linux: /proc."""
import ctypes
import ctypes.util
import ipaddress
import logging
import platform
import re
import struct
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _sysctl(name):
    """Raw bytes of a macOS sysctl, read through libc's sysctlbyname."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    size = ctypes.c_size_t(0)
    if libc.sysctlbyname(name.encode(), None, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), f"sysctlbyname({name})")
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctlbyname(name.encode(), buf, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), f"sysctlbyname({name})")
    return buf.raw[:size.value]


def _read(path):
    with open(path) as f:
        return f.read()


class HostMemory:
    def __init__(self, max_swap_used_pct, *, system=None, sysctl=_sysctl, read=_read):
        self.max_swap = max_swap_used_pct
        self.system = system or platform.system()
        self.sysctl, self.read = sysctl, read
        self._noticed = False

    def pressure(self):
        """A short reason when this machine is short on memory, else None."""
        try:
            if self.system == "Darwin":
                return self._darwin()
            if self.system == "Linux":
                return self._linux()
        except (OSError, ValueError, struct.error) as e:
            logger.warning("host memory check failed: %s", e)
            return None
        if not self._noticed:
            logger.warning("host memory guard is not supported on %s; it is inactive", self.system)
            self._noticed = True
        return None

    def _darwin(self):
        # vm.swapusage is struct xsw_usage { u64 total, avail, used; ... }
        total, _avail, used = struct.unpack_from("<QQQ", self.sysctl("vm.swapusage"))
        if total and 100 * used / total >= self.max_swap:
            return f"swap {100 * used / total:.0f}% used"
        level = struct.unpack_from("<i", self.sysctl("kern.memorystatus_vm_pressure_level"))[0]
        return f"OS memory pressure level {level}" if level >= 2 else None

    def _linux(self):
        info = {k.strip(): int(v.split()[0]) for k, v in
                (line.split(":", 1) for line in self.read("/proc/meminfo").splitlines() if ":" in line)}
        st, sf = info.get("SwapTotal", 0), info.get("SwapFree", 0)
        if st and 100 * (st - sf) / st >= self.max_swap:
            return f"swap {100 * (st - sf) / st:.0f}% used"
        if info.get("MemTotal") and info.get("MemAvailable", 0) < 0.10 * info["MemTotal"]:
            return f"available memory {100 * info['MemAvailable'] / info['MemTotal']:.0f}%"
        try:
            some = self.read("/proc/pressure/memory").splitlines()[0]
        except OSError:
            return None
        avg10 = float(re.search(r"avg10=([\d.]+)", some).group(1))
        return f"memory pressure (PSI some avg10={avg10:.1f})" if avg10 >= 10 else None


def is_loopback(base_url):
    host = urlsplit(base_url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def for_config(cfg):
    """The HostMemory to consult for this reviewer, or None when the model isn't on this machine."""
    rc = cfg.reviewer
    on = rc.host_memory_guard
    if on == "auto":
        on = rc.provider == "openai" and is_loopback(rc.base_url)
    return HostMemory(rc.max_swap_used_pct) if on is True else None
