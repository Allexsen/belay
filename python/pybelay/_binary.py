"""The vendored binary (PY-D4, PY-D5): its path, checked once per process
against the digest recorded when the wheel was built. No environment variable
or argument selects another."""
import hashlib
import os
import threading

from ._errors import BinaryMismatch

_HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_bin")
_lock = threading.Lock()
_checked = None


def binary_path():
    """The vendored binary's path: for an orchestrator to copy into a sandbox
    (in-sandbox mode)."""
    return os.path.join(_HERE, "belay")


def checked_binary():
    """The binary, after its digest was checked (once per process)."""
    global _checked
    with _lock:
        if _checked is None:
            path = binary_path()
            try:
                with open(os.path.join(_HERE, "SHA256"), encoding="ascii") as f:
                    want = f.read().strip()
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
            except OSError as e:
                raise BinaryMismatch("the vendored belay binary cannot be read: %s" % e) from None
            if len(want) != 64 or h.hexdigest() != want:
                raise BinaryMismatch("the vendored belay binary hashes to %s, not the recorded %s: nothing runs"
                                     % (h.hexdigest(), want))
            _checked = path
        return _checked
