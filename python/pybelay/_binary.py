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


def _check(path, digest_file, what):
    try:
        with open(digest_file, encoding="ascii") as f:
            want = f.read().strip()
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        raise BinaryMismatch("%s cannot be read: %s" % (what, e)) from None
    if len(want) != 64 or h.hexdigest() != want:
        raise BinaryMismatch("%s hashes to %s, not the recorded %s: nothing runs" % (what, h.hexdigest(), want))


def checked_binary():
    """The binary, after its digest was checked (once per process)."""
    global _checked
    with _lock:
        if _checked is None:
            path = binary_path()
            _check(path, os.path.join(_HERE, "SHA256"), "the vendored belay binary")
            _checked = path
        return _checked


def carried_binary(arch):
    """A Linux binary a macOS wheel carries for sandboxes (PY-D4), after its
    digest was checked, or None. `arch` is x86_64 or arm64, as release assets
    name them. Never run on this machine."""
    path = os.path.join(_HERE, "linux-" + arch)
    if not os.path.exists(path):
        return None
    _check(path, path + ".sha256", "the carried belay binary for Linux %s" % arch)
    return path
