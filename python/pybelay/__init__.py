"""pybelay: belay from Python (test/expect/pybelay.md).

Each call runs the vendored binary once, with an argument list (never a
shell), and parses its output strictly by the pinned formats: a key missing
or one not known is a FormatError. Paths come back as str, decoded as
os.fsdecode decodes them; a `*_b64` key is decoded into its plain name.
"""
import base64
import dataclasses
import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ._binary import binary_path, checked_binary
from ._errors import BelayError, BinaryMismatch, Failed, FormatError, Refused, UsageError

__all__ = ["check", "mark", "log", "diff", "baseline_export", "verify", "binary_path",
           "Checkpoint", "Prefilter", "Diff", "DiffRecord", "DiffEvent", "Baseline", "Policy", "Flag",
           "BelayError", "UsageError", "Refused", "Failed", "FormatError", "BinaryMismatch"]

_KEYS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_keys.json")


def _keys() -> Dict[str, Any]:
    try:
        with open(_KEYS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise FormatError("pybelay's key sets cannot be read: %s" % e) from None


# ---- running the binary ----

def _run(args: List[str]) -> Tuple[List[dict], int]:
    b = checked_binary()
    r = subprocess.run([b] + args, capture_output=True)
    return _parsed(r.stdout, r.returncode, r.stderr.decode("utf-8", "replace"))


def _parsed(stdout: bytes, code: int, err: str) -> Tuple[List[dict], int]:
    """A run's result, wherever it ran: its lines, or the error its exit code means."""
    if code == 2:
        raise UsageError(err.strip() or "usage", 2, err)
    if code == 3:
        raise Refused(err.strip() or "refused", 3, err)
    if code == 4:
        raise Failed(err.strip() or "failed", 4, err)
    if code not in (0, 1):
        raise FormatError("belay exited %d, which the CLI does not document" % code, code, err)
    lines = []
    for raw in stdout.splitlines():
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            raise FormatError("a line that is not JSON: %r" % raw[:200], code, err) from None
        if not isinstance(obj, dict):
            raise FormatError("a line that is not a JSON object", code, err)
        lines.append(obj)
    return lines, code


def _p(x) -> str:
    return os.fspath(x) if not isinstance(x, str) else x


def _decode_b64(obj: dict) -> dict:
    """`k_b64` decoded into `k` (os.fsdecode), never both."""
    out = {}
    for k, v in obj.items():
        if k.endswith("_b64"):
            plain = k[:-4]
            if plain in obj:
                raise FormatError("both %s and %s" % (plain, k))
            dec = lambda s: os.fsdecode(base64.b64decode(s, validate=True))
            out[plain] = [dec(s) for s in v] if isinstance(v, list) else dec(v)
        else:
            out[k] = v
    return out


def _exact(obj: dict, want: List[str], what: str) -> None:
    """The key set and order a fixed line has; `k_b64` stands for `k`."""
    norm = lambda ks: [k[:-4] if k.endswith("_b64") else k for k in ks]
    if norm(obj) != norm(want):
        raise FormatError("%s keys %s, expected %s" % (what, list(obj), want))


# ---- results ----

@dataclasses.dataclass(frozen=True)
class Prefilter:
    used: bool
    reference: str
    trusted: int
    racy: int
    full_reason: str


@dataclasses.dataclass(frozen=True)
class Checkpoint:
    """checkpoint.v2 (PY-R1)."""
    id: int
    kind: str
    created_ns: int
    scope: str
    manifest: Optional[str]         # None for a checkpoint stored as a delta (C2-2)
    entries: int
    raced: int
    unstable: int
    vanished: int
    provisional: bool
    excluded: int
    excluded_paths: Tuple[dict, ...]
    prefilter: Prefilter
    stored: str                     # "whole" or "delta" (C2-3)
    kept: bool                      # C2-4
    source: Optional[dict]          # checkpoint.v1 CK-16: None, or {"docker": ..., "image": ...}


def _checkpoint(obj: dict) -> Checkpoint:
    _exact(obj, _keys()["checkpoint"], "checkpoint")
    o = _decode_b64(obj)
    pf = o["prefilter"]
    if not isinstance(pf, dict):
        raise FormatError("prefilter is not an object")
    _exact(pf, _keys()["prefilter"], "prefilter")
    o["prefilter"] = Prefilter(**pf)
    o["excluded_paths"] = tuple(_decode_b64(x) for x in o["excluded_paths"])
    return Checkpoint(**o)


@dataclasses.dataclass(frozen=True)
class DiffRecord:
    """One path's record (PY-R2): diff.v1's record keys; `findings` as dicts."""
    path: str
    outcome: str
    type: str
    type_before: Optional[str] = None
    changed: Optional[Tuple[str, ...]] = None
    before: Optional[dict] = None
    after: Optional[dict] = None
    unknown: Optional[Tuple[str, ...]] = None
    findings: Tuple[dict, ...] = ()


@dataclasses.dataclass(frozen=True)
class DiffEvent:
    """An event record: its kind, its fields as a dict."""
    event: str
    interp: str
    text: str
    paths: Tuple[str, ...]
    provisional: bool = False
    fields: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Diff:
    header: Dict[str, Any]
    records: Tuple[DiffRecord, ...]
    events: Tuple[DiffEvent, ...]
    trailer: Dict[str, Any]


_RECORD = {f.name for f in dataclasses.fields(DiffRecord)}


def _event(o: dict) -> DiffEvent:
    for k in ("event", "interp", "text"):
        if not isinstance(o.get(k), str):
            raise FormatError("an event without %s" % k)
    fixed = {"event", "interp", "text", "paths", "provisional"}
    return DiffEvent(o["event"], o["interp"], o["text"], tuple(o.get("paths", ())), bool(o.get("provisional", False)),
                     {k: v for k, v in o.items() if k not in fixed})


def _diff(lines: List[dict]) -> Diff:
    k = _keys()
    if len(lines) < 2:
        raise FormatError("a diff without its header and trailer")
    _exact(lines[0], k["diff_header"], "diff header")
    _exact(lines[-1], k["diff_trailer"], "diff trailer")
    recs, evs = [], []
    for raw in lines[1:-1]:
        o = _decode_b64(raw)
        if "event" in o:
            evs.append(_event(o))
            continue
        extra = set(o) - _RECORD
        if extra or not {"path", "outcome", "type"} <= set(o):
            raise FormatError("a diff record with keys %s" % sorted(o))
        for t in ("changed", "unknown", "findings"):
            if t in o:
                o[t] = tuple(o[t])
        recs.append(DiffRecord(**o))
    return Diff(_decode_b64(lines[0]), tuple(recs), tuple(evs), lines[-1])


@dataclasses.dataclass(frozen=True)
class Baseline:
    """baseline export's result (PY-R3, B-R4)."""
    bundle: str
    sha256: str
    baseline_integrity: Tuple[dict, ...]


@dataclasses.dataclass(frozen=True)
class Flag:
    """A policy.v1 flag record (PY-R4, P-F1): its kind's own fields in `fields`."""
    flag: str
    level: str
    text: str
    provisional: bool
    paths: Tuple[str, ...]
    fields: Dict[str, Any]


@dataclasses.dataclass(frozen=True)
class Policy:
    header: Dict[str, Any]
    flags: Tuple[Flag, ...]
    trailer: Dict[str, Any]

    @property
    def violations(self) -> int:
        return self.trailer["violations"]

    @property
    def signals(self) -> int:
        return self.trailer["signals"]

    def lines(self) -> List[dict]:
        """The policy as its JSON lines: header, flags, trailer."""
        out = [dict(self.header)]
        for f in self.flags:
            d = {"flag": f.flag, "level": f.level}
            d.update(f.fields)
            d["text"] = f.text
            if f.provisional:
                d["provisional"] = True
            d["paths"] = list(f.paths)
            out.append(d)
        out.append(dict(self.trailer))
        return out


def _policy(lines: List[dict]) -> Policy:
    k = _keys()
    if len(lines) < 2:
        raise FormatError("a policy without its header and trailer")
    _exact(lines[0], k["policy_header"], "policy header")
    _exact(lines[-1], k["policy_trailer"], "policy trailer")
    flags = []
    for raw in lines[1:-1]:
        o = _decode_b64(raw)
        if not isinstance(o.get("flag"), str) or o.get("level") not in ("violation", "signal") or \
                not isinstance(o.get("text"), str):
            raise FormatError("a flag record with keys %s" % sorted(o))
        fixed = {"flag", "level", "text", "provisional", "paths"}
        flags.append(Flag(o["flag"], o["level"], o["text"], bool(o.get("provisional", False)),
                          tuple(o.get("paths", ())), {x: v for x, v in o.items() if x not in fixed}))
    return Policy(_decode_b64(lines[0]), tuple(flags), lines[-1])


# ---- the calls (PY-F1..PY-F6) ----

def _scope(scope, docker) -> List[str]:
    a = ["--scope", _p(scope)]
    if docker is not None:
        a += ["--docker", docker]
    return a


def check(scope, *, docker: Optional[str] = None) -> Checkpoint:
    lines, _ = _run(["check"] + _scope(scope, docker) + ["--json"])
    if len(lines) != 1:
        raise FormatError("check printed %d lines" % len(lines))
    return _checkpoint(lines[0])


def mark(scope, *, docker: Optional[str] = None, full: bool = False, full_every: Optional[int] = None) -> Checkpoint:
    a = ["mark"] + _scope(scope, docker) + ["--json"]
    if full:
        a.append("--full")
    if full_every is not None:
        a += ["--full-every", str(int(full_every))]
    lines, _ = _run(a)
    if len(lines) != 1:
        raise FormatError("mark printed %d lines" % len(lines))
    return _checkpoint(lines[0])


def log(scope, *, docker: Optional[str] = None) -> List[Checkpoint]:
    lines, _ = _run(["log"] + _scope(scope, docker) + ["--json"])
    return [_checkpoint(o) for o in lines]


def diff(scope, since, to=None, *, docker: Optional[str] = None, all: bool = False,
         full_every: Optional[int] = None) -> Diff:
    a = ["diff"] + _scope(scope, docker) + ["--since", str(since), "--json"]
    if to is not None:
        a += ["--to", str(to)]
    if all:
        a.append("--all")
    if full_every is not None:
        a += ["--full-every", str(int(full_every))]
    lines, _ = _run(a)
    return _diff(lines)


def baseline_export(scope, out, *, protect=None, docker: Optional[str] = None) -> Baseline:
    a = ["baseline", "export"] + _scope(scope, docker) + ["--out", _p(out), "--json"]
    if protect is not None:
        a += ["--protect", _p(protect)]
    lines, _ = _run(a)
    if len(lines) != 1:
        raise FormatError("baseline export printed %d lines" % len(lines))
    _exact(lines[0], _keys()["export"], "export")
    o = _decode_b64(lines[0])
    return Baseline(o["bundle"], o["sha256"], tuple(_decode_b64(x) for x in o["baseline_integrity"]))


def verify(scope, baseline, sha256: str, *, protect=None, to=None, docker: Optional[str] = None) -> Policy:
    a = ["verify"] + _scope(scope, docker) + ["--baseline", _p(baseline), "--baseline-sha256", sha256]
    if protect is not None:
        a += ["--protect", _p(protect)]
    if to is not None:
        a += ["--to", str(to)]
    lines, _ = _run(a)
    return _policy(lines)
