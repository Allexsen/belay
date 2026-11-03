"""pybelay's errors (test/expect/pybelay.md, PY-E1..PY-E5). A violation is
never one: it is in the result."""


class BelayError(Exception):
    """Every error pybelay raises. `exit_code` is the binary's (None when it
    did not run); `stderr` what it said."""

    def __init__(self, message, exit_code=None, stderr=""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class UsageError(BelayError):
    """Exit 2: the call was malformed (PY-E1)."""


class Refused(BelayError):
    """Exit 3: refused -- a digest that does not match, a source that differs,
    an unsupported container, ... (PY-E2)."""


class Failed(BelayError):
    """Exit 4: failed (PY-E3)."""


class FormatError(BelayError):
    """Output a strict parse rejects, or an exit code the CLI does not
    document (PY-E4)."""


class BinaryMismatch(BelayError):
    """The vendored binary does not hash to its recorded digest (PY-E5)."""
