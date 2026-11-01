#!/bin/sh
#
# Installs the M1.5 hooks outside the repository and prints the Claude Code
# user-settings block that runs them, with the binary's and the script's
# sha256 pinned (NOTES design m1.5-structure, section 1). Changes no settings
# file: the block is pasted by hand.
#
#   scripts/dogfood/install.sh BELAY_BINARY REPOSITORY
#
# BELAY_BINARY is the release binary (installed as ~/.local/bin/belay);
# REPOSITORY is the scope the hooks watch (this repo).

set -eu
BIN=$1
REPO=$(cd "$2" && pwd -P)
DEST=$HOME/.local/share/belay/dogfood
mkdir -p "$DEST" "$HOME/.local/bin"
install -m 0755 scripts/dogfood/belay-dogfood "$DEST/belay-dogfood"
install -m 0644 scripts/dogfood/receipt.py "$DEST/receipt.py"
[ "$BIN" -ef "$HOME/.local/bin/belay" ] || install -m 0755 "$BIN" "$HOME/.local/bin/belay"
bsha=$(sha256sum "$HOME/.local/bin/belay" | cut -d' ' -f1)
hsha=$(sha256sum "$DEST/belay-dogfood" | cut -d' ' -f1)
rsha=$(sha256sum "$DEST/receipt.py" | cut -d' ' -f1)
# The command checks all three files before it runs anything: a changed
# binary or script makes the hook fail (non-blocking) instead of reviewing.
cmd() {
    printf 'cd / && printf \\"%s  %s\\\\n%s  %s\\\\n%s  %s\\\\n\\" | sha256sum -c --status && BELAY_DOGFOOD_SCOPE=%s %s %s' \
        "$bsha" "$HOME/.local/bin/belay" "$hsha" "$DEST/belay-dogfood" "$rsha" "$DEST/receipt.py" \
        "$REPO" "$DEST/belay-dogfood" "$1"
}
W='Bash|Edit|Write|NotebookEdit|Agent|mcp__.*'
cat <<JSON
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "$(cmd start)"}]}],
    "PreToolUse":   [{"matcher": "$W", "hooks": [{"type": "command", "command": "$(cmd pre)"}]}],
    "PostToolUse":  [{"matcher": "$W", "hooks": [{"type": "command", "command": "$(cmd post)"}]}],
    "PostToolUseFailure": [{"matcher": "$W", "hooks": [{"type": "command", "command": "$(cmd post)"}]}],
    "Stop":         [{"hooks": [{"type": "command", "command": "$(cmd stop)"}]}],
    "SessionEnd":   [{"hooks": [{"type": "command", "command": "$(cmd end)", "timeout": 10}]}]
  }
}
JSON
echo "installed: $DEST (belay sha256 $bsha)" >&2
