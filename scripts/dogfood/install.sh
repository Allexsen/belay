#!/bin/sh
#
# Installs the M1.5 hooks outside the repository, writes the Claude Code
# settings that run them -- the binary's and the scripts' sha256 pinned (NOTES
# design m1.5-structure, section 1) -- to settings-hooks.json beside them, and
# prints the one command that merges those into ~/.claude/settings.json after
# a backup (decision 115). It changes no settings file itself.
#
#   scripts/dogfood/install.sh BELAY_BINARY REPOSITORY
#
# BELAY_BINARY is the release binary (installed as ~/.local/bin/belay);
# REPOSITORY is the scope the hooks watch (this repo). Standard output is the
# merge command and nothing else; the rest goes to standard error. Linux only,
# for now. The commands it writes time a failure as the hook does (decision
# 131): `date +%s%N` where it prints only digits, else python3's clock, else
# the seconds padded.

set -eu
BIN=$1
REPO=$(cd "$2" && pwd -P)
DEST=$HOME/.local/share/belay/dogfood
command -v jq >/dev/null || { echo "install.sh: jq is needed (the hooks use it too)" >&2; exit 1; }
mkdir -p "$DEST" "$HOME/.local/bin"
install -m 0755 scripts/dogfood/belay-dogfood "$DEST/belay-dogfood"
install -m 0644 scripts/dogfood/receipt.py "$DEST/receipt.py"
[ "$BIN" -ef "$HOME/.local/bin/belay" ] || install -m 0755 "$BIN" "$HOME/.local/bin/belay"
bsha=$(sha256sum "$HOME/.local/bin/belay" | cut -d' ' -f1)
hsha=$(sha256sum "$DEST/belay-dogfood" | cut -d' ' -f1)
rsha=$(sha256sum "$DEST/receipt.py" | cut -d' ' -f1)
sums="$bsha  $HOME/.local/bin/belay
$hsha  $DEST/belay-dogfood
$rsha  $DEST/receipt.py"

# Each command checks all three files before it runs anything: a changed
# binary or script makes the hook do nothing instead of reviewing. Never in
# silence (decision 114): every hook then records when it was inactive, in the
# file the hook keeps its failures in (the receipt labels what changed
# meanwhile unattributed, decision 122), and the Stop hook says so, naming
# the files, every Stop until this is run again.
cmd() {
    rec="d=\"\${BELAY_STATE_DIR:-\${XDG_STATE_HOME:-\$HOME/.local/state}/belay}/dogfood\"; t=\$(date +%s%N 2>/dev/null); case \$t in ''|*[!0-9]*) t=\$(python3 -I -c 'import time; print(time.time_ns())' 2>/dev/null) ;; esac; case \$t in ''|*[!0-9]*) t=\$(date +%s)000000000 ;; esac; mkdir -p \"\$d\" && printf '%s\t$1: checksum mismatch (hooks inactive)\n' \"\$t\" >> \"\$d/failing\""
    if [ "$1" = stop ]; then
        cat <<EOF
cd / && s='$sums'; if printf '%s\n' "\$s" | sha256sum -c --status 2>/dev/null; then BELAY_DOGFOOD_SCOPE='$REPO' '$DEST/belay-dogfood' stop; else $rec; printf '{"systemMessage":"belay: hooks inactive: checksum mismatch: %s-- run scripts/dogfood/install.sh"}\n' "\$(printf '%s\n' "\$s" | sha256sum -c 2>/dev/null | sed -n 's/: FAILED.*/ /p' | tr -d '\n"\\\\')"; fi
EOF
    else
        cat <<EOF
cd / && s='$sums'; if printf '%s\n' "\$s" | sha256sum -c --status 2>/dev/null; then BELAY_DOGFOOD_SCOPE='$REPO' '$DEST/belay-dogfood' $1; else $rec; fi
EOF
    fi
}
W='Bash|Edit|Write|NotebookEdit|Agent|mcp__.*'
jq -n --arg w "$W" --arg start "$(cmd start)" --arg pre "$(cmd pre)" --arg post "$(cmd post)" \
      --arg batch "$(cmd batch)" --arg prompt "$(cmd prompt)" \
      --arg stop "$(cmd stop)" --arg end "$(cmd end)" '
  def h($c): [{"type": "command", "command": $c}];
  {"hooks": {
     "SessionStart":       [{"hooks": h($start)}],
     "PreToolUse":         [{"matcher": $w, "hooks": h($pre)}],
     "PostToolUse":        [{"matcher": $w, "hooks": h($post)}],
     "PostToolUseFailure": [{"matcher": $w, "hooks": h($post)}],
     "PostToolBatch":      [{"hooks": h($batch)}],
     "UserPromptSubmit":   [{"hooks": h($prompt)}],
     "Stop":               [{"hooks": h($stop)}],
     "SessionEnd":         [{"hooks": [{"type": "command", "command": $end, "timeout": 10}]}]}}' \
    > "$DEST/settings-hooks.json"

# The merge: settings.json's own keys and other hooks kept, every earlier
# belay-dogfood hook replaced by these.
cat > "$DEST/merge.jq" <<'EOF'
.[0] as $s | .[1].hooks as $b
| $s + {"hooks": (reduce ($b | keys_unsorted[]) as $k (($s.hooks // {});
    .[$k] = ([(.[$k] // [])[] | select([.hooks[]?.command // ""] | any(test("belay-dogfood")) | not)]
             + $b[$k])))}
EOF
S=$HOME/.claude/settings.json
echo "installed: $DEST (belay sha256 $bsha); settings: $DEST/settings-hooks.json" >&2
echo "to enable them, run (it backs up $S first, under a name of its own each time):" >&2
printf '%s\n' "mkdir -p '$HOME/.claude' && { [ -f '$S' ] || echo '{}' > '$S'; } && b='$S.bak-'\$(date +%Y%m%dT%H%M%S%N) && cp -p '$S' \"\$b\" && jq -s -f '$DEST/merge.jq' '$S' '$DEST/settings-hooks.json' > '$S.new' && mv '$S.new' '$S' && echo \"belay hooks merged; backup: \$b\""
