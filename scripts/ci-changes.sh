#!/bin/sh
# Prints code=false when every file changed between BASE and HEAD is prose that no
# build or test reads (test/accounting/docs-only.txt), else code=true. The dco job
# writes it to $GITHUB_OUTPUT; the other CI jobs run only when it is true.
# Anything it cannot decide (no base, a git error, an empty diff) is code=true.
#   ci-changes.sh BASE HEAD
set -u
LIST="$(dirname "$0")/../test/accounting/docs-only.txt"
code() { echo "code=$1"; echo "ci-changes: $2" >&2; exit 0; }

base=${1:-}; head=${2:-}
case "$base" in ''|0000000000000000000000000000000000000000) code true "no base commit";; esac
files=$(git diff --name-only "$base" "$head" 2>/dev/null) || code true "git diff failed"
[ -n "$files" ] || code true "no changed files"
entries=$(grep -v '^[[:space:]]*#' "$LIST" | grep -v '^[[:space:]]*$') || code true "empty list"

first=$(echo "$files" | while IFS= read -r f; do
    hit=no
    for e in $entries; do
        case "$e" in
            */) case "$f" in "$e"*) hit=yes;; esac;;
            *)  [ "$f" = "$e" ] && hit=yes;;
        esac
    done
    [ "$hit" = yes ] || { echo "$f"; break; }
done)
[ -z "$first" ] || code true "$first is not prose-only, so every job runs"
code false "only prose changed ($(echo "$files" | wc -l) files): the build and test jobs are skipped"
