#!/bin/sh
#
# The version this build reports, from the header's version (BASE) and git:
#
#   scripts/version.sh BASE
#
# A release -- a clean tree at the tag v<BASE> -- reports BASE as it is. Any
# other build reports BASE+<n>-g<sha>, with -dirty when tracked files differ
# from HEAD (git describe --tags --long's count and abbreviated id), so a
# development build is never taken for a release. With no git, or no tag to
# describe from, or a tree that is not its own repository (a source tarball
# unpacked inside another one), it reports BASE+unknown.
#
# Nothing here writes to the repository: `git describe --dirty` and
# `git diff` refresh .git/index when its stat data is stale (checked, git
# 2.43.0), so dirtiness comes from `git status` with optional locks off,
# which leaves the index alone.

base=$1
[ -n "$base" ] || { echo "version.sh: no base version" >&2; exit 2; }
export GIT_OPTIONAL_LOCKS=0
top=$(git rev-parse --show-toplevel 2>/dev/null) || top=
if [ -z "$top" ] || [ "$(cd "$top" && pwd -P)" != "$(pwd -P)" ]; then
    echo "$base+unknown"
    exit 0
fi
desc=$(git describe --tags --long --match 'v[0-9]*' 2>/dev/null) || desc=
case $desc in
    *-*-g*) ;;
    *) echo "$base+unknown"; exit 0 ;;
esac
sha=${desc##*-}                 # g<abbreviated id>
rest=${desc%-*}
n=${rest##*-}                   # commits since the tag
tag=${rest%-*}
dirty=
[ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ] && dirty=-dirty
if [ "$n" = 0 ] && [ -z "$dirty" ] && [ "$tag" = "v$base" ]; then
    echo "$base"
else
    echo "$base+$n-$sha$dirty"
fi
