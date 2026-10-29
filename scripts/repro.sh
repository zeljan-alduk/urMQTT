#!/usr/bin/env bash
# Checks that the image is reproducible (M17): builds the current commit
# twice, in two fresh worktrees at different paths with separate target
# directories, and compares the kernel ELF, the ISO and the raw disk image
# byte for byte.
#
#   scripts/repro.sh [ENV]        # default: prod
#
# The untracked inputs of deploy/<ENV>/ (certificates, keys, revocation
# list) are copied into both worktrees: they are inputs, not build products.
# Uncommitted changes are not part of the check (it builds HEAD).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENV=${1:-prod}
[[ -d "$ROOT/deploy/$ENV" ]] || { echo "error: deploy/$ENV not found" >&2; exit 2; }
WORK=$(mktemp -d)
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    for d in "$WORK/a" "$WORK/b/deeper/path"; do
        git -C "$ROOT" worktree remove --force "$d" 2>/dev/null || true
    done
    rm -rf "$WORK"
    git -C "$ROOT" worktree prune
}
trap cleanup EXIT

commit=$(git -C "$ROOT" rev-parse HEAD)
echo "repro: $ENV image of $commit, built twice"
for d in a b; do
    # Different path depths, so a path leaking into the image shows up.
    dir="$WORK/$d"
    [[ $d == b ]] && dir="$WORK/b/deeper/path"
    mkdir -p "$(dirname "$dir")"
    git -C "$ROOT" worktree add --detach --quiet "$dir" "$commit"
    (cd "$ROOT" && git ls-files --others --ignored --exclude-standard -- "deploy/$ENV") | while read -r f; do
        mkdir -p "$dir/$(dirname "$f")"
        cp -p "$ROOT/$f" "$dir/$f"
    done
    # Same version string as the original checkout (a worktree has no tags
    # of its own to differ on, but keep it explicit).
    (cd "$dir" && make --no-print-directory iso raw ENV="$ENV" VERSION="$(git -C "$ROOT" describe --tags --always)" \
        >"$WORK/$d.log" 2>&1) || { tail -30 "$WORK/$d.log"; echo "repro: build $d failed" >&2; exit 1; }
    eval "DIR_$d=\$dir"
done

status=0
compare() {
    local what=$1 fa=$2 fb=$3
    local ha hb
    ha=$(shasum -a 256 "$fa" | cut -d' ' -f1)
    hb=$(shasum -a 256 "$fb" | cut -d' ' -f1)
    if [[ "$ha" == "$hb" ]]; then
        echo "  ✓ $what identical: $ha"
    else
        echo "  ✗ $what differs: $ha vs $hb ($(cmp -l "$fa" "$fb" | wc -l | tr -d ' ') byte(s))"
        status=1
    fi
}
# shellcheck disable=SC2154 # set through eval above
compare "kernel ELF" "$DIR_a/target/aarch64-unknown-none/release/urmqtt" "$DIR_b/target/aarch64-unknown-none/release/urmqtt"
# The versioned files (not the urmqtt-<env>.iso symlink).
v=$(git -C "$ROOT" describe --tags --always)
compare "ISO" "$DIR_a/build/urmqtt-$ENV-$v.iso" "$DIR_b/build/urmqtt-$ENV-$v.iso"
compare "raw disk image" "$DIR_a/build/urmqtt-$ENV-$v.img" "$DIR_b/build/urmqtt-$ENV-$v.img"
exit $status
