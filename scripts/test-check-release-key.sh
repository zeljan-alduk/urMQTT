#!/usr/bin/env bash
# Tests scripts/check-release-key.sh: the placeholder, the former test key and a
# broken key ring are refused; a real (throwaway, generated here) key passes.
#
#   scripts/test-check-release-key.sh
#
# The key generated here is a THROWAWAY key in a temp directory; the real
# release key is never touched. Needs minisign for the positive case (skipped
# with a message without it).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHECK=$ROOT/scripts/check-release-key.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0

# A copy of the files the check reads, with minisign.pub replaced by $1.
tree() {
    local dir=$TMP/$2
    mkdir -p "$dir/keys"
    cp "$ROOT/keys/release-keys.json" "$ROOT/keys/minisign-test-9229E05252D01F8E.pub" "$dir/keys/"
    cp "$1" "$dir/minisign.pub"
    echo "$dir"
}
expect() { # expect <0|1> <what> <command...>
    local want=$1 what=$2 out
    shift 2
    if out=$("$@" 2>&1); then got=0; else got=1; fi
    if [[ $got == "$want" ]]; then
        echo "ok: $what"
    else
        echo "FAIL: $what (exit $got, wanted $want)"; printf '    %s\n' "$out"; fails=$((fails + 1))
    fi
}

printf 'untrusted comment: minisign public key REPLACE-WITH-THE-NEW-PUBLIC-KEY\nREPLACE-WITH-THE-NEW-PUBLIC-KEY\n' > "$TMP/placeholder.pub"
expect 1 "the placeholder is refused" "$CHECK" --root "$(tree "$TMP/placeholder.pub" placeholder)"
expect 0 "the placeholder passes with --allow-placeholder (never for a release)" "$CHECK" --root "$TMP/placeholder" --allow-placeholder
expect 1 "the former test key as minisign.pub is refused" "$CHECK" --root "$(tree "$ROOT/keys/minisign-test-9229E05252D01F8E.pub" test)"
printf 'untrusted comment: x\nnot a key\n' > "$TMP/junk.pub"
expect 1 "a minisign.pub that is not a key is refused" "$CHECK" --root "$(tree "$TMP/junk.pub" junk)"
# The repository itself: refused while the placeholder is there, else it must pass.
if grep -q REPLACE-WITH-THE-NEW-PUBLIC-KEY "$ROOT/minisign.pub"; then
    expect 1 "this checkout (still the placeholder) is not releasable" "$CHECK"
else
    expect 0 "this checkout's release key passes" "$CHECK"
fi

if command -v minisign >/dev/null; then
    HOME=$TMP minisign -G -W -p "$TMP/new.pub" -s "$TMP/new.key" >/dev/null
    dir=$(tree "$TMP/new.pub" new)
    # The ring names the repository's release key id; the copy must name the new key's.
    old_id=$(head -1 "$ROOT/minisign.pub" | awk '{print $NF}')
    new_id=$(head -1 "$TMP/new.pub" | awk '{print $NF}')
    sed -i.bak "s/\"key_id\": \"$old_id\"/\"key_id\": \"$new_id\"/" "$dir/keys/release-keys.json"
    rm -f "$dir/keys/release-keys.json.bak"
    expect 0 "a new release key passes" "$CHECK" --root "$dir"
    # A broken ring: the test key's declared id does not match its file.
    sed -i.bak 's/"key_id": "9229E05252D01F8E"/"key_id": "0000000000000000"/' "$dir/keys/release-keys.json"
    expect 1 "a key id that does not match its file is refused" "$CHECK" --root "$dir"
    mv "$dir/keys/release-keys.json.bak" "$dir/keys/release-keys.json"
    # The test key without its upper bound would be trusted for every future tag.
    sed -i.bak 's/"valid_to": "v0.4.1"/"valid_to": null/' "$dir/keys/release-keys.json"
    expect 1 "an unbounded former test key is refused" "$CHECK" --root "$dir"
    mv "$dir/keys/release-keys.json.bak" "$dir/keys/release-keys.json"
    # A pin outside the range, or a malformed one, is refused.
    sed -i.bak 's/"v0.4.1": "3cca/"v0.5.1": "3cca/' "$dir/keys/release-keys.json"
    expect 1 "a pinned tag outside the test key's range is refused" "$CHECK" --root "$dir"
    mv "$dir/keys/release-keys.json.bak" "$dir/keys/release-keys.json"
    sed -i.bak 's/"v0.1.0": "25ba/"v0.1.0": "ZZba/' "$dir/keys/release-keys.json"
    expect 1 "a malformed pin is refused" "$CHECK" --root "$dir"
    mv "$dir/keys/release-keys.json.bak" "$dir/keys/release-keys.json"
    expect 0 "the restored ring passes again" "$CHECK" --root "$dir"
else
    echo "skip: minisign is not installed; the positive case was not run"
fi

if ((fails)); then echo "test-check-release-key: $fails failure(s)"; exit 1; fi
echo "test-check-release-key: all passed"
