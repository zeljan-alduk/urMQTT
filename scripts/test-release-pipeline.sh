#!/usr/bin/env bash
# Tests the release pipeline's guards (security review of v0.6.0, SUPPLY-1, ADR-380):
# - scripts/check-release-tag.sh: a release tag on main passes; a tag on a branch
#   that is not on main, a tag that is not the workflow's commit and a tag that is
#   not a release tag are refused (in a throwaway git repository made here);
# - scripts/check-release-workflow.py: the Release workflow keeps the release key
#   in a signing job that builds nothing, and each way back to the single job
#   (the secret in the build job, signing without the environment, the key in a
#   file, the build or a write permission in the signing job, no tag check) is
#   refused.
#
#   scripts/test-release-pipeline.sh
# The mutations are Python expressions on the workflow's text: its `$VARS` are literal.
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAGCHECK=$ROOT/scripts/check-release-tag.sh
WFCHECK=$ROOT/scripts/check-release-workflow.py
WF=$ROOT/.github/workflows/release.yml
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fails=0

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

# --- the tag is on main -----------------------------------------------------------
repo=$TMP/repo
git init -q -b main "$repo"
g() { git -C "$repo" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
g commit -q --allow-empty -m one
g tag v0.6.0
g commit -q --allow-empty -m two
g tag v0.6.1-rc.1
on_main=$(g rev-parse HEAD)
g checkout -q -b feature
g commit -q --allow-empty -m unreviewed
g tag v0.6.2
g checkout -q main
in_repo() { (cd "$repo" && "$@"); }
expect 0 "a tag on main passes" in_repo "$TAGCHECK" --main main v0.6.0
expect 0 "a tag on main with the workflow's commit passes" in_repo "$TAGCHECK" --main main --commit "$on_main" v0.6.1-rc.1
expect 1 "a tag on a branch that is not on main is refused" in_repo "$TAGCHECK" --main main v0.6.2
expect 1 "a tag that is not the workflow's commit is refused" in_repo "$TAGCHECK" --main main --commit "$on_main" v0.6.0
expect 1 "a tag that is not a release tag is refused" in_repo "$TAGCHECK" --main main "v0.6.0 x"
expect 1 "a tag that does not exist is refused" in_repo "$TAGCHECK" --main main v9.9.9
expect 1 "a missing main is refused" in_repo "$TAGCHECK" --main origin/main v0.6.0

# --- the workflow's shape ---------------------------------------------------------
expect 0 "the Release workflow keeps the key in a signing job that builds nothing" python3 -I "$WFCHECK" "$WF"
mutant() { # mutant <name> <python expression on s>
    python3 -I -c 'import sys; s = open(sys.argv[1]).read(); t = eval(sys.argv[2]); assert t != s, "mutation did not apply"; open(sys.argv[3], "w").write(t)' "$WF" "$2" "$TMP/$1.yml"
    echo "$TMP/$1.yml"
}
expect 1 "the secret in the build job is refused" python3 -I "$WFCHECK" "$(mutant secret-in-build \
    's.replace("    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout", "    env:\n      HAS_MINISIGN: ${{ secrets.MINISIGN_SECRET_KEY != \x27\x27 }}\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout", 1)')"
expect 1 "signing without the environment release is refused" python3 -I "$WFCHECK" "$(mutant no-environment \
    's.replace("    environment: release\n", "")')"
expect 1 "the key written to a file is refused" python3 -I "$WFCHECK" "$(mutant key-file \
    's.replace("minisign -S -s <(printf \x27%s\\n\x27 \"$MINISIGN_SECRET_KEY\")", "printf \x27%s\\n\x27 \"$MINISIGN_SECRET_KEY\" > \"$RUNNER_TEMP/minisign.key\"; minisign -S -s \"$RUNNER_TEMP/minisign.key\"")')"
expect 1 "building in the signing job is refused" python3 -I "$WFCHECK" "$(mutant build-in-sign \
    's.replace("      - name: Install minisign\n", "      - run: make dist ENV=release\n      - name: Install minisign\n")')"
expect 1 "a write permission in the signing job is refused" python3 -I "$WFCHECK" "$(mutant sign-writes \
    's.replace("    environment: release\n    permissions:\n      contents: read\n", "    environment: release\n    permissions:\n      contents: write\n")')"
expect 1 "id-token in the build job is refused" python3 -I "$WFCHECK" "$(mutant build-id-token \
    's.replace("    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout", "    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout", 1)')"
expect 1 "building without the tag check is refused" python3 -I "$WFCHECK" "$(mutant no-tag-check \
    's.replace("        run: scripts/check-release-tag.sh --commit \"$GITHUB_SHA\" \"$GITHUB_REF_NAME\"\n", "        run: true\n")')"
expect 1 "a full checkout in the signing job is refused" python3 -I "$WFCHECK" "$(mutant full-checkout \
    's.replace("          sparse-checkout: minisign.pub\n          sparse-checkout-cone-mode: false\n", "")')"
expect 1 "checking out code in the publishing job is refused" python3 -I "$WFCHECK" "$(mutant publish-checkout \
    's.replace("      - name: The build job\x27s files and the signature\n", "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - name: The build job\x27s files and the signature\n")')"
expect 1 "a third-party action in the signing job is refused" python3 -I "$WFCHECK" "$(mutant sign-action \
    's.replace("      - name: Install minisign\n", "      - uses: someone/setup-minisign@0123456789012345678901234567890123456789\n      - name: Install minisign\n")')"

if [[ $fails -ne 0 ]]; then
    echo "$fails failure(s)"
    exit 1
fi
echo "all release pipeline checks passed"
