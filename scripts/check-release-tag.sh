#!/usr/bin/env bash
# The release tag must name a commit that is on main (security review of v0.6.0,
# SUPPLY-1, ADR-380): a `v*` tag pushed on a branch nobody reviewed is not
# built into a release, so its build scripts never run in the Release workflow.
#
#   scripts/check-release-tag.sh [--main REF] [--commit SHA] TAG
#
# REF defaults to origin/main (the Release workflow checks out with
# fetch-depth 0, so every branch is there). SHA, when given (the workflow
# passes $GITHUB_SHA), must be the commit the tag names. The tag must look like
# a release tag (vMAJOR.MINOR.PATCH, an optional -suffix): the signed trusted
# comment `urMQTT <tag> release <commit>` is read back by the builder page, the
# mirror and `urmqtt-config check-release`, which split it at spaces.
set -euo pipefail

main=origin/main
commit=""
while [[ $# -gt 1 ]]; do
    case $1 in
        --main) main=$2; shift 2 ;;
        --commit) commit=$2; shift 2 ;;
        *) echo "usage: $0 [--main REF] [--commit SHA] TAG" >&2; exit 2 ;;
    esac
done
[[ $# -eq 1 ]] || { echo "usage: $0 [--main REF] [--commit SHA] TAG" >&2; exit 2; }
tag=$1

fail() { echo "::error::$*" >&2; exit 1; }

[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
    || fail "$tag is not a release tag (vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-suffix)"
tagged=$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}") \
    || fail "there is no tag $tag here"
if [[ -n $commit ]]; then
    full=$(git rev-parse --verify --quiet "$commit^{commit}") || fail "$commit is not a commit here"
    [[ $full == "$tagged" ]] || fail "the tag $tag names $tagged, but the workflow runs $full"
fi
git rev-parse --verify --quiet "$main^{commit}" >/dev/null || fail "$main is not here (check out with fetch-depth: 0)"
git merge-base --is-ancestor "$tagged" "$main" \
    || fail "the tag $tag names $tagged, which is not on $main: a release is built from main only (SUPPLY-1, ADR-380)"
echo "release tag $tag: $tagged, on $main"
