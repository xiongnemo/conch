#!/usr/bin/env bash
# Derives conch's version from git, the one implementation of the rules in
# docs/versioning.md, so CI and a local build cannot disagree.
#
#   scripts/version.sh            the version, e.g. v0.0.5-main-0123456789ab
#   scripts/version.sh --ldflags  the -X flags for go build
#
# Needs a full clone: a shallow one has no tags and yields the v0.0.1
# fallback, which is why the workflows check out with fetch-depth: 0.
#
# CONCH_BRANCH overrides the branch, for builds of a commit that is not
# what the checkout's ref says (a release run started by CI).
set -euo pipefail

pkg=github.com/xiongnemo/conch/internal/version

# --exclude='*-*' keeps build markers such as v0.0.5-main-0123456789ab out:
# only an exact vMAJOR.MINOR.PATCH tag is a base.
tag=$(git describe --tags --abbrev=0 --match='v[0-9]*' --exclude='*-*' HEAD 2>/dev/null || true)
if [ -n "$tag" ]; then
  commits=$(git rev-list --count "${tag}..HEAD")
else
  commits=$(git rev-list --count HEAD)
fi

# GitHub checks out a detached HEAD; on a tag push GITHUB_REF_NAME is the
# tag, which is no branch.
branch=${CONCH_BRANCH:-${GITHUB_HEAD_REF:-}}
if [ -z "$branch" ] && [ "${GITHUB_REF_TYPE:-}" != tag ]; then
  branch=${GITHUB_REF_NAME:-}
fi
if [ -z "$branch" ]; then
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
fi
if [ -z "$branch" ] || [ "$branch" = HEAD ]; then
  if [ "${GITHUB_REF_TYPE:-}" = tag ]; then branch=release; else branch=detached; fi
fi

commit=$(git rev-parse HEAD)
dirty=false
if [ -n "$(git status --porcelain)" ]; then
  dirty=true
fi

ldflags="-X $pkg.tag=$tag -X $pkg.commitsSinceTag=$commits -X $pkg.branch=$branch -X $pkg.commit=$commit -X $pkg.dirty=$dirty"
if [ "${1:-}" = --ldflags ]; then
  printf '%s\n' "$ldflags"
  exit 0
fi
# The Go package renders the version, so there is one formatter.
out=$(go run -ldflags "$ldflags" ./cmd/conch version)
out=${out#conch }
printf '%s\n' "${out%% *}"
