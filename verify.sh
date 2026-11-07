#!/usr/bin/env bash
# verify.sh <tag> — rebuilds the release <tag> of owdeploy-agent from this repository and compares the binaries with
# the published ones, byte for byte. Run it in a clone of https://github.com/openwaf-dev/deploy-agent; it needs what
# scripts/build-release.sh needs (README.md, «Build from source»), curl and, to check the signature of SHA256SUMS,
# cosign. Exit 0: every published binary is exactly what the source of <tag> builds.
#
# SHA256SUMS_FILE=<path> compares with a local SHA256SUMS instead of downloading the release's (e.g. the one the
# control plane's binaries were checked against: sha256sum of the files served at /v1/agent/binary/<target>).
set -euo pipefail
repo=openwaf-dev/deploy-agent
tag=${1:?usage: verify.sh <tag>}
cd "$(dirname "$0")"
die() { echo "verify: $*" >&2; exit 1; }

git rev-parse --verify -q "refs/tags/$tag" >/dev/null || git fetch -q origin "refs/tags/$tag:refs/tags/$tag" ||
  die "no tag $tag"
work=$(mktemp -d)
cleanup() { git worktree remove --force "$work/src" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

if [ -n "${SHA256SUMS_FILE:-}" ]; then
  cp "$SHA256SUMS_FILE" "$work/SHA256SUMS"
else
  base=https://github.com/$repo/releases/download/$tag
  curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
  if command -v cosign >/dev/null; then
    curl -fsSL "$base/SHA256SUMS.sigstore.json" -o "$work/SHA256SUMS.sigstore.json"
    cosign verify-blob --bundle "$work/SHA256SUMS.sigstore.json" \
      --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com "$work/SHA256SUMS" ||
      die "the signature of SHA256SUMS does not verify"
  else
    echo "verify: cosign not installed: the signature of SHA256SUMS is not checked" >&2
  fi
fi

# A clean checkout of the tag elsewhere: the build does not depend on where it runs.
git worktree add -q --detach "$work/src" "$tag"
(cd "$work/src" && scripts/build-release.sh "$work/out")

fail=0 seen=0
while read -r want file; do
  case $file in owdeploy-agent-linux-amd64 | owdeploy-agent-linux-arm64) seen=$((seen + 1)) ;; *) continue ;; esac
  got=$(awk -v f="$file" '$2 == f {print $1}' "$work/out/SHA256SUMS")
  if [ "$got" = "$want" ]; then
    echo "verify: $file $want: reproduced"
  else
    echo "verify: $file: published $want, rebuilt ${got:-nothing}" >&2
    fail=1
  fi
done <"$work/SHA256SUMS"
[ "$seen" = 2 ] || die "SHA256SUMS does not list both binaries"
[ "$fail" = 0 ] || die "$tag is not reproduced"
echo "verify: $tag is reproduced from source"
