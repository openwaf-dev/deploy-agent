#!/usr/bin/env bash
# scripts/build-release.sh [out dir] — the release build of owdeploy-agent: static musl binaries for linux-amd64 and
# linux-arm64 in <out dir> (default dist/), named as the control plane serves them, and their SHA256SUMS. The release
# workflow (.github/workflows/release.yml) and verify.sh run exactly this, so anyone can rebuild a release and get the
# same bytes. Needs the toolchain of rust-toolchain.toml (rustup installs it), zig $ZIG_VERSION and cargo-zigbuild
# $CARGO_ZIGBUILD_VERSION (README.md, «Build from source»).
#
# What makes the output independent of the machine and the checkout:
# - pinned toolchain, linker (zig), cargo-zigbuild and Cargo.lock (--locked);
# - the release profile set explicitly (CARGO_PROFILE_RELEASE_*), whatever a local configuration says;
# - the checkout and the Cargo home remapped to /build and /cargo in Rust (--remap-path-prefix) and C
#   (-ffile-prefix-map) code, so no local path reaches the binaries; no incremental compilation;
# - SOURCE_DATE_EPOCH: the commit's own time; the version names the commit (OWDEPLOY_BUILD below).
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist}
ZIG_VERSION=0.17.0
CARGO_ZIGBUILD_VERSION=0.23.4
die() { echo "build-release: $*" >&2; exit 1; }

command -v zig >/dev/null || die "zig $ZIG_VERSION is required"
[ "$(zig version)" = "$ZIG_VERSION" ] || die "zig $(zig version) found, $ZIG_VERSION required"
command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild $CARGO_ZIGBUILD_VERSION is required"
[ "$(cargo-zigbuild -V)" = "cargo-zigbuild $CARGO_ZIGBUILD_VERSION" ] ||
  die "$(cargo-zigbuild -V) found, cargo-zigbuild $CARGO_ZIGBUILD_VERSION required"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "the checkout has uncommitted changes"
ordinal=$(cat BUILD_ORDINAL)
[[ $ordinal =~ ^[0-9]+$ ]] || die "BUILD_ORDINAL is not a number"

# The version agents report and order updates by: <crate version>+<ordinal>.<commit> (PROTOCOL.md, «Versions»).
OWDEPLOY_BUILD="$ordinal.$(git rev-parse --short=12 HEAD)"
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export OWDEPLOY_BUILD SOURCE_DATE_EPOCH
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_STRIP=true
export CARGO_PROFILE_RELEASE_DEBUG=false
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR=$PWD/target
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)
src=$PWD
# C flags are split at whitespace (cc-rs), so the remapped paths cannot contain any.
case "$src$cargo_home" in
  *[[:space:]]*) die "the checkout ($src) and CARGO_HOME ($cargo_home) must not contain spaces" ;;
esac
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$src=/build"$'\x1f'"--remap-path-prefix=$cargo_home=/cargo"
cflags="-ffile-prefix-map=$src=/build -ffile-prefix-map=$cargo_home=/cargo"

rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)
for pair in x86_64-unknown-linux-musl:linux-amd64 aarch64-unknown-linux-musl:linux-arm64; do
  triple=${pair%%:*} name=${pair#*:}
  env "CFLAGS_${triple//-/_}=$cflags" "CXXFLAGS_${triple//-/_}=$cflags" \
    cargo zigbuild --release --locked -p deploy-agent --target "$triple"
  install -m 0755 "target/$triple/release/owdeploy-agent" "$out/owdeploy-agent-$name"
done
if command -v sha256sum >/dev/null; then sum=(sha256sum); else sum=(shasum -a 256); fi
(cd "$out" && "${sum[@]}" owdeploy-agent-linux-amd64 owdeploy-agent-linux-arm64 >SHA256SUMS && cat SHA256SUMS)
echo "build-release: owdeploy-agent $(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)+$OWDEPLOY_BUILD in $out"
