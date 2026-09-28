#!/bin/sh
# Build the native crypto sidecar for one or more targets and vendor the
# results under engine/native/<target>/.  Requires a Rust toolchain
# (rustup target add <target> for cross-compiles).  Run from the repo root:
#
#   ./native/build.sh                          # host target only
#   ./native/build.sh x86_64-unknown-linux-gnu aarch64-apple-darwin ...
#
# The resulting files are what engine/native.py looks for.
set -e

cd "$(dirname "$0")"

TARGETS="$@"
if [ -z "$TARGETS" ]; then
    TARGETS=$(rustc -vV | awk '/^host:/ {print $2}')
fi

for T in $TARGETS; do
    echo "== building $T"
    cargo build --release --target "$T"
    OUT="../engine/native/$T"
    mkdir -p "$OUT"
    SRC="target/$T/release"
    # cdylib file name per OS family: Cargo gives Windows DLLs no lib prefix
    case "$T" in
        *windows*) NAME=strata_native.dll ;;
        *darwin*)  NAME=libstrata_native.dylib ;;
        *)         NAME=libstrata_native.so ;;
    esac
    cp "$SRC/$NAME" "$OUT/$NAME"
    ls -l "$OUT/$NAME"
done
echo "done"