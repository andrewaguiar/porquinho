#!/usr/bin/env bash
#
# Build the porquinho release binary for Linux.
# The artifact is written to dist/.

set -euo pipefail

cd "$(dirname "$0")/.."

NAME="porquinho"
TARGET="x86_64-unknown-linux-gnu"
DIST="dist"

mkdir -p "$DIST"

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "Adding rust target $TARGET..."
    rustup target add "$TARGET"
fi

echo "==> Building $TARGET"
cargo build --release --target "$TARGET"

OUT="$DIST/$NAME"
cp "target/$TARGET/release/$NAME" "$OUT"

echo
echo "Built: $OUT"
