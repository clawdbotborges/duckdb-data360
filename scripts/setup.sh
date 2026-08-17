#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUCKDB_REV="d8cdaa33fda8df955cc76ef58a280f68f4cd43fa"
EXTENSION_CI_TOOLS_REV="72e76e99cd7fee45a99739cd118ec2db64e034ec"
VCPKG_REV="94a541197763a4f449a1b91478df48c0584a6256"

# DuckDB and extension-ci-tools are tracked submodules in the standalone
# source repository. Do not replace them with local symlinks.
git -C "$ROOT" submodule update --init --recursive

if [[ "$(git -C "$ROOT/duckdb" rev-parse HEAD)" != "$DUCKDB_REV" ]]; then
  printf 'Pinned DuckDB revision verification failed\n' >&2
  exit 1
fi
if [[ "$(git -C "$ROOT/extension-ci-tools" rev-parse HEAD)" != "$EXTENSION_CI_TOOLS_REV" ]]; then
  printf 'Pinned extension-ci-tools revision verification failed\n' >&2
  exit 1
fi

mkdir -p "$ROOT/.deps"
VCPKG_DIR="$ROOT/.deps/vcpkg"
if [[ ! -d "$VCPKG_DIR/.git" ]]; then
  git clone https://github.com/microsoft/vcpkg.git "$VCPKG_DIR"
else
  actual_url="$(git -C "$VCPKG_DIR" remote get-url origin)"
  if [[ "$actual_url" != "https://github.com/microsoft/vcpkg.git" ]]; then
    printf 'Refusing unexpected vcpkg origin: %s\n' "$actual_url" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$VCPKG_DIR" status --porcelain)" ]]; then
    printf 'Refusing to overwrite dirty dependency checkout: %s\n' "$VCPKG_DIR" >&2
    exit 1
  fi
fi

git -C "$VCPKG_DIR" fetch --quiet --depth 1 origin "$VCPKG_REV"
git -C "$VCPKG_DIR" checkout --quiet --detach "$VCPKG_REV"
if [[ "$(git -C "$VCPKG_DIR" rev-parse HEAD)" != "$VCPKG_REV" ]]; then
  printf 'Pinned vcpkg revision verification failed\n' >&2
  exit 1
fi
ln -sfn .deps/vcpkg "$ROOT/vcpkg"
