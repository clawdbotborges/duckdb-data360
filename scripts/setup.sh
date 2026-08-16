#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUCKDB_REV="d8cdaa33fda8df955cc76ef58a280f68f4cd43fa"
EXTENSION_CI_TOOLS_REV="35759fd21acdb0ba8acbb3342a0b959dc46fefac"
mkdir -p "$ROOT/.deps"

setup_repo() {
  local name="$1"
  local url="$2"
  local revision="$3"
  local directory="$ROOT/.deps/$name"

  if [[ ! -d "$directory/.git" ]]; then
    git clone "$url" "$directory"
  else
    local actual_url
    actual_url="$(git -C "$directory" remote get-url origin)"
    if [[ "$actual_url" != "$url" ]]; then
      printf 'Refusing unexpected %s origin: %s\n' "$name" "$actual_url" >&2
      return 1
    fi
    if [[ -n "$(git -C "$directory" status --porcelain)" ]]; then
      printf 'Refusing to overwrite dirty dependency checkout: %s\n' "$directory" >&2
      return 1
    fi
  fi

  git -C "$directory" fetch --quiet --depth 1 origin "$revision"
  git -C "$directory" checkout --quiet --detach "$revision"
  if [[ "$(git -C "$directory" rev-parse HEAD)" != "$revision" ]]; then
    printf 'Pinned revision verification failed for %s\n' "$name" >&2
    return 1
  fi
}

setup_repo duckdb https://github.com/duckdb/duckdb.git "$DUCKDB_REV"
setup_repo extension-ci-tools https://github.com/duckdb/extension-ci-tools.git "$EXTENSION_CI_TOOLS_REV"
ln -sfn .deps/duckdb "$ROOT/duckdb"
ln -sfn .deps/extension-ci-tools "$ROOT/extension-ci-tools"
