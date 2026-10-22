#!/usr/bin/env bash
# 本地一键检查：格式 + clippy（严格，零警告）+ 单元测试 + release 构建
set -euo pipefail
cd "$(dirname "$0")/../src-tauri"

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy (-D warnings)"
cargo clippy --all-targets -- -D warnings

echo "==> cargo test"
cargo test

echo "==> cargo build --release"
cargo build --release

BIN="target/release/agy-credential-manager"
echo "==> 构建产物：$BIN ($(du -h "$BIN" | cut -f1))"
echo "==> 全部通过"
