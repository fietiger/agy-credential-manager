#!/usr/bin/env bash
# 本地一键检查：格式 + clippy（严格，零警告）+ 单元测试 + 生产构建
# 注意：最后一步必须用 Tauri CLI 构建。直接 cargo build 产出的是开发模式
# 二进制，运行时会去连 localhost:1420 的开发服务器，无法独立使用。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
cargo fmt --all --manifest-path src-tauri/Cargo.toml -- --check

echo "==> cargo clippy (-D warnings)"
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings

echo "==> cargo test"
cargo test --manifest-path src-tauri/Cargo.toml

echo "==> tauri build --no-bundle（生产构建）"
if command -v cargo-tauri >/dev/null 2>&1; then
  cargo tauri build --no-bundle
elif command -v tauri >/dev/null 2>&1; then
  tauri build --no-bundle
else
  npx -y @tauri-apps/cli@^2 build --no-bundle
fi

BIN="src-tauri/target/release/agy-credential-manager"
echo "==> 构建产物：$BIN ($(du -h "$BIN" | cut -f1))"
echo "==> 全部通过"
