#!/usr/bin/env bash
# 在 Debian/Ubuntu 上准备 agy-credential-manager 的本地构建/测试环境（幂等，可重复执行）
set -euo pipefail

echo "==> 安装 Tauri Linux 构建依赖"
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
  patchelf libssl-dev build-essential pkg-config libgtk-3-dev

echo "==> 检查 Rust 工具链"
if command -v cargo >/dev/null 2>&1; then
  echo "cargo: $(cargo --version)"
  echo "rustc: $(rustc --version)"
else
  echo "未找到 cargo，请先安装 Rust：https://rustup.rs" >&2
  exit 1
fi

# fmt / clippy 组件（经 rustup 安装的工具链才需要）
if command -v rustup >/dev/null 2>&1; then
  rustup component add rustfmt clippy || true
fi

echo "==> 环境就绪。运行 ./scripts/check.sh 执行检查与构建"
