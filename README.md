# Agy Credential Manager

本地 Antigravity（agy）凭证管理器。纯本地运行：无代理、无中继、不上传任何数据。

基于 Tauri 2 + Rust 构建的桌面应用，用来管理多个 Google / Antigravity 账号的 OAuth 凭证，并一键把选定账号同步给 agy CLI 使用。

## 功能

- **多账号管理**：添加、删除多个账号，列表展示邮箱、标签、状态与掩码后的 token
- **Google OAuth 登录**：内置 OAuth 流程（本地回调），登录成功后自动保存凭证
- **导入 refresh token**：已有 refresh token 时可直接导入生成账号
- **一键切换账号**：将账号设为活跃时，把它的 access token 写入系统 keyring（service `antigravity` / entry `oauth_token`），agy CLI 下次启动即使用该账号；写入后会读回校验
- **自动刷新**：读取账号时若 access token 已过期（提前 60 秒判定），自动用 refresh token 刷新
- **导出备份**：一键导出全部账号（邮箱 + refresh token 等）为 JSON，便于备份与迁移
- **文件日志**：结构化日志写入应用数据目录，界面内可直接打开日志目录

## 数据存储

所有数据只存在本机应用数据目录下的 `agy-credential-manager/` 文件夹：

| 内容 | 文件 |
| --- | --- |
| 账号索引 | `accounts.json` |
| 单个账号凭证 | `accounts/<id>.json` |
| 日志 | `logs/app.log` |

各平台应用数据目录：

- Windows：`%APPDATA%\agy-credential-manager\`
- macOS：`~/Library/Application Support/agy-credential-manager/`
- Linux：`~/.local/share/agy-credential-manager/`

> ⚠️ 账号凭证以明文 JSON 保存在本地，请注意本机账户与磁盘安全；导出的备份文件包含 refresh token，不要分享给他人。

## 构建

环境要求：Rust ≥ 1.77；Linux 还需要 webkit2gtk 等系统依赖。

```bash
# Linux 先装系统依赖
sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
  librsvg2-dev patchelf libssl-dev

# 构建 release 可执行文件
cargo build --release --manifest-path src-tauri/Cargo.toml
```

GitHub Actions（`.github/workflows/build.yml`）会在 push 时自动构建 Windows / macOS / Linux 三平台产物；打 `v*` tag 时自动发布 Release。

## 开发

```bash
cargo fmt --all --manifest-path src-tauri/Cargo.toml
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

调试日志：设置环境变量 `AGY_LOG_DEBUG=1` 后再启动应用，可输出 debug 级别日志。

## 项目结构

```
ui/                  单页前端（index.html）
src-tauri/
  src/
    commands/        Tauri IPC 命令（账号、OAuth、状态、导出、日志）
    models/          Account / TokenData 数据模型
    modules/         account_store 本地存储、oauth 授权与刷新、
                     agy_sync 同步 keyring、logger 文件日志
```

## 许可证

MIT
