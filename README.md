# Agy Credential Manager

本地 Antigravity（agy）凭证管理器。纯本地运行：无代理、无中继、不上传任何数据。

基于 Tauri 2 + Rust 构建的桌面应用，用来管理多个 Google / Antigravity 账号的 OAuth 凭证，并一键把选定账号同步给 agy CLI 使用。

## 功能

- **多账号管理**：添加、删除多个账号，列表展示邮箱、标签、状态与掩码后的 token
- **Google OAuth 登录**：内置 OAuth 流程（本地 loopback 回调），登录成功后自动保存凭证。链接不会替你自动打开，由你选择「在浏览器中打开」或「复制链接」（也可以复制到另一台机器的浏览器）；如果浏览器没有回调回本机，还可以把地址栏里的回调链接或 authorization code 粘回来完成登录
- **导入 refresh token**：已有 refresh token 时可直接导入生成账号
- **一键导入本地账号**：读取本机三个客户端当前登录的凭证（agy CLI 的 keyring、Antigravity 与 Antigravity IDE 的 `state.vscdb`），一键收进管理器统一管理；按邮箱与 refresh token 去重，重复的只跳过不报错，每个客户端的处理结果（已导入 / 已存在 / 未登录 / 读不到邮箱）都会显示出来
- **文件批量导入**：可直接导入 Antigravity-Manager 导出的 JSON 文件（裸数组 `[{email, refresh_token}]`），也兼容本应用自己的导出格式；自动跳过无效条目与重复账号并报告数量，邮箱取自文件、不会显示 unknown
- **一键切换账号**：将账号设为活跃时，把它的凭证按 agy CLI 的格式写入系统 keyring（service `gemini` / entry `antigravity`，同时更新 `~/.gemini/antigravity-cli/antigravity-oauth-token`），agy CLI 下次启动即使用该账号；写入后会读回校验
- **多客户端切换（逐客户端选择）**：每个账号可分别切入指定客户端——agy CLI（系统 keyring）、Antigravity 经典版、Antigravity IDE（各自 `state.vscdb` 的 unified state 格式注入，含 token、`authStateWithContext` 登录态、userStatus 与项目偏好）；每个客户端独立保存自己的当前账号、互不影响（与 Antigravity-Manager 相同的模型）；账号卡上的徽章显示该账号正被哪些客户端使用，界面 Clients 区显示每个客户端的安装状态、登录态（`signed in` / `signed out` / `no account`）与当前登录邮箱。写入后立即回读校验：客户端在运行中把自己的内存状态写回、吞掉了这次切换时，会直接报错并提示先关闭客户端，而不是假装成功
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

# 构建可独立运行的 release 可执行文件（必须用 Tauri CLI）
npx -y @tauri-apps/cli@^2 build --no-bundle

# 注意：不要直接 cargo build —— 产出的是开发模式二进制，
# 运行时会去连接 localhost:1420 的开发服务器，无法独立使用。
```

GitHub Actions（`.github/workflows/build.yml`）会在 push 时自动构建 Windows / macOS / Linux 三平台产物；打 `v*` tag 时自动发布 Release。

## 开发

```bash
cargo fmt --all --manifest-path src-tauri/Cargo.toml
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

本地一键环境与检查（Debian/Ubuntu，含 InstaBox 机器）：

```bash
./scripts/dev-setup.sh   # 安装系统依赖并检查 Rust 工具链（幂等）
./scripts/check.sh       # fmt 检查 + clippy 严格模式 + 单元测试 + release 构建
```

调试日志：设置环境变量 `AGY_LOG_DEBUG=1` 后再启动应用，可输出 debug 级别日志。

OAuth 客户端密钥：Antigravity 用的是「已安装应用」类型的 OAuth 客户端，换取 token 时只需 client id，不需要密钥。如果换成其他类型的客户端、需要带 client secret，用环境变量 `AGY_OAUTH_CLIENT_SECRET` 提供，不要把密钥写进源码（GitHub 的推送保护会直接拒绝含密钥的提交）。

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
