<div align="center">

# 🔐 rust-acmesh

**小巧、原生、跨平台的 ACME DNS-01 客户端**<br>
**A small, native, cross-platform ACME DNS-01 client**

[简体中文](#简体中文) · [English](#english) · [下载 / Downloads](https://github.com/kci-lnk/acmesh-rs/releases)

[![CI](https://github.com/kci-lnk/acmesh-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/kci-lnk/acmesh-rs/actions/workflows/ci.yml)
[![Release](https://github.com/kci-lnk/acmesh-rs/actions/workflows/release.yml/badge.svg)](https://github.com/kci-lnk/acmesh-rs/actions/workflows/release.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

</div>

---

## 简体中文

`rust-acmesh` 是一个使用 Rust 编写的 ACME DNS-01 命令行客户端，面向服务集成、无人值守签发与证书自动化场景。它兼容常用的 `acme.sh` 操作参数，但运行时不依赖 Shell、Cygwin、OpenSSL 或独立的 ACME 环境。

> [!IMPORTANT]
> 本项目源自并借鉴 [ACME.sh](https://github.com/acmesh-official/acme.sh) 的工作流、命令行习惯和 DNS API 设计，是独立的 Rust 实现，并非 ACME.sh 官方项目。项目遵循 `GPL-3.0-or-later` 许可证。

### 特性

- 跨平台单文件程序：Windows、Linux 与 macOS，覆盖 x86_64 和 ARM64。
- 支持 ACME DNS-01 的签发、续期、吊销、CSR 签名与证书安装。
- 支持 RSA、ECDSA P-256/P-384、PKCS#8，以及可选的 PKCS#12 导出。
- 使用 rustls 与 Ring，不依赖系统 OpenSSL。
- 兼容 `acme.sh` 风格的操作参数，例如 `--issue`、`--renew`、`--install-cert`。
- DNS 凭据可由子进程环境或重复的 `--env NAME=VALUE` 参数传入。
- 使用 `--no-save-credentials` 时不会把 DNS 密钥复制到 `account.conf`。

### 下载

版本标签会自动生成以下发行包：

| 平台 | 架构 | Rust target | 包格式 |
| --- | --- | --- | --- |
| Windows | x86_64 | `x86_64-pc-windows-msvc` | `.zip` |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | `.zip` |
| Linux | x86_64 | `x86_64-unknown-linux-musl` | `.tar.gz` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` | `.tar.gz` |
| macOS | Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS | Apple Silicon | `aarch64-apple-darwin` | `.tar.gz` |

请从 [Releases](https://github.com/kci-lnk/acmesh-rs/releases) 下载对应平台的压缩包，并用同名 `.sha256` 文件校验完整性。Linux 产物使用 musl 静态链接，便于在不同发行版之间部署。

### 快速开始

签发 Let's Encrypt 证书：

```bash
rust-acmesh --issue \
  --home ./acme-data \
  --server letsencrypt \
  --email admin@example.com \
  --dns dns_cf \
  --dnssleep 30 \
  --no-save-credentials \
  -d example.com \
  -d '*.example.com' \
  --env CF_Token=REDACTED
```

首次签发时会自动创建账户密钥并注册 ACME 账户。集成测试请加 `--staging`，避免触发生产 CA 的速率限制。

ZeroSSL 需要外部账户绑定（EAB）凭据：

```bash
rust-acmesh --issue --server zerossl --email admin@example.com \
  --dns dns_cf -d example.com \
  --env EAB_KID=REDACTED \
  --env EAB_HMAC_KEY=REDACTED \
  --env CF_Token=REDACTED
```

操作标志与子命令两种写法均可：

```bash
rust-acmesh --issue -d example.com ...
rust-acmesh issue -d example.com ...
```

### DNS 服务商

| 服务商 | `--dns` | 必需凭据 | 可选值 |
| --- | --- | --- | --- |
| 阿里云 DNS | `dns_ali` | `Ali_Key`, `Ali_Secret` | `Ali_Domain` |
| 百度智能云 DNS | `dns_baiducloud` | `BAIDU_ACCESS_KEY_ID`, `BAIDU_SECRET_ACCESS_KEY` | `root_domain` |
| Cloudflare | `dns_cf` | `CF_Token`，或 `CF_Key` + `CF_Email` | `CF_Zone_ID`, `CF_Account_ID` |
| DNSPod | `dns_dp` | `DP_Id`, `DP_Key` | `DP_Domain` |
| 腾讯云 DNSPod | `dns_tencent` | `Tencent_SecretId`, `Tencent_SecretKey` | — |
| DuckDNS | `dns_duckdns` | `DuckDNS_Token` | — |
| Dynu | `dns_dynu` | `Dynu_ClientId`, `Dynu_Secret` | — |
| dynv6 | `dns_dynv6` | `DYNV6_TOKEN` | — |
| GoDaddy | `dns_gd` | `GD_Key`, `GD_Secret` | `GD_Domain` |
| 华为云 DNS | `dns_huaweicloud` | `HUAWEICLOUD_Username`, `HUAWEICLOUD_Password`, `HUAWEICLOUD_DomainName` | Region、ProjectName |
| Porkbun | `dns_porkbun` | `PORKBUN_API_KEY`, `PORKBUN_SECRET_API_KEY` | `PORKBUN_DOMAIN` |

Cloudflare 和 DNSPod 在未显式提供 Zone 时会自动发现托管区域。若使用委派的 DNS-01 区域或特殊公共后缀，建议显式指定 Zone。

### 证书文件与安装

签发结果位于 `<home>/<主域名>/`：

```text
cert.cer       站点证书
ca.cer         中间证书链
fullchain.cer  站点证书与中间证书链
domain.key     生成的域名私钥
key.pem        签发证书对应的私钥
```

复制证书到服务管理的路径：

```bash
rust-acmesh --install-cert \
  --home ./acme-data \
  -d example.com \
  --key-file ./ssl/example.com.key \
  --fullchain-file ./ssl/fullchain.cer
```

续期不会自动创建计划任务，调用方应自行调度：

```bash
rust-acmesh --renew --home ./acme-data --server letsencrypt -d example.com
```

### 从源码构建

需要 Rust 1.88 或更高版本：

```bash
cargo build --locked --release
cargo test --locked --all-targets --all-features
```

构建指定目标：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release --target x86_64-unknown-linux-musl
```

默认构建不包含 PKCS#12，以减小程序体积；按需启用：

```bash
cargo build --locked --release --features pkcs12
```

### 服务集成建议

1. 直接启动二进制，不要通过 Shell 包装执行。
2. 通过仅对子进程可见的环境变量传递密钥，并使用 `--no-save-credentials`。
3. 捕获 stdout、stderr 和子进程 PID，以便记录日志与取消任务。
4. 成功签发后调用 `--install-cert`，不要依赖内部目录结构。
5. 限制 `--home` 目录权限，仅允许服务身份和管理员读取。

---

## English

`rust-acmesh` is an ACME DNS-01 command-line client written in Rust for service integration, unattended issuance, and certificate automation. It supports familiar `acme.sh` operation flags without requiring a shell, Cygwin, OpenSSL, or a separate ACME runtime.

> [!IMPORTANT]
> This project originates from and draws on the workflows, CLI conventions, and DNS API design of [ACME.sh](https://github.com/acmesh-official/acme.sh). It is an independent Rust implementation and is not an official ACME.sh project. It is licensed under `GPL-3.0-or-later`.

### Highlights

- Single-file binaries for Windows, Linux, and macOS on x86_64 and ARM64.
- ACME DNS-01 issuance, renewal, revocation, CSR signing, and certificate installation.
- RSA, ECDSA P-256/P-384, PKCS#8, and optional PKCS#12 export.
- rustls with Ring; no system OpenSSL dependency.
- Familiar `acme.sh` flags such as `--issue`, `--renew`, and `--install-cert`.
- DNS credentials accepted from the process environment or repeated `--env NAME=VALUE` arguments.
- `--no-save-credentials` prevents DNS secrets from being copied into `account.conf`.

### Downloads

Each version tag produces six release archives:

| Platform | Architecture | Rust target | Archive |
| --- | --- | --- | --- |
| Windows | x86_64 | `x86_64-pc-windows-msvc` | `.zip` |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | `.zip` |
| Linux | x86_64 | `x86_64-unknown-linux-musl` | `.tar.gz` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` | `.tar.gz` |
| macOS | Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS | Apple Silicon | `aarch64-apple-darwin` | `.tar.gz` |

Download an archive from [Releases](https://github.com/kci-lnk/acmesh-rs/releases) and verify it with the matching `.sha256` file. Linux releases use musl for portable static binaries.

### Quick start

Issue a Let's Encrypt certificate:

```bash
rust-acmesh --issue \
  --home ./acme-data \
  --server letsencrypt \
  --email admin@example.com \
  --dns dns_cf \
  --dnssleep 30 \
  --no-save-credentials \
  -d example.com \
  -d '*.example.com' \
  --env CF_Token=REDACTED
```

The first issuance creates an account key and registers the ACME account. Add `--staging` during integration testing to avoid production CA rate limits.

Both operation flags and subcommands are accepted:

```bash
rust-acmesh --issue -d example.com ...
rust-acmesh issue -d example.com ...
```

The supported DNS providers and credential names are listed in the [Chinese provider table](#dns-服务商) above. They are identical on every platform.

### Certificate installation and renewal

Issued files are stored below `<home>/<primary-domain>/`. Copy them atomically into service-owned paths with:

```bash
rust-acmesh --install-cert \
  --home ./acme-data \
  -d example.com \
  --key-file ./ssl/example.com.key \
  --fullchain-file ./ssl/fullchain.cer
```

Renewal is intentionally scheduler-neutral:

```bash
rust-acmesh --renew --home ./acme-data --server letsencrypt -d example.com
```

If issuance used `--no-save-credentials`, the parent process must provide the DNS credentials again during renewal.

### Build from source

Rust 1.88 or newer is required:

```bash
cargo build --locked --release
cargo test --locked --all-targets --all-features
```

The default build excludes PKCS#12 support to keep the binary small. Enable it when needed:

```bash
cargo build --locked --release --features pkcs12
```

The release profile enables size optimization, fat LTO, a single codegen unit, symbol stripping, and abort-on-panic. Windows MSVC x86_64 builds also use a static CRT.

### Operational guidance

1. Start the executable directly instead of wrapping it in a shell.
2. Pass secrets through child-only environment variables and use `--no-save-credentials`.
3. Capture stdout, stderr, and the child PID for logging and cancellation.
4. Run `--install-cert` after successful issuance rather than depending on internal paths.
5. Restrict the `--home` directory to the service identity and administrators.

---

## License and attribution

Copyright © 2026 KCI-LNK.

Licensed under the [GNU General Public License, version 3 or later](LICENSE). This project is derived from concepts and compatibility behavior provided by [ACME.sh](https://github.com/acmesh-official/acme.sh), which is also distributed under GPLv3. ACME.sh and its contributors retain their respective copyrights.
