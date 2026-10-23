logblur
=======

logblur 在你分享 Linux 日志压缩包之前，把里面的敏感信息清洗掉：口令、密钥、令牌、IP 和
MAC 地址、邮箱、用户名和主机名。它能读取 `.zip`、`.tar`、`.tar.gz`、`.gz` 压缩包，以及普通
文件、文件夹和标准输入，并按原格式输出清洗后的副本。未清洗的明文只在内存中解压、扫描和重新
压缩，永远不会写到磁盘上。

[![CI](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml/badge.svg)](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/logblur.svg)](https://crates.io/crates/logblur)
[![docs.rs](https://img.shields.io/docsrs/logblur-core)](https://docs.rs/logblur-core)

以 MIT 或 [Apache License 2.0](LICENSE-APACHE) 双许可证发布。

[English](README.md)


### 示例

输入：

```
Oct 23 11:02:41 web-prod-01 sshd[2211]: Accepted publickey for alice from 203.0.113.45 port 52144 ssh2: ED25519 SHA256:Xb3kq9Lw2mR7uT0yVv1zN4pQ8sJ6hF5dC2aE0gB9iKo
Oct 23 11:02:43 web-prod-01 app[880]: login ok user=alice@acme-corp.internal token=9f8e7d6c5b4a39281706aa31 mac=52:54:00:12:34:56
Oct 23 11:02:44 web-prod-01 bash[999]: mysql -u root -pHunter2Secret -h db.acme-corp.internal
```

`logblur app.log`（默认级别和打码方式）：

```
Oct 23 11:02:41 ░░░░░░░░░░░ sshd[2211]: Accepted publickey for ░░░░░ from ░░░░░░░░░░░░ port 52144 ssh2: ED25519 SHA256:░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
Oct 23 11:02:43 ░░░░░░░░░░░ app[880]: login ok user=░░░░░░░░░░░░░░░░░░░░░░░░ token=░░░░░░░░░░░░░░░░░░░░░░░░ mac=░░░░░░░░░░░░░░░░░
Oct 23 11:02:44 ░░░░░░░░░░░ bash[999]: mysql -u root -p░░░░░░░░░░░░░ -h ░░░░░░░░░░░░░░░░░░░░░
```

`logblur -m pseudo --salt demo app.log` 让日志保持可读：同一个值总是变成同一个假名，所以仍然
能顺着一台主机或一个用户读下去。

```
Oct 23 11:02:41 HOST_4eq4e4is sshd[2211]: Accepted publickey for USER_ehw6hsjg from IP_vscvpx4y port 52144 ssh2: ED25519 SHA256:SSHKEY_rose4dng
Oct 23 11:02:43 HOST_4eq4e4is app[880]: login ok user=EMAIL_yhy2rit3 token=PWD_edv2peyp mac=MAC_misb2tuf
Oct 23 11:02:44 HOST_4eq4e4is bash[999]: mysql -u root -pPWD_v3565g2m -h HOST_k2lucjld
```


### 为什么用 logblur？

* 直接处理整个压缩包。把用户附在 bug 报告里的 `.tar.gz` 交给它，拿回一个目录结构相同的
  `.tar.gz`，里面轮转出来的 `.gz` 日志也会一并清洗。压缩包内的文件名同样会被清洗。
* 未清洗的内容不落盘。没有“先解压到临时目录”这一步，也就不会忘了删。
* 了解 Linux 日志长什么样：sshd、PAM、sudo、cron、systemd、内核、wpa_supplicant、Web
  服务器访问日志和 shell 历史，共 31 个类别、75 条规则。
* 会学习。第一遍先从容易识别的位置（比如 `Accepted publickey for alice`）收集用户名和主机名，
  第二遍在整个压缩包里把它们全部打码，包括规则本来认不出来的地方。
* 避开常见误报：长得像 IP 的版本号、长得像域名的文件名、uid、公共 DNS 服务器和知名基础设施
  域名都不会被打码。
* 用四个安全级别决定藏多少，用八种打码方式决定怎么藏，从 `░░░░` 到一致的假名和加盐哈希。
* 支持非 UTF-8 文本。自动识别每个文件的编码（GBK、Shift_JIS、windows-1252 等），输出时保持
  原编码。
* 快，而且有上限。条目在所有核心上并行扫描，大文件分块流式处理，内存占用控制在预算之内（默认
  为可用内存的 70%）。
* 告诉你它做了什么。每次运行后给出摘要，还可以输出 JSON 或 Markdown 报告，列出每个条目、
  各类别打码了多少，以及哪些内容*没能*清洗。
* 提供桌面应用 `logblur-gui`，适合更习惯把文件拖进窗口的人。


### 什么时候不该用 logblur？

logblur 基于模式匹配。它只能找出规则和你的允许、拒绝名单描述得到的东西。如果某个秘密的格式
没有任何规则认识，它就会原样漏过去。公开之前一定要亲自看一遍输出，`logblur preview` 和
`--report` 可以帮你省些力气。

下面这些会在报告里列出，但故意不清洗：

* 二进制文件，包括 systemd 日志文件（`*.journal`）和 `wtmp`/`btmp`/`lastlog`。它们会被原样
  复制，或者用 `--binary drop` 丢弃。请先导出为文本，比如用 `journalctl -o short-iso` 或
  `last -f`。
* 压缩包里嵌套的压缩包。
* 加密的 zip 条目。


### 安装

需要 [Rust 工具链](https://rustup.rs)（1.95 或更新）：

```
$ cargo install logblur          # 命令行工具
$ cargo install logblur-gui      # 桌面应用
```

每个 [release](https://github.com/HiroGitea/logblur/releases) 都附有预编译的二进制文件。


### 用法

```
$ logblur logs.zip                        # 在旁边生成 logs.blurred.zip
$ logblur -l 4 -m pseudo --salt s3 logs.tar.gz
$ logblur logs.tar.gz -o clean.zip        # 清洗的同时转换格式
$ logblur /var/log --out-dir ~/shared     # 整个文件夹
$ journalctl -b | logblur - > boot.txt    # 从标准输入到标准输出
$ logblur logs.zip --report md            # 同时写一份 Markdown 报告
$ logblur preview logs.zip -n 30          # 写出任何东西之前先看看
$ logblur rules list --all                # 所有规则和类别
$ logblur rules test "Accepted publickey for alice from 203.0.113.5"
```

全部选项见 `logblur --help`。退出码：`0` 成功，`1` 用法或配置错误，`2` 处理失败，`3` 已取消。


### 安全级别

每个级别都包含比它低的级别。用 `-l`/`--level` 选择。

| 级别 | 名称       | 打码内容                                                          |
|------|------------|-------------------------------------------------------------------|
| 1    | 凭据       | 口令、密钥、令牌、私钥、连接串、cookie                            |
| 2    | 身份       | + 邮箱、手机号、身份证号和银行卡号、车牌、SSH 密钥、坐标          |
| 3    | 网络与设备 | + IP / MAC 地址、主机名和用户名、UUID、序列号、Wi-Fi 名称（**默认**） |
| 4    | 偏执       | + 硬件 ID、User-Agent、完整 URL、长数字 / 十六进制 / base64       |

用 `--only`、`--enable`、`--skip` 单独调整某些类别，类别 id 见 `logblur rules list`。


### 打码方式

用 `-m`/`--mask` 选择。

| 方式      | `203.0.113.45` 变成     | 说明                                                |
|-----------|-------------------------|-----------------------------------------------------|
| `block`   | `░░░░░░░░░░░░`          | 默认。保留长度；字符用 `--mask-char` 指定           |
| `fixed`   | `░░░░░░`                | 隐藏长度                                            |
| `star`    | `************`          |                                                     |
| `tag`     | `[IPV4]`                |                                                     |
| `pseudo`  | `IP_vscvpx4y`           | 相同输入得到相同假名；`--counter` 得到 `IP_1`、`IP_2`…… |
| `partial` | `203.░.░░░.░░`          | 保留第一段、邮箱的域名、数字的后 4 位               |
| `remove`  | （空）                  |                                                     |
| `hash`    | `ac8557df98b2`          | 加盐哈希；长度由 `hash_len` 决定                    |

多次运行时使用同一个 `--salt`，不同压缩包里就会得到相同的假名。


### 配置

所有选项也可以写进 TOML 文件：

```
$ logblur config init -o logblur.toml     # 带注释的模板
$ logblur -c logblur.toml logs.zip
```

命令行选项优先于文件。除了上面的选项，文件里还可以写自定义规则（一个正则表达式加上要打码的
捕获组）。

**允许名单。** 永远不打码的值：精确文本、`*.example.org`、`prefix*`、`203.0.113.0/24` 这样的
CIDR 网段，或 `re:正则`。`--allow @FILE` 从文件逐行读取。

**拒绝名单。** 无论出现在哪里都要打码的词，比如公司名或项目名：普通文本（不区分大小写）或
`re:正则`。

```
$ logblur logs.zip --allow '*.mirror.example.org' --deny 'Acme Corp' --keep-private-ips
```


### 语言

界面支持英文和简体中文。logblur 依次参考 `--lang`、`LOGBLUR_LANG`、`LANGUAGE`、`LC_ALL`、
`LC_MESSAGES` 和 `LANG`。翻译是 TOML 文件，额外的翻译会从 `$LOGBLUR_LOCALE_DIR` 或
`~/.local/share/logblur/locales` 加载。


### 构建

```
$ git clone https://github.com/HiroGitea/logblur
$ cd logblur
$ cargo build --release
$ ./target/release/logblur --version
```

`cargo build` 会构建库和命令行工具，加上 `-p logblur-gui` 构建桌面应用。用
`cargo test --workspace` 运行测试。

项目分为三个 crate：

* [`logblur-core`](crates/logblur-core)：库，包括规则、压缩包处理和清洗流水线。
* [`logblur`](crates/logblur)：命令行工具。
* [`logblur-gui`](crates/logblur-gui)：桌面应用（egui）。


### 许可证

可任选以下之一：

* Apache License, Version 2.0（[LICENSE-APACHE](LICENSE-APACHE) 或
  <https://www.apache.org/licenses/LICENSE-2.0>）
* MIT license（[LICENSE-MIT](LICENSE-MIT) 或 <https://opensource.org/licenses/MIT>）

除非你明确声明，否则你有意提交并纳入本项目的任何贡献（按 Apache-2.0 许可证的定义），都将按上述
方式双重许可，不附加任何其他条款或条件。
