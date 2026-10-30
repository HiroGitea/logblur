logblur
=======

分享 Linux 日志之前，先用 logblur 过一遍。它会把口令、密钥、令牌、IP 和 MAC 地址、邮箱、用户名、主机名等敏感信息打上码。`.zip`、`.tar`、`.tar.gz`、`.gz` 压缩包，单个文件、整个文件夹和标准输入都能处理，输出格式和输入保持一致。整个过程在内存中完成，未脱敏的明文不会写到磁盘上。

[![CI](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml/badge.svg)](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/logblur.svg)](https://crates.io/crates/logblur)
[![docs.rs](https://img.shields.io/docsrs/logblur-core)](https://docs.rs/logblur-core)

采用 MIT 或 [Apache License 2.0](LICENSE-APACHE) 双许可证。

[English](README.md)


### 示例

原始日志：

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

如果还想读懂日志，可以用假名模式 `logblur -m pseudo --salt demo app.log`。同一个值永远对应同一个假名，某台主机、某个用户的行踪照样能追下去：

```
Oct 23 11:02:41 HOST_4eq4e4is sshd[2211]: Accepted publickey for USER_ehw6hsjg from IP_vscvpx4y port 52144 ssh2: ED25519 SHA256:SSHKEY_rose4dng
Oct 23 11:02:43 HOST_4eq4e4is app[880]: login ok user=EMAIL_yhy2rit3 token=PWD_edv2peyp mac=MAC_misb2tuf
Oct 23 11:02:44 HOST_4eq4e4is bash[999]: mysql -u root -pPWD_v3565g2m -h HOST_k2lucjld
```


### 为什么选 logblur？

* **整包处理。** 用户在 bug 报告里附了个 `.tar.gz`？直接丢给它，拿回来的还是一个目录结构不变的 `.tar.gz`。里面轮转出来的 `.gz` 日志一并处理，连包内的文件名也会脱敏。
* **明文不落盘。** 不需要“先解压到临时目录”，自然也不存在忘了删的风险。
* **懂 Linux 日志。** sshd、PAM、sudo、cron、systemd、内核、wpa_supplicant、Web 服务器访问日志、shell 历史……内置 78 条规则，覆盖 31 个类别。
* **会举一反三。** 第一遍先从格式明确的地方（比如 `Accepted publickey for alice`）收集用户名和主机名，第二遍再把它们在整个压缩包里出现的地方统统打码，规则本身认不出的位置也逃不掉。
* **少误伤。** 形似 IP 的版本号、形似域名的文件名、uid、公共 DNS、知名基础设施域名，都会原样保留。
* **收放自如。** 四档安全级别决定藏多少，八种打码方式决定怎么藏：从 `░░░░` 到稳定的假名，再到加盐哈希。
* **不挑编码。** 自动识别每个文件的编码（GBK、Shift_JIS、windows-1252 等），输出时保留原编码。
* **又快又省。** 性能经过专门优化：用 SIMD 关键词预筛选跳过不可能命中的规则，其余规则只扫描可能命中的行；多核并行扫描，大文件分块流式处理，`.gz` / `.tar.gz` 输出也用所有核心并行压缩。内存占用不超出预算（默认是可用内存的 70%）。
* **处理结果一目了然。** 每次运行都会给出摘要；还可以生成 JSON 或 Markdown 报告，逐个列出文件、各类别的打码数量，以及哪些内容*没能*处理。
* **有图形界面。** 不想敲命令？`logblur-gui` 支持把文件直接拖进窗口。


### 什么时候不该用 logblur？

logblur 靠模式匹配工作，只能找出规则以及你的允许、拒绝名单所描述的内容。格式没被任何规则覆盖的秘密，会原封不动地漏过去。所以公开之前，请务必亲自检查一遍输出；`logblur preview` 和 `--report` 能帮你省不少事。

以下内容会在报告中标出，但有意不做处理：

* 二进制文件，包括 systemd 日志（`*.journal`）和 `wtmp`/`btmp`/`lastlog`。默认原样复制，也可以用 `--binary drop` 丢弃。建议先用 `journalctl -o short-iso` 或 `last -f` 导出成文本再处理。
* 压缩包里嵌套的压缩包。
* 加密的 zip 条目。


### 安装

需要 [Rust 工具链](https://rustup.rs) 1.95 或更新版本：

```
$ cargo install logblur          # 命令行工具
$ cargo install logblur-gui      # 桌面应用
```

也可以直接从 [Releases](https://github.com/HiroGitea/logblur/releases) 页面下载预编译的二进制文件。


### 用法

```
$ logblur logs.zip                        # 在同目录生成 logs.blurred.zip
$ logblur -l 4 -m pseudo --salt s3 logs.tar.gz
$ logblur logs.tar.gz -o clean.zip        # 脱敏的同时转换格式
$ logblur /var/log --out-dir ~/shared     # 处理整个文件夹
$ journalctl -b | logblur - > boot.txt    # 标准输入进，标准输出出
$ tail -f app.log | logblur --line-buffered -
$ logblur logs.zip --report md            # 顺便生成 Markdown 报告
$ logblur preview logs.zip -n 30          # 先预览，不写任何文件
$ logblur rules list --all                # 列出所有规则和类别
$ logblur rules test "Accepted publickey for alice from 203.0.113.5"
```

完整选项见 `logblur --help`。退出码：`0` 成功，`1` 用法或配置错误，`2` 处理失败，`3` 已取消。


### 实时日志

默认情况下，logblur 会读完全部标准输入再统一输出。加上 `--line-buffered` 后，每行打完码立即输出，可以直接接在 `tail -f`、`journalctl -f`、`kubectl logs -f` 后面：

```
$ journalctl -f | logblur --line-buffered -
```

这个模式下没有学习阶段，也不生成报告，输入按 UTF-8 读取。跨多行的私钥照样会被打码，每到一行处理一行。同时到达的多行会并行处理。

如果有很多程序同时产生日志，请给每个程序各接一个 logblur，或者先用 journald、rsyslog 把日志收集起来，再处理汇总后的流。不要让它们往同一个管道里写：很多程序往管道输出时是按块写、而不是按行写，而且只有不超过 4 KiB 的单次写入才保证不被打断，所以不同程序的行可能被拼接在一起，被拆成两半的值就可能认不出来。


### 安全级别

高级别包含低级别的全部内容，用 `-l`/`--level` 指定。

| 级别 | 名称       | 打码内容                                                          |
|------|------------|-------------------------------------------------------------------|
| 1    | 凭据       | 口令、密钥、令牌、私钥、连接串、Cookie                            |
| 2    | 身份       | + 邮箱、电话、证件号、银行卡、车牌、SSH 公钥、经纬度              |
| 3    | 网络与设备 | + IP / MAC 地址、主机名、用户名、UUID、序列号、Wi-Fi 名称（**默认**） |
| 4    | 偏执       | + 硬件标识、User-Agent、整条 URL、长数字 / 十六进制 / base64 串   |

想单独开关某些类别，可以用 `--only`、`--enable`、`--skip`；类别 id 用 `logblur rules list` 查看。


### 打码方式

用 `-m`/`--mask` 指定。

| 方式      | `203.0.113.45` 会变成   | 说明                                                |
|-----------|-------------------------|-----------------------------------------------------|
| `block`   | `░░░░░░░░░░░░`          | 默认。保留原长度；字符可用 `--mask-char` 更换       |
| `fixed`   | `░░░░░░`                | 固定宽度，不暴露原长度                              |
| `star`    | `************`          |                                                     |
| `tag`     | `[IPV4]`                |                                                     |
| `pseudo`  | `IP_vscvpx4y`           | 同值同假名；加 `--counter` 则编号为 `IP_1`、`IP_2`…… |
| `partial` | `203.░.░░░.░░`          | 保留 IP 第一段、邮箱域名、数字末 4 位               |
| `remove`  | （直接删除）            |                                                     |
| `hash`    | `ac8557df98b2`          | 加盐哈希，长度由 `hash_len` 设置                    |

每次都用同一个 `--salt`，不同批次的压缩包也会得到相同的假名，方便交叉比对。


### 配置

所有选项都可以写进 TOML 配置文件：

```
$ logblur config init -o logblur.toml     # 生成带注释的模板
$ logblur -c logblur.toml logs.zip
```

命令行参数优先于配置文件。配置文件里还能写自定义规则：一个正则表达式，加上要打码的捕获组。

**允许名单**：永远不打码的值。支持精确文本、`*.example.org`、`prefix*`、`203.0.113.0/24` 这样的 CIDR 网段，以及 `re:正则`。用 `--allow @FILE` 可以从文件逐行读入。

**拒绝名单**：不管出现在哪里都要打码的词，比如公司名、项目代号。支持普通文本（不区分大小写）和 `re:正则`。

```
$ logblur logs.zip --allow '*.mirror.example.org' --deny 'Acme Corp' --keep-private-ips
```


### 界面语言

目前支持英文和简体中文。语言按以下顺序确定：`--lang`、`LOGBLUR_LANG`、`LANGUAGE`、`LC_ALL`、`LC_MESSAGES`、`LANG`。翻译文件是 TOML 格式，额外的翻译放在 `$LOGBLUR_LOCALE_DIR` 或 `~/.local/share/logblur/locales` 下即可加载。


### 从源码构建

```
$ git clone https://github.com/HiroGitea/logblur
$ cd logblur
$ cargo build --release
$ ./target/release/logblur --version
```

`cargo build` 默认构建库和命令行工具，桌面应用需要加 `-p logblur-gui`。运行测试用 `cargo test --workspace`。

项目由三个 crate 组成：

* [`logblur-core`](crates/logblur-core)：核心库，包含规则、压缩包读写和脱敏流水线。
* [`logblur`](crates/logblur)：命令行工具。
* [`logblur-gui`](crates/logblur-gui)：桌面应用（基于 egui）。


### 许可证

本项目可任选以下任一许可证使用：

* Apache License, Version 2.0（[LICENSE-APACHE](LICENSE-APACHE) 或 <https://www.apache.org/licenses/LICENSE-2.0>）
* MIT license（[LICENSE-MIT](LICENSE-MIT) 或 <https://opensource.org/licenses/MIT>）

除非你另行声明，你有意提交并被纳入本项目的任何贡献（定义见 Apache-2.0 许可证），均按上述方式双重许可，不附加任何额外条款或条件。
