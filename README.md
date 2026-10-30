logblur
=======

logblur scrubs sensitive data — passwords, keys, tokens, IP and MAC addresses,
e-mails, user and host names — from Linux log archives before you share them.
It reads `.zip`, `.tar`, `.tar.gz` and `.gz` archives, plain files, directories
and standard input, and writes a scrubbed copy in the same format. Unscrubbed
text is decompressed, scanned and re-compressed in memory; it is never written
to disk.

[![CI](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml/badge.svg)](https://github.com/HiroGitea/logblur/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/logblur.svg)](https://crates.io/crates/logblur)
[![docs.rs](https://img.shields.io/docsrs/logblur-core)](https://docs.rs/logblur-core)

Dual-licensed under MIT or the [Apache License 2.0](LICENSE-APACHE).

[中文说明](README.zh-CN.md)


### Example

Input:

```
Oct 23 11:02:41 web-prod-01 sshd[2211]: Accepted publickey for alice from 203.0.113.45 port 52144 ssh2: ED25519 SHA256:Xb3kq9Lw2mR7uT0yVv1zN4pQ8sJ6hF5dC2aE0gB9iKo
Oct 23 11:02:43 web-prod-01 app[880]: login ok user=alice@acme-corp.internal token=9f8e7d6c5b4a39281706aa31 mac=52:54:00:12:34:56
Oct 23 11:02:44 web-prod-01 bash[999]: mysql -u root -pHunter2Secret -h db.acme-corp.internal
```

`logblur app.log` (default level and mask):

```
Oct 23 11:02:41 ░░░░░░░░░░░ sshd[2211]: Accepted publickey for ░░░░░ from ░░░░░░░░░░░░ port 52144 ssh2: ED25519 SHA256:░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
Oct 23 11:02:43 ░░░░░░░░░░░ app[880]: login ok user=░░░░░░░░░░░░░░░░░░░░░░░░ token=░░░░░░░░░░░░░░░░░░░░░░░░ mac=░░░░░░░░░░░░░░░░░
Oct 23 11:02:44 ░░░░░░░░░░░ bash[999]: mysql -u root -p░░░░░░░░░░░░░ -h ░░░░░░░░░░░░░░░░░░░░░
```

`logblur -m pseudo --salt demo app.log` keeps the logs readable: the same value
always becomes the same pseudonym, so you can still follow one host or user
through the file.

```
Oct 23 11:02:41 HOST_4eq4e4is sshd[2211]: Accepted publickey for USER_ehw6hsjg from IP_vscvpx4y port 52144 ssh2: ED25519 SHA256:SSHKEY_rose4dng
Oct 23 11:02:43 HOST_4eq4e4is app[880]: login ok user=EMAIL_yhy2rit3 token=PWD_edv2peyp mac=MAC_misb2tuf
Oct 23 11:02:44 HOST_4eq4e4is bash[999]: mysql -u root -pPWD_v3565g2m -h HOST_k2lucjld
```


### Why should I use logblur?

* It works on whole archives. Hand it the `.tar.gz` a user attached to a bug
  report and get back a `.tar.gz` with the same layout, rotated `.gz` logs
  inside it included. File names inside the archive are scrubbed too.
* Nothing unscrubbed touches the disk. There is no "extract to a temp
  directory" step to forget to clean up.
* It knows what Linux logs look like: sshd, PAM, sudo, cron, systemd, the kernel,
  wpa_supplicant, web server access logs and shell history, with 78 rules in 31
  categories.
* It learns. A first pass collects the user and host names it finds in
  well-understood places (such as `Accepted publickey for alice`) and then masks
  them everywhere else in the archive, where no rule would have recognized them.
* It avoids the usual false positives: version numbers that look like IP
  addresses, file names that look like domains, uids, public DNS servers and
  well-known infrastructure domains are left alone.
* Pick how much to hide with four security levels, and how to hide it with
  eight mask modes, from `░░░░` to consistent pseudonyms and salted hashes.
* It handles text that isn't UTF-8. The encoding of each file is detected
  (GBK, Shift_JIS, windows-1252, …) and preserved in the output.
* It is fast and bounded. Performance has been optimized: a SIMD keyword
  prefilter skips rules that cannot match and narrows the rest to the lines
  that can, every core scans in parallel, large files are streamed in chunks,
  and `.gz` / `.tar.gz` output is compressed on all cores. Memory use stays
  within a budget (70% of available memory by default).
* It tells you what it did. A summary after each run, and optionally a JSON or
  Markdown report listing every entry, what was masked by category, and what
  could *not* be scrubbed.
* There is a desktop app, `logblur-gui`, for people who would rather drag a
  file into a window.


### Why shouldn't I use logblur?

logblur is pattern-based. It catches what its rules and your allow and deny
lists describe, and nothing else. A secret written in a format no rule knows
about will go through. Always read the output before you publish it, and use
`logblur preview` and `--report` to make that easier.

Some things are reported but deliberately not scrubbed:

* Binary files, including systemd journal files (`*.journal`) and
  `wtmp`/`btmp`/`lastlog`. They are copied unchanged, or dropped with
  `--binary drop`. Export them as text first, for example with
  `journalctl -o short-iso` or `last -f`.
* Archives nested inside the archive.
* Encrypted zip entries.


### Installation

With a [Rust toolchain](https://rustup.rs) (1.95 or newer):

```
$ cargo install logblur          # command-line tool
$ cargo install logblur-gui      # desktop app
```

Prebuilt binaries are attached to each
[release](https://github.com/HiroGitea/logblur/releases).


### Usage

```
$ logblur logs.zip                        # writes logs.blurred.zip next to it
$ logblur -l 4 -m pseudo --salt s3 logs.tar.gz
$ logblur logs.tar.gz -o clean.zip        # convert while scrubbing
$ logblur /var/log --out-dir ~/shared     # a whole directory
$ journalctl -b | logblur - > boot.txt    # standard input to standard output
$ tail -f app.log | logblur --line-buffered -
$ logblur logs.zip --report md            # also write a Markdown report
$ logblur preview logs.zip -n 30          # look before you write anything
$ logblur rules list --all                # every rule and category
$ logblur rules test "Accepted publickey for alice from 203.0.113.5"
```

Run `logblur --help` for every option. Exit codes: `0` success, `1` usage or
configuration error, `2` processing failed, `3` cancelled.


### Live logs

By default logblur reads all of standard input before it writes anything. With
`--line-buffered` each line is written as soon as it has been scrubbed, so it
can sit at the end of `tail -f`, `journalctl -f` or `kubectl logs -f`:

```
$ journalctl -f | logblur --line-buffered -
```

In this mode there is no learning pass and no report, and input is read as
UTF-8. Multi-line private keys are still masked, line by line as they arrive.
Lines that arrive together are scrubbed in parallel.

When many programs produce logs at once, give each one its own logblur, or
collect their logs first (journald, rsyslog) and scrub the collected stream. Do
not let them all write into one pipe. Many programs write to a pipe in blocks
rather than whole lines, and only writes of up to 4 KiB are kept in one piece,
so lines from different programs can be spliced together, and a value split in
two may not be recognized.


### Security levels

Each level includes everything below it. Select one with `-l`/`--level`.

| Level | Name              | Masks                                                                       |
|-------|-------------------|-----------------------------------------------------------------------------|
| 1     | Credentials       | Passwords, keys, tokens, private keys, connection strings, cookies          |
| 2     | Identity          | + e-mail, phone, ID and card numbers, licence plates, SSH keys, coordinates  |
| 3     | Network & devices | + IP / MAC addresses, host and user names, UUIDs, serial numbers, Wi-Fi names (**default**) |
| 4     | Paranoid          | + hardware IDs, User-Agents, whole URLs, long numbers / hex / base64        |

Fine-tune individual categories with `--only`, `--enable` and `--skip`;
`logblur rules list` shows their ids.


### Mask modes

Select one with `-m`/`--mask`.

| Mode      | `203.0.113.45` becomes  | Notes                                               |
|-----------|-------------------------|-----------------------------------------------------|
| `block`   | `░░░░░░░░░░░░`          | Default. Keeps the length; character set with `--mask-char` |
| `fixed`   | `░░░░░░`                | Hides the length                                    |
| `star`    | `************`          |                                                     |
| `tag`     | `[IPV4]`                |                                                     |
| `pseudo`  | `IP_vscvpx4y`           | Same input, same pseudonym; `--counter` gives `IP_1`, `IP_2`, … |
| `partial` | `203.░.░░░.░░`          | Keeps the first octet, an e-mail's domain, the last 4 digits of numbers |
| `remove`  | (empty)                 |                                                     |
| `hash`    | `ac8557df98b2`          | Salted hash; length set by `hash_len`               |

Use the same `--salt` across runs to get the same pseudonyms in different
archives.


### Configuration

Every option can also live in a TOML file:

```
$ logblur config init -o logblur.toml     # commented template
$ logblur -c logblur.toml logs.zip
```

Command-line options override the file. Besides the options above, the file
can hold custom rules (a regex plus the capture group to mask).

**Allow list.** Values that must never be masked: exact text, `*.example.org`,
`prefix*`, CIDR ranges such as `203.0.113.0/24`, or `re:REGEX`. Pass
`--allow @FILE` to read one entry per line.

**Deny list.** Words that are always masked wherever they appear, such as a
company or project name: plain text (case-insensitive) or `re:REGEX`.

```
$ logblur logs.zip --allow '*.mirror.example.org' --deny 'Acme Corp' --keep-private-ips
```


### Language

The interface is available in English and Simplified Chinese. logblur follows
`--lang`, then `LOGBLUR_LANG`, `LANGUAGE`, `LC_ALL`, `LC_MESSAGES` and `LANG`.
Translations are TOML files; extra ones are loaded from
`$LOGBLUR_LOCALE_DIR` or `~/.local/share/logblur/locales`.


### Building

```
$ git clone https://github.com/HiroGitea/logblur
$ cd logblur
$ cargo build --release
$ ./target/release/logblur --version
```

`cargo build` builds the library and the command-line tool; add
`-p logblur-gui` for the desktop app. Run the tests with `cargo test --workspace`.

The project is split into three crates:

* [`logblur-core`](crates/logblur-core): the library: rules, archive
  handling and the scrubbing pipeline.
* [`logblur`](crates/logblur): the command-line tool.
* [`logblur-gui`](crates/logblur-gui): the desktop app (egui).


### License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
