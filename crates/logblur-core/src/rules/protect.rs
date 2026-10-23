//! Protected ranges: text such as version numbers and timestamps that "looks sensitive but isn't".
//! Rules marked `protect` (IPv4, long numbers, hex, phone numbers, etc.) do not mask candidates that overlap a
//! protected range. Over-masking beats under-masking: forms like `host-10.0.0.1`, where a version number cannot be told
//! apart from an IP, are not protected. All patterns are compiled in multi-line mode, so `^` means start of line.

/// (description, regex)
pub const PROTECT_PATTERNS: &[(&str, &str)] = &[
    (
        "关键词后的版本号：version 1.2.3.4、jdk 17.0.0.1、firmware: 2.10.0.4",
        r"(?i)(?:^|[^A-Za-z0-9_])(?:version|ver|release|build|jdk|jre|java|openssl|firmware|fw|bios|rev|revision|kernel version|ver\.)[ \t]*[:=/_\-]?[ \t]*v?[0-9]+(?:\.[0-9]+){1,4}",
    ),
    ("v 前缀版本号：v1.2.3.4", r"(?:^|[^A-Za-z0-9_])[vV][0-9]+(?:\.[0-9]+){1,4}"),
    (
        "ISO 8601 时间",
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?",
    ),
    ("syslog 时间", r"[A-Z][a-z]{2}[ \t]+[0-9]{1,2}[ \t]+[0-9]{2}:[0-9]{2}:[0-9]{2}"),
    ("dmesg 时间戳 [  12.345678]", r"\[[ \t]*[0-9]+\.[0-9]+\]"),
    (
        "Unix 时间戳（2017–2033，秒/毫秒/微秒）",
        r"(?:^|[^0-9])1[5-9][0-9]{8}(?:[0-9]{3}){0,2}(?:\.[0-9]{1,9})?(?:[^0-9]|$)",
    ),
    (
        "紧凑日期 20261023 / 20261023T101112",
        r"(?:^|[^0-9])20[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[T_\-]?[0-9]{6})?(?:[^0-9]|$)",
    ),
];
