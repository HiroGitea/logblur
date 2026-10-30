//! Validators and trailing boundary checks.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::Cand;

// ───────────────────────── Trailing boundary ─────────────────────────

#[inline]
fn first(rest: &[u8]) -> Option<u8> {
    rest.first().copied()
}

#[inline]
fn second(rest: &[u8]) -> Option<u8> {
    rest.get(1).copied()
}

/// Not followed by an alphanumeric character.
pub fn after_not_alnum(rest: &[u8]) -> bool {
    !matches!(first(rest), Some(b) if b.is_ascii_alphanumeric())
}

/// Not followed by an alphanumeric character or underscore.
pub fn after_not_word(rest: &[u8]) -> bool {
    !matches!(first(rest), Some(b) if b.is_ascii_alphanumeric() || b == b'_')
}

/// Numeric targets: not followed by an alphanumeric character, nor by a `.` / `-` / `,` immediately followed by a
/// digit (avoids cutting off a longer digit string).
pub fn after_number(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() => false,
        Some(b'.' | b'-' | b',') => !matches!(second(rest), Some(d) if d.is_ascii_digit()),
        _ => true,
    }
}

/// IPv4: not followed by an alphanumeric character or `_`, nor by `.` + an alphanumeric character (as in a version
/// number like 1.2.3.4.5 or a host name like 1.2.3.4.example).
pub fn after_ipv4(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' => false,
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_alphanumeric()),
        _ => true,
    }
}

/// IPv6: not followed by an alphanumeric character or `_`, nor by `:` + hex or `:` (a longer address), nor by
/// `.` + digit (an embedded IPv4 tail).
pub fn after_ipv6(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' => false,
        Some(b':') => !matches!(second(rest), Some(d) if d.is_ascii_hexdigit() || d == b':'),
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_digit()),
        _ => true,
    }
}

/// MAC: not followed by hex, nor by `:`/`-` + hex (a longer EUI sequence).
pub fn after_mac(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() => false,
        Some(b':' | b'-') => !matches!(second(rest), Some(d) if d.is_ascii_hexdigit()),
        _ => true,
    }
}

/// Hostname: not followed by a label character, nor by `.` + alphanumeric.
pub fn after_host(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' => false,
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_alphanumeric()),
        _ => true,
    }
}

/// Email: same as hostname.
pub fn after_email(rest: &[u8]) -> bool {
    after_host(rest)
}

// ───────────────────────── General ─────────────────────────

fn is_placeholder(v: &str) -> bool {
    let t = v.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
    if t.is_empty() {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "null",
        "(null)",
        "nil",
        "none",
        "undefined",
        "true",
        "false",
        "n/a",
        "na",
        "redacted",
        "<redacted>",
        "[redacted]",
        "(redacted)",
        "hidden",
        "<hidden>",
        "masked",
        "<masked>",
        "secret",
        "password",
        "changeme",
        "xxx",
        "xxxx",
        "-",
        "--",
        "?",
        "{}",
        "[]",
        "<none>",
        "(none)",
        "empty",
        "unset",
        "not set",
        "<secret>",
        "filtered",
        "[filtered]",
        "***",
        "<password>",
        "your_password",
        "yourpassword",
        "<token>",
        "your_token",
        "...",
        "…",
    ];
    if WORDS.contains(&lower.as_str()) {
        return true;
    }
    // Already masked
    if t.chars().all(|c| matches!(c, '*' | '░' | '▒' | '▓' | '█' | 'x' | 'X' | '#' | '•' | '·')) {
        return true;
    }
    // Template variables
    t.starts_with("${")
        || t.starts_with("{{")
        || t.starts_with("%(")
        || t.starts_with("$(")
        || t.starts_with('<') && t.ends_with('>')
}

/// Password/secret value: excludes placeholders, template variables and sudo's `PWD=/path`.
pub fn secret_value(c: &Cand) -> bool {
    if is_placeholder(c.payload) {
        return false;
    }
    // PWD=/home/x in sudo logs is the working directory, not a password
    if c.payload.starts_with('/') && c.whole.contains("PWD=") {
        return false;
    }
    true
}

/// Token: at least 8 characters and not a placeholder.
pub fn token_value(c: &Cand) -> bool {
    c.payload.chars().count() >= 8 && !is_placeholder(c.payload)
}

pub fn not_placeholder(c: &Cand) -> bool {
    !is_placeholder(c.payload)
}

fn digits(s: &str) -> Vec<u8> {
    s.bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect()
}

pub fn luhn(d: &[u8]) -> bool {
    if d.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &x) in d.iter().rev().enumerate() {
        let mut v = x as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Separators are either absent or all identical.
fn consistent_separators(s: &str) -> bool {
    let mut sep: Option<char> = None;
    for ch in s.chars().filter(|c| !c.is_ascii_digit()) {
        match sep {
            None => sep = Some(ch),
            Some(p) if p != ch => return false,
            _ => {}
        }
    }
    true
}

/// Separated card numbers are printed in groups of four (the last may be shorter) or as Amex 4-6-5 / 4-6-4; other
/// groupings are separate numbers that happen to sit next to each other, such as `202503 202610 16`.
fn card_grouping(s: &str) -> bool {
    let groups: Vec<usize> = s.split(|ch: char| !ch.is_ascii_digit()).map(str::len).collect();
    match groups.as_slice() {
        [_] => true,
        [4, 6, 4 | 5] => true,
        [init @ .., last] => init.iter().all(|&n| n == 4) && (1..=4).contains(last),
        [] => false,
    }
}

/// Bank card: 13–19 digits, passes Luhn, consistent separators grouped like a card, not all the same digit.
pub fn bank_card(c: &Cand) -> bool {
    let d = digits(c.payload);
    if !(13..=19).contains(&d.len()) || !consistent_separators(c.payload) || !card_grouping(c.payload) {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    luhn(&d)
}

/// Card/account number with keyword context: 12–19 digits suffice (some Chinese debit cards fail Luhn).
pub fn account_number(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (12..=19).contains(&n)
}

/// Check digit of the 18-digit Chinese resident ID number (GB 11643-1999).
pub fn cn_id(c: &Cand) -> bool {
    let b = c.payload.as_bytes();
    if b.len() != 18 {
        return false;
    }
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: &[u8; 11] = b"10X98765432";
    let mut sum = 0u32;
    for i in 0..17 {
        if !b[i].is_ascii_digit() {
            return false;
        }
        sum += (b[i] - b'0') as u32 * W[i];
    }
    CHECK[(sum % 11) as usize] == b[17].to_ascii_uppercase()
}

/// US SSN: area is not 000/666/9xx, group is not 00, serial is not 0000.
pub fn ssn(c: &Cand) -> bool {
    let p: Vec<&str> = c.payload.split('-').collect();
    if p.len() != 3 {
        return false;
    }
    let area = p[0];
    !(area == "000" || area == "666" || area.starts_with('9') || p[1] == "00" || p[2] == "0000")
}

/// IBAN mod-97 check.
pub fn iban(c: &Cand) -> bool {
    let s: Vec<u8> = c.payload.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let mut rem: u32 = 0;
    for &b in s[4..].iter().chain(s[..4].iter()) {
        let v = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'A'..=b'Z' => (b - b'A') as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

pub fn ipv4(c: &Cand) -> bool {
    c.payload.parse::<Ipv4Addr>().is_ok()
}

pub fn ipv6(c: &Cand) -> bool {
    let addr = c.payload.split('%').next().unwrap_or("");
    if addr.matches(':').count() < 2 {
        return false;
    }
    // Plain decimal digits and colons (e.g. a 12:34:56 time) don't count
    if addr.bytes().all(|b| b.is_ascii_digit() || b == b':') && !addr.contains("::") {
        return false;
    }
    match addr.parse::<Ipv6Addr>() {
        Ok(ip) => !ip.is_unspecified(),
        Err(_) => false,
    }
}

/// MAC: consistent separators.
pub fn mac(c: &Cand) -> bool {
    let seps: Vec<u8> = c.payload.bytes().filter(|b| !b.is_ascii_hexdigit()).collect();
    seps.windows(2).all(|w| w[0] == w[1])
}

/// Common file extensions and systemd unit suffixes: must not be treated as top-level domains.
pub const FILE_LIKE_SUFFIXES: &[&str] = &[
    "log",
    "txt",
    "conf",
    "cfg",
    "ini",
    "json",
    "yaml",
    "yml",
    "xml",
    "html",
    "htm",
    "js",
    "ts",
    "css",
    "py",
    "rs",
    "go",
    "c",
    "h",
    "cpp",
    "hpp",
    "cc",
    "java",
    "class",
    "jar",
    "so",
    "dll",
    "exe",
    "sh",
    "bash",
    "zsh",
    "service",
    "socket",
    "target",
    "timer",
    "mount",
    "automount",
    "slice",
    "scope",
    "path",
    "device",
    "swap",
    "network",
    "netdev",
    "link",
    "pid",
    "lock",
    "sock",
    "tmp",
    "bak",
    "gz",
    "zip",
    "tar",
    "xz",
    "bz2",
    "zst",
    "img",
    "iso",
    "deb",
    "rpm",
    "md",
    "rst",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "pdf",
    "csv",
    "tsv",
    "sql",
    "db",
    "sqlite",
    "key",
    "pem",
    "crt",
    "cer",
    "csr",
    "pub",
    "ko",
    "mod",
    "rules",
    "desktop",
    "list",
    "sources",
    "policy",
    "cache",
    "state",
    "journal",
    "old",
    "new",
    "orig",
    "swp",
    "toml",
    "lua",
    "rb",
    "pl",
    "php",
    "jsp",
    "war",
    "properties",
    "gradle",
    "kt",
    "swift",
    "vue",
    "tsx",
    "jsx",
    "mjs",
    "cjs",
    "map",
    "wasm",
    "bin",
    "dat",
    "out",
    "err",
    "d",
    "conf~",
    "rpmnew",
    "rpmsave",
    "dpkg-old",
    "dpkg-new",
    "ucf-dist",
    "lst",
    "repo",
    "env",
    "service~",
    "efi",
    "cpio",
    "vmlinuz",
    "initrd",
    "cmd",
    "bat",
    "ps1",
    "msi",
    "dmg",
    "pkg",
    "app",
    "mp3",
    "mp4",
    "mkv",
    "avi",
    "mov",
    "wav",
    "ttf",
    "otf",
    "woff",
    "woff2",
    "ico",
    "bmp",
    "webp",
    "tiff",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "rtf",
    "epub",
    "md5",
    "sha1",
    "sha256",
    "sig",
    "asc",
    "gpg",
    "pcap",
    "core",
    "dump",
    "trace",
    "prof",
    "test",
    "spec",
    "lockfile",
    "patch",
    "diff",
    "in",
    "am",
    "ac",
];

fn tld_of(host: &str) -> &str {
    host.rsplit('.').next().unwrap_or("")
}

/// Email: the last label of the domain must not be a file extension or systemd unit suffix (e.g. user@1000.service).
pub fn email(c: &Cand) -> bool {
    let Some((local, domain)) = c.payload.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.starts_with('.') || domain.contains("..") {
        return false;
    }
    let tld = tld_of(domain).to_ascii_lowercase();
    if !tld.bytes().all(|b| b.is_ascii_alphabetic()) || FILE_LIKE_SUFFIXES.contains(&tld.as_str()) {
        return false;
    }
    domain.split('.').all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') && l.len() <= 63)
}

/// Hostname: not part of a path, not a file name, valid labels.
pub fn hostname(c: &Cand) -> bool {
    if matches!(c.before.last(), Some(b'/' | b'\\' | b'@' | b'.' | b'$' | b'%')) {
        return false;
    }
    let h = c.payload.trim_end_matches('.');
    if h.len() > 253 || !h.contains('.') {
        return false;
    }
    let tld = tld_of(h).to_ascii_lowercase();
    if FILE_LIKE_SUFFIXES.contains(&tld.as_str()) {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.iter().any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-')) {
        return false;
    }
    // At least one non-TLD label contains a letter (rules out all-digit / IP-like shapes)
    labels[..labels.len() - 1].iter().any(|l| l.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// Username: not purely numeric (a uid), not a placeholder, reasonable length.
pub fn username(c: &Cand) -> bool {
    let u = c.payload.trim_matches(|ch: char| ch == '\'' || ch == '"');
    if u.is_empty() || u.len() > 64 || u.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let lower = u.to_ascii_lowercase();
    const SKIP: &[&str] = &["unknown", "(unknown)", "<unknown>", "-", "?", "none", "(none)", "null", "nobody?", "n/a"];
    !SKIP.contains(&lower.as_str()) && !is_placeholder(u)
}

/// Chinese mobile number: not preceded by a numeric field such as size/bytes/id.
pub fn phone_cn(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    if !(11..=13).contains(&n) {
        return false;
    }
    !numeric_field_before(c.before)
}

/// Immediately preceded by a numeric field name such as `size=`, `bytes:`, `id=`.
fn numeric_field_before(before: &[u8]) -> bool {
    let s = String::from_utf8_lossy(before).to_ascii_lowercase();
    let s = s.trim_end_matches([' ', '\t', '=', ':', '"', '\'', '[', '(']);
    const KEYS: &[&str] = &[
        "size",
        "bytes",
        "len",
        "length",
        "offset",
        "sector",
        "sectors",
        "block",
        "blocks",
        "inode",
        "count",
        "total",
        "sum",
        "free",
        "used",
        "avail",
        "available",
        "mem",
        "memory",
        "id",
        "pid",
        "tid",
        "uid",
        "gid",
        "seq",
        "ts",
        "time",
        "timestamp",
        "epoch",
        "duration",
        "elapsed",
        "ms",
        "us",
        "ns",
        "nanos",
        "micros",
        "millis",
        "cookie",
        "hash",
        "crc",
        "checksum",
        "nonce",
        "port",
        "serial",
        "lba",
        "addr",
        "address",
        "rx",
        "tx",
        "packets",
        "frames",
        "errors",
        "dropped",
        "jiffies",
        "ticks",
        "cycles",
        "pages",
        "kb",
        "mb",
        "requestid",
        "request_id",
        "trace",
        "traceid",
        "trace_id",
        "span",
        "spanid",
        "span_id",
        "order",
        "txid",
    ];
    KEYS.iter().any(|k| {
        s.ends_with(k) && {
            let cut = s.len() - k.len();
            cut == 0 || !s.as_bytes()[cut - 1].is_ascii_alphanumeric()
        }
    })
}

/// International phone number: 8–15 digits.
pub fn phone_intl(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (8..=15).contains(&n)
}

/// Phone number with keyword context: 7–15 digits.
pub fn phone_kw(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (7..=15).contains(&n)
}

/// Latitude/longitude pair: within valid ranges and not both 0.x (avoids treating ordinary decimal pairs as
/// coordinates).
pub fn geo_pair(c: &Cand) -> bool {
    let mut it = c.payload.split(',').map(|s| s.trim().parse::<f64>());
    let (Some(Ok(lat)), Some(Ok(lon))) = (it.next(), it.next()) else {
        return false;
    };
    lat.abs() <= 90.0 && lon.abs() <= 180.0 && !(lat.abs() < 1.0 && lon.abs() < 1.0)
}

pub fn geo_single(c: &Cand) -> bool {
    c.payload.parse::<f64>().map(|v| v.abs() <= 180.0).unwrap_or(false)
}

/// Serial number: excludes common DMI placeholder values.
pub fn serial(c: &Cand) -> bool {
    let v = c.payload.trim();
    let lower = v.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "0",
        "00000000",
        "0000000000",
        "123456789",
        "0123456789",
        "none",
        "n/a",
        "na",
        "default",
        "default string",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "not specified",
        "not applicable",
        "system serial number",
        "chassis serial number",
        "base board serial number",
        "unknown",
        "empty",
        "oem",
        "xxxxxxxx",
        "serial",
    ];
    v.len() >= 4 && !PLACEHOLDERS.contains(&lower.as_str()) && !v.bytes().all(|b| b == b'0' || b == b'F' || b == b'f')
}

pub fn uuid(c: &Cand) -> bool {
    let hex: String = c.payload.chars().filter(|ch| *ch != '-').collect();
    !(hex.bytes().all(|b| b == b'0') || hex.bytes().all(|b| b == b'f' || b == b'F'))
}

/// Hex string: contains both digits and letters (all-digit strings are left to the long-number rule).
pub fn hex_mixed(c: &Cand) -> bool {
    let b = c.payload.as_bytes();
    b.iter().any(u8::is_ascii_digit) && b.iter().any(u8::is_ascii_alphabetic)
}

fn shannon_entropy(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s {
        freq[b as usize] += 1;
    }
    let n = s.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// base64 / high-entropy string: contains uppercase, lowercase and digits, entropy ≥ 3.5 bits/char, not pure hex.
pub fn high_entropy(c: &Cand) -> bool {
    let b = c.payload.trim_end_matches('=').as_bytes();
    let has_upper = b.iter().any(u8::is_ascii_uppercase);
    let has_lower = b.iter().any(u8::is_ascii_lowercase);
    let has_digit = b.iter().any(u8::is_ascii_digit);
    if !(has_upper && has_lower && has_digit) {
        return false;
    }
    if b.iter().all(u8::is_ascii_hexdigit) {
        return false;
    }
    shannon_entropy(b) >= 3.5
}

/// Wi-Fi network name: excludes default names of wired connections and virtual NICs.
pub fn ssid(c: &Cand) -> bool {
    let v = c.payload.trim();
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("wired connection") || lower.starts_with("有线连接") {
        return false;
    }
    const SKIP: &[&str] = &["lo", "docker0", "virbr0", "br0", "any", "<hidden>", "hidden", "off/any", "off"];
    !SKIP.contains(&lower.as_str()) && !is_placeholder(v)
}

/// Hardware identifier: excludes empty values.
pub fn hardware(c: &Cand) -> bool {
    !c.payload.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(p: &str) -> Cand<'_> {
        Cand { payload: p, whole: p, before: b"", after: b"" }
    }

    #[test]
    fn luhn_cards() {
        assert!(bank_card(&cand("4111 1111 1111 1111")));
        assert!(bank_card(&cand("4111111111111111")));
        assert!(!bank_card(&cand("4111 1111-1111 1111")));
        assert!(!bank_card(&cand("4111111111111112")));
        assert!(!bank_card(&cand("4444444444444444")));
        assert!(bank_card(&cand("3782 822463 10005")));
        assert!(bank_card(&cand("4111-1111-1111-1111-003")));
        assert!(!bank_card(&cand("202503 202610 16")));
    }

    #[test]
    fn cn_id_checksum() {
        assert!(cn_id(&cand("11010519491231002X")));
        assert!(!cn_id(&cand("110105194912310021")));
    }

    #[test]
    fn iban_mod97() {
        assert!(iban(&cand("GB82WEST12345698765432")));
        assert!(iban(&cand("GB82 WEST 1234 5698 7654 32")));
        assert!(!iban(&cand("GB82WEST12345698765433")));
    }

    #[test]
    fn ssn_rules() {
        assert!(ssn(&cand("123-45-6789")));
        assert!(!ssn(&cand("000-45-6789")));
        assert!(!ssn(&cand("912-45-6789")));
    }

    #[test]
    fn email_rejects_units() {
        assert!(email(&cand("alice@corp.example.cn")));
        assert!(!email(&cand("user@1000.service")));
        assert!(!email(&cand("getty@tty1.service")));
        assert!(!email(&cand("foo@bar.log")));
    }

    #[test]
    fn ipv6_validation() {
        assert!(ipv6(&cand("fe80::1ff:fe23:4567:890a%eth0")));
        assert!(ipv6(&cand("2001:db8::1")));
        assert!(!ipv6(&cand("12:34:56")));
        assert!(!ipv6(&cand("aa:bb:cc:dd:ee:ff")));
        assert!(!ipv6(&cand("::")));
    }

    #[test]
    fn placeholders() {
        assert!(!secret_value(&cand("null")));
        assert!(!secret_value(&cand("********")));
        assert!(!secret_value(&cand("${DB_PASSWORD}")));
        assert!(secret_value(&cand("hunter2")));
    }

    #[test]
    fn numeric_fields() {
        let c = Cand { payload: "15032385536", whole: "", before: b"size=", after: b"" };
        assert!(!phone_cn(&c));
        let c = Cand { payload: "13800138000", whole: "", before: b"mobile ", after: b"" };
        assert!(phone_cn(&c));
    }

    #[test]
    fn entropy() {
        assert!(high_entropy(&cand("dGhpcyBpcyBhIHNlY3JldCBrZXkgMTIzNDU2Nzg5MA")));
        assert!(!high_entropy(&cand("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        assert!(!high_entropy(&cand("deadbeefdeadbeefdeadbeefdeadbeef")));
    }

    #[test]
    fn after_checks() {
        assert!(after_ipv4(b". next"));
        assert!(!after_ipv4(b".5"));
        assert!(after_ipv4(b":8080"));
        assert!(!after_mac(b":11"));
        assert!(after_host(b". done"));
        assert!(!after_host(b".com"));
    }
}
