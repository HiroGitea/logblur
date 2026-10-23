//! 校验函数与尾部边界检查。

use std::net::{Ipv4Addr, Ipv6Addr};

use super::Cand;

// ───────────────────────── 尾部边界 ─────────────────────────

#[inline]
fn first(rest: &[u8]) -> Option<u8> {
    rest.first().copied()
}

#[inline]
fn second(rest: &[u8]) -> Option<u8> {
    rest.get(1).copied()
}

/// 后面不是字母数字。
pub fn after_not_alnum(rest: &[u8]) -> bool {
    !matches!(first(rest), Some(b) if b.is_ascii_alphanumeric())
}

/// 后面不是字母数字下划线。
pub fn after_not_word(rest: &[u8]) -> bool {
    !matches!(first(rest), Some(b) if b.is_ascii_alphanumeric() || b == b'_')
}

/// 数字类目标：后面不是字母数字，也不是紧跟数字的 `.` / `-`（避免截断更长的数字串）。
pub fn after_number(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() => false,
        Some(b'.' | b'-' | b',') => !matches!(second(rest), Some(d) if d.is_ascii_digit()),
        _ => true,
    }
}

/// IPv4：后面不是字母数字，不是 `.数字`（如 1.2.3.4.5 版本号）。
pub fn after_ipv4(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' => false,
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_alphanumeric()),
        _ => true,
    }
}

/// IPv6：后面不是十六进制字母数字或 `:`+十六进制。
pub fn after_ipv6(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' => false,
        Some(b':') => !matches!(second(rest), Some(d) if d.is_ascii_hexdigit() || d == b':'),
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_digit()),
        _ => true,
    }
}

/// MAC：后面不是十六进制或 `:`/`-` + 十六进制（更长的 EUI 序列）。
pub fn after_mac(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() => false,
        Some(b':' | b'-') => !matches!(second(rest), Some(d) if d.is_ascii_hexdigit()),
        _ => true,
    }
}

/// 主机名：后面不是标签字符，也不是 `.`+字母数字。
pub fn after_host(rest: &[u8]) -> bool {
    match first(rest) {
        Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' => false,
        Some(b'.') => !matches!(second(rest), Some(d) if d.is_ascii_alphanumeric()),
        _ => true,
    }
}

/// 邮箱：同主机名。
pub fn after_email(rest: &[u8]) -> bool {
    after_host(rest)
}

// ───────────────────────── 通用 ─────────────────────────

fn is_placeholder(v: &str) -> bool {
    let t = v.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
    if t.is_empty() {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "null", "(null)", "nil", "none", "undefined", "true", "false", "n/a", "na", "redacted", "<redacted>",
        "[redacted]", "(redacted)", "hidden", "<hidden>", "masked", "<masked>", "secret", "password", "changeme",
        "xxx", "xxxx", "-", "--", "?", "{}", "[]", "<none>", "(none)", "empty", "unset", "not set", "<secret>",
        "filtered", "[filtered]", "***", "<password>", "your_password", "yourpassword", "<token>", "your_token",
        "...", "…",
    ];
    if WORDS.contains(&lower.as_str()) {
        return true;
    }
    // 已经打过码的
    if t.chars().all(|c| matches!(c, '*' | '░' | '▒' | '▓' | '█' | 'x' | 'X' | '#' | '•' | '·')) {
        return true;
    }
    // 模板变量
    t.starts_with("${") || t.starts_with("{{") || t.starts_with("%(") || t.starts_with("$(") || t.starts_with('<') && t.ends_with('>')
}

/// 口令/密钥值：排除占位符、模板变量、sudo 的 `PWD=/path`。
pub fn secret_value(c: &Cand) -> bool {
    if is_placeholder(c.payload) {
        return false;
    }
    // sudo 日志的 PWD=/home/x 是工作目录，不是口令
    if c.payload.starts_with('/') && c.whole.contains("PWD=") {
        return false;
    }
    true
}

/// 令牌：至少 8 个字符且不是占位符。
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
    sum % 10 == 0
}

/// 分隔符要么没有，要么全部相同。
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

/// 银行卡：13–19 位、Luhn 校验、分隔符一致、不全是同一个数字。
pub fn bank_card(c: &Cand) -> bool {
    let d = digits(c.payload);
    if !(13..=19).contains(&d.len()) || !consistent_separators(c.payload) {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    luhn(&d)
}

/// 有关键词上下文的卡号/账号：12–19 位即可（部分国内借记卡不满足 Luhn）。
pub fn account_number(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (12..=19).contains(&n)
}

/// 中国居民身份证 18 位校验码（GB 11643-1999）。
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

/// 美国 SSN：区号不为 000/666/9xx，组号不为 00，序号不为 0000。
pub fn ssn(c: &Cand) -> bool {
    let p: Vec<&str> = c.payload.split('-').collect();
    if p.len() != 3 {
        return false;
    }
    let area = p[0];
    !(area == "000" || area == "666" || area.starts_with('9') || p[1] == "00" || p[2] == "0000")
}

/// IBAN mod-97 校验。
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
    // 纯十进制数字加冒号（如 12:34:56 时间）不算
    if addr.bytes().all(|b| b.is_ascii_digit() || b == b':') && !addr.contains("::") {
        return false;
    }
    match addr.parse::<Ipv6Addr>() {
        Ok(ip) => !ip.is_unspecified(),
        Err(_) => false,
    }
}

/// MAC：分隔符一致。
pub fn mac(c: &Cand) -> bool {
    let seps: Vec<u8> = c.payload.bytes().filter(|b| !b.is_ascii_hexdigit()).collect();
    seps.windows(2).all(|w| w[0] == w[1])
}

/// 常见文件扩展名与 systemd 单元后缀：不能当作顶级域名。
pub const FILE_LIKE_SUFFIXES: &[&str] = &[
    "log", "txt", "conf", "cfg", "ini", "json", "yaml", "yml", "xml", "html", "htm", "js", "ts", "css", "py", "rs",
    "go", "c", "h", "cpp", "hpp", "cc", "java", "class", "jar", "so", "dll", "exe", "sh", "bash", "zsh", "service",
    "socket", "target", "timer", "mount", "automount", "slice", "scope", "path", "device", "swap", "network",
    "netdev", "link", "pid", "lock", "sock", "tmp", "bak", "gz", "zip", "tar", "xz", "bz2", "zst", "img", "iso",
    "deb", "rpm", "md", "rst", "png", "jpg", "jpeg", "gif", "svg", "pdf", "csv", "tsv", "sql", "db", "sqlite",
    "key", "pem", "crt", "cer", "csr", "pub", "ko", "mod", "rules", "desktop", "list", "sources", "policy",
    "cache", "state", "journal", "old", "new", "orig", "swp", "toml", "lua", "rb", "pl", "php", "jsp", "war",
    "properties", "gradle", "kt", "swift", "vue", "tsx", "jsx", "mjs", "cjs", "map", "wasm", "bin", "dat", "out",
    "err", "d", "conf~", "rpmnew", "rpmsave", "dpkg-old", "dpkg-new", "ucf-dist", "lst", "repo", "env",
    "service~", "efi", "cpio", "vmlinuz", "initrd", "cmd", "bat", "ps1", "msi", "dmg", "pkg", "app", "mp3",
    "mp4", "mkv", "avi", "mov", "wav", "ttf", "otf", "woff", "woff2", "ico", "bmp", "webp", "tiff", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf", "epub", "md5", "sha1", "sha256", "sig", "asc", "gpg",
    "pcap", "core", "dump", "trace", "prof", "test", "spec", "lockfile", "patch", "diff", "in", "am", "ac",
];

fn tld_of(host: &str) -> &str {
    host.rsplit('.').next().unwrap_or("")
}

/// 邮箱：域名的最后一段不能是文件扩展名或 systemd 单元后缀（如 user@1000.service）。
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

/// 主机名：不是路径的一部分，不是文件名，标签合法。
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
    // 至少有一个非 TLD 标签含字母（排除纯数字/IP 形状）
    labels[..labels.len() - 1].iter().any(|l| l.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// 用户名：不是纯数字（uid），不是占位符，长度合理。
pub fn username(c: &Cand) -> bool {
    let u = c.payload.trim_matches(|ch: char| ch == '\'' || ch == '"');
    if u.is_empty() || u.len() > 64 || u.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let lower = u.to_ascii_lowercase();
    const SKIP: &[&str] = &["unknown", "(unknown)", "<unknown>", "-", "?", "none", "(none)", "null", "nobody?", "n/a"];
    !SKIP.contains(&lower.as_str()) && !is_placeholder(u)
}

/// 中国手机号：前面不是 size/bytes/id 之类的数值字段。
pub fn phone_cn(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    if !(11..=13).contains(&n) {
        return false;
    }
    !numeric_field_before(c.before)
}

/// 前面紧挨着 `size=`、`bytes:`、`id=` 这类数值字段名。
fn numeric_field_before(before: &[u8]) -> bool {
    let s = String::from_utf8_lossy(before).to_ascii_lowercase();
    let s = s.trim_end_matches([' ', '\t', '=', ':', '"', '\'', '[', '(']);
    const KEYS: &[&str] = &[
        "size", "bytes", "len", "length", "offset", "sector", "sectors", "block", "blocks", "inode", "count",
        "total", "sum", "free", "used", "avail", "available", "mem", "memory", "id", "pid", "tid", "uid", "gid",
        "seq", "ts", "time", "timestamp", "epoch", "duration", "elapsed", "ms", "us", "ns", "nanos", "micros",
        "millis", "cookie", "hash", "crc", "checksum", "nonce", "port", "serial", "lba", "addr", "address",
        "rx", "tx", "packets", "frames", "errors", "dropped", "jiffies", "ticks", "cycles", "pages", "kb", "mb",
        "requestid", "request_id", "trace", "traceid", "trace_id", "span", "spanid", "span_id", "order", "txid",
    ];
    KEYS.iter().any(|k| {
        s.ends_with(k) && {
            let cut = s.len() - k.len();
            cut == 0 || !s.as_bytes()[cut - 1].is_ascii_alphanumeric()
        }
    })
}

/// 国际电话：8–15 位数字。
pub fn phone_intl(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (8..=15).contains(&n)
}

/// 关键词上下文的电话：7–15 位数字。
pub fn phone_kw(c: &Cand) -> bool {
    let n = digits(c.payload).len();
    (7..=15).contains(&n)
}

/// 经纬度对：范围合法，且不全是 0.x（避免把普通小数对当坐标）。
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

/// 序列号：排除 DMI 常见占位值。
pub fn serial(c: &Cand) -> bool {
    let v = c.payload.trim();
    let lower = v.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "0", "00000000", "0000000000", "123456789", "0123456789", "none", "n/a", "na", "default", "default string",
        "to be filled by o.e.m.", "to be filled by oem", "not specified", "not applicable", "system serial number",
        "chassis serial number", "base board serial number", "unknown", "empty", "oem", "xxxxxxxx", "serial",
    ];
    v.len() >= 4 && !PLACEHOLDERS.contains(&lower.as_str()) && !v.bytes().all(|b| b == b'0' || b == b'F' || b == b'f')
}

pub fn uuid(c: &Cand) -> bool {
    let hex: String = c.payload.chars().filter(|ch| *ch != '-').collect();
    !(hex.bytes().all(|b| b == b'0') || hex.bytes().all(|b| b == b'f' || b == b'F'))
}

/// 十六进制串：同时含数字和字母（纯数字交给长数字规则）。
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

/// base64 / 高熵串：含大写、小写、数字，熵 ≥ 3.5 bit/字符，不是纯十六进制。
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

/// Wi-Fi 名称：排除有线连接的默认名和虚拟网卡。
pub fn ssid(c: &Cand) -> bool {
    let v = c.payload.trim();
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("wired connection") || lower.starts_with("有线连接") {
        return false;
    }
    const SKIP: &[&str] = &["lo", "docker0", "virbr0", "br0", "any", "<hidden>", "hidden", "off/any", "off"];
    !SKIP.contains(&lower.as_str()) && !is_placeholder(v)
}

/// 硬件标识：排除空值。
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
