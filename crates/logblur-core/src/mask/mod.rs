//! 打码：把命中区间替换成打码字符、标签、伪名或哈希。

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};

use crate::category::{Category, Counts};
use crate::config::{JobConfig, MaskMode};
use crate::scan::Found;
use crate::util::{base32_lower, hex_lower, hmac_sha256, random_salt, sha256};

#[derive(Default)]
struct CounterState {
    map: HashMap<(Category, String), u32>,
    next: HashMap<Category, u32>,
}

#[derive(Clone)]
pub struct Masker {
    mode: MaskMode,
    mask_char: char,
    fixed_width: usize,
    hash_len: usize,
    salt: Arc<Vec<u8>>,
    user_salt: bool,
    counter: Option<Arc<Mutex<CounterState>>>,
}

impl Masker {
    pub fn new(cfg: &JobConfig, mode: MaskMode) -> Masker {
        let (salt, user_salt) = match &cfg.salt {
            Some(s) if !s.is_empty() => (s.as_bytes().to_vec(), true),
            _ => (random_salt(), false),
        };
        Masker {
            mode,
            mask_char: cfg.mask_char,
            fixed_width: cfg.fixed_width,
            hash_len: cfg.hash_len,
            salt: Arc::new(salt),
            user_salt,
            counter: (cfg.counter && mode == MaskMode::Pseudo).then(|| Arc::new(Mutex::new(CounterState::default()))),
        }
    }

    /// 同一个盐与计数器，换一种模式（用于文件名）。
    pub fn with_mode(&self, mode: MaskMode) -> Masker {
        Masker { mode, ..self.clone() }
    }

    pub fn mode(&self) -> MaskMode {
        self.mode
    }

    pub fn mask_char(&self) -> char {
        self.mask_char
    }

    /// 报告里展示的盐指纹（只有用户给定盐时才有意义）。
    pub fn salt_fingerprint(&self) -> Option<String> {
        self.user_salt.then(|| hex_lower(&sha256(&self.salt)[..4]))
    }

    /// 计数模式需要单线程才能保证编号确定。
    pub fn needs_sequential(&self) -> bool {
        self.counter.is_some()
    }

    /// 按命中区间生成输出。
    pub fn apply(&self, hay: &[u8], found: &[Found], out: &mut Vec<u8>, counts: &mut Counts, ch: char) {
        out.reserve(hay.len() + hay.len() / 8 + 16);
        let mut last = 0usize;
        for f in found {
            if f.start < last {
                continue;
            }
            out.extend_from_slice(&hay[last..f.start]);
            let payload = String::from_utf8_lossy(&hay[f.start..f.end]);
            self.emit(f.category, &payload, out, ch);
            counts.add(f.category, 1);
            last = f.end;
        }
        out.extend_from_slice(&hay[last..]);
    }

    fn push_char(out: &mut Vec<u8>, c: char) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }

    fn block(payload: &str, ch: char, out: &mut Vec<u8>) {
        for c in payload.chars() {
            if c == '\n' || c == '\r' {
                Self::push_char(out, c);
            } else {
                Self::push_char(out, ch);
            }
        }
    }

    fn digest(&self, cat: Category, payload: &str) -> [u8; 32] {
        let norm = normalize(cat, payload);
        hmac_sha256(&self.salt, &[cat.id().as_bytes(), b"\0", norm.as_bytes()])
    }

    fn emit(&self, cat: Category, payload: &str, out: &mut Vec<u8>, ch: char) {
        match self.mode {
            MaskMode::Block => Self::block(payload, ch, out),
            MaskMode::Star => Self::block(payload, '*', out),
            MaskMode::Fixed => {
                for _ in 0..self.fixed_width {
                    Self::push_char(out, ch);
                }
            }
            MaskMode::Tag => {
                out.push(b'[');
                out.extend_from_slice(cat.tag().as_bytes());
                out.push(b']');
            }
            MaskMode::Remove => {}
            MaskMode::Hash => {
                let h = hex_lower(&self.digest(cat, payload));
                out.extend_from_slice(&h.as_bytes()[..self.hash_len.min(h.len())]);
            }
            MaskMode::Pseudo => {
                out.extend_from_slice(cat.pseudo_prefix().as_bytes());
                out.push(b'_');
                if let Some(counter) = &self.counter {
                    let key = (cat, normalize(cat, payload));
                    let mut st = counter.lock().unwrap_or_else(|e| e.into_inner());
                    let n = match st.map.get(&key) {
                        Some(&n) => n,
                        None => {
                            let next = st.next.entry(cat).or_insert(0);
                            *next += 1;
                            let n = *next;
                            st.map.insert(key, n);
                            n
                        }
                    };
                    out.extend_from_slice(n.to_string().as_bytes());
                } else {
                    let b32 = base32_lower(&self.digest(cat, payload));
                    out.extend_from_slice(&b32.as_bytes()[..8]);
                }
            }
            MaskMode::Partial => partial(cat, payload, ch, out),
        }
    }
}

/// 伪名/哈希前的规范化：同一个值的不同写法得到同一个代号。
fn normalize(cat: Category, s: &str) -> String {
    use Category::*;
    match cat {
        Email | Hostname | Username | Url | Uuid | MachineId | HexString | WifiSsid => s.to_lowercase(),
        Mac => s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase(),
        Ipv6 => {
            let addr = s.split('%').next().unwrap_or(s);
            addr.parse::<Ipv6Addr>().map(|a| a.to_string()).unwrap_or_else(|_| s.to_ascii_lowercase())
        }
        Phone | BankCard | Imei | LongNumber => s.chars().filter(|c| c.is_ascii_digit()).collect(),
        IdCard | Ssn | Iban => s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase(),
        _ => s.to_string(),
    }
}

/// 部分保留：
/// - 邮箱保留 `@域名`；电话/卡号/证件号保留末 4 位；
/// - IPv4 保留第一段，IPv6 保留第一组，MAC 保留厂商前缀（前 3 字节）；
/// - 主机名保留顶级域，URL 保留协议；口令和密钥一律全部遮盖。
fn partial(cat: Category, payload: &str, ch: char, out: &mut Vec<u8>) {
    use Category::*;
    let keep_sep = |c: char| matches!(c, '.' | ':' | '-' | ' ' | '@' | '/' | '\n' | '\r');
    let masked = |s: &str, out: &mut Vec<u8>| {
        for c in s.chars() {
            if keep_sep(c) { Masker::push_char(out, c) } else { Masker::push_char(out, ch) }
        }
    };
    match cat {
        Email => match payload.rsplit_once('@') {
            Some((local, domain)) => {
                masked(local, out);
                out.push(b'@');
                out.extend_from_slice(domain.as_bytes());
            }
            None => masked(payload, out),
        },
        Phone | BankCard | IdCard | Ssn | Iban | Imei | LongNumber | Serial => {
            let total = payload.chars().filter(|c| c.is_ascii_alphanumeric()).count();
            let keep_from = total.saturating_sub(4);
            let mut seen = 0usize;
            for c in payload.chars() {
                if c.is_ascii_alphanumeric() {
                    if seen >= keep_from && total > 6 {
                        Masker::push_char(out, c)
                    } else {
                        Masker::push_char(out, ch)
                    }
                    seen += 1;
                } else {
                    Masker::push_char(out, c);
                }
            }
        }
        Ipv4 => match payload.split_once('.') {
            Some((first, rest)) => {
                out.extend_from_slice(first.as_bytes());
                out.push(b'.');
                masked(rest, out);
            }
            None => masked(payload, out),
        },
        Ipv6 => match payload.split_once(':') {
            Some((first, rest)) => {
                out.extend_from_slice(first.as_bytes());
                out.push(b':');
                masked(rest, out);
            }
            None => masked(payload, out),
        },
        Mac => {
            let mut octet = 0usize;
            let mut in_octet = 0usize;
            for c in payload.chars() {
                if c.is_ascii_hexdigit() {
                    if octet < 3 {
                        Masker::push_char(out, c)
                    } else {
                        Masker::push_char(out, ch)
                    }
                    in_octet += 1;
                    if in_octet == 2 {
                        octet += 1;
                        in_octet = 0;
                    }
                } else {
                    Masker::push_char(out, c);
                }
            }
        }
        Hostname => match payload.rsplit_once('.') {
            Some((head, tld)) => {
                masked(head, out);
                out.push(b'.');
                out.extend_from_slice(tld.as_bytes());
            }
            None => masked(payload, out),
        },
        Url => match payload.find("://") {
            Some(i) => {
                out.extend_from_slice(&payload.as_bytes()[..i + 3]);
                masked(&payload[i + 3..], out);
            }
            None => masked(payload, out),
        },
        Username | WifiSsid if payload.chars().count() > 3 => {
            let mut it = payload.chars();
            if let Some(first) = it.next() {
                Masker::push_char(out, first);
            }
            for c in it {
                Masker::push_char(out, if c == '\n' { c } else { ch });
            }
        }
        _ => Masker::block(payload, ch, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(mode: MaskMode, cat: Category, s: &str) -> String {
        let cfg = JobConfig { salt: Some("t".into()), ..Default::default() };
        let m = Masker::new(&cfg, mode);
        let mut out = Vec::new();
        let f = [Found { start: 0, end: s.len(), category: cat, rule: 0 }];
        m.apply(s.as_bytes(), &f, &mut out, &mut Counts::default(), '░');
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn block_keeps_char_count() {
        let s = run(MaskMode::Block, Category::Ipv4, "192.168.1.10");
        assert_eq!(s.chars().count(), 12);
        assert!(s.chars().all(|c| c == '░'));
        let pem = run(MaskMode::Block, Category::PrivateKey, "\nAAA\nBBB\n");
        assert_eq!(pem, "\n░░░\n░░░\n");
    }

    #[test]
    fn tag_and_fixed() {
        assert_eq!(run(MaskMode::Tag, Category::Ipv4, "10.0.0.1"), "[IPV4]");
        assert_eq!(run(MaskMode::Fixed, Category::Email, "a@b.cn").chars().count(), 6);
        assert_eq!(run(MaskMode::Remove, Category::Email, "a@b.cn"), "");
    }

    #[test]
    fn pseudo_is_consistent() {
        let a = run(MaskMode::Pseudo, Category::Ipv6, "2001:DB8::1");
        let b = run(MaskMode::Pseudo, Category::Ipv6, "2001:db8:0::1");
        assert_eq!(a, b);
        assert!(a.starts_with("IP6_"));
        let c = run(MaskMode::Pseudo, Category::Ipv6, "2001:db8::2");
        assert_ne!(a, c);
    }

    #[test]
    fn counter_mode() {
        let cfg = JobConfig { counter: true, ..Default::default() };
        let m = Masker::new(&cfg, MaskMode::Pseudo);
        let s = b"a b a";
        let f = [
            Found { start: 0, end: 1, category: Category::Username, rule: 0 },
            Found { start: 2, end: 3, category: Category::Username, rule: 0 },
            Found { start: 4, end: 5, category: Category::Username, rule: 0 },
        ];
        let mut out = Vec::new();
        m.apply(s, &f, &mut out, &mut Counts::default(), '░');
        assert_eq!(String::from_utf8(out).unwrap(), "USER_1 USER_2 USER_1");
    }

    #[test]
    fn partial_modes() {
        assert_eq!(run(MaskMode::Partial, Category::Email, "alice@corp.cn"), "░░░░░@corp.cn");
        assert_eq!(run(MaskMode::Partial, Category::Phone, "13800138000"), "░░░░░░░8000");
        assert_eq!(run(MaskMode::Partial, Category::Ipv4, "192.168.1.10"), "192.░░░.░.░░");
        assert_eq!(run(MaskMode::Partial, Category::Mac, "52:54:00:12:34:56"), "52:54:00:░░:░░:░░");
        assert_eq!(run(MaskMode::Partial, Category::Password, "hunter2"), "░░░░░░░");
    }

    #[test]
    fn hash_len() {
        assert_eq!(run(MaskMode::Hash, Category::Email, "a@b.cn").len(), 12);
    }
}
