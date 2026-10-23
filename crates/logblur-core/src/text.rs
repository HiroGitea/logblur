//! 文本层：二进制判定、编码检测、解码与回编码。
//!
//! 策略：
//! - UTF-8（含少量非法字节）直接按字节扫描，零拷贝。
//! - UTF-16、GBK/GB18030、Big5、Shift_JIS、EUC-KR 等先解码成 UTF-8 再扫描，打码后按原编码写回，
//!   避免 ASCII 范围的尾字节被误当成 `@`、字母参与匹配。
//! - 无法解码或明显是二进制的内容不做清洗。

use encoding_rs::Encoding;

/// 用于判定编码的样本大小。
pub const SAMPLE_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    /// 含 NUL 字节。
    Nul,
    /// 控制字符过多。
    Control,
    /// 已知文件格式的魔数（值是翻译键 `binary.kind.*` 的后缀）。
    Magic(&'static str),
    /// systemd journal 二进制文件。
    Journal,
    /// wtmp / btmp / lastlog 登录记录。
    LoginRecords,
}

impl BinaryKind {
    /// 说明文字（按当前语言）。
    pub fn describe(self) -> String {
        match self {
            BinaryKind::Nul => crate::t!("binary.nul"),
            BinaryKind::Control => crate::t!("binary.control"),
            BinaryKind::Magic(m) => crate::t!("binary.magic", what = crate::i18n::tr(&format!("binary.kind.{m}"))),
            BinaryKind::Journal => crate::t!("binary.journal"),
            BinaryKind::LoginRecords => crate::t!("binary.login_records"),
        }
    }

    /// 是否是需要特别提醒的、肯定含隐私的二进制。
    pub fn is_sensitive(self) -> bool {
        matches!(self, BinaryKind::Journal | BinaryKind::LoginRecords | BinaryKind::Magic("nested_archive"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    Binary(BinaryKind),
    /// UTF-8（可能夹杂少量非法字节），直接扫描原始字节。
    Utf8 { bom: bool },
    /// 需要解码的编码。`bom_len` 是要跳过（并在输出时原样写回）的 BOM 字节数。
    Legacy { enc: &'static Encoding, bom_len: usize },
}

impl TextKind {
    pub fn is_binary(self) -> bool {
        matches!(self, TextKind::Binary(_))
    }

    pub fn label(self) -> String {
        match self {
            TextKind::Binary(_) => "binary".into(),
            TextKind::Utf8 { bom: false } => "utf-8".into(),
            TextKind::Utf8 { bom: true } => "utf-8 (BOM)".into(),
            TextKind::Legacy { enc, bom_len } => {
                let n = enc.name().to_ascii_lowercase();
                if bom_len > 0 { format!("{n} (BOM)") } else { n }
            }
        }
    }
}

fn magic(sample: &[u8], name: &str) -> Option<BinaryKind> {
    let starts = |m: &[u8]| sample.starts_with(m);
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    if starts(b"LPKSHHRH") || base.ends_with(".journal") || base.ends_with(".journal~") {
        return Some(BinaryKind::Journal);
    }
    if matches!(base, "wtmp" | "btmp" | "utmp" | "lastlog" | "faillog")
        || base.starts_with("wtmp.")
        || base.starts_with("btmp.")
        || base.starts_with("wtmp-")
        || base.starts_with("btmp-")
    {
        return Some(BinaryKind::LoginRecords);
    }
    let m: &'static str = if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        "nested_archive"
    } else if starts(&[0x1f, 0x8b]) {
        "nested_archive"
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        "nested_archive"
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        "nested_archive"
    } else if sample.len() >= 4 && starts(b"BZh") && (b'1'..=b'9').contains(&sample[3]) {
        "nested_archive"
    } else if starts(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) || starts(b"Rar!\x1a\x07") {
        "nested_archive"
    } else if sample.len() > 262 && &sample[257..262] == b"ustar" {
        "nested_archive"
    } else if starts(b"\x7fELF") {
        "elf"
    } else if starts(&[0x89, b'P', b'N', b'G']) || starts(&[0xff, 0xd8, 0xff]) || starts(b"GIF8") {
        "image"
    } else if starts(b"%PDF-") {
        "pdf"
    } else if starts(b"SQLite format 3\0") {
        "sqlite"
    } else if starts(&[0xd4, 0xc3, 0xb2, 0xa1]) || starts(&[0xa1, 0xb2, 0xc3, 0xd4]) || starts(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        "pcap"
    } else if starts(&[0xca, 0xfe, 0xba, 0xbe]) || starts(&[0xcf, 0xfa, 0xed, 0xfe]) || starts(&[0xfe, 0xed, 0xfa, 0xcf]) {
        "executable"
    } else {
        return None;
    };
    Some(BinaryKind::Magic(m))
}

fn utf16_guess(sample: &[u8]) -> Option<&'static Encoding> {
    let n = sample.len().min(4096) / 2;
    if n < 8 {
        return None;
    }
    let (mut even0, mut odd0) = (0usize, 0usize);
    for i in 0..n {
        if sample[2 * i] == 0 {
            even0 += 1;
        }
        if sample[2 * i + 1] == 0 {
            odd0 += 1;
        }
    }
    if odd0 * 10 > n * 3 && even0 * 20 < n {
        Some(encoding_rs::UTF_16LE)
    } else if even0 * 10 > n * 3 && odd0 * 20 < n {
        Some(encoding_rs::UTF_16BE)
    } else {
        None
    }
}

fn is_cjk_multibyte(enc: &'static Encoding) -> bool {
    enc == encoding_rs::GBK
        || enc == encoding_rs::GB18030
        || enc == encoding_rs::BIG5
        || enc == encoding_rs::SHIFT_JIS
        || enc == encoding_rs::EUC_JP
        || enc == encoding_rs::EUC_KR
        || enc == encoding_rs::ISO_2022_JP
}

/// 判定一段内容是二进制还是文本、用什么编码。`complete` 表示 `sample` 是否就是全部内容。
pub fn detect(sample: &[u8], name: &str, complete: bool) -> TextKind {
    if let Some(b) = magic(sample, name) {
        return TextKind::Binary(b);
    }
    // BOM
    if sample.starts_with(&[0xef, 0xbb, 0xbf]) {
        return TextKind::Utf8 { bom: true };
    }
    if sample.starts_with(&[0xff, 0xfe]) {
        return TextKind::Legacy { enc: encoding_rs::UTF_16LE, bom_len: 2 };
    }
    if sample.starts_with(&[0xfe, 0xff]) {
        return TextKind::Legacy { enc: encoding_rs::UTF_16BE, bom_len: 2 };
    }
    if let Some(enc) = utf16_guess(sample) {
        return TextKind::Legacy { enc, bom_len: 0 };
    }
    let probe = &sample[..sample.len().min(8192)];
    if memchr::memchr(0, probe).is_some() {
        return TextKind::Binary(BinaryKind::Nul);
    }
    let control = probe
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1b | 0x08))
        .count();
    if !probe.is_empty() && control * 20 > probe.len() {
        return TextKind::Binary(BinaryKind::Control);
    }
    // UTF-8？不完整的样本允许末尾截断一个字符。
    match std::str::from_utf8(sample) {
        Ok(_) => return TextKind::Utf8 { bom: false },
        Err(e) if e.error_len().is_none() && !complete => return TextKind::Utf8 { bom: false },
        Err(_) => {}
    }
    let invalid: usize = sample.utf8_chunks().map(|c| c.invalid().len()).sum();
    let mut det = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Deny);
    det.feed(sample, complete);
    let guess = det.guess(None, chardetng::Utf8Detection::Deny);
    if is_cjk_multibyte(guess) {
        return TextKind::Legacy { enc: guess, bom_len: 0 };
    }
    if invalid * 200 <= sample.len() {
        // 基本是 UTF-8，夹杂个别坏字节
        return TextKind::Utf8 { bom: false };
    }
    TextKind::Legacy { enc: guess, bom_len: 0 }
}

/// 预览用：把（可能被 gzip 压缩的）开头一段内容解码成 UTF-8 文本；二进制返回 `None`。
pub fn decode_for_preview(name: &str, head: &[u8]) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let mut data = std::borrow::Cow::Borrowed(head);
    if head.starts_with(&[0x1f, 0x8b]) && lower.ends_with(".gz") && !lower.ends_with(".tar.gz") {
        let mut d = flate2::read::MultiGzDecoder::new(head);
        let mut out = Vec::new();
        let _ = crate::archive::read_up_to(&mut d, &mut out, 1 << 20);
        data = std::borrow::Cow::Owned(out);
    }
    match detect(&data, name, false) {
        TextKind::Binary(_) => None,
        TextKind::Utf8 { .. } => Some(String::from_utf8_lossy(&data).into_owned()),
        TextKind::Legacy { enc, bom_len } => {
            Some(enc.decode_without_bom_handling(&data[bom_len.min(data.len())..]).0.into_owned())
        }
    }
}

/// 不带替换地解码；有非法序列时返回 `None`。
pub fn decode_strict(data: &[u8], enc: &'static Encoding) -> Option<String> {
    enc.decode_without_bom_handling_and_without_replacement(data).map(|c| c.into_owned())
}

/// 把 UTF-8 文本编码回 `enc`。UTF-16 由 encoding_rs 规范输出 UTF-8，这里手工处理。
pub fn encode(text: &str, enc: &'static Encoding) -> Vec<u8> {
    if enc == encoding_rs::UTF_16LE {
        return text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    }
    if enc == encoding_rs::UTF_16BE {
        return text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    }
    let (bytes, _, _) = enc.encode(text);
    bytes.into_owned()
}

/// 打码字符在目标编码里能否表示；不能则用后备字符。
pub fn mask_char_for(kind: TextKind, want: char, fallback: char, utf8_output: bool) -> char {
    match kind {
        TextKind::Legacy { enc, .. } if !utf8_output => {
            if enc == encoding_rs::UTF_16LE || enc == encoding_rs::UTF_16BE || enc == encoding_rs::GB18030 {
                return want;
            }
            let mut buf = [0u8; 4];
            let (_, _, unmappable) = enc.encode(want.encode_utf8(&mut buf));
            if unmappable { fallback } else { want }
        }
        _ => want,
    }
}

/// 流式增量解码器（非 UTF-8 的大文件）。
pub struct StreamDecoder {
    dec: encoding_rs::Decoder,
    pub had_errors: bool,
}

impl StreamDecoder {
    pub fn new(enc: &'static Encoding) -> Self {
        StreamDecoder { dec: enc.new_decoder_without_bom_handling(), had_errors: false }
    }

    /// 解码 `src` 追加到 `dst`（UTF-8 字节）。
    pub fn push(&mut self, src: &[u8], dst: &mut Vec<u8>, last: bool) {
        let mut s = String::new();
        let mut input = src;
        loop {
            let need = self.dec.max_utf8_buffer_length(input.len()).unwrap_or(input.len() * 4 + 16);
            s.reserve(need.max(16));
            let (res, read, replaced) = self.dec.decode_to_string(input, &mut s, last);
            self.had_errors |= replaced;
            input = &input[read..];
            match res {
                encoding_rs::CoderResult::InputEmpty => break,
                encoding_rs::CoderResult::OutputFull => continue,
            }
        }
        dst.extend_from_slice(s.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_utf8_and_binary() {
        assert_eq!(detect(b"hello\nworld\n", "a.log", true), TextKind::Utf8 { bom: false });
        assert_eq!(detect("你好 world".as_bytes(), "a.log", true), TextKind::Utf8 { bom: false });
        assert!(detect(b"\x7fELF\x02\x01", "a", true).is_binary());
        assert!(detect(b"abc\0def", "a", true).is_binary());
        assert_eq!(detect(b"LPKSHHRH....", "system.journal", true), TextKind::Binary(BinaryKind::Journal));
        assert_eq!(detect(b"whatever", "var/log/wtmp", true), TextKind::Binary(BinaryKind::LoginRecords));
    }

    #[test]
    fn detects_utf16() {
        let mut v = vec![0xff, 0xfe];
        v.extend("hello world, password=abc\n".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(detect(&v, "a.log", true), TextKind::Legacy { enc: encoding_rs::UTF_16LE, bom_len: 2 });
        let no_bom: Vec<u8> = "plain ascii text in utf16".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(detect(&no_bom, "a.log", true), TextKind::Legacy { enc: encoding_rs::UTF_16LE, bom_len: 0 });
    }

    #[test]
    fn detects_gbk_and_roundtrips() {
        let text = "2026-10-23 用户张三登录失败，密码错误，来源 192.0.2.10，手机号 13800138000\n".repeat(20);
        let (gbk, _, _) = encoding_rs::GBK.encode(&text);
        let kind = detect(&gbk, "app.log", true);
        let TextKind::Legacy { enc, .. } = kind else { panic!("应识别为 GBK: {kind:?}") };
        let s = decode_strict(&gbk, enc).expect("可以解码");
        assert_eq!(s, text);
        assert_eq!(encode(&s, enc), gbk.into_owned());
    }

    #[test]
    fn mask_char_fallback() {
        let k = TextKind::Legacy { enc: encoding_rs::WINDOWS_1252, bom_len: 0 };
        assert_eq!(mask_char_for(k, '░', '*', false), '*');
        assert_eq!(mask_char_for(k, '░', '*', true), '░');
        assert_eq!(mask_char_for(TextKind::Utf8 { bom: false }, '░', '*', false), '░');
    }

    #[test]
    fn stream_decoder_splits_multibyte() {
        let (gbk, _, _) = encoding_rs::GBK.encode("中文日志测试");
        let mut d = StreamDecoder::new(encoding_rs::GBK);
        let mut out = Vec::new();
        for b in gbk.iter() {
            d.push(std::slice::from_ref(b), &mut out, false);
        }
        d.push(&[], &mut out, true);
        assert_eq!(String::from_utf8(out).unwrap(), "中文日志测试");
        assert!(!d.had_errors);
    }
}
