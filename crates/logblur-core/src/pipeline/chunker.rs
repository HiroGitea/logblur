//! Splits large entries into chunks of roughly `chunk` bytes so multiple threads can scrub them in parallel.
//!
//! - Cuts at newlines when possible (single-line rules never span lines, so no hit gets cut);
//! - hard-cuts only when a line exceeds `max_line`, preferably right after whitespace/a separator;
//! - never cuts inside a PEM private key block (blocks are at most 64 KiB);
//! - non-UTF-8 text is first incrementally decoded to UTF-8, then cut.

use memchr::{memchr, memmem, memrchr};

use crate::text::StreamDecoder;
use crate::util::floor_char_boundary;

/// Minimum extra lookahead before cutting, used to pull in the end of the line and PEM blocks.
const SLACK: usize = 64 * 1024;
const PEM_MAX: usize = 64 * 1024;

pub struct Chunker {
    buf: Vec<u8>,
    chunk: usize,
    max_line: usize,
    /// false: binary, cut at fixed lengths.
    lines: bool,
    decoder: Option<StreamDecoder>,
}

enum PemCut {
    Keep,
    Extend(usize),
    NeedMore,
}

impl Chunker {
    pub fn new(chunk: usize, lines: bool, decoder: Option<StreamDecoder>) -> Chunker {
        let chunk = chunk.max(16);
        Chunker { buf: Vec::new(), chunk, max_line: (chunk * 8).clamp(chunk, 8 << 20), lines, decoder }
    }

    pub fn push(&mut self, data: &[u8]) {
        match &mut self.decoder {
            Some(d) => d.push(data, &mut self.buf, false),
            None => self.buf.extend_from_slice(data),
        }
    }

    /// End of input: flushes the decoder.
    pub fn finish_input(&mut self) {
        if let Some(d) = &mut self.decoder {
            d.push(&[], &mut self.buf, true);
        }
    }

    pub fn had_decode_errors(&self) -> bool {
        self.decoder.as_ref().is_some_and(|d| d.had_errors)
    }

    fn split(&mut self, cut: usize) -> Vec<u8> {
        let rest = self.buf.split_off(cut);
        std::mem::replace(&mut self.buf, rest)
    }

    /// Takes the next chunk; `eof` means no more input will follow. Returns `None` when more data is needed (or
    /// everything has been taken).
    pub fn take(&mut self, eof: bool) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            return None;
        }
        if !self.lines {
            if self.buf.len() >= self.chunk {
                return Some(self.split(self.chunk));
            }
            return eof.then(|| std::mem::take(&mut self.buf));
        }
        if !eof && self.buf.len() < self.chunk + SLACK {
            return None;
        }
        if eof && self.buf.len() <= self.chunk {
            return Some(std::mem::take(&mut self.buf));
        }
        let limit = self.chunk.min(self.buf.len());
        let mut cut = match memrchr(b'\n', &self.buf[..limit]) {
            Some(i) => i + 1,
            None => match memchr(b'\n', &self.buf[limit..]) {
                Some(j) if limit + j < self.max_line => limit + j + 1,
                _ => {
                    if !eof && self.buf.len() < self.max_line {
                        return None;
                    }
                    hard_cut(&self.buf, self.chunk)
                }
            },
        };
        match pem_extend(&self.buf, cut) {
            PemCut::Keep => {}
            PemCut::Extend(c) => cut = c,
            PemCut::NeedMore => {
                if !eof && self.buf.len() < cut + PEM_MAX {
                    return None;
                }
            }
        }
        Some(self.split(cut.min(self.buf.len())))
    }
}

/// Cut point for an overlong line: preferably after whitespace/a separator within the last 4 KiB, otherwise at a
/// character boundary.
fn hard_cut(buf: &[u8], chunk: usize) -> usize {
    let c = chunk.min(buf.len());
    let lo = c.saturating_sub(4096);
    if let Some(i) = buf[lo..c]
        .iter()
        .rposition(|&b| matches!(b, b' ' | b'\t' | b',' | b';' | b'&' | b'"' | b'\'' | b'|' | b'>' | b'<'))
    {
        return lo + i + 1;
    }
    match floor_char_boundary(buf, c) {
        0 => c,
        f => f,
    }
}

/// If an unclosed `-----BEGIN` precedes the cut point, moves the cut point past the matching `-----END` line.
fn pem_extend(buf: &[u8], cut: usize) -> PemCut {
    let head = &buf[..cut];
    let Some(b) = memmem::rfind(head, b"-----BEGIN ") else { return PemCut::Keep };
    if let Some(e) = memmem::rfind(head, b"-----END ")
        && e > b
    {
        return PemCut::Keep;
    }
    if cut - b > PEM_MAX {
        return PemCut::Keep;
    }
    let window_end = (b + PEM_MAX).min(buf.len()).max(cut);
    if let Some(e) = memmem::find(&buf[cut..window_end], b"-----END ") {
        let e_abs = cut + e;
        return match memchr(b'\n', &buf[e_abs..]) {
            Some(nl) => PemCut::Extend(e_abs + nl + 1),
            None => PemCut::NeedMore,
        };
    }
    if buf.len() >= b + PEM_MAX { PemCut::Keep } else { PemCut::NeedMore }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_chunks(input: &[u8], chunk: usize, step: usize) -> Vec<Vec<u8>> {
        let mut c = Chunker::new(chunk, true, None);
        let mut out = Vec::new();
        for piece in input.chunks(step) {
            c.push(piece);
            while let Some(x) = c.take(false) {
                out.push(x);
            }
        }
        c.finish_input();
        while let Some(x) = c.take(true) {
            out.push(x);
        }
        out
    }

    #[test]
    fn cuts_on_newlines_and_reassembles() {
        let text: Vec<u8> = (0..20000).flat_map(|i| format!("line {i} some text here\n").into_bytes()).collect();
        let chunks = all_chunks(&text, 1000, 777);
        assert!(chunks.len() > 10);
        for c in &chunks[..chunks.len() - 1] {
            assert_eq!(*c.last().unwrap(), b'\n');
        }
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn keeps_pem_together() {
        let mut text = Vec::new();
        for i in 0..5000 {
            text.extend_from_slice(format!("noise {i}\n").as_bytes());
        }
        text.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
        for _ in 0..200 {
            text.extend_from_slice(b"MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n");
        }
        text.extend_from_slice(b"-----END RSA PRIVATE KEY-----\n");
        for i in 0..5000 {
            text.extend_from_slice(format!("tail {i}\n").as_bytes());
        }
        let chunks = all_chunks(&text, 4096, 1000);
        assert_eq!(chunks.concat(), text);
        let holder = chunks.iter().find(|c| memmem::find(c, b"-----BEGIN").is_some()).unwrap();
        assert!(memmem::find(holder, b"-----END").is_some(), "PEM block was split");
    }

    #[test]
    fn hard_cuts_very_long_lines() {
        let line = "word ".repeat(10_000);
        let chunks = all_chunks(line.as_bytes(), 1024, 4096);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), line.as_bytes());
        for c in &chunks[..chunks.len() - 1] {
            assert_eq!(*c.last().unwrap(), b' ');
        }
    }

    #[test]
    fn binary_fixed_size() {
        let data = vec![7u8; 10_000];
        let mut c = Chunker::new(4096, false, None);
        c.push(&data);
        let a = c.take(false).unwrap();
        let b = c.take(false).unwrap();
        assert_eq!((a.len(), b.len()), (4096, 4096));
        assert!(c.take(false).is_none());
        assert_eq!(c.take(true).unwrap().len(), 10_000 - 8192);
    }
}
