//! Parallel gzip writer in the style of pigz.
//!
//! The input is cut into blocks that are deflated on several threads at once. Each block is primed with the last
//! 32 KiB of the block before it as a preset dictionary, so back-references work across blocks and the ratio is close
//! to single-threaded compression. Non-final blocks end with a sync flush (byte-aligned, not final), so the blocks
//! concatenate into one ordinary deflate stream, and their CRC-32s are combined into the trailer. The result is a
//! single standard gzip member that any gzip reader accepts.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::thread::JoinHandle;

use crc32fast::Hasher;
use flate2::{Compress, Compression, FlushCompress, Status};

/// Uncompressed bytes per block.
const BLOCK: usize = 1 << 20;
/// Deflate's window: the most a back-reference can reach.
const WINDOW: usize = 32 << 10;
/// gzip header: magic, deflate, no flags, no mtime, no extra flags, OS unknown.
const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];

type Block = io::Result<(Vec<u8>, Hasher)>;

pub struct ParGzWriter<W: Write> {
    inner: W,
    level: Compression,
    threads: usize,
    buf: Vec<u8>,
    /// Tail of the previous block, the dictionary of the next one.
    dict: Vec<u8>,
    /// Blocks being compressed, oldest first.
    pending: VecDeque<JoinHandle<Block>>,
    crc: Hasher,
    len: u64,
    header_written: bool,
}

impl<W: Write> ParGzWriter<W> {
    /// Compresses at `level` on up to `threads` threads.
    pub fn new(inner: W, level: Compression, threads: usize) -> ParGzWriter<W> {
        ParGzWriter {
            inner,
            level,
            threads: threads.max(1),
            buf: Vec::with_capacity(BLOCK),
            dict: Vec::new(),
            pending: VecDeque::new(),
            crc: Hasher::new(),
            len: 0,
            header_written: false,
        }
    }

    /// Writes the remaining data and the trailer and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.submit(true)?;
        while !self.pending.is_empty() {
            self.write_oldest()?;
        }
        self.inner.write_all(&self.crc.clone().finalize().to_le_bytes())?;
        self.inner.write_all(&(self.len as u32).to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    /// Starts compressing the buffered block on a new thread.
    fn submit(&mut self, last: bool) -> io::Result<()> {
        if !self.header_written {
            self.inner.write_all(&HEADER)?;
            self.header_written = true;
        }
        while self.pending.len() >= self.threads {
            self.write_oldest()?;
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(if last { 0 } else { BLOCK }));
        let dict = std::mem::replace(&mut self.dict, data[data.len().saturating_sub(WINDOW)..].to_vec());
        let level = self.level;
        self.len += data.len() as u64;
        let handle = std::thread::Builder::new()
            .name("logblur-gzip".into())
            .spawn(move || deflate_block(level, &dict, &data, last))?;
        self.pending.push_back(handle);
        Ok(())
    }

    fn write_oldest(&mut self) -> io::Result<()> {
        let Some(h) = self.pending.pop_front() else { return Ok(()) };
        let (out, crc) = h.join().unwrap_or_else(|p| std::panic::resume_unwind(p))?;
        self.crc.combine(&crc);
        self.inner.write_all(&out)
    }
}

impl<W: Write> Write for ParGzWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(BLOCK - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == BLOCK {
            self.submit(false)?;
        }
        Ok(n)
    }

    /// Only flushes what has already been compressed; a partial block stays buffered so blocks keep their size.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Deflates one block as raw deflate data: sync-flushed, or finished if it is the last one.
fn deflate_block(level: Compression, dict: &[u8], data: &[u8], last: bool) -> Block {
    let mut c = Compress::new(level, false);
    if !dict.is_empty() {
        c.set_dictionary(dict).map_err(io::Error::other)?;
    }
    let flush = if last { FlushCompress::Finish } else { FlushCompress::Sync };
    let mut out = Vec::with_capacity(data.len() / 2 + 1024);
    loop {
        if out.capacity() - out.len() < 1024 {
            out.reserve(out.capacity().max(64 << 10));
        }
        let consumed = c.total_in() as usize;
        let status = c.compress_vec(&data[consumed..], &mut out, flush).map_err(io::Error::other)?;
        let all_in = c.total_in() as usize == data.len();
        // Done once all input is in and the flush did not stop for lack of output space.
        if all_in && (status == Status::StreamEnd || (!last && out.len() < out.capacity())) {
            break;
        }
    }
    let mut crc = Hasher::new();
    crc.update(data);
    Ok((out, crc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn roundtrip(data: &[u8], threads: usize) -> Vec<u8> {
        let mut w = ParGzWriter::new(Vec::new(), Compression::new(6), threads);
        // Odd write sizes so blocks are filled across several calls.
        for piece in data.chunks(7919) {
            w.write_all(piece).unwrap();
        }
        let gz = w.finish().unwrap();
        let mut out = Vec::new();
        GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        out
    }

    fn sample(len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut i = 0u64;
        while v.len() < len {
            v.extend_from_slice(
                format!("line {i} host web-{} value {}\n", i % 97, i.wrapping_mul(2654435761)).as_bytes(),
            );
            i += 1;
        }
        v.truncate(len);
        v
    }

    #[test]
    fn roundtrips_across_block_boundaries() {
        for len in [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 3 * BLOCK + 12345] {
            let data = sample(len);
            assert_eq!(roundtrip(&data, 4), data, "len {len}");
        }
    }

    #[test]
    fn one_thread_and_many_threads_agree() {
        let data = sample(5 * BLOCK / 2);
        let gz = |threads| {
            let mut w = ParGzWriter::new(Vec::new(), Compression::new(6), threads);
            w.write_all(&data).unwrap();
            w.finish().unwrap()
        };
        assert_eq!(gz(1), gz(8));
    }

    #[test]
    fn ratio_close_to_single_stream() {
        let data = sample(4 * BLOCK);
        let mut single = flate2::write::GzEncoder::new(Vec::new(), Compression::new(6));
        single.write_all(&data).unwrap();
        let single = single.finish().unwrap().len();
        let mut w = ParGzWriter::new(Vec::new(), Compression::new(6), 4);
        w.write_all(&data).unwrap();
        let par = w.finish().unwrap().len();
        assert!(par <= single + single / 50, "parallel {par} vs single {single}");
    }

    #[test]
    fn gzip_tool_accepts_it() {
        let Ok(mut child) = std::process::Command::new("gzip")
            .arg("-dc")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            return;
        };
        let data = sample(2 * BLOCK + 99);
        let mut w = ParGzWriter::new(Vec::new(), Compression::new(6), 4);
        w.write_all(&data).unwrap();
        let gz = w.finish().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let feeder = std::thread::spawn(move || stdin.write_all(&gz));
        let out = child.wait_with_output().unwrap();
        feeder.join().unwrap().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, data);
    }
}
