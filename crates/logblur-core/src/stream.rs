//! Line-buffered scrubbing for live streams such as `tail -f` or `journalctl -f`: every line is written and flushed
//! as soon as it has been scrubbed, instead of after the input ends.
//!
//! Compared with [`job::run`](crate::job::run) there is no learning pass, no encoding detection (input is scanned as
//! UTF-8 / ASCII-compatible bytes) and no report. Lines that are already waiting are taken as one batch, scrubbed in
//! parallel when the batch is large, and written in their original order.
//!
//! Multi-line private keys are masked without holding lines back: inside a `-----BEGIN … PRIVATE KEY-----` block,
//! each line is wrapped in synthetic BEGIN/END markers before scanning, so the private key rule masks it on its own.
//! When several sources share one stream, their lines are only ever over-masked, never leaked.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crossbeam_channel::{RecvTimeoutError, Sender, TryRecvError, bounded};
use memchr::{memchr, memmem};
use regex::bytes::Regex;

use crate::category::{Category, Counts};
use crate::config::JobConfig;
use crate::error::{Error, Result};
use crate::job::CancelToken;
use crate::scan::Engine;

/// Longest line scrubbed as a unit; longer lines are cut into segments of this size.
pub const MAX_LINE: usize = 1 << 20;
/// Most lines taken into one batch.
const BATCH_LINES: usize = 8192;
/// Most bytes taken into one batch.
const BATCH_BYTES: usize = 8 << 20;
/// Batches with fewer lines than this are scrubbed on the calling thread.
const PARALLEL_MIN_LINES: usize = 256;
/// How often a blocked read checks for cancellation.
const CANCEL_POLL: Duration = Duration::from_millis(100);

const PEM_PREFIX: &[u8] = b"-----BEGIN PRIVATE KEY-----";
const PEM_SUFFIX: &[u8] = b"-----END PRIVATE KEY-----";

static PEM_BEGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----").unwrap());
static PEM_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----").unwrap());

/// Totals for one [`scrub_lines`] run.
#[derive(Debug, Default, Clone)]
pub struct LineStats {
    /// Lines read (an over-long line counts once per segment).
    pub lines: u64,
    /// Bytes read.
    pub bytes: u64,
    /// Masked items by category.
    pub counts: Counts,
    /// Wall-clock time of the run.
    pub elapsed: Duration,
}

/// Which synthetic private key markers a line is wrapped in before scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wrap {
    /// The line starts inside a key block.
    prefix: bool,
    /// The line ends inside a key block.
    suffix: bool,
}

/// Scrubs `input` line by line into `output`, flushing after every batch of lines, until the input ends.
///
/// Reading happens on a background thread so that cancellation is noticed while the input is idle; on cancel the
/// function returns [`Error::Cancelled`] and that thread stays blocked in its read until the process exits.
/// Uses one thread per core (or `cfg.threads`), and a single thread when pseudonyms are counters.
pub fn scrub_lines<R, W>(
    engine: &Engine,
    cfg: &JobConfig,
    input: R,
    mut output: W,
    cancel: &CancelToken,
) -> Result<LineStats>
where
    R: Read + Send + 'static,
    W: Write,
{
    let start = Instant::now();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let threads = if cfg.counter { 1 } else { cfg.threads.unwrap_or(cores).clamp(1, 256) };
    let read_err = |e| Error::io(crate::t!("io.read", path = "-"), e);
    let write_err = |e| Error::io(crate::t!("io.write", path = "-"), e);

    let (tx, rx) = bounded(BATCH_LINES);
    std::thread::Builder::new().name("logblur-read".into()).spawn(move || read_lines(input, tx)).map_err(read_err)?;

    let mut stats = LineStats::default();
    let mut in_key = false;
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut eof = false;
    while !eof {
        // 阻塞等第一行，期间定期检查取消
        let first = loop {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            match rx.recv_timeout(CANCEL_POLL) {
                Ok(r) => break Some(r),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break None,
            }
        };
        let Some(first) = first else { break };

        // 再把已经到达的行一并取走，凑成一批
        batch.clear();
        let mut bytes = 0usize;
        let mut next = Some(first);
        while let Some(r) = next.take() {
            let line = r.map_err(read_err)?;
            bytes += line.len();
            batch.push(line);
            if batch.len() >= BATCH_LINES || bytes >= BATCH_BYTES {
                break;
            }
            match rx.try_recv() {
                Ok(r) => next = Some(r),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => eof = true,
            }
        }

        let wraps = classify(&batch, &mut in_key);
        let out = scrub_batch(engine, threads, &batch, &wraps, &mut stats.counts);
        output.write_all(&out).and_then(|()| output.flush()).map_err(write_err)?;
        stats.lines += batch.len() as u64;
        stats.bytes += bytes as u64;
    }
    stats.elapsed = start.elapsed();
    Ok(stats)
}

fn read_lines<R: Read>(input: R, tx: Sender<io::Result<Vec<u8>>>) {
    let mut rd = BufReader::with_capacity(64 << 10, input);
    loop {
        let mut line = Vec::new();
        match read_segment(&mut rd, &mut line) {
            Ok(0) => return,
            Ok(_) => {
                if tx.send(Ok(line)).is_err() {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        }
    }
}

/// Reads up to and including the next `\n`, but at most [`MAX_LINE`] bytes. Returns 0 at the end of the input.
fn read_segment<R: BufRead>(rd: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
    loop {
        let avail = match rd.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(out.len());
        }
        let take = avail.len().min(MAX_LINE - out.len());
        let (n, done) = match memchr(b'\n', &avail[..take]) {
            Some(i) => (i + 1, true),
            None => (take, out.len() + take == MAX_LINE),
        };
        out.extend_from_slice(&avail[..n]);
        rd.consume(n);
        if done {
            return Ok(out.len());
        }
    }
}

/// Tracks private key blocks across lines and decides how each line is wrapped.
fn classify(batch: &[Vec<u8>], in_key: &mut bool) -> Vec<Wrap> {
    batch
        .iter()
        .map(|line| {
            let prefix = *in_key;
            if memmem::find(line, b"-----").is_some() {
                let begin = PEM_BEGIN.find_iter(line).last().map(|m| m.start());
                let end = PEM_END.find_iter(line).last().map(|m| m.start());
                *in_key = match (begin, end) {
                    (Some(b), Some(e)) => b > e,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => *in_key,
                };
            }
            Wrap { prefix, suffix: *in_key }
        })
        .collect()
}

fn scrub_batch(engine: &Engine, threads: usize, batch: &[Vec<u8>], wraps: &[Wrap], counts: &mut Counts) -> Vec<u8> {
    let workers = threads.min(batch.len() / PARALLEL_MIN_LINES).max(1);
    if workers == 1 {
        let mut out = Vec::with_capacity(batch.iter().map(Vec::len).sum());
        scrub_range(engine, batch, wraps, &mut out, counts);
        return out;
    }
    let per = batch.len().div_ceil(workers);
    let parts: Vec<(Vec<u8>, Counts)> = std::thread::scope(|s| {
        let handles: Vec<_> = batch
            .chunks(per)
            .zip(wraps.chunks(per))
            .map(|(lines, wraps)| {
                s.spawn(move || {
                    let mut out = Vec::with_capacity(lines.iter().map(Vec::len).sum());
                    let mut c = Counts::default();
                    scrub_range(engine, lines, wraps, &mut out, &mut c);
                    (out, c)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p))).collect()
    });
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.0.len()).sum());
    for (o, c) in &parts {
        out.extend_from_slice(o);
        counts.merge(c);
    }
    out
}

/// Scrubs consecutive lines. Runs of ordinary lines are joined and scanned as one block (as the batch pipeline
/// does), which is much cheaper than one scan per line; lines inside private key blocks are scanned one by one.
fn scrub_range(engine: &Engine, lines: &[Vec<u8>], wraps: &[Wrap], out: &mut Vec<u8>, counts: &mut Counts) {
    let plain = Wrap { prefix: false, suffix: false };
    let mut run: Vec<u8> = Vec::new();
    for (line, &wrap) in lines.iter().zip(wraps) {
        if wrap == plain {
            run.extend_from_slice(line);
            continue;
        }
        if !run.is_empty() {
            engine.scrub(&run, out, counts, engine.masker().mask_char());
            run.clear();
        }
        scrub_line(engine, line, wrap, out, counts);
    }
    if !run.is_empty() {
        engine.scrub(&run, out, counts, engine.masker().mask_char());
    }
}

/// Scrubs one line inside a private key block, keeping its `\n` / `\r\n` ending unchanged.
fn scrub_line(engine: &Engine, line: &[u8], wrap: Wrap, out: &mut Vec<u8>, counts: &mut Counts) {
    let mut len = line.len();
    if line[..len].ends_with(b"\n") {
        len -= 1;
        if line[..len].ends_with(b"\r") {
            len -= 1;
        }
    }
    let (content, ending) = line.split_at(len);
    let mask_char = engine.masker().mask_char();
    // 补上合成的 BEGIN/END 标记单独扫描，再去掉标记
    let pre = if wrap.prefix { PEM_PREFIX } else { b"" };
    let suf = if wrap.suffix { PEM_SUFFIX } else { b"" };
    let hay = [pre, content, suf].concat();
    let mut tmp = Vec::with_capacity(hay.len());
    engine.scrub(&hay, &mut tmp, counts, mask_char);
    if tmp.len() >= pre.len() + suf.len() && tmp.starts_with(pre) && tmp.ends_with(suf) {
        out.extend_from_slice(&tmp[pre.len()..tmp.len() - suf.len()]);
    } else {
        // 标记被其他规则改写了（比如拒绝名单里有 PRIVATE），整行按私钥打码
        for _ in String::from_utf8_lossy(content).chars() {
            let mut b = [0; 4];
            out.extend_from_slice(mask_char.encode_utf8(&mut b).as_bytes());
        }
        counts.add(Category::PrivateKey, 1);
    }
    out.extend_from_slice(ending);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::Receiver;
    use std::sync::{Arc, Mutex};

    fn cfg() -> JobConfig {
        JobConfig { mask_char: '#', ..JobConfig::default() }
    }

    fn run(input: &str, cfg: &JobConfig) -> String {
        let engine = Engine::new(cfg).unwrap();
        let mut out = Vec::new();
        scrub_lines(&engine, cfg, io::Cursor::new(input.as_bytes().to_vec()), &mut out, &CancelToken::new()).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn keeps_line_endings() {
        let out = run("a 203.0.113.1\r\nb 203.0.113.2\nc 203.0.113.3", &cfg());
        assert_eq!(out, "a ###########\r\nb ###########\nc ###########");
    }

    #[test]
    fn private_key_block_across_lines() {
        let input = "pre 203.0.113.1\n\
                     -----BEGIN OPENSSH PRIVATE KEY-----\n\
                     b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n\
                     host 203.0.113.9 inside\n\
                     -----END OPENSSH PRIVATE KEY-----\n\
                     post 203.0.113.2\n";
        let out = run(input, &cfg());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "pre ###########");
        assert_eq!(lines[1], "-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(lines[2], "#".repeat(42));
        assert_eq!(lines[3], "#".repeat(23));
        assert_eq!(lines[4], "-----END OPENSSH PRIVATE KEY-----");
        assert_eq!(lines[5], "post ###########");
    }

    #[test]
    fn rewritten_markers_fall_back_to_masking_the_line() {
        let c = JobConfig { deny: vec!["PRIVATE".into()], ..cfg() };
        let out = run("-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\n", &c);
        assert_eq!(out.lines().nth(1), Some("#######"));
    }

    #[test]
    fn parallel_batches_match_sequential() {
        let mut input = String::new();
        for i in 0..5000 {
            input.push_str(&format!(
                "{i} user=alice{i} from 203.0.{}.{} host web-{i}.acme-corp.internal\n",
                i % 200,
                i % 250
            ));
        }
        let one = run(&input, &JobConfig { threads: Some(1), ..cfg() });
        let many = run(&input, &JobConfig { threads: Some(8), ..cfg() });
        assert_eq!(one, many);
        assert_eq!(one.lines().count(), 5000);
    }

    #[test]
    fn long_lines_are_cut_into_segments() {
        let mut line = vec![b'x'; MAX_LINE + 10];
        line.push(b'\n');
        let mut rd = io::Cursor::new(line);
        let mut seg = Vec::new();
        assert_eq!(read_segment(&mut rd, &mut seg).unwrap(), MAX_LINE);
        seg.clear();
        assert_eq!(read_segment(&mut rd, &mut seg).unwrap(), 11);
    }

    /// A reader fed one piece at a time, blocking in between like a pipe.
    struct ChanReader(Receiver<Vec<u8>>, Vec<u8>);

    impl Read for ChanReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.1.is_empty() {
                match self.0.recv() {
                    Ok(v) => self.1 = v,
                    Err(_) => return Ok(0),
                }
            }
            let n = buf.len().min(self.1.len());
            buf[..n].copy_from_slice(&self.1[..n]);
            self.1.drain(..n);
            Ok(n)
        }
    }

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn wait_for(out: &Shared, want: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while String::from_utf8_lossy(&out.0.lock().unwrap()) != want {
            assert!(Instant::now() < deadline, "timed out waiting for {want:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn writes_each_line_before_the_input_ends() {
        let (tx, rx) = bounded(4);
        let out = Shared::default();
        let w = out.clone();
        let h = std::thread::spawn(move || {
            let c = cfg();
            let engine = Engine::new(&c).unwrap();
            scrub_lines(&engine, &c, ChanReader(rx, Vec::new()), w, &CancelToken::new()).unwrap()
        });
        tx.send(b"a 203.0.113.1\n".to_vec()).unwrap();
        wait_for(&out, "a ###########\n");
        tx.send(b"b 203.0.113.2\n".to_vec()).unwrap();
        wait_for(&out, "a ###########\nb ###########\n");
        drop(tx);
        let stats = h.join().unwrap();
        assert_eq!(stats.lines, 2);
        assert_eq!(stats.counts.total(), 2);
    }

    #[test]
    fn cancel_while_idle() {
        let (tx, rx) = bounded::<Vec<u8>>(1);
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        let h = std::thread::spawn(move || {
            let c = cfg();
            let engine = Engine::new(&c).unwrap();
            scrub_lines(&engine, &c, ChanReader(rx, Vec::new()), io::sink(), &c2)
        });
        std::thread::sleep(Duration::from_millis(50));
        cancel.cancel();
        assert!(h.join().unwrap().unwrap_err().is_cancelled());
        drop(tx);
    }
}
