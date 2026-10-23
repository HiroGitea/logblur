//! Concurrent pipeline:
//!
//! ```text
//! reader (archive order) ──Job──▶ N workers (decode/scan/mask/compress) ──Piece──▶ writer (in order)
//!        │                                                                         ▲
//!        └──── directories, links, verbatim copies, heads of streamed entries ─────┘
//! ```
//!
//! - Small entries are read whole into memory and handed to one worker; large entries are cut into chunks along lines,
//!   processed by several workers in parallel and concatenated in order by the writer.
//! - The reader acquires memory from the [`Budget`] before sending data and the writer releases it once written, so
//!   in-flight data never exceeds the budget.
//! - Plaintext only lives in memory; only scrubbed data is written to disk.

mod budget;
mod chunker;

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use encoding_rs::Encoding;
use flate2::Compression;
use flate2::read::{GzDecoder, MultiGzDecoder};
use flate2::write::GzEncoder;

pub use budget::Budget;
use chunker::Chunker;

use crate::archive::sink::{Sink, gzip, make_zip_blob};
use crate::archive::{EntryKind, EntryMeta, Source, read_up_to};
use crate::category::{Category, Counts};
use crate::config::{BinaryPolicy, JobConfig, MemoryLimit};
use crate::error::{Error, IoContext, Result};
use crate::job::{CancelToken, Phase, ProgressEvent, ProgressSink};
use crate::report::{EntryReport, EntryStatus};
use crate::scan::Engine;
use crate::text::{self, SAMPLE_LEN, StreamDecoder, TextKind};

/// Roughly how many copies of memory one byte of input occupies while being processed (original + decoded/output +
/// compressed).
const FACTOR: u64 = 3;
const READ_BLOCK: usize = 256 * 1024;

/// Resource plan.
#[derive(Debug, Clone)]
pub struct Plan {
    pub workers: usize,
    pub budget: u64,
    pub chunk: usize,
    /// Entries no larger than this are processed whole; larger ones are streamed in chunks.
    pub whole_max: usize,
    /// Process sequentially on the reader thread (counter pseudonyms need a deterministic numbering order).
    pub inline: bool,
}

/// Available memory × ratio, also capped by the cgroup limit.
pub fn memory_budget(limit: MemoryLimit) -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let mut avail = sys.available_memory();
    if avail == 0 {
        avail = sys.total_memory() / 2;
    }
    if avail == 0 {
        avail = 1 << 30;
    }
    if let Some(cg) = sys.cgroup_limits()
        && cg.free_memory > 0
    {
        avail = avail.min(cg.free_memory);
    }
    let b = match limit {
        MemoryLimit::Auto => avail / 10 * 7,
        MemoryLimit::Bytes(b) => b,
        MemoryLimit::Percent(p) => avail / 100 * p as u64,
    };
    b.max(64 << 20)
}

pub fn plan(cfg: &JobConfig, sequential: bool) -> Plan {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let workers = if sequential { 1 } else { cfg.threads.unwrap_or(cores).clamp(1, 256) };
    let chunk = cfg.chunk_size.clamp(64, 64 << 20);
    let budget = memory_budget(cfg.memory).max(chunk as u64 * FACTOR * 4);
    let auto_whole = (budget / (workers as u64 * 2 * FACTOR)).clamp(256 << 10, 16 << 20) as usize;
    let whole_max = cfg.whole_max.unwrap_or(auto_whole.max(chunk));
    Plan { workers, budget, chunk, whole_max, inline: sequential }
}

/// Shared pipeline state.
pub struct Ctx<'a> {
    pub cfg: &'a JobConfig,
    pub engine: &'a Engine,
    pub plan: &'a Plan,
    pub cancel: &'a CancelToken,
    pub progress: &'a dyn ProgressSink,
    pub phase: Phase,
    pub budget: Budget,
    failed: AtomicBool,
    error: Mutex<Option<Error>>,
    warnings: Mutex<Vec<String>>,
    bytes: AtomicU64,
    last_tick: Mutex<Instant>,
    sink_blob: bool,
    sink_raw: bool,
    utf8_out: bool,
}

impl<'a> Ctx<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: &'a JobConfig,
        engine: &'a Engine,
        plan: &'a Plan,
        cancel: &'a CancelToken,
        progress: &'a dyn ProgressSink,
        phase: Phase,
        sink_blob: bool,
        sink_raw: bool,
    ) -> Ctx<'a> {
        Ctx {
            cfg,
            engine,
            plan,
            cancel,
            progress,
            phase,
            budget: Budget::new(plan.budget),
            failed: AtomicBool::new(false),
            error: Mutex::new(None),
            warnings: Mutex::new(Vec::new()),
            bytes: AtomicU64::new(0),
            last_tick: Mutex::new(Instant::now()),
            sink_blob,
            sink_raw,
            utf8_out: cfg.output_encoding == crate::config::OutputEncoding::Utf8,
        }
    }

    pub fn stop(&self) -> bool {
        self.failed.load(Ordering::Relaxed) || self.cancel.is_cancelled()
    }

    pub fn fail(&self, e: Error) {
        let mut slot = self.error.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(e);
        }
        self.failed.store(true, Ordering::Relaxed);
    }

    /// Error to report at the end: a real error takes precedence, then cancellation.
    pub fn outcome(&self) -> Result<()> {
        if let Some(e) = self.error.lock().unwrap_or_else(|p| p.into_inner()).take() {
            return Err(e);
        }
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    pub fn warn(&self, msg: String) {
        self.progress.event(ProgressEvent::Warning(msg.clone()));
        let mut w = self.warnings.lock().unwrap_or_else(|p| p.into_inner());
        if w.len() < 1000 {
            w.push(msg);
        }
    }

    pub fn take_warnings(&self) -> Vec<String> {
        std::mem::take(&mut *self.warnings.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn add_bytes(&self, n: u64) {
        let done = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        let mut last = self.last_tick.lock().unwrap_or_else(|p| p.into_inner());
        if last.elapsed() >= Duration::from_millis(100) {
            *last = Instant::now();
            self.progress.event(ProgressEvent::Bytes { phase: self.phase, done });
        }
    }

    fn acquire(&self, n: u64) -> Result<u64> {
        self.budget.acquire(n, &|| self.stop()).ok_or(Error::Cancelled)
    }

    /// Adjusts the currently held `have` bytes to `need`.
    fn adjust(&self, have: u64, need: u64) -> Result<u64> {
        if need > have {
            let got = self.acquire(need - have)?;
            Ok(have + got)
        } else {
            self.budget.release(have - need);
            Ok(need)
        }
    }

    fn learning(&self) -> bool {
        self.phase == Phase::Learn
    }
}

#[derive(Clone, Copy)]
enum ChunkMode {
    Utf8,
    Legacy(&'static Encoding),
    Copy,
}

#[expect(
    clippy::large_enum_variant,
    reason = "a Job only moves through channels; copying a few hundred bytes is negligible next to the work"
)]
enum Job {
    Whole {
        seq: u64,
        meta: Arc<EntryMeta>,
        data: Vec<u8>,
        kind: TextKind,
        mask: char,
        inner_gz: bool,
        permit: u64,
        info: EntryReport,
    },
    Chunk {
        seq: u64,
        part: u32,
        last: bool,
        data: Vec<u8>,
        mode: ChunkMode,
        mask: char,
        prefix: Vec<u8>,
        permit: u64,
        note: Option<String>,
    },
}

impl Job {
    fn permit(&self) -> u64 {
        match self {
            Job::Whole { permit, .. } | Job::Chunk { permit, .. } => *permit,
        }
    }
}

struct Piece {
    seq: u64,
    part: u32,
    last: bool,
    permit: u64,
    body: Body,
}

enum Body {
    Dir(Arc<EntryMeta>, EntryReport),
    Link(Arc<EntryMeta>, String, bool, EntryReport),
    RawCopy(Arc<EntryMeta>, usize, EntryReport),
    Whole { meta: Arc<EntryMeta>, data: Vec<u8>, blob: bool, info: EntryReport },
    Begin { meta: Arc<EntryMeta>, inner_gz: bool, info: EntryReport },
    Chunk { data: Vec<u8>, counts: Counts, bytes_in: u64, note: Option<String> },
    End,
    Skip(EntryReport),
    Learned(Vec<(Category, String)>),
}

fn send_piece(out: &Sender<Piece>, p: Piece) -> Result<()> {
    out.send(p).map_err(|_| Error::Other(crate::t!("pipeline.writer_gone")))
}

fn send_job(ctx: &Ctx, jobs: &Sender<Job>, out: &Sender<Piece>, j: Job) -> Result<()> {
    if ctx.plan.inline {
        let permit = j.permit();
        return process(ctx, j, out).inspect_err(|_| ctx.budget.release(permit));
    }
    jobs.send(j).map_err(|_| Error::Other(crate::t!("pipeline.workers_gone")))
}

fn is_nested_gz_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.ends_with(".gz") && !l.ends_with(".tar.gz")
}

/// Decompresses a (possibly truncated) gzip prefix; only used to sniff the content type.
fn gunzip_prefix(head: &[u8]) -> Vec<u8> {
    let mut d = GzDecoder::new(head);
    let mut out = Vec::new();
    let _ = read_up_to(&mut d, &mut out, SAMPLE_LEN);
    out
}

// ───────────────────────── Reader thread ─────────────────────────

fn reader(ctx: &Ctx, src: &mut dyn Source, jobs: &Sender<Job>, out: &Sender<Piece>) -> Result<()> {
    let mut seq = 0u64;
    src.visit(&mut |meta, rd| {
        if ctx.stop() {
            return Ok(false);
        }
        let s = seq;
        seq += 1;
        entry(ctx, s, meta, rd, jobs, out)?;
        Ok(!ctx.stop())
    })
}

fn entry(
    ctx: &Ctx,
    seq: u64,
    mut meta: EntryMeta,
    rd: Option<&mut dyn Read>,
    jobs: &Sender<Job>,
    out: &Sender<Piece>,
) -> Result<()> {
    let learn = ctx.learning();
    if learn {
        // File names contain usernames and hostnames too
        let mut set = HashSet::new();
        ctx.engine.learn(format!("/{}", meta.name).as_bytes(), &mut set);
        if !set.is_empty() {
            send_piece(
                out,
                Piece { seq, part: 0, last: true, permit: 0, body: Body::Learned(set.into_iter().collect()) },
            )?;
        }
    }
    let mut name_counts = Counts::default();
    if !learn && ctx.cfg.scrub_names {
        meta.name = ctx.engine.scrub_name(&meta.name, &mut name_counts);
    }
    ctx.progress.event(ProgressEvent::Entry { phase: ctx.phase, index: seq, name: meta.name.clone() });
    let mut info = EntryReport::new(&meta.name);
    info.by_category.merge(&name_counts);
    let one = |body: Body| Piece { seq, part: 0, last: true, permit: 0, body };
    match meta.kind.clone() {
        EntryKind::Dir => {
            if learn {
                return Ok(());
            }
            info.status = EntryStatus::Dir;
            send_piece(out, one(Body::Dir(Arc::new(meta), info)))
        }
        EntryKind::Symlink(t) | EntryKind::HardLink(t) => {
            if learn {
                return Ok(());
            }
            let hard = matches!(meta.kind, EntryKind::HardLink(_));
            let target = if ctx.cfg.scrub_names { ctx.engine.scrub_name(&t, &mut info.by_category) } else { t };
            info.status = EntryStatus::Link;
            send_piece(out, one(Body::Link(Arc::new(meta), target, hard, info)))
        }
        EntryKind::Other(desc) => {
            if learn {
                return Ok(());
            }
            info.status = EntryStatus::Skipped;
            info.set_note(crate::t!("pipeline.skip_special", desc = desc));
            ctx.warn(crate::t!("pipeline.warn_skip_special", name = meta.name, desc = desc));
            send_piece(out, one(Body::Skip(info)))
        }
        EntryKind::File => file_entry(ctx, seq, meta, rd, info, jobs, out),
    }
}

fn file_entry(
    ctx: &Ctx,
    seq: u64,
    meta: EntryMeta,
    rd: Option<&mut dyn Read>,
    mut info: EntryReport,
    jobs: &Sender<Job>,
    out: &Sender<Piece>,
) -> Result<()> {
    let learn = ctx.learning();
    let one = |body: Body| Piece { seq, part: 0, last: true, permit: 0, body };
    if meta.encrypted {
        if learn {
            return Ok(());
        }
        info.status = EntryStatus::Encrypted;
        info.set_note(crate::t!("pipeline.encrypted"));
        ctx.warn(crate::t!("pipeline.warn_encrypted", name = meta.name));
        if ctx.cfg.binary == BinaryPolicy::Copy
            && ctx.sink_raw
            && let Some(idx) = meta.zip_index
        {
            info.bytes_in = meta.size.unwrap_or(0);
            info.bytes_out = info.bytes_in;
            return send_piece(out, one(Body::RawCopy(Arc::new(meta), idx, info)));
        }
        info.status = EntryStatus::Dropped;
        return send_piece(out, one(Body::Skip(info)));
    }
    let Some(rd) = rd else {
        info.status = EntryStatus::Skipped;
        return send_piece(out, one(Body::Skip(info)));
    };
    let mut head = Vec::new();
    let eof = read_up_to(rd, &mut head, SAMPLE_LEN).ctx(|| crate::t!("io.read", path = meta.name))?;

    // .gz from log rotation: decompress, scrub, recompress
    if head.starts_with(&[0x1f, 0x8b]) && is_nested_gz_name(&meta.name) {
        let inner_name = meta.name[..meta.name.len() - 3].to_string();
        let peek = gunzip_prefix(&head);
        if !text::detect(&peek, &inner_name, false).is_binary() {
            let mut dec = MultiGzDecoder::new(Cursor::new(head).chain(rd));
            let mut head2 = Vec::new();
            let eof2 =
                read_up_to(&mut dec, &mut head2, SAMPLE_LEN).ctx(|| crate::t!("io.decompress", path = meta.name))?;
            let kind = text::detect(&head2, &inner_name, eof2);
            info.set_note(crate::t!("pipeline.gz_note"));
            return content_entry(ctx, seq, meta, &mut dec, head2, eof2, kind, true, info, jobs, out);
        }
    }
    let kind = text::detect(&head, &meta.name, eof);
    content_entry(ctx, seq, meta, rd, head, eof, kind, false, info, jobs, out)
}

#[allow(clippy::too_many_arguments)]
fn content_entry(
    ctx: &Ctx,
    seq: u64,
    meta: EntryMeta,
    rd: &mut dyn Read,
    head: Vec<u8>,
    eof: bool,
    kind: TextKind,
    inner_gz: bool,
    mut info: EntryReport,
    jobs: &Sender<Job>,
    out: &Sender<Piece>,
) -> Result<()> {
    let learn = ctx.learning();
    if let TextKind::Binary(bk) = kind {
        if learn {
            return Ok(());
        }
        info.status = EntryStatus::Binary;
        info.set_note(bk.describe());
        if bk.is_sensitive() {
            ctx.warn(crate::t!("pipeline.warn_binary", name = meta.name, desc = bk.describe()));
        }
        if ctx.cfg.binary == BinaryPolicy::Drop {
            info.status = EntryStatus::Dropped;
            return send_piece(out, Piece { seq, part: 0, last: true, permit: 0, body: Body::Skip(info) });
        }
        if !inner_gz
            && ctx.sink_raw
            && let Some(idx) = meta.zip_index
        {
            let n = meta.size.unwrap_or(0);
            info.bytes_in = n;
            info.bytes_out = n;
            ctx.add_bytes(n);
            return send_piece(
                out,
                Piece { seq, part: 0, last: true, permit: 0, body: Body::RawCopy(Arc::new(meta), idx, info) },
            );
        }
    } else {
        info.encoding = Some(kind.label());
    }
    let mask = text::mask_char_for(kind, ctx.cfg.mask_char, ctx.cfg.fallback_char, ctx.utf8_out);
    let whole_max = ctx.plan.whole_max;
    let mut data = head;
    let mut done = eof && data.len() <= whole_max;
    let mut permit = 0u64;
    if !eof {
        let known = if inner_gz { None } else { meta.size };
        if let Some(sz) = known.filter(|&s| s <= whole_max as u64) {
            permit = ctx.acquire(sz * FACTOR + 4096)?;
            let hit_eof = read_up_to(rd, &mut data, whole_max + 1).ctx(|| crate::t!("io.read", path = meta.name))?;
            done = hit_eof && data.len() <= whole_max;
        }
    }
    if done {
        permit = ctx.adjust(permit, data.len() as u64 * FACTOR)?;
        ctx.add_bytes(data.len() as u64);
        let job = Job::Whole { seq, meta: Arc::new(meta), data, kind, mask, inner_gz, permit, info };
        return send_job(ctx, jobs, out, job);
    }
    ctx.budget.release(permit);
    stream_entry(ctx, seq, meta, rd, data, kind, mask, inner_gz, info, jobs, out)
}

#[allow(clippy::too_many_arguments)]
fn stream_entry(
    ctx: &Ctx,
    seq: u64,
    meta: EntryMeta,
    rd: &mut dyn Read,
    initial: Vec<u8>,
    kind: TextKind,
    mask: char,
    inner_gz: bool,
    info: EntryReport,
    jobs: &Sender<Job>,
    out: &Sender<Piece>,
) -> Result<()> {
    let learn = ctx.learning();
    let (mode, decoder, skip) = match kind {
        TextKind::Binary(_) => (ChunkMode::Copy, None, 0),
        TextKind::Utf8 { .. } => (ChunkMode::Utf8, None, 0),
        TextKind::Legacy { enc, bom_len } => {
            (ChunkMode::Legacy(enc), Some(StreamDecoder::new(enc)), bom_len.min(initial.len()))
        }
    };
    let mut prefix = if ctx.utf8_out { Vec::new() } else { initial[..skip].to_vec() };
    let mut ch = Chunker::new(ctx.plan.chunk, !matches!(mode, ChunkMode::Copy), decoder);
    ch.push(&initial[skip..]);
    ctx.add_bytes(initial.len() as u64);
    drop(initial);
    let name = meta.name.clone();
    let meta = Arc::new(meta);
    if !learn {
        send_piece(
            out,
            Piece { seq, part: 0, last: false, permit: 0, body: Body::Begin { meta: meta.clone(), inner_gz, info } },
        )?;
    }
    let mut part = 0u32;
    let mut emit = |data: Vec<u8>, last: bool, note: Option<String>| -> Result<()> {
        part += 1;
        let permit = ctx.acquire(data.len() as u64 * FACTOR)?;
        let job = Job::Chunk { seq, part, last, data, mode, mask, prefix: std::mem::take(&mut prefix), permit, note };
        send_job(ctx, jobs, out, job)
    };
    let mut held: Option<Vec<u8>> = None;
    let mut buf = vec![0u8; READ_BLOCK];
    loop {
        while let Some(c) = ch.take(false) {
            if let Some(h) = held.replace(c) {
                emit(h, false, None)?;
            }
        }
        if ctx.stop() {
            return Ok(());
        }
        let n = match rd.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::io(crate::t!("io.read", path = name), e)),
        };
        if n == 0 {
            break;
        }
        ctx.add_bytes(n as u64);
        ch.push(&buf[..n]);
    }
    ch.finish_input();
    while let Some(c) = ch.take(true) {
        if let Some(h) = held.replace(c) {
            emit(h, false, None)?;
        }
    }
    let note = ch.had_decode_errors().then(|| crate::t!("pipeline.decode_replaced"));
    match held {
        Some(h) => emit(h, true, note),
        None => {
            if learn {
                Ok(())
            } else {
                send_piece(out, Piece { seq, part: part + 1, last: true, permit: 0, body: Body::End })
            }
        }
    }
}

// ───────────────────────── Worker threads ─────────────────────────

/// Scrubs a chunk of UTF-8 / decoded text and encodes it back to the original encoding if needed.
fn scrub_text(ctx: &Ctx, data: &[u8], kind: TextKind, mask: char, counts: &mut Counts) -> (Vec<u8>, Option<String>) {
    let engine = ctx.engine;
    match kind {
        TextKind::Legacy { enc, bom_len } => {
            let body = &data[bom_len.min(data.len())..];
            let utf16 = enc == encoding_rs::UTF_16LE || enc == encoding_rs::UTF_16BE || enc == encoding_rs::GB18030;
            let decoded = if utf16 {
                let (s, _) = enc.decode_without_bom_handling(body);
                Some(s.into_owned())
            } else {
                text::decode_strict(body, enc)
            };
            match decoded {
                Some(s) => {
                    let mut o = Vec::with_capacity(s.len() + s.len() / 8);
                    engine.scrub(s.as_bytes(), &mut o, counts, mask);
                    if ctx.utf8_out {
                        return (o, None);
                    }
                    let txt = String::from_utf8_lossy(&o);
                    let mut b = data[..bom_len.min(data.len())].to_vec();
                    b.extend_from_slice(&text::encode(&txt, enc));
                    (b, None)
                }
                None => {
                    let mut o = Vec::with_capacity(data.len());
                    engine.scrub(data, &mut o, counts, ctx.cfg.fallback_char);
                    (o, Some(crate::t!("pipeline.decode_failed", encoding = enc.name())))
                }
            }
        }
        _ => {
            let mut o = Vec::with_capacity(data.len() + data.len() / 8);
            engine.scrub(data, &mut o, counts, mask);
            (o, None)
        }
    }
}

fn learn_text(ctx: &Ctx, data: &[u8], kind: TextKind) -> Vec<(Category, String)> {
    let mut set = HashSet::new();
    match kind {
        TextKind::Legacy { enc, bom_len } => {
            let (s, _) = enc.decode_without_bom_handling(&data[bom_len.min(data.len())..]);
            ctx.engine.learn(s.as_bytes(), &mut set);
        }
        TextKind::Utf8 { .. } => ctx.engine.learn(data, &mut set),
        TextKind::Binary(_) => {}
    }
    set.into_iter().collect()
}

fn process(ctx: &Ctx, job: Job, out: &Sender<Piece>) -> Result<()> {
    match job {
        Job::Whole { seq, meta, data, kind, mask, inner_gz, permit, mut info } => {
            if ctx.learning() {
                let v = learn_text(ctx, &data, kind);
                return send_piece(out, Piece { seq, part: 0, last: true, permit, body: Body::Learned(v) });
            }
            info.bytes_in = data.len() as u64;
            let mut bytes = if kind.is_binary() {
                data
            } else {
                let (b, note) = scrub_text(ctx, &data, kind, mask, &mut info.by_category);
                if let Some(n) = note {
                    info.set_note(n);
                }
                drop(data);
                b
            };
            info.bytes_out = bytes.len() as u64;
            if inner_gz {
                bytes = gzip(&bytes)?;
            }
            let (data, blob) = if ctx.sink_blob { (make_zip_blob(&meta, &bytes)?, true) } else { (bytes, false) };
            send_piece(out, Piece { seq, part: 0, last: true, permit, body: Body::Whole { meta, data, blob, info } })
        }
        Job::Chunk { seq, part, last, data, mode, mask, prefix, permit, note } => {
            if ctx.learning() {
                let kind = match mode {
                    ChunkMode::Copy => TextKind::Binary(text::BinaryKind::Nul),
                    // Already UTF-8
                    ChunkMode::Utf8 | ChunkMode::Legacy(_) => TextKind::Utf8 { bom: false },
                };
                let v = learn_text(ctx, &data, kind);
                return send_piece(out, Piece { seq, part, last, permit, body: Body::Learned(v) });
            }
            let mut counts = Counts::default();
            let bytes_in = data.len() as u64;
            let bytes = match mode {
                ChunkMode::Copy => data,
                ChunkMode::Utf8 => {
                    let mut o = Vec::with_capacity(data.len() + data.len() / 8);
                    ctx.engine.scrub(&data, &mut o, &mut counts, mask);
                    o
                }
                ChunkMode::Legacy(enc) => {
                    let mut o = Vec::with_capacity(data.len() + data.len() / 8);
                    ctx.engine.scrub(&data, &mut o, &mut counts, mask);
                    if ctx.utf8_out {
                        o
                    } else {
                        let mut b = prefix;
                        b.extend_from_slice(&text::encode(&String::from_utf8_lossy(&o), enc));
                        b
                    }
                }
            };
            send_piece(
                out,
                Piece { seq, part, last, permit, body: Body::Chunk { data: bytes, counts, bytes_in, note } },
            )
        }
    }
}

fn worker(ctx: &Ctx, rx: Receiver<Job>, out: Sender<Piece>) {
    for job in rx.iter() {
        if ctx.stop() {
            ctx.budget.release(job.permit());
            continue;
        }
        let permit = job.permit();
        if let Err(e) = process(ctx, job, &out) {
            ctx.budget.release(permit);
            ctx.fail(e);
        }
    }
}

// ───────────────────────── Writer thread ─────────────────────────

struct Stream {
    gz: Option<GzEncoder<Vec<u8>>>,
    info: EntryReport,
}

fn finish_stream(st: Stream, sink: &mut dyn Sink, entries: &mut Vec<EntryReport>) -> Result<()> {
    if let Some(gz) = st.gz {
        let tail = gz.finish().ctx(|| "gzip".into())?;
        if !tail.is_empty() {
            sink.write(&tail)?;
        }
    }
    sink.end()?;
    entries.push(st.info);
    Ok(())
}

fn handle(
    body: Body,
    last: bool,
    sink: &mut dyn Sink,
    stream: &mut Option<Stream>,
    entries: &mut Vec<EntryReport>,
) -> Result<()> {
    match body {
        Body::Dir(meta, info) => {
            sink.dir(&meta)?;
            entries.push(info);
        }
        Body::Link(meta, target, hard, info) => {
            sink.link(&meta, &target, hard)?;
            entries.push(info);
        }
        Body::RawCopy(meta, idx, info) => {
            sink.raw_copy(&meta, idx)?;
            entries.push(info);
        }
        Body::Whole { meta, data, blob, info } => {
            if blob {
                sink.zip_blob(&meta, data)?;
            } else {
                sink.file(&meta, &data)?;
            }
            entries.push(info);
        }
        Body::Begin { meta, inner_gz, info } => {
            sink.begin(&meta)?;
            let st = Stream { gz: inner_gz.then(|| GzEncoder::new(Vec::new(), Compression::new(6))), info };
            if last {
                finish_stream(st, sink, entries)?;
            } else {
                *stream = Some(st);
            }
        }
        Body::Chunk { data, counts, bytes_in, note } => {
            let st = stream.as_mut().ok_or_else(|| Error::Other(crate::t!("pipeline.stream_no_begin")))?;
            st.info.by_category.merge(&counts);
            st.info.bytes_in += bytes_in;
            st.info.bytes_out += data.len() as u64;
            if let Some(n) = note {
                st.info.set_note(n);
            }
            match &mut st.gz {
                Some(gz) => {
                    gz.write_all(&data).ctx(|| "gzip".into())?;
                    let buf = std::mem::take(gz.get_mut());
                    if !buf.is_empty() {
                        sink.write(&buf)?;
                    }
                }
                None => sink.write(&data)?,
            }
            if last {
                let st = stream.take().expect("checked above");
                finish_stream(st, sink, entries)?;
            }
        }
        Body::End => {
            if let Some(st) = stream.take() {
                finish_stream(st, sink, entries)?;
            }
        }
        Body::Skip(info) => entries.push(info),
        Body::Learned(_) => {}
    }
    Ok(())
}

fn writer(ctx: &Ctx, rx: Receiver<Piece>, sink: &mut dyn Sink, entries: &mut Vec<EntryReport>) {
    let mut pending: BTreeMap<(u64, u32), Piece> = BTreeMap::new();
    let mut cur = (0u64, 0u32);
    let mut stream: Option<Stream> = None;
    for piece in rx.iter() {
        if ctx.stop() {
            ctx.budget.release(piece.permit);
            continue;
        }
        pending.insert((piece.seq, piece.part), piece);
        while let Some(p) = pending.remove(&cur) {
            let (last, permit) = (p.last, p.permit);
            let r = handle(p.body, last, sink, &mut stream, entries);
            ctx.budget.release(permit);
            if let Err(e) = r {
                ctx.fail(e);
                break;
            }
            cur = if last { (cur.0 + 1, 0) } else { (cur.0, cur.1 + 1) };
        }
    }
    for (_, p) in pending {
        ctx.budget.release(p.permit);
    }
    if !ctx.stop() && stream.is_some() {
        ctx.fail(Error::Other(crate::t!("pipeline.stream_unfinished")));
    }
}

fn learn_collector(ctx: &Ctx, rx: Receiver<Piece>) -> HashSet<(Category, String)> {
    let mut set = HashSet::new();
    for piece in rx.iter() {
        ctx.budget.release(piece.permit);
        if let Body::Learned(v) = piece.body {
            set.extend(v);
        }
    }
    set
}

// ───────────────────────── Entry point ─────────────────────────

/// Second pass: scrubs and writes output. Returns the entry reports and the sink (the caller calls finish / abort).
pub fn scrub_pass(
    ctx: &Ctx,
    src: &mut dyn Source,
    sink: Box<dyn Sink>,
) -> (Result<()>, Box<dyn Sink>, Vec<EntryReport>) {
    let (job_tx, job_rx) = bounded::<Job>(ctx.plan.workers * 2);
    let (out_tx, out_rx) = unbounded::<Piece>();
    let (sink, entries) = std::thread::scope(|s| {
        if !ctx.plan.inline {
            for _ in 0..ctx.plan.workers {
                let rx = job_rx.clone();
                let tx = out_tx.clone();
                s.spawn(move || worker(ctx, rx, tx));
            }
        }
        drop(job_rx);
        let w = s.spawn(move || {
            let mut sink = sink;
            let mut entries = Vec::new();
            writer(ctx, out_rx, sink.as_mut(), &mut entries);
            (sink, entries)
        });
        if let Err(e) = reader(ctx, src, &job_tx, &out_tx) {
            ctx.fail(e);
        }
        drop(job_tx);
        drop(out_tx);
        w.join().expect("writer thread panicked")
    });
    (ctx.outcome(), sink, entries)
}

/// First pass: only collects "learned" values such as usernames and hostnames.
pub fn learn_pass(ctx: &Ctx, src: &mut dyn Source) -> Result<HashSet<(Category, String)>> {
    let (job_tx, job_rx) = bounded::<Job>(ctx.plan.workers * 2);
    let (out_tx, out_rx) = unbounded::<Piece>();
    let set = std::thread::scope(|s| {
        if !ctx.plan.inline {
            for _ in 0..ctx.plan.workers {
                let rx = job_rx.clone();
                let tx = out_tx.clone();
                s.spawn(move || worker(ctx, rx, tx));
            }
        }
        drop(job_rx);
        let c = s.spawn(move || learn_collector(ctx, out_rx));
        if let Err(e) = reader(ctx, src, &job_tx, &out_tx) {
            ctx.fail(e);
        }
        drop(job_tx);
        drop(out_tx);
        c.join().expect("collector thread panicked")
    });
    ctx.outcome()?;
    Ok(set)
}
