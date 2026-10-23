//! Output sinks. All output is first written to `<target>.part` and renamed on success; it is deleted on error or
//! cancellation. Only scrubbed data is ever written to disk.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use super::pargz::{ParDeflate, ParGzWriter};
use super::{EntryMeta, OutputKind, unix_to_zip_time};
use crate::error::{Error, IoContext, Result, ZipContext};

pub trait Sink: Send {
    /// Whether the sink accepts "single-entry zips" pre-compressed by worker threads (parallel compression).
    fn supports_zip_blob(&self) -> bool {
        false
    }
    /// Whether the sink can copy entries verbatim from the source zip (binary and encrypted entries).
    fn supports_raw_copy(&self) -> bool {
        false
    }
    fn dir(&mut self, m: &EntryMeta) -> Result<()>;
    fn link(&mut self, m: &EntryMeta, target: &str, hard: bool) -> Result<()>;
    fn file(&mut self, m: &EntryMeta, data: &[u8]) -> Result<()>;
    fn zip_blob(&mut self, m: &EntryMeta, _blob: Vec<u8>) -> Result<()> {
        Err(Error::Other(crate::t!("pipeline.no_zip_blob", name = m.name)))
    }
    fn raw_copy(&mut self, m: &EntryMeta, _index: usize) -> Result<()> {
        Err(Error::Other(crate::t!("pipeline.no_raw_copy", name = m.name)))
    }
    /// Streams one large entry: begin → write… → end.
    fn begin(&mut self, m: &EntryMeta) -> Result<()>;
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn end(&mut self) -> Result<()>;
    /// Finishes and renames the output; returns the number of bytes written.
    fn finish(self: Box<Self>) -> Result<u64>;
    /// Gives up: deletes the unfinished output.
    fn abort(self: Box<Self>);
}

/// Streamed zip entries up to this input size are deflated on all cores in memory and then copied into the archive;
/// larger ones (or ones of unknown size) are compressed by the zip writer as they stream, keeping memory bounded.
const PARALLEL_ZIP_MAX: u64 = 512 << 20;

/// Threads for compressing a .gz / .tar.gz output stream or a large zip entry.
fn gzip_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// `<target>.part`
pub fn part_path(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

fn remove_any(p: &Path) {
    if let Ok(md) = fs::symlink_metadata(p) {
        if md.is_dir() {
            let _ = fs::remove_dir_all(p);
        } else {
            let _ = fs::remove_file(p);
        }
    }
}

/// Renames the `.part` file to the final path.
fn commit(part: &Path, final_path: &Path, force: bool) -> Result<()> {
    if fs::symlink_metadata(final_path).is_ok() {
        if !force {
            remove_any(part);
            return Err(Error::OutputExists(final_path.display().to_string()));
        }
        remove_any(final_path);
    }
    fs::rename(part, final_path).map_err(|e| Error::io_path("io.rename", final_path, e))
}

fn size_of(p: &Path) -> u64 {
    fn walk(p: &Path) -> u64 {
        match fs::symlink_metadata(p) {
            Ok(md) if md.is_dir() => {
                fs::read_dir(p).map(|it| it.filter_map(|e| e.ok()).map(|e| walk(&e.path())).sum()).unwrap_or(0)
            }
            Ok(md) => md.len(),
            Err(_) => 0,
        }
    }
    walk(p)
}

/// Strips absolute-path prefixes and `..` so nothing can be written outside the target directory.
pub fn sanitize_rel(name: &str) -> String {
    let unified = name.replace('\\', "/");
    let mut parts: Vec<String> = Vec::new();
    for c in Path::new(&unified).components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::ParentDir => {
                parts.pop();
            }
            _ => {}
        }
    }
    let s = parts.join("/");
    if s.is_empty() { "_".into() } else { s }
}

fn zip_options(m: &EntryMeta, large: bool) -> SimpleFileOptions {
    let mut o = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6))
        .large_file(large);
    if let Some(mode) = m.mode {
        o = o.unix_permissions(mode & 0o7777);
    }
    if let Some(t) = m.zip_time.or_else(|| m.mtime.and_then(unix_to_zip_time)) {
        o = o.last_modified_time(t);
    }
    o
}

/// For worker threads: compresses one entry into an in-memory zip containing only that entry; the writer thread then
/// merges it into the output without recompressing.
pub fn make_zip_blob(m: &EntryMeta, data: &[u8]) -> Result<Vec<u8>> {
    let mut w = ZipWriter::new(Cursor::new(Vec::with_capacity(data.len() / 3 + 512)));
    w.start_file(m.name.clone(), zip_options(m, data.len() as u64 >= 0xF000_0000)).zctx(|| m.name.clone())?;
    w.write_all(data).ctx(|| crate::t!("io.compress", path = m.name))?;
    Ok(w.finish().zctx(|| m.name.clone())?.into_inner())
}

/// A single-entry zip holding already-deflated data. The zip crate writes it as a stored entry, so the name, times and
/// permissions are encoded exactly as for any other entry; then the method, version, CRC-32 and uncompressed size in
/// the local and central headers are patched to describe the deflate stream.
pub fn deflated_zip_blob(m: &EntryMeta, deflated: &[u8], crc: u32, size: u64) -> Result<Vec<u8>> {
    let too_big = || Error::Other(crate::t!("pipeline.no_zip_blob", name = m.name));
    let size = u32::try_from(size).map_err(|_| too_big())?;
    u32::try_from(deflated.len()).map_err(|_| too_big())?;
    let o = zip_options(m, false).compression_method(CompressionMethod::Stored).compression_level(None);
    let mut w = ZipWriter::new(Cursor::new(Vec::with_capacity(deflated.len() + 512)));
    w.start_file(m.name.clone(), o).zctx(|| m.name.clone())?;
    w.write_all(deflated).ctx(|| crate::t!("io.compress", path = m.name))?;
    let mut b = w.finish().zctx(|| m.name.clone())?.into_inner();

    let u16_at = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let put16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    // The layout is fixed: no archive comment, no zip64, sizes in the local header (the output is seekable).
    let eocd = b.len().checked_sub(22).ok_or_else(too_big)?;
    let central = u32_at(&b, eocd + 16) as usize;
    if u32_at(&b, 0) != 0x0403_4b50 || u32_at(&b, eocd) != 0x0605_4b50 || u32_at(&b, central) != 0x0201_4b50 {
        return Err(too_big());
    }
    debug_assert_eq!((u16_at(&b, 8), u16_at(&b, central + 10)), (0, 0), "stored entries");
    // Local header: version needed, method, CRC-32, uncompressed size.
    put16(&mut b, 4, 20);
    put16(&mut b, 8, 8);
    put32(&mut b, 14, crc);
    put32(&mut b, 22, size);
    // Central header: the same fields, 2 bytes further in, and "version made by" (low byte; the high byte is the OS).
    b[central + 4] = b[central + 4].max(20);
    put16(&mut b, central + 6, 20);
    put16(&mut b, central + 10, 8);
    put32(&mut b, central + 16, crc);
    put32(&mut b, central + 24, size);
    Ok(b)
}

/// Gzip-compresses a chunk of data (used when writing nested .gz logs back).
pub fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut e = GzEncoder::new(Vec::with_capacity(data.len() / 3 + 64), Compression::new(6));
    e.write_all(data).ctx(|| "gzip".into())?;
    e.finish().ctx(|| "gzip".into())
}

// ───────────────────────── zip ─────────────────────────

pub struct ZipSink {
    w: Option<ZipWriter<BufWriter<File>>>,
    part: PathBuf,
    final_path: PathBuf,
    force: bool,
    src_path: Option<PathBuf>,
    src: Option<ZipArchive<BufReader<File>>>,
    /// The streamed entry being deflated in parallel, if any.
    stream: Option<(EntryMeta, ParDeflate<Vec<u8>>)>,
}

impl ZipSink {
    pub fn create(final_path: &Path, force: bool, src_zip: Option<&Path>) -> Result<ZipSink> {
        let part = part_path(final_path);
        let f = File::create(&part).map_err(|e| Error::io_path("io.create", &part, e))?;
        Ok(ZipSink {
            w: Some(ZipWriter::new(BufWriter::with_capacity(1 << 20, f))),
            part,
            final_path: final_path.to_path_buf(),
            force,
            src_path: src_zip.map(Path::to_path_buf),
            src: None,
            stream: None,
        })
    }

    fn w(&mut self) -> &mut ZipWriter<BufWriter<File>> {
        self.w.as_mut().expect("zip writer already closed")
    }
}

impl Sink for ZipSink {
    fn supports_zip_blob(&self) -> bool {
        true
    }

    fn supports_raw_copy(&self) -> bool {
        self.src_path.is_some()
    }

    fn dir(&mut self, m: &EntryMeta) -> Result<()> {
        let name = format!("{}/", m.name.trim_end_matches('/'));
        let o = zip_options(m, false);
        self.w().add_directory(name, o).zctx(|| m.name.clone())
    }

    fn link(&mut self, m: &EntryMeta, target: &str, _hard: bool) -> Result<()> {
        let o = zip_options(m, false);
        self.w().add_symlink(m.name.clone(), target, o).zctx(|| m.name.clone())
    }

    fn file(&mut self, m: &EntryMeta, data: &[u8]) -> Result<()> {
        let o = zip_options(m, data.len() as u64 >= 0xF000_0000);
        let w = self.w();
        w.start_file(m.name.clone(), o).zctx(|| m.name.clone())?;
        w.write_all(data).ctx(|| crate::t!("io.write", path = m.name))
    }

    fn zip_blob(&mut self, m: &EntryMeta, blob: Vec<u8>) -> Result<()> {
        let mut a = ZipArchive::new(Cursor::new(blob)).zctx(|| m.name.clone())?;
        let f = a.by_index_raw(0).zctx(|| m.name.clone())?;
        self.w.as_mut().expect("zip writer already closed").raw_copy_file(f).zctx(|| m.name.clone())
    }

    fn raw_copy(&mut self, m: &EntryMeta, index: usize) -> Result<()> {
        if self.src.is_none() {
            let p = self.src_path.clone().ok_or_else(|| Error::Other(crate::t!("pipeline.missing_src_zip")))?;
            let f = File::open(&p).map_err(|e| Error::io_path("io.open", &p, e))?;
            self.src = Some(ZipArchive::new(BufReader::new(f)).zctx(|| p.display().to_string())?);
        }
        let src = self.src.as_mut().expect("just opened");
        let f = src.by_index_raw(index).zctx(|| m.name.clone())?;
        self.w
            .as_mut()
            .expect("zip writer already closed")
            .raw_copy_file_rename(f, m.name.clone())
            .zctx(|| m.name.clone())
    }

    fn begin(&mut self, m: &EntryMeta) -> Result<()> {
        if m.size.is_some_and(|s| s <= PARALLEL_ZIP_MAX) {
            self.stream = Some((m.clone(), ParDeflate::new(Vec::new(), Compression::new(6), gzip_threads())));
            return Ok(());
        }
        let large = m.size.is_none_or(|s| s.saturating_mul(3) >= 0xF000_0000);
        let o = zip_options(m, large);
        self.w().start_file(m.name.clone(), o).zctx(|| m.name.clone())
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.stream {
            Some((m, d)) => d.write_all(data).ctx(|| crate::t!("io.compress", path = m.name)),
            None => self.w().write_all(data).ctx(|| crate::t!("io.write_output")),
        }
    }

    fn end(&mut self) -> Result<()> {
        let Some((m, d)) = self.stream.take() else { return Ok(()) };
        let (deflated, crc, size) = d.finish().ctx(|| crate::t!("io.compress", path = m.name))?;
        let blob = deflated_zip_blob(&m, &deflated, crc, size)?;
        self.zip_blob(&m, blob)
    }

    fn finish(mut self: Box<Self>) -> Result<u64> {
        let w = self.w.take().expect("zip writer already closed");
        let mut buf = w.finish().zctx(|| self.part.display().to_string())?;
        buf.flush().ctx(|| crate::t!("io.write", path = self.part.display()))?;
        let f = buf.into_inner().map_err(|e| Error::io(crate::t!("io.write_output"), e.into_error()))?;
        f.sync_all().ok();
        drop(f);
        commit(&self.part, &self.final_path, self.force)?;
        Ok(size_of(&self.final_path))
    }

    fn abort(mut self: Box<Self>) {
        drop(self.w.take());
        remove_any(&self.part);
    }
}

// ───────────────────────── tar / tar.gz ─────────────────────────

enum TarOut {
    Plain(BufWriter<File>),
    Gz(ParGzWriter<BufWriter<File>>),
}

impl Write for TarOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TarOut::Plain(w) => w.write(buf),
            TarOut::Gz(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TarOut::Plain(w) => w.flush(),
            TarOut::Gz(w) => w.flush(),
        }
    }
}

/// Staging buffer for a streamed entry: a tar header must contain the size up front, but masking changes the byte
/// count. Data is kept in memory first and spills to an anonymous temporary file past a limit (scrubbed data only).
struct Spill {
    mem: Vec<u8>,
    file: Option<File>,
    len: u64,
    limit: usize,
    dir: PathBuf,
}

impl Spill {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.file.is_none() && self.mem.len() + data.len() > self.limit {
            let mut f =
                tempfile::tempfile_in(&self.dir).ctx(|| crate::t!("io.temp_create", path = self.dir.display()))?;
            f.write_all(&self.mem).ctx(|| crate::t!("io.temp_io"))?;
            self.mem = Vec::new();
            self.file = Some(f);
        }
        match &mut self.file {
            Some(f) => f.write_all(data).ctx(|| crate::t!("io.temp_io"))?,
            None => self.mem.extend_from_slice(data),
        }
        self.len += data.len() as u64;
        Ok(())
    }
}

pub struct TarSink {
    b: Option<tar::Builder<TarOut>>,
    part: PathBuf,
    final_path: PathBuf,
    force: bool,
    stream: Option<(EntryMeta, Spill)>,
    spill_limit: usize,
}

fn tar_header(m: &EntryMeta, kind: tar::EntryType, size: u64, default_mode: u32) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_size(size);
    h.set_mode(m.mode.unwrap_or(default_mode));
    let mtime = m.mtime.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
    });
    h.set_mtime(mtime.max(0) as u64);
    h
}

impl TarSink {
    pub fn create(final_path: &Path, gz: bool, force: bool, spill_limit: usize) -> Result<TarSink> {
        let part = part_path(final_path);
        let f = File::create(&part).map_err(|e| Error::io_path("io.create", &part, e))?;
        let w = BufWriter::with_capacity(1 << 20, f);
        let out =
            if gz { TarOut::Gz(ParGzWriter::new(w, Compression::new(6), gzip_threads())) } else { TarOut::Plain(w) };
        let mut b = tar::Builder::new(out);
        b.follow_symlinks(false);
        Ok(TarSink {
            b: Some(b),
            part,
            final_path: final_path.to_path_buf(),
            force,
            stream: None,
            spill_limit: spill_limit.max(1 << 20),
        })
    }

    fn b(&mut self) -> &mut tar::Builder<TarOut> {
        self.b.as_mut().expect("tar builder already closed")
    }
}

impl Sink for TarSink {
    fn dir(&mut self, m: &EntryMeta) -> Result<()> {
        let mut h = tar_header(m, tar::EntryType::Directory, 0, 0o755);
        let name = format!("{}/", sanitize_rel(&m.name));
        self.b().append_data(&mut h, name, io::empty()).ctx(|| crate::t!("io.write", path = m.name))
    }

    fn link(&mut self, m: &EntryMeta, target: &str, hard: bool) -> Result<()> {
        let kind = if hard { tar::EntryType::Link } else { tar::EntryType::Symlink };
        let mut h = tar_header(m, kind, 0, 0o777);
        let name = sanitize_rel(&m.name);
        self.b().append_link(&mut h, name, target).ctx(|| crate::t!("io.write_link", path = m.name))
    }

    fn file(&mut self, m: &EntryMeta, data: &[u8]) -> Result<()> {
        let mut h = tar_header(m, tar::EntryType::Regular, data.len() as u64, 0o644);
        let name = sanitize_rel(&m.name);
        self.b().append_data(&mut h, name, data).ctx(|| crate::t!("io.write", path = m.name))
    }

    fn begin(&mut self, m: &EntryMeta) -> Result<()> {
        let dir =
            self.final_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
        self.stream = Some((m.clone(), Spill { mem: Vec::new(), file: None, len: 0, limit: self.spill_limit, dir }));
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.stream {
            Some((_, s)) => s.write(data),
            None => Err(Error::Other(crate::t!("pipeline.stream_not_started"))),
        }
    }

    fn end(&mut self) -> Result<()> {
        let Some((m, spill)) = self.stream.take() else { return Ok(()) };
        let mut h = tar_header(&m, tar::EntryType::Regular, spill.len, 0o644);
        let name = sanitize_rel(&m.name);
        match spill.file {
            Some(mut f) => {
                f.seek(SeekFrom::Start(0)).ctx(|| crate::t!("io.temp_io"))?;
                let r = BufReader::new(f).take(spill.len);
                self.b().append_data(&mut h, name, r).ctx(|| crate::t!("io.write", path = m.name))
            }
            None => {
                self.b().append_data(&mut h, name, spill.mem.as_slice()).ctx(|| crate::t!("io.write", path = m.name))
            }
        }
    }

    fn finish(mut self: Box<Self>) -> Result<u64> {
        let b = self.b.take().expect("tar builder already closed");
        let out = b.into_inner().ctx(|| crate::t!("io.write", path = self.part.display()))?;
        let mut w = match out {
            TarOut::Plain(w) => w,
            TarOut::Gz(g) => g.finish().ctx(|| crate::t!("io.write", path = self.part.display()))?,
        };
        w.flush().ctx(|| crate::t!("io.write", path = self.part.display()))?;
        let f = w.into_inner().map_err(|e| Error::io(crate::t!("io.write_output"), e.into_error()))?;
        f.sync_all().ok();
        drop(f);
        commit(&self.part, &self.final_path, self.force)?;
        Ok(size_of(&self.final_path))
    }

    fn abort(mut self: Box<Self>) {
        drop(self.b.take());
        remove_any(&self.part);
    }
}

// ───────────────────────── Folder ─────────────────────────

pub struct DirSink {
    root: PathBuf,
    final_path: PathBuf,
    force: bool,
    current: Option<(PathBuf, BufWriter<File>, EntryMeta)>,
}

impl DirSink {
    pub fn create(final_path: &Path, force: bool) -> Result<DirSink> {
        let root = part_path(final_path);
        remove_any(&root);
        fs::create_dir_all(&root).map_err(|e| Error::io_path("io.mkdir", &root, e))?;
        Ok(DirSink { root, final_path: final_path.to_path_buf(), force, current: None })
    }

    fn path_for(&self, name: &str) -> Result<PathBuf> {
        let p = self.root.join(sanitize_rel(name));
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io_path("io.mkdir", parent, e))?;
        }
        Ok(p)
    }

    fn set_meta(path: &Path, m: &EntryMeta) {
        if let Some(t) = m.mtime.filter(|t| *t > 0)
            && let Ok(f) = File::options().write(true).open(path)
        {
            let _ = f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t as u64));
        }
        #[cfg(unix)]
        if let Some(mode) = m.mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
        }
    }
}

impl Sink for DirSink {
    fn dir(&mut self, m: &EntryMeta) -> Result<()> {
        let p = self.root.join(sanitize_rel(&m.name));
        fs::create_dir_all(&p).map_err(|e| Error::io_path("io.mkdir", &p, e))
    }

    fn link(&mut self, m: &EntryMeta, target: &str, _hard: bool) -> Result<()> {
        let p = self.path_for(&m.name)?;
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(target, &p);
        }
        #[cfg(not(unix))]
        {
            let _ = (p, target);
        }
        Ok(())
    }

    fn file(&mut self, m: &EntryMeta, data: &[u8]) -> Result<()> {
        let p = self.path_for(&m.name)?;
        fs::write(&p, data).map_err(|e| Error::io_path("io.write", &p, e))?;
        Self::set_meta(&p, m);
        Ok(())
    }

    fn begin(&mut self, m: &EntryMeta) -> Result<()> {
        let p = self.path_for(&m.name)?;
        let f = File::create(&p).map_err(|e| Error::io_path("io.create", &p, e))?;
        self.current = Some((p, BufWriter::with_capacity(1 << 20, f), m.clone()));
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.current {
            Some((p, w, _)) => w.write_all(data).map_err(|e| Error::io_path("io.write", p, e)),
            None => Err(Error::Other(crate::t!("pipeline.stream_not_started"))),
        }
    }

    fn end(&mut self) -> Result<()> {
        if let Some((p, mut w, m)) = self.current.take() {
            w.flush().map_err(|e| Error::io_path("io.write", &p, e))?;
            drop(w);
            Self::set_meta(&p, &m);
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<u64> {
        self.end()?;
        commit(&self.root, &self.final_path, self.force)?;
        Ok(size_of(&self.final_path))
    }

    fn abort(mut self: Box<Self>) {
        drop(self.current.take());
        remove_any(&self.root);
    }
}

// ───────────────────────── Single file / .gz / stdout / discard ─────────────────────────

enum OneOut {
    Plain(BufWriter<File>),
    Gz(ParGzWriter<BufWriter<File>>),
    Stdout(BufWriter<io::Stdout>),
    Discard(u64),
}

impl OneOut {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            OneOut::Plain(w) => w.write_all(data),
            OneOut::Gz(w) => w.write_all(data),
            OneOut::Stdout(w) => w.write_all(data),
            OneOut::Discard(n) => {
                *n += data.len() as u64;
                Ok(())
            }
        }
    }
}

pub struct OneSink {
    out: Option<OneOut>,
    part: Option<PathBuf>,
    final_path: Option<PathBuf>,
    force: bool,
    written: u64,
    files: usize,
}

impl OneSink {
    pub fn file(final_path: &Path, gz: bool, force: bool) -> Result<OneSink> {
        let part = part_path(final_path);
        let f = File::create(&part).map_err(|e| Error::io_path("io.create", &part, e))?;
        let w = BufWriter::with_capacity(1 << 20, f);
        let out =
            if gz { OneOut::Gz(ParGzWriter::new(w, Compression::new(6), gzip_threads())) } else { OneOut::Plain(w) };
        Ok(OneSink {
            out: Some(out),
            part: Some(part),
            final_path: Some(final_path.to_path_buf()),
            force,
            written: 0,
            files: 0,
        })
    }

    pub fn stdout() -> OneSink {
        OneSink {
            out: Some(OneOut::Stdout(BufWriter::with_capacity(1 << 20, io::stdout()))),
            part: None,
            final_path: None,
            force: false,
            written: 0,
            files: 0,
        }
    }

    pub fn discard() -> OneSink {
        OneSink { out: Some(OneOut::Discard(0)), part: None, final_path: None, force: false, written: 0, files: 0 }
    }

    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.written += data.len() as u64;
        self.out.as_mut().expect("output already closed").write_all(data).ctx(|| crate::t!("io.write_output"))
    }

    fn start_file(&mut self, m: &EntryMeta) -> Result<()> {
        self.files += 1;
        let multi_ok = matches!(self.out, Some(OneOut::Discard(_)));
        if self.files > 1 && !multi_ok {
            return Err(Error::Unsupported(crate::t!("pipeline.one_file_only", name = m.name)));
        }
        Ok(())
    }
}

impl Sink for OneSink {
    fn dir(&mut self, _m: &EntryMeta) -> Result<()> {
        Ok(())
    }

    fn link(&mut self, _m: &EntryMeta, _target: &str, _hard: bool) -> Result<()> {
        Ok(())
    }

    fn file(&mut self, m: &EntryMeta, data: &[u8]) -> Result<()> {
        self.start_file(m)?;
        self.put(data)
    }

    fn begin(&mut self, m: &EntryMeta) -> Result<()> {
        self.start_file(m)
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.put(data)
    }

    fn end(&mut self) -> Result<()> {
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<u64> {
        match self.out.take() {
            Some(OneOut::Plain(mut w)) => {
                w.flush().ctx(|| crate::t!("io.write_output"))?;
            }
            Some(OneOut::Gz(g)) => {
                let mut w = g.finish().ctx(|| crate::t!("io.write_output"))?;
                w.flush().ctx(|| crate::t!("io.write_output"))?;
            }
            Some(OneOut::Stdout(mut w)) => {
                w.flush().ctx(|| crate::t!("io.write_stdout"))?;
                return Ok(self.written);
            }
            Some(OneOut::Discard(n)) => return Ok(n),
            None => {}
        }
        if let (Some(part), Some(fin)) = (&self.part, &self.final_path) {
            commit(part, fin, self.force)?;
            return Ok(size_of(fin));
        }
        Ok(self.written)
    }

    fn abort(mut self: Box<Self>) {
        drop(self.out.take());
        if let Some(p) = &self.part {
            remove_any(p);
        }
    }
}

/// Creates the output sink for the given output kind.
pub fn create_sink(
    kind: OutputKind,
    path: Option<&Path>,
    force: bool,
    src_zip: Option<&Path>,
    spill_limit: usize,
) -> Result<Box<dyn Sink>> {
    let need = || path.ok_or_else(|| Error::Other(crate::t!("pipeline.missing_output")));
    Ok(match kind {
        OutputKind::Zip => Box::new(ZipSink::create(need()?, force, src_zip)?),
        OutputKind::Tar => Box::new(TarSink::create(need()?, false, force, spill_limit)?),
        OutputKind::TarGz => Box::new(TarSink::create(need()?, true, force, spill_limit)?),
        OutputKind::Dir => Box::new(DirSink::create(need()?, force)?),
        OutputKind::Gz => Box::new(OneSink::file(need()?, true, force)?),
        OutputKind::File => Box::new(OneSink::file(need()?, false, force)?),
        OutputKind::Stdout => Box::new(OneSink::stdout()),
        OutputKind::Discard => Box::new(OneSink::discard()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Losing an auto trait on a public type is a breaking change; keep the sinks unwind-safe.
    #[test]
    fn sinks_keep_their_auto_traits() {
        fn check<T: Send + std::panic::RefUnwindSafe>() {}
        check::<ZipSink>();
        check::<TarSink>();
        check::<OneSink>();
    }

    #[test]
    fn deflated_blob_matches_a_normal_entry() {
        let mut m = EntryMeta::file("var/log/日志.log");
        m.mode = Some(0o640);
        m.mtime = Some(1_761_200_000);
        let data: Vec<u8> =
            (0..(5usize << 20) / 2).flat_map(|i| format!("line {i} 203.0.113.{}\n", i % 250).into_bytes()).collect();
        let mut d = ParDeflate::new(Vec::new(), Compression::new(6), 4);
        d.write_all(&data).unwrap();
        let (deflated, crc, size) = d.finish().unwrap();
        let blob = deflated_zip_blob(&m, &deflated, crc, size).unwrap();
        let normal = make_zip_blob(&m, &data).unwrap();

        let mut a = ZipArchive::new(Cursor::new(blob)).unwrap();
        let mut n = ZipArchive::new(Cursor::new(normal)).unwrap();
        let mut out = Vec::new();
        let mut fa = a.by_index(0).unwrap();
        fa.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        let fn_ = n.by_index(0).unwrap();
        assert_eq!(fa.name().unwrap(), fn_.name().unwrap());
        assert_eq!(fa.compression(), CompressionMethod::Deflated);
        assert_eq!(fa.crc32(), fn_.crc32());
        assert_eq!(fa.size(), fn_.size());
        assert_eq!(fa.last_modified(), fn_.last_modified());
        assert_eq!(fa.unix_mode(), fn_.unix_mode());
        assert_eq!(fa.version_made_by(), fn_.version_made_by());
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_rel("/etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_rel("../../x"), "x");
        assert_eq!(sanitize_rel("a/../b/c"), "b/c");
        assert_eq!(sanitize_rel("a\\b"), "a/b");
        assert_eq!(sanitize_rel(""), "_");
    }

    #[test]
    fn blob_roundtrip() {
        let m = EntryMeta::file("x/y.log");
        let blob = make_zip_blob(&m, b"hello").unwrap();
        let mut a = ZipArchive::new(Cursor::new(blob)).unwrap();
        let mut f = a.by_index(0).unwrap();
        assert_eq!(f.name().unwrap(), "x/y.log");
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
    }
}
