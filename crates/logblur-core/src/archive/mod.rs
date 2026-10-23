//! 输入源与输出端：zip、tar、tar.gz、单个 .gz、单个文件、文件夹、标准输入输出。

pub mod sink;

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::error::{Error, IoContext, Result, ZipContext};
use crate::util::{civil_from_unix, unix_from_civil};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Zip,
    Tar,
    TarGz,
    /// 单个 gzip 压缩的文本（如 syslog.2.gz）。
    Gz,
    File,
    Dir,
    Stdin,
}

impl InputKind {
    pub fn label(self) -> &'static str {
        match self {
            InputKind::Zip => "zip",
            InputKind::Tar => "tar",
            InputKind::TarGz => "tar.gz",
            InputKind::Gz => "gz",
            InputKind::File => "file",
            InputKind::Dir => "dir",
            InputKind::Stdin => "stdin",
        }
    }

    /// 能否读第二遍（学习阶段需要）。
    pub fn rereadable(self) -> bool {
        self != InputKind::Stdin
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    Zip,
    Tar,
    TarGz,
    Gz,
    File,
    Dir,
    Stdout,
    Discard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink(String),
    HardLink(String),
    /// 设备文件、FIFO 等：跳过。
    Other(String),
}

/// 条目的元数据。进入流水线后 `name` 会被替换成清洗过的名字。
#[derive(Debug, Clone)]
pub struct EntryMeta {
    pub name: String,
    pub kind: EntryKind,
    /// 解压后的大小（已知时）。
    pub size: Option<u64>,
    pub mode: Option<u32>,
    /// Unix 秒。
    pub mtime: Option<i64>,
    pub zip_time: Option<zip::DateTime>,
    /// 源 zip 中的序号（用于原样复制二进制条目）。
    pub zip_index: Option<usize>,
    pub encrypted: bool,
}

impl EntryMeta {
    pub fn file(name: impl Into<String>) -> EntryMeta {
        EntryMeta {
            name: name.into(),
            kind: EntryKind::File,
            size: None,
            mode: None,
            mtime: None,
            zip_time: None,
            zip_index: None,
            encrypted: false,
        }
    }
}

/// 访问者：返回 `Ok(false)` 停止遍历。
pub type Visitor<'a> = dyn FnMut(EntryMeta, Option<&mut dyn Read>) -> Result<bool> + 'a;

pub trait Source {
    fn kind(&self) -> InputKind;
    /// 所有条目解压后的总字节数（已知时，用于进度）。
    fn total_bytes(&self) -> Option<u64>;
    fn entry_count(&self) -> Option<u64>;
    fn visit(&mut self, f: &mut Visitor<'_>) -> Result<()>;
}

/// 读满 `buf` 直到 `limit` 字节或 EOF；返回是否到达 EOF。
pub fn read_up_to(r: &mut dyn Read, buf: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
    let mut chunk = [0u8; 64 * 1024];
    while buf.len() < limit {
        let want = (limit - buf.len()).min(chunk.len());
        match r.read(&mut chunk[..want]) {
            Ok(0) => return Ok(true),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

fn lower_name(p: &Path) -> String {
    p.file_name().map(|s| s.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

/// 根据魔数和扩展名判断输入类型。
pub fn detect_input(path: &Path) -> Result<InputKind> {
    let md = fs::metadata(path).map_err(|e| Error::io_path("io.access", path, e))?;
    if md.is_dir() {
        return Ok(InputKind::Dir);
    }
    let mut f = File::open(path).map_err(|e| Error::io_path("io.open", path, e))?;
    let mut head = Vec::new();
    read_up_to(&mut f, &mut head, 512).ctx(|| crate::t!("io.read", path = path.display()))?;
    let name = lower_name(path);
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Ok(InputKind::Zip);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        let mut dec = flate2::read::MultiGzDecoder::new(BufReader::new(File::open(path).map_err(|e| Error::io_path("io.open", path, e))?));
        let mut inner = Vec::new();
        let _ = read_up_to(&mut dec, &mut inner, 512);
        let ustar = inner.len() > 262 && &inner[257..262] == b"ustar";
        if ustar || name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            return Ok(InputKind::TarGz);
        }
        return Ok(InputKind::Gz);
    }
    if (head.len() > 262 && &head[257..262] == b"ustar") || name.ends_with(".tar") {
        return Ok(InputKind::Tar);
    }
    Ok(InputKind::File)
}

/// 默认输出路径：`foo.zip → foo.blurred.zip`、`app.log → app.blurred.log`、
/// `syslog.2.gz → syslog.2.blurred.gz`、`dir → dir.blurred.zip`。
pub fn default_output_path(input: &Path, kind: InputKind) -> PathBuf {
    let parent = input.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    let lower = name.to_ascii_lowercase();
    let split = |suffix_len: usize, ext: &str| -> String {
        format!("{}.blurred{}", &name[..name.len() - suffix_len], ext)
    };
    let file_name = match kind {
        InputKind::Dir => format!("{}.blurred.zip", name.trim_end_matches(['/', '\\'])),
        InputKind::TarGz if lower.ends_with(".tar.gz") => split(7, ".tar.gz"),
        InputKind::TarGz if lower.ends_with(".tgz") => split(4, ".tgz"),
        InputKind::TarGz => format!("{name}.blurred.tar.gz"),
        InputKind::Tar if lower.ends_with(".tar") => split(4, ".tar"),
        InputKind::Tar => format!("{name}.blurred.tar"),
        InputKind::Zip if lower.ends_with(".zip") => split(4, ".zip"),
        InputKind::Zip => format!("{name}.blurred.zip"),
        InputKind::Gz if lower.ends_with(".gz") => split(3, ".gz"),
        InputKind::Gz => format!("{name}.blurred.gz"),
        InputKind::File | InputKind::Stdin => match name.rsplit_once('.') {
            Some((stem, ext))
                if !stem.is_empty() && ext.len() <= 8 && ext.bytes().any(|b| b.is_ascii_alphabetic()) =>
            {
                format!("{stem}.blurred.{ext}")
            }
            _ => format!("{name}.blurred"),
        },
    };
    parent.join(file_name)
}

/// 由输出路径的扩展名决定输出格式。
pub fn output_kind_for(input: InputKind, out: &Path) -> OutputKind {
    let lower = out.to_string_lossy().to_ascii_lowercase();
    if lower.ends_with(".zip") {
        OutputKind::Zip
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        OutputKind::TarGz
    } else if lower.ends_with(".tar") {
        OutputKind::Tar
    } else {
        match input {
            InputKind::Zip | InputKind::Tar | InputKind::TarGz | InputKind::Dir => OutputKind::Dir,
            InputKind::Gz if lower.ends_with(".gz") => OutputKind::Gz,
            InputKind::Gz | InputKind::File | InputKind::Stdin => OutputKind::File,
        }
    }
}

/// 压缩包里的名字：UTF-8 优先，其次 GBK（中文 Windows 打的包），最后按原样有损转换。
pub fn decode_name(raw: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(raw) {
        return s.to_string();
    }
    if let Some(s) = encoding_rs::GBK.decode_without_bom_handling_and_without_replacement(raw) {
        return s.into_owned();
    }
    String::from_utf8_lossy(raw).into_owned()
}

pub fn zip_time_to_unix(t: &zip::DateTime) -> i64 {
    unix_from_civil(t.year() as i32, t.month(), t.day(), t.hour(), t.minute(), t.second())
}

pub fn unix_to_zip_time(secs: i64) -> Option<zip::DateTime> {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    if !(1980..=2107).contains(&y) {
        return None;
    }
    zip::DateTime::from_date_and_time(y as u16, mo, d, h, mi, s).ok()
}

fn system_time_secs(t: std::time::SystemTime) -> Option<i64> {
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

#[cfg(unix)]
fn file_mode(md: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(md.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_md: &fs::Metadata) -> Option<u32> {
    None
}

// ───────────────────────── zip ─────────────────────────

pub struct ZipSource {
    archive: zip::ZipArchive<BufReader<File>>,
    total: u64,
}

impl ZipSource {
    pub fn open(path: &Path) -> Result<ZipSource> {
        let f = File::open(path).map_err(|e| Error::io_path("io.open", path, e))?;
        let mut archive = zip::ZipArchive::new(BufReader::new(f)).zctx(|| path.display().to_string())?;
        let mut total = 0u64;
        for i in 0..archive.len() {
            if let Ok(zf) = archive.by_index_raw(i) {
                total += zf.size();
            }
        }
        Ok(ZipSource { archive, total })
    }
}

impl Source for ZipSource {
    fn kind(&self) -> InputKind {
        InputKind::Zip
    }

    fn total_bytes(&self) -> Option<u64> {
        Some(self.total)
    }

    fn entry_count(&self) -> Option<u64> {
        Some(self.archive.len() as u64)
    }

    fn visit(&mut self, f: &mut Visitor<'_>) -> Result<()> {
        for i in 0..self.archive.len() {
            let (mut meta, is_symlink) = {
                let zf = self.archive.by_index_raw(i).zctx(|| crate::t!("io.read_entry", index = i))?;
                let name = decode_name(zf.name_raw());
                let zip_time = zf.last_modified();
                let meta = EntryMeta {
                    name,
                    kind: if zf.is_dir() { EntryKind::Dir } else { EntryKind::File },
                    size: Some(zf.size()),
                    mode: zf.unix_mode().map(|m| m & 0o7777),
                    mtime: zip_time.as_ref().map(zip_time_to_unix),
                    zip_time,
                    zip_index: Some(i),
                    encrypted: zf.encrypted(),
                };
                (meta, zf.is_symlink())
            };
            let go_on = if meta.kind == EntryKind::Dir || meta.encrypted {
                f(meta, None)?
            } else if is_symlink {
                let mut zf = self.archive.by_index(i).zctx(|| crate::t!("io.read", path = meta.name))?;
                let mut target = Vec::new();
                read_up_to(&mut zf, &mut target, 4096).ctx(|| crate::t!("io.read_link", path = meta.name))?;
                meta.kind = EntryKind::Symlink(decode_name(&target));
                f(meta, None)?
            } else {
                let name = meta.name.clone();
                let mut zf = self.archive.by_index(i).zctx(|| crate::t!("io.read", path = name))?;
                f(meta, Some(&mut zf))?
            };
            if !go_on {
                break;
            }
        }
        Ok(())
    }
}

// ───────────────────────── tar / tar.gz ─────────────────────────

pub struct TarSource {
    archive: tar::Archive<Box<dyn Read>>,
    kind: InputKind,
}

impl TarSource {
    pub fn open(path: &Path, gz: bool) -> Result<TarSource> {
        let f = BufReader::with_capacity(256 * 1024, File::open(path).map_err(|e| Error::io_path("io.open", path, e))?);
        let reader: Box<dyn Read> = if gz { Box::new(flate2::read::MultiGzDecoder::new(f)) } else { Box::new(f) };
        Ok(TarSource { archive: tar::Archive::new(reader), kind: if gz { InputKind::TarGz } else { InputKind::Tar } })
    }
}

impl Source for TarSource {
    fn kind(&self) -> InputKind {
        self.kind
    }

    fn total_bytes(&self) -> Option<u64> {
        None
    }

    fn entry_count(&self) -> Option<u64> {
        None
    }

    fn visit(&mut self, f: &mut Visitor<'_>) -> Result<()> {
        use tar::EntryType as T;
        let entries = self.archive.entries().ctx(|| crate::t!("io.read_tar"))?;
        for entry in entries {
            let mut e = entry.ctx(|| crate::t!("io.read_tar_entry"))?;
            let (et, mode, mtime) = {
                let h = e.header();
                (h.entry_type(), h.mode().ok().map(|m| m & 0o7777), h.mtime().ok().map(|t| t as i64))
            };
            let name = decode_name(&e.path_bytes());
            let link = e.link_name_bytes().map(|b| decode_name(&b));
            let size = e.size();
            let kind = match et {
                T::Regular | T::Continuous | T::GNUSparse => EntryKind::File,
                T::Directory => EntryKind::Dir,
                T::Symlink => EntryKind::Symlink(link.unwrap_or_default()),
                T::Link => EntryKind::HardLink(link.unwrap_or_default()),
                T::XGlobalHeader | T::XHeader | T::GNULongName | T::GNULongLink => continue,
                other => EntryKind::Other(format!("{other:?}")),
            };
            let meta = EntryMeta {
                name,
                kind: kind.clone(),
                size: Some(size),
                mode,
                mtime,
                zip_time: None,
                zip_index: None,
                encrypted: false,
            };
            let go_on = if kind == EntryKind::File { f(meta, Some(&mut e))? } else { f(meta, None)? };
            if !go_on {
                break;
            }
        }
        Ok(())
    }
}

// ───────────────────────── 单文件 / .gz / stdin ─────────────────────────

pub struct SingleSource {
    name: String,
    reader: Option<Box<dyn Read>>,
    kind: InputKind,
    size: Option<u64>,
    mode: Option<u32>,
    mtime: Option<i64>,
}

impl SingleSource {
    pub fn file(path: &Path) -> Result<SingleSource> {
        let f = File::open(path).map_err(|e| Error::io_path("io.open", path, e))?;
        let md = f.metadata().ctx(|| crate::t!("io.read", path = path.display()))?;
        Ok(SingleSource {
            name: path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "input".into()),
            reader: Some(Box::new(BufReader::with_capacity(256 * 1024, f))),
            kind: InputKind::File,
            size: Some(md.len()),
            mode: file_mode(&md),
            mtime: md.modified().ok().and_then(system_time_secs),
        })
    }

    pub fn gz(path: &Path) -> Result<SingleSource> {
        let f = File::open(path).map_err(|e| Error::io_path("io.open", path, e))?;
        let md = f.metadata().ctx(|| crate::t!("io.read", path = path.display()))?;
        let fname = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "input.gz".into());
        let name = fname.strip_suffix(".gz").or_else(|| fname.strip_suffix(".GZ")).unwrap_or(&fname).to_string();
        Ok(SingleSource {
            name,
            reader: Some(Box::new(flate2::read::MultiGzDecoder::new(BufReader::with_capacity(256 * 1024, f)))),
            kind: InputKind::Gz,
            size: None,
            mode: file_mode(&md),
            mtime: md.modified().ok().and_then(system_time_secs),
        })
    }

    pub fn stdin() -> SingleSource {
        SingleSource {
            name: "stdin".into(),
            reader: Some(Box::new(io::stdin())),
            kind: InputKind::Stdin,
            size: None,
            mode: None,
            mtime: None,
        }
    }
}

impl Source for SingleSource {
    fn kind(&self) -> InputKind {
        self.kind
    }

    fn total_bytes(&self) -> Option<u64> {
        self.size
    }

    fn entry_count(&self) -> Option<u64> {
        Some(1)
    }

    fn visit(&mut self, f: &mut Visitor<'_>) -> Result<()> {
        let Some(mut r) = self.reader.take() else { return Ok(()) };
        let meta = EntryMeta {
            name: self.name.clone(),
            kind: EntryKind::File,
            size: self.size,
            mode: self.mode,
            mtime: self.mtime,
            zip_time: None,
            zip_index: None,
            encrypted: false,
        };
        f(meta, Some(&mut *r))?;
        Ok(())
    }
}

// ───────────────────────── 文件夹 ─────────────────────────

pub struct DirSource {
    root: PathBuf,
    entries: Vec<(PathBuf, String)>,
    total: u64,
}

impl DirSource {
    pub fn open(root: &Path) -> Result<DirSource> {
        let mut entries = Vec::new();
        let mut total = 0u64;
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, prefix)) = stack.pop() {
            let mut children: Vec<_> = fs::read_dir(&dir)
                .map_err(|e| Error::io_path("io.read_dir", &dir, e))?
                .filter_map(|e| e.ok())
                .collect();
            children.sort_by_key(|e| e.file_name());
            let mut subdirs = Vec::new();
            for c in children {
                let name = format!("{prefix}{}", c.file_name().to_string_lossy());
                let path = c.path();
                let md = fs::symlink_metadata(&path).map_err(|e| Error::io_path("io.access", &path, e))?;
                if md.is_dir() {
                    entries.push((path.clone(), format!("{name}/")));
                    subdirs.push((path, format!("{name}/")));
                } else {
                    if md.is_file() {
                        total += md.len();
                    }
                    entries.push((path, name));
                }
            }
            // 保持字典序：逆序压栈
            for s in subdirs.into_iter().rev() {
                stack.push(s);
            }
        }
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        Ok(DirSource { root: root.to_path_buf(), entries, total })
    }
}

impl Source for DirSource {
    fn kind(&self) -> InputKind {
        InputKind::Dir
    }

    fn total_bytes(&self) -> Option<u64> {
        Some(self.total)
    }

    fn entry_count(&self) -> Option<u64> {
        Some(self.entries.len() as u64)
    }

    fn visit(&mut self, f: &mut Visitor<'_>) -> Result<()> {
        let _ = &self.root;
        for (path, name) in &self.entries {
            let md = fs::symlink_metadata(path).map_err(|e| Error::io_path("io.access", path, e))?;
            let mut meta = EntryMeta {
                name: name.trim_end_matches('/').to_string(),
                kind: EntryKind::File,
                size: Some(md.len()),
                mode: file_mode(&md),
                mtime: md.modified().ok().and_then(system_time_secs),
                zip_time: None,
                zip_index: None,
                encrypted: false,
            };
            let go_on = if md.is_dir() {
                meta.kind = EntryKind::Dir;
                meta.size = None;
                f(meta, None)?
            } else if md.file_type().is_symlink() {
                let target = fs::read_link(path).map(|t| t.to_string_lossy().into_owned()).unwrap_or_default();
                meta.kind = EntryKind::Symlink(target);
                f(meta, None)?
            } else if md.is_file() {
                let file = File::open(path).map_err(|e| Error::io_path("io.open", path, e))?;
                let mut r = BufReader::with_capacity(256 * 1024, file);
                f(meta, Some(&mut r))?
            } else {
                meta.kind = EntryKind::Other(crate::t!("pipeline.special_file"));
                f(meta, None)?
            };
            if !go_on {
                break;
            }
        }
        Ok(())
    }
}

/// 打开输入源。
pub fn open_source(path: Option<&Path>, kind: InputKind) -> Result<Box<dyn Source>> {
    Ok(match (kind, path) {
        (InputKind::Stdin, _) => Box::new(SingleSource::stdin()),
        (InputKind::Zip, Some(p)) => Box::new(ZipSource::open(p)?),
        (InputKind::Tar, Some(p)) => Box::new(TarSource::open(p, false)?),
        (InputKind::TarGz, Some(p)) => Box::new(TarSource::open(p, true)?),
        (InputKind::Gz, Some(p)) => Box::new(SingleSource::gz(p)?),
        (InputKind::File, Some(p)) => Box::new(SingleSource::file(p)?),
        (InputKind::Dir, Some(p)) => Box::new(DirSource::open(p)?),
        (_, None) => return Err(Error::Unsupported(crate::t!("pipeline.missing_input"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names() {
        let p = |s: &str, k| default_output_path(Path::new(s), k).to_string_lossy().replace('\\', "/");
        assert_eq!(p("/tmp/logs.zip", InputKind::Zip), "/tmp/logs.blurred.zip");
        assert_eq!(p("/tmp/logs.tar.gz", InputKind::TarGz), "/tmp/logs.blurred.tar.gz");
        assert_eq!(p("/tmp/logs.tgz", InputKind::TarGz), "/tmp/logs.blurred.tgz");
        assert_eq!(p("/tmp/syslog.2.gz", InputKind::Gz), "/tmp/syslog.2.blurred.gz");
        assert_eq!(p("/tmp/app.log", InputKind::File), "/tmp/app.blurred.log");
        assert_eq!(p("/tmp/syslog.1", InputKind::File), "/tmp/syslog.1.blurred");
        assert_eq!(p("/tmp/messages", InputKind::File), "/tmp/messages.blurred");
        assert_eq!(p("/tmp/logdir", InputKind::Dir), "/tmp/logdir.blurred.zip");
        assert_eq!(p("app.log", InputKind::File), "./app.blurred.log");
    }

    #[test]
    fn output_kinds() {
        assert_eq!(output_kind_for(InputKind::Zip, Path::new("x.zip")), OutputKind::Zip);
        assert_eq!(output_kind_for(InputKind::Zip, Path::new("x.tgz")), OutputKind::TarGz);
        assert_eq!(output_kind_for(InputKind::Zip, Path::new("outdir")), OutputKind::Dir);
        assert_eq!(output_kind_for(InputKind::Gz, Path::new("a.gz")), OutputKind::Gz);
        assert_eq!(output_kind_for(InputKind::Gz, Path::new("a.log")), OutputKind::File);
        assert_eq!(output_kind_for(InputKind::File, Path::new("a.log")), OutputKind::File);
    }

    #[test]
    fn zip_time_roundtrip() {
        let t = unix_to_zip_time(1_698_062_400).unwrap();
        assert_eq!(zip_time_to_unix(&t), 1_698_062_400);
        assert!(unix_to_zip_time(0).is_none());
    }

    #[test]
    fn gbk_names() {
        let (gbk, _, _) = encoding_rs::GBK.encode("日志/系统.log");
        assert_eq!(decode_name(&gbk), "日志/系统.log");
    }
}
