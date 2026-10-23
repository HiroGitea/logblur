//! 端到端测试：构造压缩包 → 清洗 → 读回检查。

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use logblur_core::{
    BinaryPolicy, CancelToken, Error, Input, JobConfig, JobSpec, MaskMode, NoProgress, Output, Report, run,
};
use zip::write::SimpleFileOptions;

const AUTH_LOG: &str =
    "Oct 23 11:12:13 web-prod-01 sshd[2211]: Failed password for invalid user admin2 from 203.0.113.45 port 52234 ssh2
Oct 23 11:15:02 web-prod-01 sshd[2301]: Accepted publickey for alice from 198.51.100.7 port 50122 ssh2
Oct 23 11:20:41 web-prod-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
";

const APP_LOG: &str = "2026-10-23T11:12:13Z db password=hunter2 url=postgres://app:S3cret@10.20.30.40/db
backup host web-prod-01 finished for alice
";

const BLOB: &[u8] = &[0, 1, 2, 3, 0, 255, 254, 0];

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn gunzip(data: &[u8]) -> String {
    let mut s = String::new();
    GzDecoder::new(data).read_to_string(&mut s).unwrap();
    s
}

fn build_zip(path: &Path, entries: &[(&str, Vec<u8>)]) {
    let mut w = zip::ZipWriter::new(File::create(path).unwrap());
    for (name, data) in entries {
        if name.ends_with('/') {
            w.add_directory(name.to_string(), SimpleFileOptions::default()).unwrap();
        } else {
            w.start_file(name.to_string(), SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
    }
    w.finish().unwrap();
}

fn read_zip(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut a = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    (0..a.len())
        .map(|i| {
            let mut f = a.by_index(i).unwrap();
            let name = f.name().unwrap().to_string();
            let mut v = Vec::new();
            f.read_to_end(&mut v).unwrap();
            (name, v)
        })
        .collect()
}

fn get(entries: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
    entries
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("缺少条目 {name}，现有：{:?}", entries.iter().map(|(n, _)| n).collect::<Vec<_>>()))
}

fn job(input: &Path, output: Output, cfg: &JobConfig) -> Result<Report, Error> {
    let spec = JobSpec { input: Input::Path(input.to_path_buf()), output, force: false };
    run(&spec, cfg, &NoProgress, &CancelToken::new())
}

fn tag_cfg() -> JobConfig {
    JobConfig { level: 3, mask: MaskMode::Tag, ..Default::default() }
}

fn assert_clean(text: &str, secrets: &[&str]) {
    for s in secrets {
        assert!(!text.contains(s), "仍包含 {s:?}：\n{text}");
    }
}

fn sample_zip(dir: &Path) -> PathBuf {
    let input = dir.join("logs.zip");
    let gbk_text = "用户张三 登录失败 手机号 13800138000 来自 203.0.113.7\n".repeat(20);
    let gbk = encoding_rs::GBK.encode(&gbk_text).0.into_owned();
    build_zip(
        &input,
        &[
            ("var/", vec![]),
            ("var/log/auth.log", AUTH_LOG.as_bytes().to_vec()),
            ("var/log/app.log", APP_LOG.as_bytes().to_vec()),
            ("var/log/syslog.2.gz", gzip(AUTH_LOG.as_bytes())),
            ("var/log/cn.log", gbk),
            ("home/alice/.bash_history", b"ssh alice@203.0.113.9\n".to_vec()),
            ("bin/blob.bin", BLOB.to_vec()),
        ],
    );
    input
}

#[test]
fn zip_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let report = job(&input, Output::Auto, &tag_cfg()).unwrap();
    let out = d.path().join("logs.blurred.zip");
    assert!(out.exists());
    assert!(!d.path().join("logs.blurred.zip.part").exists());

    let entries = read_zip(&out);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"var/"), "{names:?}");
    assert!(names.contains(&"home/[USER]/.bash_history"), "文件名应被清洗：{names:?}");

    let auth = String::from_utf8(get(&entries, "var/log/auth.log")).unwrap();
    assert_clean(&auth, &["web-prod-01", "admin2", "203.0.113.45", "alice", "198.51.100.7"]);
    assert!(auth.contains("port 52234") && auth.contains("USER=root"));

    // 第二个文件里没有上下文，靠第一遍学到的主机名和用户名
    let app = String::from_utf8(get(&entries, "var/log/app.log")).unwrap();
    assert_clean(&app, &["hunter2", "S3cret", "10.20.30.40", "web-prod-01", "alice"]);
    assert!(app.contains("backup host [HOST] finished for [USER]"), "{app}");

    let rotated = gunzip(&get(&entries, "var/log/syslog.2.gz"));
    assert_clean(&rotated, &["203.0.113.45", "alice"]);
    assert!(rotated.contains("port 52234"));

    let cn = get(&entries, "var/log/cn.log");
    let (text, _, had_errors) = encoding_rs::GBK.decode(&cn);
    assert!(!had_errors, "应保持 GBK 编码");
    assert!(text.contains("用户张三 登录失败"));
    assert_clean(&text, &["13800138000", "203.0.113.7"]);

    let history = String::from_utf8(get(&entries, "home/[USER]/.bash_history")).unwrap();
    assert_clean(&history, &["alice", "203.0.113.9"]);

    assert_eq!(get(&entries, "bin/blob.bin"), BLOB, "二进制条目应原样复制");
    assert_eq!(report.binary_entries, 1);
    assert!(report.matches_total > 10, "{report:?}");
    assert!(report.learn);
    assert!(!report.warnings.is_empty() || report.binary_entries == 1);
}

#[test]
fn streaming_matches_whole_processing() {
    let d = tempfile::tempdir().unwrap();
    let mut big = String::new();
    for i in 0..3000u32 {
        big.push_str(&format!(
            "Oct 23 11:{:02}:{:02} web-prod-01 sshd[{i}]: Failed password for invalid user u{i} from 203.0.113.{} port {} ssh2\n",
            i / 60 % 60,
            i % 60,
            i % 250 + 1,
            40000 + i
        ));
        if i % 500 == 0 {
            big.push_str("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789abcdefABCDEF\nMIIEowIBAAKCAQEA0123456789abcdefABCDEF\n-----END RSA PRIVATE KEY-----\n");
        }
    }
    let input = d.path().join("big.log");
    fs::write(&input, &big).unwrap();

    let whole_out = d.path().join("whole.log");
    job(&input, Output::Path(whole_out.clone()), &tag_cfg()).unwrap();

    let streamed_out = d.path().join("streamed.log");
    let cfg = JobConfig { chunk_size: 777, whole_max: Some(0), threads: Some(4), ..tag_cfg() };
    job(&input, Output::Path(streamed_out.clone()), &cfg).unwrap();

    let a = fs::read_to_string(&whole_out).unwrap();
    let b = fs::read_to_string(&streamed_out).unwrap();
    assert_eq!(a.lines().count(), big.lines().count() - 3 * 6, "每个 PEM 块（4 行）在 tag 模式下合并成 1 行");
    assert!(a == b, "流式分块与整体处理的结果不同");
    assert_clean(&a, &["203.0.113.", "MIIEowIBAAKCAQEA", "web-prod-01"]);
}

#[test]
fn streamed_zip_entries_and_gz() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let cfg = JobConfig { chunk_size: 64, whole_max: Some(0), ..tag_cfg() };
    job(&input, Output::Auto, &cfg).unwrap();
    let entries = read_zip(&d.path().join("logs.blurred.zip"));
    let auth = String::from_utf8(get(&entries, "var/log/auth.log")).unwrap();
    assert_clean(&auth, &["web-prod-01", "203.0.113.45", "alice"]);
    let rotated = gunzip(&get(&entries, "var/log/syslog.2.gz"));
    assert_clean(&rotated, &["203.0.113.45", "alice"]);
    let cn = get(&entries, "var/log/cn.log");
    let (text, _, _) = encoding_rs::GBK.decode(&cn);
    assert_clean(&text, &["13800138000"]);
    assert!(text.contains("用户张三"));
    assert_eq!(get(&entries, "bin/blob.bin"), BLOB);
}

#[test]
fn zip_to_tar_gz_and_back() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let tgz = d.path().join("converted.tar.gz");
    job(&input, Output::Path(tgz.clone()), &tag_cfg()).unwrap();

    let mut a = tar::Archive::new(GzDecoder::new(File::open(&tgz).unwrap()));
    let mut seen = Vec::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        let path = e.path().unwrap().to_string_lossy().into_owned();
        if path == "var/log/auth.log" {
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            assert_clean(&s, &["alice", "203.0.113.45"]);
        }
        if path == "bin/blob.bin" {
            let mut v = Vec::new();
            e.read_to_end(&mut v).unwrap();
            assert_eq!(v, BLOB);
        }
        seen.push(path);
    }
    assert!(seen.iter().any(|p| p == "var/log/auth.log"), "{seen:?}");

    // tar.gz 输入
    let again = d.path().join("again.tar.gz");
    job(&tgz, Output::Path(again.clone()), &tag_cfg()).unwrap();
    assert!(again.exists());
}

#[test]
fn tar_gz_keeps_modes() {
    let d = tempfile::tempdir().unwrap();
    let input = d.path().join("logs.tar.gz");
    {
        let gz = GzEncoder::new(File::create(&input).unwrap(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(AUTH_LOG.len() as u64);
        h.set_mode(0o640);
        h.set_mtime(1_698_062_400);
        b.append_data(&mut h, "var/log/auth.log", AUTH_LOG.as_bytes()).unwrap();
        b.into_inner().unwrap().finish().unwrap();
    }
    job(&input, Output::Auto, &tag_cfg()).unwrap();
    let out = d.path().join("logs.blurred.tar.gz");
    let mut a = tar::Archive::new(GzDecoder::new(File::open(&out).unwrap()));
    let mut found = false;
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        if e.path().unwrap().to_string_lossy() == "var/log/auth.log" {
            assert_eq!(e.header().mode().unwrap() & 0o777, 0o640);
            assert_eq!(e.header().mtime().unwrap(), 1_698_062_400);
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            assert_clean(&s, &["alice"]);
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn directory_to_zip() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("bundle");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub").join("app.log"), APP_LOG).unwrap();
    fs::write(root.join("auth.log"), AUTH_LOG).unwrap();
    job(&root, Output::Auto, &tag_cfg()).unwrap();
    let entries = read_zip(&d.path().join("bundle.blurred.zip"));
    let auth = String::from_utf8(get(&entries, "auth.log")).unwrap();
    assert_clean(&auth, &["alice"]);
    let app = String::from_utf8(get(&entries, "sub/app.log")).unwrap();
    assert_clean(&app, &["hunter2", "alice"]);
}

#[test]
fn zip_to_directory() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let out = d.path().join("unpacked");
    job(&input, Output::Path(out.clone()), &tag_cfg()).unwrap();
    let auth = fs::read_to_string(out.join("var/log/auth.log")).unwrap();
    assert_clean(&auth, &["alice"]);
    assert!(out.join("home/[USER]/.bash_history").exists());
    assert!(!d.path().join("unpacked.part").exists());
}

#[test]
fn single_files() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("app.log");
    fs::write(&log, AUTH_LOG).unwrap();
    job(&log, Output::Auto, &tag_cfg()).unwrap();
    let text = fs::read_to_string(d.path().join("app.blurred.log")).unwrap();
    assert_clean(&text, &["203.0.113.45", "alice", "web-prod-01"]);

    let gz = d.path().join("syslog.2.gz");
    fs::write(&gz, gzip(AUTH_LOG.as_bytes())).unwrap();
    job(&gz, Output::Auto, &tag_cfg()).unwrap();
    let text = gunzip(&fs::read(d.path().join("syslog.2.blurred.gz")).unwrap());
    assert_clean(&text, &["203.0.113.45", "alice"]);
    assert!(text.contains("port 52234"));
}

#[test]
fn block_mode_keeps_line_lengths_in_chars() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("auth.log");
    fs::write(&log, AUTH_LOG).unwrap();
    job(&log, Output::Auto, &JobConfig::default()).unwrap();
    let text = fs::read_to_string(d.path().join("auth.blurred.log")).unwrap();
    for (a, b) in AUTH_LOG.lines().zip(text.lines()) {
        assert_eq!(a.chars().count(), b.chars().count(), "{a}\n{b}");
    }
    assert!(text.contains('░'));
}

#[test]
fn dry_run_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let report = job(&input, Output::Discard, &tag_cfg()).unwrap();
    assert!(report.matches_total > 0);
    assert!(!d.path().join("logs.blurred.zip").exists());
    assert!(!d.path().join("logs.blurred.zip.part").exists());
}

#[test]
fn refuses_to_overwrite_without_force() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("app.log");
    fs::write(&log, AUTH_LOG).unwrap();
    let out = d.path().join("app.blurred.log");
    fs::write(&out, "existing").unwrap();
    let err = job(&log, Output::Auto, &tag_cfg()).unwrap_err();
    assert!(matches!(err, Error::OutputExists(_)), "{err}");
    assert_eq!(fs::read_to_string(&out).unwrap(), "existing");

    let spec = JobSpec { input: Input::Path(log.clone()), output: Output::Auto, force: true };
    run(&spec, &tag_cfg(), &NoProgress, &CancelToken::new()).unwrap();
    assert_ne!(fs::read_to_string(&out).unwrap(), "existing");
}

#[test]
fn input_and_output_must_differ() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("app.log");
    fs::write(&log, AUTH_LOG).unwrap();
    let spec = JobSpec { input: Input::Path(log.clone()), output: Output::Path(log.clone()), force: true };
    assert!(run(&spec, &tag_cfg(), &NoProgress, &CancelToken::new()).is_err());
    assert_eq!(fs::read_to_string(&log).unwrap(), AUTH_LOG);
}

#[test]
fn cancelled_job_leaves_no_output() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let cancel = CancelToken::new();
    cancel.cancel();
    let spec = JobSpec { input: Input::Path(input), output: Output::Auto, force: false };
    let err = run(&spec, &tag_cfg(), &NoProgress, &cancel).unwrap_err();
    assert!(err.is_cancelled(), "{err}");
    assert!(!d.path().join("logs.blurred.zip").exists());
    assert!(!d.path().join("logs.blurred.zip.part").exists());
}

#[test]
fn drop_binary_entries() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let cfg = JobConfig { binary: BinaryPolicy::Drop, ..tag_cfg() };
    let report = job(&input, Output::Auto, &cfg).unwrap();
    let entries = read_zip(&d.path().join("logs.blurred.zip"));
    assert!(entries.iter().all(|(n, _)| n != "bin/blob.bin"));
    assert_eq!(report.skipped_entries, 1);
}

#[test]
fn counter_pseudonyms_are_deterministic() {
    let d = tempfile::tempdir().unwrap();
    let input = sample_zip(d.path());
    let cfg = JobConfig { mask: MaskMode::Pseudo, counter: true, ..Default::default() };
    job(&input, Output::Path(d.path().join("a.zip")), &cfg).unwrap();
    job(&input, Output::Path(d.path().join("b.zip")), &cfg).unwrap();
    let a = read_zip(&d.path().join("a.zip"));
    let b = read_zip(&d.path().join("b.zip"));
    assert_eq!(a, b);
    let auth = String::from_utf8(get(&a, "var/log/auth.log")).unwrap();
    assert!(auth.contains("IP_1") && auth.contains("USER_"), "{auth}");
}

#[test]
fn salted_pseudonyms_match_across_runs() {
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("a.log");
    fs::write(&log, "peer 203.0.113.45 up\n").unwrap();
    let log2 = d.path().join("b.log");
    fs::write(&log2, "lost 203.0.113.45\n").unwrap();
    let cfg = JobConfig { mask: MaskMode::Pseudo, salt: Some("team-salt".into()), ..Default::default() };
    job(&log, Output::Auto, &cfg).unwrap();
    job(&log2, Output::Auto, &cfg).unwrap();
    let a = fs::read_to_string(d.path().join("a.blurred.log")).unwrap();
    let b = fs::read_to_string(d.path().join("b.blurred.log")).unwrap();
    let tok = a.split_whitespace().nth(1).unwrap();
    assert!(tok.starts_with("IP_"));
    assert_eq!(b.trim(), format!("lost {tok}"));
}
