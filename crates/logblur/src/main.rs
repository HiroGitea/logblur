//! logblur CLI: scrubs sensitive information from Linux log archives.

use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use logblur_core::archive::{EntryKind, default_output_path, detect_input, open_source, read_up_to};
use logblur_core::category::Counts;
use logblur_core::report::default_report_path;
use logblur_core::scan::Engine;
use logblur_core::util::{human_bytes, parse_size};
use logblur_core::{
    BinaryPolicy, CancelToken, Category, Input, JobConfig, JobSpec, MaskMode, MemoryLimit, Output, OutputEncoding,
    Phase, ProgressEvent, ProgressSink, Report, ReportFormat, i18n, t,
};

// ───────────────────────── Command-line definition ─────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "logblur",
    version,
    about = t!("cli.about"),
    after_help = t!("cli.after_help"),
    args_conflicts_with_subcommands = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    scrub: ScrubArgs,

    // Read ahead of parsing (see prescan_lang); declared here so it shows up in the help.
    #[arg(long, global = true, value_name = "LANG", help = t!("cli.arg.lang"))]
    lang: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = t!("cli.cmd.scrub"))]
    Scrub(ScrubArgs),
    #[command(about = t!("cli.cmd.preview"))]
    Preview(PreviewArgs),
    #[command(about = t!("cli.cmd.rules"), subcommand_required = true)]
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    #[command(about = t!("cli.cmd.config"), subcommand_required = true)]
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    #[command(about = t!("cli.cmd.languages"))]
    Languages,
    #[command(about = t!("cli.cmd.bench"), hide = true)]
    Bench(BenchArgs),
}

#[derive(Subcommand, Debug)]
#[expect(clippy::large_enum_variant, reason = "the command line is parsed only once")]
enum RulesCmd {
    #[command(about = t!("cli.cmd.rules_list"))]
    List {
        #[arg(short = 'l', long, value_parser = clap::value_parser!(u8).range(1..=4), help = t!("cli.arg.level"))]
        level: Option<u8>,
        #[arg(long, help = t!("cli.arg.all"))]
        all: bool,
        #[arg(short = 'c', long, value_name = "FILE", help = t!("cli.arg.config"))]
        config: Option<PathBuf>,
    },
    #[command(about = t!("cli.cmd.rules_test"))]
    Test {
        #[arg(value_name = "TEXT", help = t!("cli.arg.text"))]
        text: String,
        #[command(flatten)]
        opts: RuleOpts,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    #[command(about = t!("cli.cmd.config_init"))]
    Init {
        #[arg(short, long, value_name = "FILE", help = t!("cli.arg.template_out"))]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, help = t!("cli.arg.force"))]
        force: bool,
    },
}

#[derive(Args, Debug, Clone, Default)]
struct ScrubArgs {
    #[arg(value_name = "INPUT", help = t!("cli.arg.input"))]
    inputs: Vec<PathBuf>,
    #[arg(short, long, value_name = "PATH", help = t!("cli.arg.output"))]
    output: Option<PathBuf>,
    #[arg(long, value_name = "DIR", help = t!("cli.arg.out_dir"))]
    out_dir: Option<PathBuf>,
    #[command(flatten)]
    opts: RuleOpts,
    #[arg(long, value_enum, value_name = "FORMAT", help = t!("cli.arg.report"))]
    report: Option<ReportArg>,
    #[arg(long, value_name = "PATH", help = t!("cli.arg.report_path"))]
    report_path: Option<PathBuf>,
    #[arg(short = 'f', long, help = t!("cli.arg.force"))]
    force: bool,
    #[arg(long, help = t!("cli.arg.dry_run"))]
    dry_run: bool,
    #[arg(short, long, help = t!("cli.arg.quiet"))]
    quiet: bool,
    #[arg(long, help = t!("cli.arg.line_buffered"))]
    line_buffered: bool,
}

/// Rule and masking options (shared by scrub, preview, rules test and bench).
#[derive(Args, Debug, Clone, Default)]
struct RuleOpts {
    #[arg(short = 'c', long, value_name = "FILE", help = t!("cli.arg.config"))]
    config: Option<PathBuf>,
    #[arg(short = 'l', long, value_parser = clap::value_parser!(u8).range(1..=4), help = t!("cli.arg.level"))]
    level: Option<u8>,
    #[arg(short = 'm', long, value_name = "MODE", help = t!("cli.arg.mask"))]
    mask: Option<String>,
    #[arg(long, value_name = "CHAR", help = t!("cli.arg.mask_char"))]
    mask_char: Option<char>,
    #[arg(long, value_name = "N", help = t!("cli.arg.fixed_width"))]
    fixed_width: Option<usize>,
    #[arg(long, value_name = "SALT", help = t!("cli.arg.salt"))]
    salt: Option<String>,
    #[arg(long, help = t!("cli.arg.counter"))]
    counter: bool,
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY", help = t!("cli.arg.only"))]
    only: Vec<String>,
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY", help = t!("cli.arg.enable"))]
    enable: Vec<String>,
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY", help = t!("cli.arg.skip"))]
    skip: Vec<String>,
    #[arg(long, help = t!("cli.arg.keep_private_ips"))]
    keep_private_ips: bool,
    #[arg(long, help = t!("cli.arg.mask_dates"))]
    mask_dates: bool,
    #[arg(long, help = t!("cli.arg.no_learn"))]
    no_learn: bool,
    #[arg(long, help = t!("cli.arg.keep_names"))]
    keep_names: bool,
    #[arg(long, value_name = "PATTERN", help = t!("cli.arg.allow"))]
    allow: Vec<String>,
    #[arg(long, value_name = "WORD", help = t!("cli.arg.deny"))]
    deny: Vec<String>,
    #[arg(long, value_enum, value_name = "POLICY", help = t!("cli.arg.binary"))]
    binary: Option<BinaryArg>,
    #[arg(long, value_enum, value_name = "ENCODING", help = t!("cli.arg.output_encoding"))]
    output_encoding: Option<EncodingArg>,
    #[arg(short = 'j', long, value_name = "N", help = t!("cli.arg.threads"))]
    threads: Option<usize>,
    #[arg(long, value_name = "SIZE", help = t!("cli.arg.memory"))]
    memory: Option<String>,
}

#[derive(Args, Debug)]
struct PreviewArgs {
    #[arg(value_name = "INPUT", help = t!("cli.arg.input"))]
    input: PathBuf,
    #[arg(short = 'n', long, default_value_t = 40, value_name = "N", help = t!("cli.arg.lines"))]
    lines: usize,
    #[arg(long, help = t!("cli.arg.show_original"))]
    show_original: bool,
    #[command(flatten)]
    opts: RuleOpts,
}

#[derive(Args, Debug)]
struct BenchArgs {
    #[arg(long, default_value = "200M", value_name = "SIZE", help = t!("cli.arg.size"))]
    size: String,
    #[command(flatten)]
    opts: RuleOpts,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ReportArg {
    Json,
    Md,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum BinaryArg {
    Copy,
    Drop,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum EncodingArg {
    Preserve,
    Utf8,
}

// ───────────────────────── Errors and exit codes ─────────────────────────

/// Exit codes: 0 success, 1 usage/config error, 2 processing failure, 3 cancelled.
struct CliError {
    msg: String,
    code: u8,
}

fn usage(msg: impl Into<String>) -> CliError {
    CliError { msg: msg.into(), code: 1 }
}

fn failed(msg: impl Into<String>) -> CliError {
    CliError { msg: msg.into(), code: 2 }
}

impl From<logblur_core::Error> for CliError {
    fn from(e: logblur_core::Error) -> Self {
        let code = match &e {
            logblur_core::Error::Cancelled => 3,
            logblur_core::Error::Config(_)
            | logblur_core::Error::Rule { .. }
            | logblur_core::Error::OutputExists(_) => 1,
            _ => 2,
        };
        CliError { msg: e.to_string(), code }
    }
}

type CliResult<T = ExitCode> = Result<T, CliError>;

// ───────────────────────── Entry point ─────────────────────────

/// Looks for `--lang` before clap parses, so the help text also uses the chosen language.
fn prescan_lang() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--" {
            break;
        }
        if a == "--lang" {
            return args.next();
        }
        if let Some(v) = a.strip_prefix("--lang=") {
            return Some(v.to_string());
        }
    }
    None
}

fn main() -> ExitCode {
    let lang = prescan_lang();
    let system = sys_locale::get_locale();
    i18n::init(lang.as_deref(), system.as_deref());

    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::from(1) } else { ExitCode::SUCCESS };
        }
    };
    let result = match cli.command {
        None => cmd_scrub(cli.scrub),
        Some(Command::Scrub(a)) => cmd_scrub(a),
        Some(Command::Preview(a)) => cmd_preview(a),
        Some(Command::Rules { cmd }) => cmd_rules(cmd),
        Some(Command::Config { cmd }) => cmd_config(cmd),
        Some(Command::Languages) => cmd_languages(),
        Some(Command::Bench(a)) => cmd_bench(a),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("logblur: {}", e.msg);
            ExitCode::from(e.code)
        }
    }
}

// ───────────────────────── Config ─────────────────────────

/// `--allow @file` / `--deny @file`: one entry per line; blank lines and # comments are ignored.
fn expand_list(items: &[String]) -> CliResult<Vec<String>> {
    let mut out = Vec::new();
    for item in items {
        match item.strip_prefix('@') {
            Some(path) => {
                let text =
                    std::fs::read_to_string(path).map_err(|e| usage(t!("cli.msg.read_list", path = path, err = e)))?;
                out.extend(
                    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string),
                );
            }
            None => out.push(item.clone()),
        }
    }
    Ok(out)
}

fn categories(list: &[String]) -> CliResult<Vec<Category>> {
    list.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| Category::from_id(s).ok_or_else(|| usage(t!("cli.msg.bad_category", value = s))))
        .collect()
}

fn build_config(o: &RuleOpts) -> CliResult<JobConfig> {
    let mut cfg = JobConfig::default();
    if let Some(p) = &o.config {
        cfg.apply_file(p)?;
    }
    if let Some(l) = o.level {
        cfg.level = l;
    }
    if let Some(m) = &o.mask {
        cfg.mask = MaskMode::from_id(m).ok_or_else(|| usage(t!("cli.msg.bad_mask", value = m)))?;
    }
    if let Some(c) = o.mask_char {
        cfg.mask_char = c;
    }
    if let Some(w) = o.fixed_width {
        cfg.fixed_width = w;
    }
    if let Some(s) = &o.salt {
        cfg.salt = Some(s.clone());
    }
    if o.counter {
        cfg.counter = true;
    }
    if !o.only.is_empty() {
        cfg.only = categories(&o.only)?;
    }
    cfg.enable.extend(categories(&o.enable)?);
    cfg.skip.extend(categories(&o.skip)?);
    if o.keep_private_ips {
        cfg.keep_private_ips = true;
    }
    if o.mask_dates {
        cfg.enable.push(Category::Timestamp);
    }
    if o.no_learn {
        cfg.learn = false;
    }
    if o.keep_names {
        cfg.scrub_names = false;
    }
    cfg.allow.extend(expand_list(&o.allow)?);
    cfg.deny.extend(expand_list(&o.deny)?);
    if let Some(b) = o.binary {
        cfg.binary = match b {
            BinaryArg::Copy => BinaryPolicy::Copy,
            BinaryArg::Drop => BinaryPolicy::Drop,
        };
    }
    if let Some(e) = o.output_encoding {
        cfg.output_encoding = match e {
            EncodingArg::Preserve => OutputEncoding::Preserve,
            EncodingArg::Utf8 => OutputEncoding::Utf8,
        };
    }
    if let Some(j) = o.threads {
        cfg.threads = (j > 0).then_some(j);
    }
    if let Some(m) = &o.memory {
        cfg.memory = MemoryLimit::parse(m)?;
    }
    cfg.validate()?;
    Ok(cfg)
}

// ───────────────────────── Progress bar ─────────────────────────

struct CliProgress {
    pb: ProgressBar,
}

impl CliProgress {
    fn new(quiet: bool) -> CliProgress {
        let pb = if quiet || !io::stderr().is_terminal() { ProgressBar::hidden() } else { ProgressBar::new_spinner() };
        CliProgress { pb }
    }

    fn bar_style() -> ProgressStyle {
        ProgressStyle::with_template(
            "{prefix:.bold} [{bar:30.cyan/blue}] {bytes}/{total_bytes} {bytes_per_sec} {eta} {wide_msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> ")
    }

    fn spinner_style() -> ProgressStyle {
        ProgressStyle::with_template("{spinner} {prefix:.bold} {bytes} {bytes_per_sec} {wide_msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
    }

    fn finish(&self) {
        self.pb.finish_and_clear();
    }
}

/// Shows only the tail of the file name in the progress bar.
fn tail_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(count - n + 1).collect();
        format!("…{tail}")
    }
}

impl ProgressSink for CliProgress {
    fn event(&self, e: ProgressEvent) {
        match e {
            ProgressEvent::Phase { phase, total_bytes, .. } => {
                let prefix = match phase {
                    Phase::Learn => t!("cli.msg.phase_learn"),
                    Phase::Scrub => t!("cli.msg.phase_scrub"),
                };
                self.pb.reset();
                match total_bytes {
                    Some(total) if total > 0 => {
                        self.pb.set_style(Self::bar_style());
                        self.pb.set_length(total);
                    }
                    _ => self.pb.set_style(Self::spinner_style()),
                }
                self.pb.set_prefix(prefix);
                self.pb.set_position(0);
                self.pb.enable_steady_tick(Duration::from_millis(120));
            }
            ProgressEvent::Entry { name, .. } => self.pb.set_message(tail_chars(&name, 60)),
            ProgressEvent::Bytes { done, .. } => self.pb.set_position(done),
            ProgressEvent::Warning(_) => {}
        }
    }
}

// ───────────────────────── scrub ─────────────────────────

fn install_ctrlc() -> CancelToken {
    let cancel = CancelToken::new();
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || {
        if c.is_cancelled() {
            std::process::exit(130);
        }
        c.cancel();
        eprintln!("\n{}", t!("cli.msg.ctrlc"));
    });
    cancel
}

fn input_label(input: &Path) -> String {
    if input.as_os_str() == "-" { "-".to_string() } else { input.display().to_string() }
}

fn resolve_output(a: &ScrubArgs, input: &Path) -> CliResult<(Input, Output)> {
    let is_stdin = input.as_os_str() == "-";
    let inp = if is_stdin { Input::Stdin } else { Input::Path(input.to_path_buf()) };
    let out = if a.dry_run {
        Output::Discard
    } else if let Some(o) = &a.output {
        if o.as_os_str() == "-" { Output::Stdout } else { Output::Path(o.clone()) }
    } else if let Some(dir) = &a.out_dir {
        if is_stdin {
            Output::Stdout
        } else {
            let kind = detect_input(input)?;
            let default = default_output_path(input, kind);
            let name = default.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            Output::Path(dir.join(name))
        }
    } else {
        Output::Auto
    };
    Ok((inp, out))
}

fn print_summary(input: &str, r: &Report) {
    eprintln!("{}", t!("cli.msg.done", input = input, output = r.output));
    eprintln!(
        "{}",
        t!(
            "cli.msg.summary",
            entries = r.entries_total,
            text = r.text_entries,
            binary = r.binary_entries,
            skipped = r.skipped_entries,
            matches = r.matches_total,
            secs = format!("{:.2}", r.elapsed_ms as f64 / 1000.0)
        )
    );
    print_top_categories(&r.by_category);
    let learned: usize = r.learned.values().sum();
    if learned > 0 {
        eprintln!("{}", t!("cli.msg.learned", n = learned));
    }
    for w in r.warnings.iter().take(5) {
        eprintln!("{}", t!("cli.msg.warning", msg = w));
    }
    if r.warnings.len() > 5 {
        eprintln!("{}", t!("cli.msg.more_warnings", n = r.warnings.len() - 5));
    }
}

fn print_top_categories(counts: &Counts) {
    let mut cats: Vec<(Category, u64)> = counts.iter().collect();
    cats.sort_by_key(|c| std::cmp::Reverse(c.1));
    if !cats.is_empty() {
        let list: Vec<String> = cats.iter().take(8).map(|(c, n)| format!("{} {n}", c.label())).collect();
        eprintln!("{}", t!("cli.msg.top_categories", list = list.join(", ")));
    }
}

fn write_report(a: &ScrubArgs, r: &Report) -> CliResult<()> {
    let Some(fmt) = a.report else { return Ok(()) };
    let fmt = match fmt {
        ReportArg::Json => ReportFormat::Json,
        ReportArg::Md => ReportFormat::Markdown,
    };
    let path = match &a.report_path {
        Some(p) => Some(p.clone()),
        None if r.output != "-" && r.output != "(dry-run)" => Some(default_report_path(Path::new(&r.output), fmt)),
        None => None,
    };
    match path {
        Some(p) => {
            r.write_to(&p, fmt)?;
            if !a.quiet {
                eprintln!("{}", t!("cli.msg.report_written", path = p.display()));
            }
        }
        None => {
            let body = match fmt {
                ReportFormat::Json => r.to_json(),
                ReportFormat::Markdown => r.to_markdown(),
            };
            eprintln!("{body}");
        }
    }
    Ok(())
}

fn cmd_scrub(a: ScrubArgs) -> CliResult {
    if a.inputs.is_empty() {
        return Err(usage(t!("cli.msg.no_input")));
    }
    if a.output.is_some() && a.inputs.len() > 1 {
        return Err(usage(t!("cli.msg.output_needs_single")));
    }
    if let Some(dir) = &a.out_dir {
        std::fs::create_dir_all(dir).map_err(|e| usage(format!("{}: {e}", dir.display())))?;
    }
    let cfg = build_config(&a.opts)?;
    if a.line_buffered {
        return scrub_line_buffered(&a, &cfg);
    }
    let cancel = install_ctrlc();
    let mut failures = 0usize;
    for input in &a.inputs {
        let label = input_label(input);
        let (inp, out) = match resolve_output(&a, input) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{}", t!("cli.msg.failed", input = label, err = e.msg));
                failures += 1;
                continue;
            }
        };
        let spec = JobSpec { input: inp, output: out, force: a.force };
        let progress = CliProgress::new(a.quiet);
        let result = logblur_core::run(&spec, &cfg, &progress, &cancel);
        progress.finish();
        match result {
            Ok(report) => {
                if !a.quiet {
                    print_summary(&label, &report);
                    if a.dry_run {
                        eprintln!("{}", t!("cli.msg.dry_run"));
                    }
                }
                if let Err(e) = write_report(&a, &report) {
                    eprintln!("{}", t!("cli.msg.failed", input = label, err = e.msg));
                    failures += 1;
                }
            }
            Err(e) if e.is_cancelled() => {
                eprintln!("{}", t!("cli.msg.cancelled"));
                return Ok(ExitCode::from(3));
            }
            Err(e) => {
                eprintln!("{}", t!("cli.msg.failed", input = label, err = e));
                failures += 1;
            }
        }
    }
    Ok(if failures > 0 { ExitCode::from(2) } else { ExitCode::SUCCESS })
}

/// `--line-buffered`: masks stdin line by line and flushes after every batch.
///
/// No Ctrl-C handler is installed: streaming mode is meant to be ended with Ctrl-C, every line written so far has
/// already been flushed, so exiting the default way (130) is fine.
fn scrub_line_buffered(a: &ScrubArgs, cfg: &JobConfig) -> CliResult {
    let cancel = &CancelToken::new();
    if a.inputs.len() != 1 || a.inputs[0].as_os_str() != "-" {
        return Err(usage(t!("cli.msg.line_buffered_stdin")));
    }
    if a.out_dir.is_some() || a.output.as_ref().is_some_and(|o| o.as_os_str() != "-") {
        return Err(usage(t!("cli.msg.line_buffered_output")));
    }
    if a.report.is_some() || a.report_path.is_some() {
        return Err(usage(t!("cli.msg.line_buffered_report")));
    }
    let engine = Engine::new(cfg)?;
    let result = if a.dry_run {
        logblur_core::stream::scrub_lines(&engine, cfg, io::stdin(), io::sink(), cancel)
    } else {
        let out = io::BufWriter::with_capacity(1 << 16, io::stdout().lock());
        logblur_core::stream::scrub_lines(&engine, cfg, io::stdin(), out, cancel)
    };
    let stats = match result {
        Ok(s) => s,
        // The downstream closing early (e.g. piped into head) isn't a failure
        Err(logblur_core::Error::Io { source, .. }) if source.kind() == io::ErrorKind::BrokenPipe => {
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => {
            eprintln!("{}", t!("cli.msg.failed", input = "-", err = e));
            return Ok(ExitCode::from(2));
        }
    };
    if !a.quiet {
        let secs = format!("{:.2}", stats.elapsed.as_secs_f64());
        eprintln!("{}", t!("cli.msg.line_summary", lines = stats.lines, matches = stats.counts.total(), secs = secs));
        print_top_categories(&stats.counts);
    }
    Ok(ExitCode::SUCCESS)
}

// ───────────────────────── preview ─────────────────────────

fn cmd_preview(a: PreviewArgs) -> CliResult {
    let cfg = build_config(&a.opts)?;
    let kind = detect_input(&a.input)?;
    let mut src = open_source(Some(&a.input), kind)?;
    let mut samples: Vec<(String, Option<String>)> = Vec::new();
    let mut lines_seen = 0usize;
    src.visit(&mut |meta, rd| {
        if lines_seen >= a.lines || samples.len() >= 256 {
            return Ok(false);
        }
        let Some(rd) = rd else { return Ok(true) };
        if meta.kind != EntryKind::File {
            return Ok(true);
        }
        let mut head = Vec::new();
        read_up_to(rd, &mut head, 1 << 20).map_err(|e| logblur_core::Error::io(meta.name.clone(), e))?;
        let text = logblur_core::text::decode_for_preview(&meta.name, &head).map(|mut s| {
            // Keep only complete lines
            if let Some(i) = s.rfind('\n') {
                s.truncate(i + 1);
            }
            s
        });
        if let Some(t) = &text {
            lines_seen += t.lines().count();
        }
        samples.push((meta.name, text));
        Ok(true)
    })?;

    let mut engine = Engine::new(&cfg)?;
    if cfg.learn {
        let mut set = std::collections::HashSet::new();
        for (name, text) in &samples {
            engine.learn(format!("/{name}").as_bytes(), &mut set);
            if let Some(t) = text {
                engine.learn(t.as_bytes(), &mut set);
            }
        }
        engine.set_learned(set)?;
    }
    let mut budget = a.lines;
    for (name, text) in &samples {
        if budget == 0 {
            break;
        }
        let shown_name = if cfg.scrub_names { engine.scrub_name(name, &mut Counts::default()) } else { name.clone() };
        println!("{}", t!("cli.msg.preview_header", name = shown_name));
        let Some(text) = text else {
            println!("{}", t!("cli.msg.preview_binary"));
            continue;
        };
        let masked = engine.scrub_str(text, &mut Counts::default());
        let orig: Vec<&str> = text.lines().collect();
        let new: Vec<&str> = masked.lines().collect();
        if a.show_original && orig.len() != new.len() {
            println!("{}", t!("cli.msg.preview_note"));
        }
        for (i, line) in new.iter().enumerate() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            match (a.show_original && orig.len() == new.len(), orig.get(i)) {
                (true, Some(o)) if o != line => {
                    println!("- {o}");
                    println!("+ {line}");
                }
                (true, _) => println!("  {line}"),
                (false, _) => println!("{line}"),
            }
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

// ───────────────────────── rules ─────────────────────────

fn is_wide(c: char) -> bool {
    matches!(c as u32,
        0x1100..=0x115F | 0x2E80..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE4F | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6 | 0x20000..=0x3FFFD)
}

/// Pads with spaces by terminal display width (CJK characters take two columns).
fn pad(s: &str, width: usize) -> String {
    let w: usize = s.chars().map(|c| if is_wide(c) { 2 } else { 1 }).sum();
    if w >= width { format!("{s} ") } else { format!("{s}{}", " ".repeat(width - w)) }
}

fn cmd_rules(cmd: RulesCmd) -> CliResult {
    match cmd {
        RulesCmd::List { level, all, config } => {
            let mut cfg = JobConfig::default();
            if let Some(p) = &config {
                cfg.apply_file(p)?;
            }
            if let Some(l) = level {
                cfg.level = l;
            }
            let infos = Engine::rule_infos(&cfg);
            let active = infos.iter().filter(|r| r.active).count();
            println!(
                "{}{}{}{}{}",
                pad(&t!("cli.col.level"), 7),
                pad(&t!("cli.col.active"), 8),
                pad(&t!("cli.col.category"), 16),
                pad(&t!("cli.col.rule"), 22),
                t!("cli.col.description")
            );
            for r in infos.iter().filter(|r| all || r.active) {
                let yes = if r.active { t!("cli.msg.yes") } else { t!("cli.msg.no") };
                println!(
                    "{}{}{}{}{}",
                    pad(&r.level.to_string(), 7),
                    pad(&yes, 8),
                    pad(r.category.id(), 16),
                    pad(&r.id, 22),
                    r.desc
                );
            }
            println!();
            println!("{}", t!("cli.msg.rules_footer", active = active, total = infos.len(), level = cfg.level));
            println!();
            println!("{}", t!("cli.msg.categories_header"));
            for c in Category::ALL {
                let on = if cfg.category_enabled(c) { "●" } else { "○" };
                println!("  {on} {}{}{}", pad(c.id(), 16), pad(&c.default_level().to_string(), 3), c.label());
            }
            Ok(ExitCode::SUCCESS)
        }
        RulesCmd::Test { text, opts } => {
            let cfg = build_config(&opts)?;
            let text = if text == "-" {
                let mut s = String::new();
                io::stdin().read_to_string(&mut s).map_err(|e| failed(e.to_string()))?;
                s
            } else {
                text
            };
            let mut engine = Engine::new(&cfg)?;
            if cfg.learn {
                let mut set = std::collections::HashSet::new();
                engine.learn(text.as_bytes(), &mut set);
                engine.set_learned(set)?;
            }
            let mut found = Vec::new();
            engine.find(text.as_bytes(), &mut found);
            println!("{}", engine.scrub_str(&text, &mut Counts::default()));
            if found.is_empty() {
                eprintln!("{}", t!("cli.msg.test_none"));
            } else {
                eprintln!("{}", t!("cli.msg.test_found"));
                for f in &found {
                    let piece = String::from_utf8_lossy(&text.as_bytes()[f.start..f.end]);
                    eprintln!("  {}{}{piece:?}", pad(f.category.id(), 16), pad(engine.rule_id(f.rule), 22));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ───────────────────────── config / languages ─────────────────────────

fn cmd_config(cmd: ConfigCmd) -> CliResult {
    match cmd {
        ConfigCmd::Init { output, force } => {
            let tpl = logblur_core::config_template();
            match output {
                None => print!("{tpl}"),
                Some(p) => {
                    if p.exists() && !force {
                        return Err(logblur_core::Error::OutputExists(p.display().to_string()).into());
                    }
                    std::fs::write(&p, tpl).map_err(|e| failed(format!("{}: {e}", p.display())))?;
                    eprintln!("{}", t!("cli.msg.config_written", path = p.display()));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_languages() -> CliResult {
    let current = i18n::language();
    for (tag, name) in i18n::languages() {
        let mark = if tag == current { format!("  {}", t!("cli.msg.languages_current")) } else { String::new() };
        println!("{}{name}{mark}", pad(&tag, 8));
    }
    Ok(ExitCode::SUCCESS)
}

// ───────────────────────── bench ─────────────────────────

/// Synthesizes a typical Linux log (with all kinds of sensitive information).
fn synth_block(target: usize) -> Vec<u8> {
    let mut s = String::with_capacity(target + 512);
    let mut i = 0u64;
    while s.len() < target {
        let n = i % 250 + 1;
        let line = match i % 8 {
            0 => format!(
                "Oct 23 11:{:02}:{:02} web-{n:03} sshd[{i}]: Failed password for invalid user u{n} from 203.0.113.{n} port {} ssh2\n",
                i / 60 % 60,
                i % 60,
                40000 + n
            ),
            1 => format!(
                "Oct 23 11:00:00 web-{n:03} sshd[{i}]: Accepted publickey for alice{n} from 198.51.100.{n} port 50122 ssh2: ED25519 SHA256:Hx2b1QKcOoa1L3dHmC7yJ4z5eQ8mN0pR6sT9uV2wX3Y\n"
            ),
            2 => format!(
                "Oct 23 11:00:01 web-{n:03} kernel: [{i}.123456] IN=eth0 OUT= MAC=ff:ff:ff:ff:ff:ff:52:54:00:12:34:{:02x}:08:00 SRC=192.0.2.{n} DST=192.0.2.255 LEN=78 PROTO=UDP\n",
                n % 256
            ),
            3 => format!(
                "Oct 23 11:00:02 web-{n:03} systemd[1]: Started session-{i}.scope - Session {i} of User bob{n}.\n"
            ),
            4 => format!(
                "2026-10-23T11:00:03Z app[{i}] INFO request id={i} user=carol{n}@acme-corp.internal token=9f8e7d6c5b4a3928{n:04} took 12ms\n"
            ),
            5 => format!(
                "Oct 23 11:00:04 web-{n:03} dhclient[612]: DHCPACK of 10.0.{n}.23 from 10.0.{n}.1 (xid=0x5a3c2e1f)\n"
            ),
            6 => format!(
                "Oct 23 11:00:05 web-{n:03} nginx[1200]: 203.0.113.{n} - - \"GET /api/v1/items?page={n} HTTP/1.1\" 200 512 \"-\" \"curl/8.5.0\"\n"
            ),
            _ => format!(
                "Oct 23 11:00:06 web-{n:03} kernel: [{i}.000001] EXT4-fs (sda2): mounted filesystem with ordered data mode. Quota mode: none.\n"
            ),
        };
        s.push_str(&line);
        i += 1;
    }
    s.into_bytes()
}

fn cmd_bench(a: BenchArgs) -> CliResult {
    let size = parse_size(&a.size).ok_or_else(|| usage(t!("config.bad_size", value = a.size)))?;
    let cfg = build_config(&a.opts)?;
    let engine = Engine::new(&cfg)?;
    let block = synth_block(4 << 20);
    let threads = cfg.threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    let blocks = (size / block.len() as u64).max(1);
    let next = AtomicU64::new(0);
    let matches = AtomicU64::new(0);
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                let mut out = Vec::with_capacity(block.len() * 2);
                let mut counts = Counts::default();
                while next.fetch_add(1, Ordering::Relaxed) < blocks {
                    out.clear();
                    engine.scrub(&block, &mut out, &mut counts, cfg.mask_char);
                }
                matches.fetch_add(counts.total(), Ordering::Relaxed);
            });
        }
    });
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    let bytes = blocks * block.len() as u64;
    println!(
        "{}",
        t!(
            "cli.msg.bench_result",
            size = human_bytes(bytes),
            secs = format!("{secs:.2}"),
            rate = human_bytes((bytes as f64 / secs) as u64),
            threads = threads,
            matches = matches.load(Ordering::Relaxed)
        )
    );
    Ok(ExitCode::SUCCESS)
}
