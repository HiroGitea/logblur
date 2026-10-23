//! 对外入口：一次清洗任务。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::archive::sink::create_sink;
use crate::archive::{InputKind, OutputKind, default_output_path, detect_input, open_source, output_kind_for};
use crate::category::Category;
use crate::config::JobConfig;
use crate::error::{Error, Result};
use crate::pipeline::{self, Ctx};
use crate::report::Report;
use crate::scan::Engine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Path(PathBuf),
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// 输入旁边的 `*.blurred.*`；stdin 输入时为 stdout。
    Auto,
    Path(PathBuf),
    Stdout,
    /// 只统计不写出（--dry-run）。
    Discard,
}

#[derive(Debug, Clone)]
pub struct JobSpec {
    pub input: Input,
    pub output: Output,
    /// 覆盖已存在的输出。
    pub force: bool,
}

/// 解析后的输入输出。
#[derive(Debug, Clone)]
pub struct Resolved {
    pub input_kind: InputKind,
    pub output_kind: OutputKind,
    pub output_path: Option<PathBuf>,
}

impl JobSpec {
    pub fn resolve(&self) -> Result<Resolved> {
        let input_kind = match &self.input {
            Input::Stdin => InputKind::Stdin,
            Input::Path(p) => detect_input(p)?,
        };
        let (output_kind, output_path) = match (&self.output, &self.input) {
            (Output::Discard, _) => (OutputKind::Discard, None),
            (Output::Stdout, _) | (Output::Auto, Input::Stdin) => {
                if matches!(input_kind, InputKind::Zip | InputKind::Tar | InputKind::TarGz | InputKind::Dir) {
                    return Err(Error::Unsupported(crate::t!("config.stdout_multi")));
                }
                (OutputKind::Stdout, None)
            }
            (Output::Auto, Input::Path(p)) => {
                let out = default_output_path(p, input_kind);
                (output_kind_for(input_kind, &out), Some(out))
            }
            (Output::Path(o), _) => (output_kind_for(input_kind, o), Some(o.clone())),
        };
        Ok(Resolved { input_kind, output_kind, output_path })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 第一遍：学习用户名、主机名等。
    Learn,
    /// 第二遍：清洗并写出。
    Scrub,
}

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Phase { phase: Phase, total_bytes: Option<u64>, total_entries: Option<u64> },
    Entry { phase: Phase, index: u64, name: String },
    /// 已读取（解压后）的字节数。
    Bytes { phase: Phase, done: u64 },
    Warning(String),
}

pub trait ProgressSink: Sync {
    fn event(&self, e: ProgressEvent);
}

impl<F: Fn(ProgressEvent) + Sync> ProgressSink for F {
    fn event(&self, e: ProgressEvent) {
        self(e)
    }
}

/// 不关心进度。
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn event(&self, _e: ProgressEvent) {}
}

/// 取消令牌：从任何线程调用 [`CancelToken::cancel`]，任务会尽快停止并删除未完成的输出。
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> CancelToken {
        CancelToken::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// 执行一次清洗任务。
pub fn run(spec: &JobSpec, cfg: &JobConfig, progress: &dyn ProgressSink, cancel: &CancelToken) -> Result<Report> {
    let started = Instant::now();
    cfg.validate()?;
    let r = spec.resolve()?;
    let input_path = match &spec.input {
        Input::Path(p) => Some(p.as_path()),
        Input::Stdin => None,
    };
    if let (Some(inp), Some(out)) = (input_path, r.output_path.as_deref()) {
        if same_file(inp, out) || inp == out {
            return Err(Error::Config(crate::t!("config.same_io", path = out.display())));
        }
        if out.exists() && !spec.force {
            return Err(Error::OutputExists(out.display().to_string()));
        }
    }

    let mut engine = Engine::new(cfg)?;
    let plan = pipeline::plan(cfg, engine.masker().needs_sequential());
    let mut warnings = Vec::new();

    // 第一遍：学习
    let learned_on = cfg.learn && r.input_kind.rereadable() && engine.has_learn_rules();
    if learned_on {
        let mut src = open_source(input_path, r.input_kind)?;
        progress.event(ProgressEvent::Phase {
            phase: Phase::Learn,
            total_bytes: src.total_bytes(),
            total_entries: src.entry_count(),
        });
        let set = {
            let ctx = Ctx::new(cfg, &engine, &plan, cancel, progress, Phase::Learn, false, false);
            let set = pipeline::learn_pass(&ctx, src.as_mut())?;
            warnings.extend(ctx.take_warnings());
            set
        };
        engine.set_learned(set)?;
    }

    // 第二遍：清洗
    let mut src = open_source(input_path, r.input_kind)?;
    progress.event(ProgressEvent::Phase {
        phase: Phase::Scrub,
        total_bytes: src.total_bytes(),
        total_entries: src.entry_count(),
    });
    let raw_src = (r.input_kind == InputKind::Zip && r.output_kind == OutputKind::Zip).then_some(()).and(input_path);
    let spill_limit = (plan.budget / 4).min(usize::MAX as u64) as usize;
    let sink = create_sink(r.output_kind, r.output_path.as_deref(), spec.force, raw_src, spill_limit)?;
    let ctx = Ctx::new(cfg, &engine, &plan, cancel, progress, Phase::Scrub, sink.supports_zip_blob(), sink.supports_raw_copy());
    let (result, sink, entries) = pipeline::scrub_pass(&ctx, src.as_mut(), sink);
    warnings.extend(ctx.take_warnings());
    let output_size = match result {
        Ok(()) => sink.finish()?,
        Err(e) => {
            sink.abort();
            return Err(e);
        }
    };

    let learned_counts = engine.learned_counts();
    let mut report = Report {
        tool: "logblur".into(),
        version: crate::VERSION.into(),
        input: input_path.map(|p| p.display().to_string()).unwrap_or_else(|| "-".into()),
        output: r.output_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| match r.output_kind {
            OutputKind::Discard => "(dry-run)".into(),
            _ => "-".into(),
        }),
        input_kind: r.input_kind.label().into(),
        output_kind: format!("{:?}", r.output_kind).to_lowercase(),
        level: cfg.level,
        mask: cfg.mask.id().into(),
        salt_fingerprint: engine.masker().salt_fingerprint(),
        learn: learned_on,
        learned: Category::ALL
            .into_iter()
            .filter(|c| learned_counts[c.index()] > 0)
            .map(|c| (c.id().to_string(), learned_counts[c.index()]))
            .collect(),
        entries_total: 0,
        text_entries: 0,
        binary_entries: 0,
        skipped_entries: 0,
        bytes_in: 0,
        bytes_out: 0,
        output_size,
        matches_total: 0,
        by_category: Default::default(),
        warnings,
        threads: plan.workers,
        memory_budget: plan.budget,
        memory_peak_reserved: ctx.budget.high_water(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        entries,
    };
    report.finalize_totals();
    Ok(report)
}
