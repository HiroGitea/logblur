//! UI state and drawing. Scrubbing runs on a background thread and reports progress back to the UI over a channel.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui::{self, Align, Align2, Color32, DroppedFile, FontId, Layout, RichText, Sense, Stroke, StrokeKind};
use logblur_core::archive::sink::part_path;
use logblur_core::archive::{default_output_path, detect_input};
use logblur_core::report::default_report_path;
use logblur_core::util::human_bytes;
use logblur_core::{
    BinaryPolicy, CancelToken, Category, Input, JobConfig, JobSpec, MaskMode, MemoryLimit, Output, OutputEncoding,
    Phase, ProgressEvent, Report, ReportFormat, i18n, t,
};

// ───────────────────────── Settings ─────────────────────────

struct Settings {
    level: u8,
    mask: MaskMode,
    mask_char: String,
    salt: String,
    counter: bool,
    enable: BTreeSet<Category>,
    skip: BTreeSet<Category>,
    keep_private_ips: bool,
    learn: bool,
    scrub_names: bool,
    binary_drop: bool,
    utf8_out: bool,
    allow: String,
    deny: String,
    threads_auto: bool,
    threads: usize,
    memory: String,
    report: bool,
    report_md: bool,
    out_dir: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        let d = JobConfig::default();
        Settings {
            level: d.level,
            mask: d.mask,
            mask_char: d.mask_char.to_string(),
            salt: String::new(),
            counter: false,
            enable: BTreeSet::new(),
            skip: BTreeSet::new(),
            keep_private_ips: d.keep_private_ips,
            learn: d.learn,
            scrub_names: d.scrub_names,
            binary_drop: false,
            utf8_out: false,
            allow: String::new(),
            deny: String::new(),
            threads_auto: true,
            threads: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
            memory: "auto".into(),
            report: true,
            report_md: false,
            out_dir: None,
        }
    }
}

fn lines(s: &str) -> Vec<String> {
    s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()
}

impl Settings {
    /// A config holding only the level and category switches, used to decide checkbox states.
    fn category_view(&self) -> JobConfig {
        JobConfig {
            level: self.level,
            enable: self.enable.iter().copied().collect(),
            skip: self.skip.iter().copied().collect(),
            ..JobConfig::default()
        }
    }

    fn toggle(&mut self, c: Category, on: bool) {
        let by_level = c.default_level() <= self.level;
        if on {
            self.skip.remove(&c);
            if !by_level {
                self.enable.insert(c);
            }
        } else {
            self.enable.remove(&c);
            if by_level {
                self.skip.insert(c);
            }
        }
    }

    fn to_config(&self) -> Result<JobConfig, String> {
        let mut cfg = self.category_view();
        cfg.mask = self.mask;
        if let Some(c) = self.mask_char.chars().next() {
            cfg.mask_char = c;
        }
        let salt = self.salt.trim();
        cfg.salt = (!salt.is_empty()).then(|| salt.to_string());
        cfg.counter = self.counter && self.mask == MaskMode::Pseudo;
        cfg.keep_private_ips = self.keep_private_ips;
        cfg.learn = self.learn;
        cfg.scrub_names = self.scrub_names;
        cfg.binary = if self.binary_drop { BinaryPolicy::Drop } else { BinaryPolicy::Copy };
        cfg.output_encoding = if self.utf8_out { OutputEncoding::Utf8 } else { OutputEncoding::Preserve };
        cfg.allow = lines(&self.allow);
        cfg.deny = lines(&self.deny);
        cfg.threads = if self.threads_auto { None } else { Some(self.threads.max(1)) };
        cfg.memory = MemoryLimit::parse(&self.memory).map_err(|e| e.to_string())?;
        cfg.validate().map_err(|e| e.to_string())?;
        Ok(cfg)
    }
}

// ───────────────────────── Jobs ─────────────────────────

struct Running {
    input: PathBuf,
    cancel: CancelToken,
    phase: Phase,
    total: Option<u64>,
    done: u64,
    entry: String,
    started: Instant,
}

enum Outcome {
    Done(Box<Report>),
    Failed(String),
    Cancelled,
}

struct JobResult {
    input: PathBuf,
    output: PathBuf,
    outcome: Outcome,
    report_path: Option<PathBuf>,
}

enum Msg {
    Progress(ProgressEvent),
    Finished(JobResult),
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}

fn tail(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n { s.to_string() } else { format!("…{}", s.chars().skip(count - n + 1).collect::<String>()) }
}

/// Picks another name when the output already exists: `logs.blurred.zip` → `logs.blurred-2.zip`.
fn unique(p: PathBuf) -> PathBuf {
    let taken = |p: &Path| p.exists() || part_path(p).exists();
    if !taken(&p) {
        return p;
    }
    let name = file_name(&p);
    for n in 2..1000 {
        let new_name = if name.contains(".blurred") {
            name.replacen(".blurred", &format!(".blurred-{n}"), 1)
        } else {
            format!("{name}-{n}")
        };
        let cand = p.with_file_name(new_name);
        if !taken(&cand) {
            return cand;
        }
    }
    p
}

// ───────────────────────── App ─────────────────────────

pub struct App {
    s: Settings,
    queue: VecDeque<PathBuf>,
    running: Option<Running>,
    results: Vec<JobResult>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    status: Option<String>,
    wayland: bool,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> App {
        let (tx, rx) = unbounded();
        App {
            s: Settings::default(),
            queue: VecDeque::new(),
            running: None,
            results: Vec::new(),
            tx,
            rx,
            status: None,
            wayland: std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty()),
        }
    }

    fn enqueue(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        for p in paths {
            if !self.queue.contains(&p) {
                self.queue.push_back(p);
            }
        }
    }

    fn output_for(&self, input: &Path) -> Result<PathBuf, String> {
        let kind = detect_input(input).map_err(|e| e.to_string())?;
        let default = default_output_path(input, kind);
        let base = match &self.s.out_dir {
            Some(dir) => dir.join(default.file_name().unwrap_or_default()),
            None => default,
        };
        Ok(unique(base))
    }

    fn drain(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Progress(e) => {
                    if let Some(r) = self.running.as_mut() {
                        match e {
                            ProgressEvent::Phase { phase, total_bytes, .. } => {
                                r.phase = phase;
                                r.total = total_bytes;
                                r.done = 0;
                            }
                            ProgressEvent::Entry { name, .. } => r.entry = name,
                            ProgressEvent::Bytes { done, .. } => r.done = done,
                            ProgressEvent::Warning(_) => {}
                        }
                    }
                }
                Msg::Finished(res) => {
                    self.running = None;
                    self.results.insert(0, res);
                }
            }
        }
    }

    fn start_next(&mut self, ctx: &egui::Context) {
        if self.running.is_some() {
            return;
        }
        let Some(input) = self.queue.pop_front() else { return };
        let cfg = match self.s.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.status = Some(t!("gui.config_error", err = e));
                self.queue.push_front(input);
                return;
            }
        };
        self.status = None;
        let output = match self.output_for(&input) {
            Ok(o) => o,
            Err(e) => {
                self.results.insert(
                    0,
                    JobResult { input, output: PathBuf::new(), outcome: Outcome::Failed(e), report_path: None },
                );
                return;
            }
        };
        let report_fmt =
            self.s.report.then_some(if self.s.report_md { ReportFormat::Markdown } else { ReportFormat::Json });
        let cancel = CancelToken::new();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let (inp, out, token) = (input.clone(), output.clone(), cancel.clone());
        std::thread::spawn(move || {
            let (ptx, pctx) = (tx.clone(), ctx.clone());
            let sink = move |e: ProgressEvent| {
                let _ = ptx.send(Msg::Progress(e));
                pctx.request_repaint();
            };
            let spec = JobSpec { input: Input::Path(inp.clone()), output: Output::Path(out.clone()), force: false };
            let (outcome, report_path) = match logblur_core::run(&spec, &cfg, &sink, &token) {
                Ok(report) => {
                    let rp = report_fmt.and_then(|fmt| {
                        let p = default_report_path(&out, fmt);
                        report.write_to(&p, fmt).ok().map(|_| p)
                    });
                    (Outcome::Done(Box::new(report)), rp)
                }
                Err(e) if e.is_cancelled() => (Outcome::Cancelled, None),
                Err(e) => (Outcome::Failed(e.to_string()), None),
            };
            let _ = tx.send(Msg::Finished(JobResult { input: inp, output: out, outcome, report_path }));
            ctx.request_repaint();
        });
        self.running = Some(Running {
            input,
            cancel,
            phase: Phase::Scrub,
            total: None,
            done: 0,
            entry: String::new(),
            started: Instant::now(),
        });
    }

    // ───────────────────────── Drawing ─────────────────────────

    fn header_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("logblur").strong());
            ui.label(RichText::new(t!("gui.subtitle")).weak());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let current = i18n::language();
                let langs = i18n::languages();
                let name = langs
                    .iter()
                    .find(|(tag, _)| *tag == current)
                    .map(|(_, n)| n.clone())
                    .unwrap_or_else(|| current.clone());
                let mut selected = current.clone();
                egui::ComboBox::from_id_salt("logblur_lang").selected_text(name).show_ui(ui, |ui| {
                    for (tag, n) in &langs {
                        ui.selectable_value(&mut selected, tag.clone(), n.clone());
                    }
                });
                ui.label(t!("gui.language"));
                if selected != current && i18n::set_language(&selected) {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Title(t!("gui.title")));
                }
            });
        });
    }

    fn settings_ui(&mut self, ui: &mut egui::Ui) {
        let s = &mut self.s;
        ui.heading(t!("gui.settings"));
        ui.add_space(4.0);

        ui.label(RichText::new(t!("gui.level")).strong());
        ui.add(egui::Slider::new(&mut s.level, 1u8..=4u8).integer());
        ui.label(
            RichText::new(format!(
                "{} — {}",
                t!(&format!("level.{}", s.level)),
                t!(&format!("level.{}_desc", s.level))
            ))
            .small(),
        );
        ui.separator();

        ui.label(RichText::new(t!("gui.mask")).strong());
        let width = ui.available_width() - 8.0;
        egui::ComboBox::from_id_salt("logblur_mask").selected_text(s.mask.label()).width(width).show_ui(ui, |ui| {
            for m in MaskMode::ALL {
                ui.selectable_value(&mut s.mask, m, m.label());
            }
        });
        if matches!(s.mask, MaskMode::Block | MaskMode::Fixed | MaskMode::Partial) {
            ui.horizontal(|ui| {
                ui.label(t!("gui.mask_char"));
                ui.add(egui::TextEdit::singleline(&mut s.mask_char).desired_width(36.0));
            });
        }
        if matches!(s.mask, MaskMode::Pseudo | MaskMode::Hash) {
            ui.horizontal(|ui| {
                ui.label(t!("gui.salt"));
                ui.add(egui::TextEdit::singleline(&mut s.salt).hint_text(t!("gui.salt_hint")).desired_width(170.0));
            });
        }
        if s.mask == MaskMode::Pseudo {
            ui.checkbox(&mut s.counter, t!("gui.counter"));
        }
        ui.separator();

        let view = s.category_view();
        ui.collapsing(t!("gui.categories"), |ui| {
            for lvl in 1u8..=5 {
                let cats: Vec<Category> =
                    Category::ALL.into_iter().filter(|c| c.default_level() == lvl && *c != Category::Custom).collect();
                if cats.is_empty() {
                    continue;
                }
                let title = if lvl <= 4 { t!(&format!("level.{lvl}")) } else { t!("gui.level_extra") };
                ui.label(RichText::new(format!("{lvl} · {title}")).small().strong());
                for c in cats {
                    let mut on = view.category_enabled(c);
                    if ui.checkbox(&mut on, c.label()).changed() {
                        s.toggle(c, on);
                    }
                }
            }
            if ui.button(t!("gui.reset_categories")).clicked() {
                s.enable.clear();
                s.skip.clear();
            }
        });
        ui.separator();

        ui.label(RichText::new(t!("gui.options")).strong());
        ui.checkbox(&mut s.keep_private_ips, t!("gui.keep_private_ips"));
        ui.checkbox(&mut s.learn, t!("gui.learn"));
        ui.checkbox(&mut s.scrub_names, t!("gui.scrub_names"));
        ui.checkbox(&mut s.binary_drop, t!("gui.binary_drop"));
        ui.checkbox(&mut s.utf8_out, t!("gui.utf8_out"));
        ui.horizontal(|ui| {
            ui.checkbox(&mut s.report, t!("gui.report"));
            if s.report {
                ui.radio_value(&mut s.report_md, false, "JSON");
                ui.radio_value(&mut s.report_md, true, "Markdown");
            }
        });
        ui.separator();

        ui.label(RichText::new(t!("gui.allow")).strong());
        ui.add(
            egui::TextEdit::multiline(&mut s.allow)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .hint_text("203.0.113.0/24\n*.example.org"),
        );
        ui.label(RichText::new(t!("gui.deny")).strong());
        ui.add(
            egui::TextEdit::multiline(&mut s.deny)
                .desired_rows(3)
                .desired_width(f32::INFINITY)
                .hint_text("Acme Corp\nre:(?i)project[-_ ]x"),
        );
        ui.separator();

        ui.label(RichText::new(t!("gui.out_dir")).strong());
        match &s.out_dir {
            Some(d) => {
                ui.monospace(d.display().to_string());
            }
            None => {
                ui.weak(t!("gui.out_dir_same"));
            }
        }
        ui.horizontal(|ui| {
            if ui.button(t!("gui.choose")).clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                s.out_dir = Some(d);
            }
            if s.out_dir.is_some() && ui.button(t!("gui.reset")).clicked() {
                s.out_dir = None;
            }
        });
        ui.separator();

        ui.collapsing(t!("gui.advanced"), |ui| {
            ui.horizontal(|ui| {
                ui.label(t!("gui.threads"));
                ui.checkbox(&mut s.threads_auto, t!("gui.auto"));
            });
            if !s.threads_auto {
                ui.add(egui::Slider::new(&mut s.threads, 1usize..=256usize));
            }
            ui.horizontal(|ui| {
                ui.label(t!("gui.memory"));
                ui.add(egui::TextEdit::singleline(&mut s.memory).desired_width(90.0));
            });
            ui.label(RichText::new(t!("gui.memory_hint")).small().weak());
        });
        ui.add_space(8.0);
        ui.label(RichText::new(t!("gui.privacy_note")).small().weak());
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 150.0), Sense::click());
        let visuals = ui.visuals().clone();
        let active = hovering || resp.hovered();
        let stroke_color =
            if active { visuals.selection.stroke.color } else { visuals.widgets.noninteractive.bg_stroke.color };
        let fill = if active { visuals.selection.bg_fill.gamma_multiply(0.25) } else { visuals.faint_bg_color };
        let painter = ui.painter();
        painter.rect_filled(rect, 10.0, fill);
        painter.rect_stroke(rect, 10.0, Stroke::new(if active { 2.5 } else { 1.5 }, stroke_color), StrokeKind::Inside);
        let title = if hovering { t!("gui.drop_release") } else { t!("gui.drop_title") };
        painter.text(
            rect.center() - egui::vec2(0.0, 14.0),
            Align2::CENTER_CENTER,
            title,
            FontId::proportional(20.0),
            visuals.strong_text_color(),
        );
        painter.text(
            rect.center() + egui::vec2(0.0, 16.0),
            Align2::CENTER_CENTER,
            t!("gui.drop_hint"),
            FontId::proportional(14.0),
            visuals.weak_text_color(),
        );
        if resp.clicked()
            && let Some(files) = rfd::FileDialog::new().pick_files()
        {
            self.enqueue(files);
        }
    }

    fn running_ui(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.running else { return };
        let mut cancel = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spinner();
                let phase = match r.phase {
                    Phase::Learn => t!("gui.phase_learn"),
                    Phase::Scrub => t!("gui.phase_scrub"),
                };
                ui.strong(format!("{phase} · {}", file_name(&r.input)));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(t!("gui.cancel")).clicked() {
                        cancel = true;
                    }
                });
            });
            let secs = r.started.elapsed().as_secs_f64().max(0.001);
            let speed = t!("gui.speed", done = human_bytes(r.done), rate = human_bytes((r.done as f64 / secs) as u64));
            let bar = match r.total {
                Some(total) if total > 0 => {
                    let frac = (r.done as f32 / total as f32).clamp(0.0, 1.0);
                    egui::ProgressBar::new(frac).text(format!("{:.0}% · {speed}", frac * 100.0))
                }
                _ => egui::ProgressBar::new(0.0).animate(true).text(speed),
            };
            ui.add(bar);
            if !r.entry.is_empty() {
                ui.label(RichText::new(tail(&r.entry, 100)).small().weak());
            }
        });
        if cancel {
            r.cancel.cancel();
        }
    }

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        self.drop_zone(ui);
        ui.add_space(6.0);
        let mut picked: Vec<PathBuf> = Vec::new();
        ui.horizontal(|ui| {
            if ui.button(t!("gui.pick_files")).clicked()
                && let Some(f) = rfd::FileDialog::new().pick_files()
            {
                picked.extend(f);
            }
            if ui.button(t!("gui.pick_folder")).clicked()
                && let Some(d) = rfd::FileDialog::new().pick_folder()
            {
                picked.push(d);
            }
            if !self.queue.is_empty() {
                ui.label(t!("gui.queue", n = self.queue.len()));
            }
        });
        self.enqueue(picked);
        if self.wayland {
            ui.label(RichText::new(t!("gui.wayland_hint")).small().weak());
        }
        if let Some(st) = &self.status {
            ui.colored_label(ui.visuals().error_fg_color, st.as_str());
        }
        ui.add_space(8.0);
        self.running_ui(ui);
        ui.add_space(8.0);

        let mut clear = false;
        ui.horizontal(|ui| {
            ui.heading(t!("gui.results"));
            if !self.results.is_empty() && ui.button(t!("gui.clear_results")).clicked() {
                clear = true;
            }
        });
        if clear {
            self.results.clear();
        }
        if self.results.is_empty() {
            ui.weak(t!("gui.no_results"));
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, res) in self.results.iter().enumerate() {
                ui.push_id(i, |ui| result_ui(ui, res));
                ui.add_space(4.0);
            }
        });
    }
}

fn result_ui(ui: &mut egui::Ui, res: &JobResult) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        match &res.outcome {
            Outcome::Done(r) => {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(Color32::from_rgb(60, 170, 90), "✔");
                    ui.strong(file_name(&res.input));
                    ui.label("→");
                    ui.monospace(res.output.display().to_string());
                });
                ui.label(t!(
                    "gui.entries_line",
                    entries = r.entries_total,
                    text = r.text_entries,
                    binary = r.binary_entries,
                    skipped = r.skipped_entries,
                    secs = format!("{:.2}", r.elapsed_ms as f64 / 1000.0)
                ));
                ui.label(RichText::new(t!("gui.masked_total", n = r.matches_total)).strong());
                let mut cats: Vec<(Category, u64)> = r.by_category.iter().collect();
                cats.sort_by_key(|c| std::cmp::Reverse(c.1));
                if !cats.is_empty() {
                    egui::Grid::new("categories").num_columns(2).striped(true).show(ui, |ui| {
                        for (c, n) in cats.iter().take(12) {
                            ui.label(c.label());
                            ui.label(n.to_string());
                            ui.end_row();
                        }
                    });
                }
                let learned: usize = r.learned.values().sum();
                if learned > 0 {
                    ui.label(RichText::new(t!("gui.learned", n = learned)).small());
                }
                if !r.warnings.is_empty() {
                    let color = ui.visuals().warn_fg_color;
                    ui.collapsing(RichText::new(t!("gui.warnings", n = r.warnings.len())).color(color), |ui| {
                        for w in &r.warnings {
                            ui.label(RichText::new(w).small());
                        }
                    });
                }
                ui.horizontal(|ui| {
                    if ui.button(t!("gui.open_folder")).clicked()
                        && let Some(dir) = res.output.parent()
                    {
                        let _ = open::that(dir);
                    }
                    if let Some(rp) = &res.report_path
                        && ui.button(t!("gui.open_report")).clicked()
                    {
                        let _ = open::that(rp);
                    }
                });
            }
            Outcome::Failed(e) => {
                let color = ui.visuals().error_fg_color;
                ui.colored_label(color, t!("gui.failed", input = file_name(&res.input), err = e));
            }
            Outcome::Cancelled => {
                ui.label(t!("gui.cancelled", input = file_name(&res.input)));
            }
        }
    });
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        let dropped: Vec<PathBuf> = ui.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if !dropped.is_empty() {
            self.enqueue(dropped);
        }
        self.start_next(ui.ctx());

        egui::Panel::top("logblur_header").show(ui, |ui| self.header_ui(ui));
        egui::Panel::left("logblur_settings").resizable(true).default_size(340.0).min_size(280.0).show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| self.settings_ui(ui));
        });
        egui::CentralPanel::default().show(ui, |ui| self.main_ui(ui));

        if self.running.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
    }
}

/// Keeps the `DroppedFile` import from being reported as unused (`path()` is one of its methods).
#[allow(dead_code)]
fn _dropped_path(f: &dyn DroppedFile) -> &Path {
    f.path()
}
