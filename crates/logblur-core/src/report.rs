//! 清洗报告。只包含统计信息，绝不包含原始值或伪名映射表。

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::category::{Category, Counts};
use crate::config::ReportFormat;
use crate::error::{Error, Result};
use crate::util::human_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// 文本，已清洗。
    Scrubbed,
    /// 二进制，原样复制（未清洗）。
    Binary,
    /// 加密条目，原样复制（未清洗）。
    Encrypted,
    /// 按配置从输出中删除。
    Dropped,
    /// 跳过（特殊文件等）。
    Skipped,
    Dir,
    Link,
}

impl EntryStatus {
    pub fn id(self) -> &'static str {
        match self {
            EntryStatus::Scrubbed => "scrubbed",
            EntryStatus::Binary => "binary",
            EntryStatus::Encrypted => "encrypted",
            EntryStatus::Dropped => "dropped",
            EntryStatus::Skipped => "skipped",
            EntryStatus::Dir => "dir",
            EntryStatus::Link => "link",
        }
    }

    /// 界面上显示的名称（按当前语言）。
    pub fn label(self) -> String {
        crate::i18n::tr(&format!("status.{}", self.id()))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryReport {
    /// 清洗后的名字。
    pub name: String,
    pub status: EntryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub matches: u64,
    pub by_category: Counts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl EntryReport {
    pub fn new(name: &str) -> EntryReport {
        EntryReport {
            name: name.to_string(),
            status: EntryStatus::Scrubbed,
            encoding: None,
            bytes_in: 0,
            bytes_out: 0,
            matches: 0,
            by_category: Counts::default(),
            note: None,
        }
    }

    pub fn set_note(&mut self, note: impl Into<String>) {
        if self.note.is_none() {
            self.note = Some(note.into());
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub input: String,
    pub output: String,
    pub input_kind: String,
    pub output_kind: String,
    pub level: u8,
    pub mask: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_fingerprint: Option<String>,
    pub learn: bool,
    /// 每个类别学到的标识数量（不含值）。
    pub learned: BTreeMap<String, usize>,
    pub entries_total: usize,
    pub text_entries: usize,
    pub binary_entries: usize,
    pub skipped_entries: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub output_size: u64,
    pub matches_total: u64,
    pub by_category: Counts,
    pub warnings: Vec<String>,
    pub threads: usize,
    pub memory_budget: u64,
    pub memory_peak_reserved: u64,
    pub elapsed_ms: u64,
    pub entries: Vec<EntryReport>,
}

impl Report {
    pub(crate) fn finalize_totals(&mut self) {
        let mut total = Counts::default();
        self.text_entries = 0;
        self.binary_entries = 0;
        self.skipped_entries = 0;
        self.bytes_in = 0;
        self.bytes_out = 0;
        for e in &mut self.entries {
            e.matches = e.by_category.total();
            total.merge(&e.by_category);
            self.bytes_in += e.bytes_in;
            self.bytes_out += e.bytes_out;
            match e.status {
                EntryStatus::Scrubbed => self.text_entries += 1,
                EntryStatus::Binary | EntryStatus::Encrypted => self.binary_entries += 1,
                EntryStatus::Dropped | EntryStatus::Skipped => self.skipped_entries += 1,
                EntryStatus::Dir | EntryStatus::Link => {}
            }
        }
        self.entries_total = self.entries.len();
        self.matches_total = total.total();
        self.by_category = total;
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    pub fn to_markdown(&self) -> String {
        use crate::t;
        let mut s = String::new();
        s.push_str(&t!("report.title"));
        s.push_str("\n\n");
        let mut line = |text: String| {
            s.push_str("- ");
            s.push_str(&text);
            s.push('\n');
        };
        line(t!("report.input", path = self.input, kind = self.input_kind));
        line(t!("report.output", path = self.output, kind = self.output_kind, size = human_bytes(self.output_size)));
        line(t!("report.level_mask", level = self.level, mask = self.mask));
        if let Some(fp) = &self.salt_fingerprint {
            line(t!("report.salt", fp = fp));
        }
        line(t!(
            "report.entries",
            total = self.entries_total,
            text = self.text_entries,
            binary = self.binary_entries,
            skipped = self.skipped_entries
        ));
        line(t!(
            "report.volume",
            bytes_in = human_bytes(self.bytes_in),
            bytes_out = human_bytes(self.bytes_out),
            secs = format!("{:.2}", self.elapsed_ms as f64 / 1000.0),
            threads = self.threads,
            budget = human_bytes(self.memory_budget)
        ));
        line(t!("report.matches", n = self.matches_total));
        s.push('\n');
        if self.matches_total > 0 {
            s.push_str(&format!("## {}\n\n| {} | {} |\n|---|---:|\n", t!("report.by_category"), t!("report.col_category"), t!("report.col_count")));
            for (c, n) in self.by_category.iter() {
                s.push_str(&format!("| {} (`{}`) | {} |\n", c.label(), c.id(), n));
            }
            s.push('\n');
        }
        if !self.learned.is_empty() {
            s.push_str(&format!("## {}\n\n", t!("report.learned")));
            for (k, n) in &self.learned {
                let label = Category::from_id(k).map(|c| c.label()).unwrap_or_else(|| k.clone());
                s.push_str(&format!("- {label}: {n}\n"));
            }
            s.push('\n');
        }
        if !self.warnings.is_empty() {
            s.push_str(&format!("## {}\n\n", t!("report.warnings")));
            for w in &self.warnings {
                s.push_str(&format!("- {w}\n"));
            }
            s.push('\n');
        }
        s.push_str(&format!(
            "## {}\n\n| {} | {} | {} | {} | {} |\n|---|---|---|---:|---|\n",
            t!("report.entries_heading"),
            t!("report.col_name"),
            t!("report.col_status"),
            t!("report.col_encoding"),
            t!("report.col_matches"),
            t!("report.col_note")
        ));
        for e in &self.entries {
            if matches!(e.status, EntryStatus::Dir) {
                continue;
            }
            s.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                e.name.replace('|', "\\|"),
                e.status.label(),
                e.encoding.as_deref().unwrap_or(""),
                e.matches,
                e.note.as_deref().unwrap_or("").replace('|', "\\|")
            ));
        }
        s
    }

    pub fn write_to(&self, path: &Path, fmt: ReportFormat) -> Result<()> {
        let body = match fmt {
            ReportFormat::Json => self.to_json(),
            ReportFormat::Markdown => self.to_markdown(),
        };
        std::fs::write(path, body).map_err(|e| Error::io_path("io.write_report", path, e))
    }
}

/// 报告文件的默认路径：`<输出>.report.json` / `.report.md`。
pub fn default_report_path(output: &Path, fmt: ReportFormat) -> std::path::PathBuf {
    let mut s = output.as_os_str().to_os_string();
    s.push(match fmt {
        ReportFormat::Json => ".report.json",
        ReportFormat::Markdown => ".report.md",
    });
    std::path::PathBuf::from(s)
}
