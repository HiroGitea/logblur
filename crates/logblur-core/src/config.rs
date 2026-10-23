//! Job configuration: secrecy level, mask mode, allow/deny lists, concurrency and memory budget.
//!
//! Merge order: built-in defaults < TOML config file < command line / GUI.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::error::{Error, Result};

/// Mask mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaskMode {
    /// Replaces each character with the mask character (default `░`), keeping the character count.
    #[default]
    Block,
    /// A fixed number of mask characters, hiding the original length.
    Fixed,
    /// Replaces each character with `*`.
    Star,
    /// Category tag, e.g. `[IPV4]`.
    Tag,
    /// Consistent pseudonym, e.g. `IP_k3f9xq2a`: the same original value always gets the same alias.
    Pseudo,
    /// Keeps part of the value: the domain of an email, the last 4 digits of a card/phone number, the first octet of an
    /// IP, etc.
    Partial,
    /// Removes the value entirely.
    Remove,
    /// Hex prefix of a salted SHA-256.
    Hash,
}

impl MaskMode {
    pub const ALL: [MaskMode; 8] = [
        MaskMode::Block,
        MaskMode::Fixed,
        MaskMode::Star,
        MaskMode::Tag,
        MaskMode::Pseudo,
        MaskMode::Partial,
        MaskMode::Remove,
        MaskMode::Hash,
    ];

    pub fn id(self) -> &'static str {
        match self {
            MaskMode::Block => "block",
            MaskMode::Fixed => "fixed",
            MaskMode::Star => "star",
            MaskMode::Tag => "tag",
            MaskMode::Pseudo => "pseudo",
            MaskMode::Partial => "partial",
            MaskMode::Remove => "remove",
            MaskMode::Hash => "hash",
        }
    }

    pub fn from_id(s: &str) -> Option<MaskMode> {
        let s = s.trim().to_ascii_lowercase();
        let s = match s.as_str() {
            "pseudonym" => "pseudo",
            "placeholder" => "tag",
            "asterisk" => "star",
            "delete" => "remove",
            other => other,
        };
        MaskMode::ALL.into_iter().find(|m| m.id() == s)
    }

    /// Display name in the UI (in the current language).
    pub fn label(self) -> String {
        crate::i18n::tr(&format!("mask.{}", self.id()))
    }
}

/// Memory limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryLimit {
    /// 70% of available memory (also capped by the cgroup limit).
    #[default]
    Auto,
    Bytes(u64),
    Percent(u8),
}

impl MemoryLimit {
    /// Parses `auto`, `2G`, `512M`, `1.5GiB`, `70%`.
    pub fn parse(s: &str) -> Result<MemoryLimit> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("auto") || t.is_empty() {
            return Ok(MemoryLimit::Auto);
        }
        if let Some(p) = t.strip_suffix('%') {
            let v: u8 = p.trim().parse().map_err(|_| Error::Config(crate::t!("config.bad_percent", value = s)))?;
            if v == 0 || v > 100 {
                return Err(Error::Config(crate::t!("config.percent_range", value = s)));
            }
            return Ok(MemoryLimit::Percent(v));
        }
        crate::util::parse_size(t)
            .map(MemoryLimit::Bytes)
            .ok_or_else(|| Error::Config(crate::t!("config.bad_size", value = s)))
    }
}

impl std::fmt::Display for MemoryLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryLimit::Auto => f.write_str("auto"),
            MemoryLimit::Bytes(b) => f.write_str(&crate::util::human_bytes(*b)),
            MemoryLimit::Percent(p) => write!(f, "{p}%"),
        }
    }
}

/// How binary entries (files that cannot be scrubbed as text) are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BinaryPolicy {
    /// Copy verbatim (listed with a warning in the report).
    #[default]
    Copy,
    /// Remove from the output.
    Drop,
}

/// Encoding of the output text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputEncoding {
    /// Same as the input (GBK in, GBK out).
    #[default]
    Preserve,
    /// Always output UTF-8.
    Utf8,
}

/// Report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Markdown,
}

/// User-defined rule (TOML `[[custom_rules]]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    pub id: String,
    /// Regex (Rust regex syntax, matched byte-wise against UTF-8 text).
    pub pattern: String,
    /// Which capture group to mask; if omitted, group 1 when the pattern has capture groups, otherwise the whole match.
    #[serde(default)]
    pub group: Option<usize>,
    /// Which category the rule belongs to; defaults to `custom`.
    #[serde(default)]
    pub category: Option<Category>,
    /// The level from which the rule takes effect; defaults to 1 (always active).
    #[serde(default)]
    pub level: Option<u8>,
}

/// Complete configuration of one scrub job.
#[derive(Debug, Clone, PartialEq)]
pub struct JobConfig {
    /// Secrecy level 1–4; defaults to 3.
    pub level: u8,
    pub mask: MaskMode,
    /// Mask character (block / fixed / partial modes); defaults to `░`.
    pub mask_char: char,
    /// Character used when the output encoding cannot represent `mask_char`; defaults to `*`.
    pub fallback_char: char,
    /// Width used by the fixed mode.
    pub fixed_width: usize,
    /// Number of hex digits output by the hash mode.
    pub hash_len: usize,
    /// Salt for pseudonyms/hashes. If empty, a random salt is generated on each run (consistent within a run, not
    /// across runs).
    pub salt: Option<String>,
    /// Pseudonyms use increasing numbers (IP_1, IP_2…) instead of hashes; to keep the numbering deterministic, the job
    /// runs single-threaded.
    pub counter: bool,
    /// Only process these categories (empty means no restriction).
    pub only: Vec<Category>,
    /// Categories enabled in addition to those selected by the level.
    pub enable: Vec<Category>,
    /// Disabled categories.
    pub skip: Vec<Category>,
    /// Keep private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7).
    pub keep_private_ips: bool,
    /// First scan everything to collect usernames, hostnames, etc., then scrub those values throughout the text (two
    /// passes).
    pub learn: bool,
    /// Also scrub file names/paths inside archives.
    pub scrub_names: bool,
    /// Allow list: exact values, `*.example.com`, `10.0.0.0/8`, `re:<regex>`.
    pub allow: Vec<String>,
    /// Deny list: words that are always masked (case-insensitive), or `re:<regex>`.
    pub deny: Vec<String>,
    pub custom_rules: Vec<CustomRule>,
    /// Number of worker threads; `None` means all logical cores.
    pub threads: Option<usize>,
    pub memory: MemoryLimit,
    pub binary: BinaryPolicy,
    pub output_encoding: OutputEncoding,
    /// Chunk size for streaming (bytes).
    pub chunk_size: usize,
    /// Entries larger than this are processed as streamed chunks; `None` decides automatically from the memory budget
    /// (for tests).
    #[doc(hidden)]
    pub whole_max: Option<usize>,
}

impl Default for JobConfig {
    fn default() -> Self {
        JobConfig {
            level: 3,
            mask: MaskMode::Block,
            mask_char: '░',
            fallback_char: '*',
            fixed_width: 6,
            hash_len: 12,
            salt: None,
            counter: false,
            only: Vec::new(),
            enable: Vec::new(),
            skip: Vec::new(),
            keep_private_ips: false,
            learn: true,
            scrub_names: true,
            allow: Vec::new(),
            deny: Vec::new(),
            custom_rules: Vec::new(),
            threads: None,
            memory: MemoryLimit::Auto,
            binary: BinaryPolicy::Copy,
            output_encoding: OutputEncoding::Preserve,
            chunk_size: 1 << 20,
            whole_max: None,
        }
    }
}

impl JobConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=4).contains(&self.level) {
            return Err(Error::Config(crate::t!("config.level_range", level = self.level)));
        }
        if self.fixed_width == 0 || self.fixed_width > 64 {
            return Err(Error::Config(crate::t!("config.fixed_width")));
        }
        if self.hash_len < 4 || self.hash_len > 64 {
            return Err(Error::Config(crate::t!("config.hash_len")));
        }
        if self.mask_char == '\n' || self.mask_char == '\r' || self.fallback_char == '\n' {
            return Err(Error::Config(crate::t!("config.mask_newline")));
        }
        if !self.fallback_char.is_ascii() {
            return Err(Error::Config(crate::t!("config.fallback_ascii")));
        }
        if self.chunk_size < 64 {
            return Err(Error::Config(crate::t!("config.chunk_small")));
        }
        Ok(())
    }

    /// Whether a category is enabled under the current configuration.
    pub fn category_enabled(&self, c: Category) -> bool {
        if self.skip.contains(&c) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.contains(&c);
        }
        c == Category::Custom || c.default_level() <= self.level || self.enable.contains(&c)
    }

    /// Whether rules of level `rule_level` within a category are enabled.
    pub fn rule_enabled(&self, c: Category, rule_level: u8) -> bool {
        if !self.category_enabled(c) {
            return false;
        }
        // Explicitly named categories are enabled at least up to the category's default level.
        let forced = self.only.contains(&c) || self.enable.contains(&c);
        let effective = if forced { self.level.max(c.default_level()) } else { self.level };
        rule_level <= effective
    }

    /// Reads a TOML config file and merges it into the current configuration.
    pub fn apply_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io_path("io.read_config", path, e))?;
        let fc: FileConfig = toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        self.apply(fc)
    }

    pub fn apply(&mut self, f: FileConfig) -> Result<()> {
        if let Some(v) = f.level {
            self.level = v;
        }
        if let Some(v) = f.mask {
            self.mask = v;
        }
        if let Some(v) = f.mask_char {
            self.mask_char = v;
        }
        if let Some(v) = f.fallback_char {
            self.fallback_char = v;
        }
        if let Some(v) = f.fixed_width {
            self.fixed_width = v;
        }
        if let Some(v) = f.hash_len {
            self.hash_len = v;
        }
        if f.salt.is_some() {
            self.salt = f.salt;
        }
        if let Some(v) = f.counter {
            self.counter = v;
        }
        if let Some(v) = f.only {
            self.only = v;
        }
        if let Some(v) = f.enable {
            self.enable.extend(v);
        }
        if let Some(v) = f.skip {
            self.skip.extend(v);
        }
        if let Some(v) = f.keep_private_ips {
            self.keep_private_ips = v;
        }
        if f.mask_dates == Some(true) {
            self.enable.push(Category::Timestamp);
        }
        if let Some(v) = f.learn {
            self.learn = v;
        }
        if let Some(v) = f.scrub_names {
            self.scrub_names = v;
        }
        if let Some(v) = f.allow {
            self.allow.extend(v);
        }
        if let Some(v) = f.deny {
            self.deny.extend(v);
        }
        if let Some(v) = f.custom_rules {
            self.custom_rules.extend(v);
        }
        if let Some(v) = f.threads {
            self.threads = (v > 0).then_some(v);
        }
        if let Some(v) = f.memory {
            self.memory = MemoryLimit::parse(&v)?;
        }
        if let Some(v) = f.binary {
            self.binary = v;
        }
        if let Some(v) = f.output_encoding {
            self.output_encoding = v;
        }
        Ok(())
    }
}

/// Structure of the TOML config file; all fields are optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub level: Option<u8>,
    pub mask: Option<MaskMode>,
    pub mask_char: Option<char>,
    pub fallback_char: Option<char>,
    pub fixed_width: Option<usize>,
    pub hash_len: Option<usize>,
    pub salt: Option<String>,
    pub counter: Option<bool>,
    pub only: Option<Vec<Category>>,
    pub enable: Option<Vec<Category>>,
    pub skip: Option<Vec<Category>>,
    pub keep_private_ips: Option<bool>,
    pub mask_dates: Option<bool>,
    pub learn: Option<bool>,
    pub scrub_names: Option<bool>,
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub custom_rules: Option<Vec<CustomRule>>,
    pub threads: Option<usize>,
    pub memory: Option<String>,
    pub binary: Option<BinaryPolicy>,
    pub output_encoding: Option<OutputEncoding>,
}

/// Commented template generated by `logblur config init` (in the current language).
pub fn config_template() -> String {
    crate::t!("config.template")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses() {
        let fc: FileConfig = toml::from_str(&config_template()).expect("template should parse");
        let mut cfg = JobConfig::default();
        cfg.apply(fc).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.level, 3);
        assert_eq!(cfg.mask_char, '░');
    }

    #[test]
    fn memory_parse() {
        assert_eq!(MemoryLimit::parse("auto").unwrap(), MemoryLimit::Auto);
        assert_eq!(MemoryLimit::parse("70%").unwrap(), MemoryLimit::Percent(70));
        assert_eq!(MemoryLimit::parse("2G").unwrap(), MemoryLimit::Bytes(2 << 30));
        assert_eq!(MemoryLimit::parse("512m").unwrap(), MemoryLimit::Bytes(512 << 20));
        assert!(MemoryLimit::parse("abc").is_err());
        assert!(MemoryLimit::parse("0%").is_err());
    }

    #[test]
    fn category_gating() {
        let mut cfg = JobConfig { level: 2, ..Default::default() };
        assert!(cfg.category_enabled(Category::Password));
        assert!(cfg.category_enabled(Category::Email));
        assert!(!cfg.category_enabled(Category::Ipv4));
        cfg.enable.push(Category::Ipv4);
        assert!(cfg.rule_enabled(Category::Ipv4, 3));
        cfg.skip.push(Category::Email);
        assert!(!cfg.category_enabled(Category::Email));
        cfg.only = vec![Category::Mac];
        assert!(!cfg.category_enabled(Category::Password));
        assert!(cfg.rule_enabled(Category::Mac, 3));
    }
}
