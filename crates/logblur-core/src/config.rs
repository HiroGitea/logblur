//! 任务配置：保密等级、打码方式、允许/拒绝名单、并发与内存预算。
//!
//! 合并顺序：内置默认值 < TOML 配置文件 < 命令行 / GUI。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::error::{Error, Result};

/// 打码方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaskMode {
    /// 每个字符替换为打码字符（默认 `░`），字符数不变。
    #[default]
    Block,
    /// 固定宽度的打码字符，隐藏原始长度。
    Fixed,
    /// 每个字符替换为 `*`。
    Star,
    /// 类别标签，如 `[IPV4]`。
    Tag,
    /// 一致的伪名，如 `IP_k3f9xq2a`：同一原值得到同一代号。
    Pseudo,
    /// 保留部分信息：邮箱保留域名、卡号/电话保留末 4 位、IP 保留首段等。
    Partial,
    /// 直接删除。
    Remove,
    /// 加盐 SHA-256 十六进制前缀。
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

    /// 界面上显示的名称（按当前语言）。
    pub fn label(self) -> String {
        crate::i18n::tr(&format!("mask.{}", self.id()))
    }
}

/// 内存上限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryLimit {
    /// 可用内存的 70%（并受 cgroup 限制）。
    #[default]
    Auto,
    Bytes(u64),
    Percent(u8),
}

impl MemoryLimit {
    /// 解析 `auto`、`2G`、`512M`、`1.5GiB`、`70%`。
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

/// 二进制条目（无法作为文本清洗的文件）如何处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BinaryPolicy {
    /// 原样复制（报告中会列出并警告）。
    #[default]
    Copy,
    /// 从输出中删除。
    Drop,
}

/// 输出文本的编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputEncoding {
    /// 与输入相同（GBK 进 GBK 出）。
    #[default]
    Preserve,
    /// 一律输出 UTF-8。
    Utf8,
}

/// 报告格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Markdown,
}

/// 用户自定义规则（TOML `[[custom_rules]]`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    pub id: String,
    /// 正则（Rust regex 语法，按字节匹配 UTF-8 文本）。
    pub pattern: String,
    /// 打码哪个捕获组；省略时：有捕获组则用第 1 组，否则整段。
    #[serde(default)]
    pub group: Option<usize>,
    /// 归入哪个类别，默认 `custom`。
    #[serde(default)]
    pub category: Option<Category>,
    /// 从哪个等级开始生效，默认 1（总是生效）。
    #[serde(default)]
    pub level: Option<u8>,
}

/// 一次清洗任务的全部配置。
#[derive(Debug, Clone, PartialEq)]
pub struct JobConfig {
    /// 保密等级 1–4，默认 3。
    pub level: u8,
    pub mask: MaskMode,
    /// 打码字符（block / fixed / partial 模式），默认 `░`。
    pub mask_char: char,
    /// 当输出编码无法表示 `mask_char` 时使用的字符，默认 `*`。
    pub fallback_char: char,
    /// fixed 模式的宽度。
    pub fixed_width: usize,
    /// hash 模式输出的十六进制位数。
    pub hash_len: usize,
    /// 伪名/哈希的盐。为空时每次运行随机生成（运行内一致，跨运行不一致）。
    pub salt: Option<String>,
    /// 伪名使用递增编号（IP_1、IP_2…）而不是哈希；为保证编号确定，会单线程运行。
    pub counter: bool,
    /// 只处理这些类别（为空表示不限制）。
    pub only: Vec<Category>,
    /// 在等级之外额外启用的类别。
    pub enable: Vec<Category>,
    /// 关闭的类别。
    pub skip: Vec<Category>,
    /// 保留内网地址（10/8、172.16/12、192.168/16、100.64/10、fc00::/7）。
    pub keep_private_ips: bool,
    /// 先扫描一遍收集用户名/主机名等，再在全文中清洗这些值（两遍扫描）。
    pub learn: bool,
    /// 同时清洗压缩包内的文件名/路径。
    pub scrub_names: bool,
    /// 允许名单：精确值、`*.example.com`、`10.0.0.0/8`、`re:正则`。
    pub allow: Vec<String>,
    /// 拒绝名单：总要打码的词（大小写不敏感），或 `re:正则`。
    pub deny: Vec<String>,
    pub custom_rules: Vec<CustomRule>,
    /// 工作线程数，`None` 表示使用全部逻辑核。
    pub threads: Option<usize>,
    pub memory: MemoryLimit,
    pub binary: BinaryPolicy,
    pub output_encoding: OutputEncoding,
    /// 流式处理的分块大小（字节）。
    pub chunk_size: usize,
    /// 超过这个大小的条目走流式分块处理；`None` 时按内存预算自动决定（测试用）。
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

    /// 某个类别在当前配置下是否启用。
    pub fn category_enabled(&self, c: Category) -> bool {
        if self.skip.contains(&c) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.contains(&c);
        }
        c == Category::Custom || c.default_level() <= self.level || self.enable.contains(&c)
    }

    /// 某个类别内，等级为 `rule_level` 的规则是否启用。
    pub fn rule_enabled(&self, c: Category, rule_level: u8) -> bool {
        if !self.category_enabled(c) {
            return false;
        }
        // 显式点名的类别：至少启用到该类别的默认等级。
        let forced = self.only.contains(&c) || self.enable.contains(&c);
        let effective = if forced { self.level.max(c.default_level()) } else { self.level };
        rule_level <= effective
    }

    /// 读取 TOML 配置文件并合并到当前配置。
    pub fn apply_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io_path("io.read_config", path, e))?;
        let fc: FileConfig =
            toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
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

/// TOML 配置文件的结构，所有字段可选。
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

/// `logblur config init` 生成的带注释模板（按当前语言）。
pub fn config_template() -> String {
    crate::t!("config.template")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses() {
        let fc: FileConfig = toml::from_str(&config_template()).expect("模板应能解析");
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
