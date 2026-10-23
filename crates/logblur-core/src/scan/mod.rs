//! Scan engine: scans a run of UTF-8 (or mostly UTF-8) bytes rule by rule, filters the hits through the trailing
//! boundary check, protected ranges, validators and the allow list, then merges overlapping ranges.
//!
//! Each rule scans the input independently (the regex crate uses literal prefixes for SIMD prefiltering), so no
//! position is ever missed because another rule matched it first. The `Scanner` boundary stays here so the
//! implementation can later be replaced with a GPU or multi-pattern automaton.

mod resolve;

use std::borrow::Cow;
use std::collections::HashSet;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::{Regex, RegexBuilder};

use crate::category::{Category, Counts};
use crate::config::{JobConfig, MaskMode};
use crate::error::{Error, Result};
use crate::mask::Masker;
use crate::rules::allow::Allowlist;
use crate::rules::protect::PROTECT_PATTERNS;
use crate::rules::table::{GENERIC_HOSTNAMES, builtin};
use crate::rules::{Cand, FIRST_GROUP, Rule};
use crate::util::ceil_char_boundary;

pub use resolve::resolve;

/// One hit: the byte range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    pub start: usize,
    pub end: usize,
    pub category: Category,
    /// Rule index; `RULE_LEARNED` / `RULE_DENY` mark special sources.
    pub rule: u16,
}

pub const RULE_LEARNED: u16 = u16::MAX;
pub const RULE_DENY: u16 = u16::MAX - 1;

struct Compiled {
    rule: Rule,
    re: Regex,
}

struct Learned {
    ac: AhoCorasick,
    cats: Vec<Category>,
}

/// Pluggable scanner interface (the only current implementation is [`Engine`]).
pub trait Scanner: Send + Sync {
    fn find(&self, hay: &[u8], out: &mut Vec<Found>);
}

pub struct Engine {
    rules: Vec<Compiled>,
    protect: Vec<Regex>,
    need_protect: bool,
    allow: Allowlist,
    deny: Option<AhoCorasick>,
    learned: Option<Learned>,
    learned_count: [usize; Category::COUNT],
    masker: Masker,
    name_masker: Masker,
}

fn compile(pattern: &str, id: &str) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .multi_line(true)
        .crlf(true)
        .size_limit(64 << 20)
        .dfa_size_limit(32 << 20)
        .build()
        .map_err(|e| Error::Rule { rule: id.to_string(), msg: e.to_string() })
}

fn as_str(b: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(b) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => String::from_utf8_lossy(b),
    }
}

/// One row of the rule list (`logblur rules list`).
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: String,
    pub category: Category,
    pub level: u8,
    pub desc: String,
    pub active: bool,
}

impl Engine {
    pub fn new(cfg: &JobConfig) -> Result<Engine> {
        cfg.validate()?;
        let mut rules = Vec::new();
        for r in builtin() {
            if cfg.rule_enabled(r.category, r.level) {
                let re = compile(&r.pattern, &r.id)?;
                rules.push(Compiled { rule: r, re });
            }
        }
        // User-defined rules
        for cr in &cfg.custom_rules {
            let cat = cr.category.unwrap_or(Category::Custom);
            let level = cr.level.unwrap_or(1);
            if !cfg.rule_enabled(cat, level) {
                continue;
            }
            let re = compile(&cr.pattern, &cr.id)?;
            let group = cr.group.unwrap_or(if re.captures_len() > 1 { 1 } else { 0 });
            if group >= re.captures_len() {
                return Err(Error::Config(crate::t!("config.custom_no_group", id = cr.id, group = group)));
            }
            let mut rule = Rule::new("custom", cat, level, "", "");
            rule.id = Cow::Owned(cr.id.clone());
            rule.desc = Cow::Owned(crate::t!("rules.custom", id = cr.id));
            rule.pattern = Cow::Owned(cr.pattern.clone());
            rule.group = group;
            rules.push(Compiled { rule, re });
        }
        // Deny list: entries starting with re: are regexes, the rest are literals
        let mut literals = Vec::new();
        if cfg.category_enabled(Category::Custom) {
            for (i, d) in cfg.deny.iter().enumerate() {
                let d = d.trim();
                if d.is_empty() {
                    continue;
                }
                if let Some(re) = d.strip_prefix("re:") {
                    let id = format!("deny_{i}");
                    let compiled = compile(re, &id)?;
                    let mut rule = Rule::new("deny", Category::Custom, 1, "", "");
                    rule.id = Cow::Owned(id);
                    rule.desc = Cow::Owned(crate::t!("rules.deny_regex", re = re));
                    rule.pattern = Cow::Owned(re.to_string());
                    rule.group = 0;
                    rules.push(Compiled { rule, re: compiled });
                } else {
                    literals.push(d.to_string());
                }
            }
        }
        let deny = if literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&literals)
                    .map_err(|e| Error::Config(crate::t!("config.bad_deny", err = e)))?,
            )
        };
        let need_protect = rules.iter().any(|c| c.rule.protect);
        let protect = PROTECT_PATTERNS
            .iter()
            .enumerate()
            .map(|(i, (_, p))| compile(p, &format!("protect_{i}")))
            .collect::<Result<Vec<_>>>()?;
        if rules.len() >= RULE_DENY as usize {
            return Err(Error::Config(crate::t!("config.too_many_rules")));
        }
        let allow = Allowlist::new(&cfg.allow, cfg.keep_private_ips)?;
        let masker = Masker::new(cfg, cfg.mask);
        let name_mode = if cfg.mask == MaskMode::Remove { MaskMode::Tag } else { cfg.mask };
        let name_masker = masker.with_mode(name_mode);
        Ok(Engine {
            rules,
            protect,
            need_protect,
            allow,
            deny,
            learned: None,
            learned_count: [0; Category::COUNT],
            masker,
            name_masker,
        })
    }

    /// All built-in rules and whether each is enabled under `cfg`.
    pub fn rule_infos(cfg: &JobConfig) -> Vec<RuleInfo> {
        let mut v: Vec<RuleInfo> = builtin()
            .into_iter()
            .map(|r| {
                let desc = crate::i18n::tr_or(&format!("rule.{}", r.id), &r.desc);
                RuleInfo {
                    active: cfg.rule_enabled(r.category, r.level),
                    id: r.id.into_owned(),
                    category: r.category,
                    level: r.level,
                    desc,
                }
            })
            .collect();
        for cr in &cfg.custom_rules {
            let cat = cr.category.unwrap_or(Category::Custom);
            let level = cr.level.unwrap_or(1);
            v.push(RuleInfo {
                id: cr.id.clone(),
                category: cat,
                level,
                desc: crate::t!("rules.custom_info", pattern = cr.pattern),
                active: cfg.rule_enabled(cat, level),
            });
        }
        v
    }

    pub fn rule_id(&self, rule: u16) -> &str {
        match rule {
            RULE_LEARNED => "learned",
            RULE_DENY => "deny_list",
            r => self.rules.get(r as usize).map(|c| c.rule.id.as_ref()).unwrap_or("?"),
        }
    }

    pub fn active_rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn masker(&self) -> &Masker {
        &self.masker
    }

    /// Number of identifiers learned per category.
    pub fn learned_counts(&self) -> [usize; Category::COUNT] {
        self.learned_count
    }

    fn protect_ranges(&self, hay: &[u8]) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        for re in &self.protect {
            for m in re.find_iter(hay) {
                v.push((m.start(), m.end()));
            }
        }
        if v.len() > 1 {
            v.sort_unstable();
            let mut merged: Vec<(usize, usize)> = Vec::with_capacity(v.len());
            for (s, e) in v {
                match merged.last_mut() {
                    Some(last) if s <= last.1 => last.1 = last.1.max(e),
                    _ => merged.push((s, e)),
                }
            }
            v = merged;
        }
        v
    }

    /// Runs one rule and calls `hit(start, end)` for every hit that passes the checks.
    fn run_rule(&self, c: &Compiled, hay: &[u8], protect: &[(usize, usize)], hit: &mut dyn FnMut(usize, usize)) {
        let mut locs = c.re.capture_locations();
        let mut pos = 0usize;
        while pos <= hay.len() {
            let Some(m) = c.re.captures_read_at(&mut locs, hay, pos) else { break };
            let (ms, me) = (m.start(), m.end());
            let span = if c.rule.group == FIRST_GROUP {
                (1..locs.len()).find_map(|g| locs.get(g))
            } else {
                locs.get(c.rule.group)
            };
            let mut next = ms + 1;
            if let Some((ps, pe)) = span
                && pe > ps
                && self.accept(&c.rule, hay, ms, me, ps, pe, protect)
            {
                hit(ps, pe);
                next = next.max(pe);
            }
            pos = ceil_char_boundary(hay, next);
            if pos > hay.len() || (pos == hay.len() && ms == hay.len()) {
                break;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn accept(
        &self,
        r: &Rule,
        hay: &[u8],
        ms: usize,
        me: usize,
        ps: usize,
        pe: usize,
        protect: &[(usize, usize)],
    ) -> bool {
        if let Some(after) = r.after
            && !after(&hay[pe..])
        {
            return false;
        }
        if r.protect && !protect.is_empty() {
            let i = protect.partition_point(|&(_, e)| e <= ps);
            if i < protect.len() && protect[i].0 < pe {
                return false;
            }
        }
        let payload = as_str(&hay[ps..pe]);
        if let Some(v) = r.validator {
            let line_start =
                memchr::memrchr(b'\n', &hay[ps.saturating_sub(64)..ps]).map(|i| ps.saturating_sub(64) + i + 1);
            let bstart = line_start.unwrap_or(ps.saturating_sub(64));
            let whole = as_str(&hay[ms..me]);
            let cand = Cand {
                payload: &payload,
                whole: &whole,
                before: &hay[bstart..ps],
                after: &hay[pe..(pe + 64).min(hay.len())],
            };
            if !v(&cand) {
                return false;
            }
        }
        !self.allow.allowed(r.category, &payload)
    }

    fn word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// Finds all hits (merged and sorted).
    pub fn find(&self, hay: &[u8], out: &mut Vec<Found>) {
        out.clear();
        let protect = if self.need_protect { self.protect_ranges(hay) } else { Vec::new() };
        for (ri, c) in self.rules.iter().enumerate() {
            let cat = c.rule.category;
            self.run_rule(c, hay, &protect, &mut |s, e| {
                out.push(Found { start: s, end: e, category: cat, rule: ri as u16 });
            });
        }
        if let Some(ac) = &self.deny {
            for m in ac.find_iter(hay) {
                out.push(Found { start: m.start(), end: m.end(), category: Category::Custom, rule: RULE_DENY });
            }
        }
        if let Some(l) = &self.learned {
            for m in l.ac.find_iter(hay) {
                let (s, e) = (m.start(), m.end());
                let before_ok = s == 0 || !Self::word_byte(hay[s - 1]);
                let after_ok = e == hay.len() || !Self::word_byte(hay[e]);
                if before_ok && after_ok {
                    out.push(Found { start: s, end: e, category: l.cats[m.pattern().as_usize()], rule: RULE_LEARNED });
                }
            }
        }
        resolve(out, |f| match f.rule {
            RULE_DENY => 0,
            RULE_LEARNED => u32::MAX - 1,
            r => r as u32 + 1,
        });
    }

    /// Scrubs a chunk of text, appending the result to `out`.
    pub fn scrub(&self, hay: &[u8], out: &mut Vec<u8>, counts: &mut Counts, mask_char: char) {
        let mut found = Vec::new();
        self.find(hay, &mut found);
        self.masker.apply(hay, &found, out, counts, mask_char);
    }

    /// Scrubs a string and returns a new one (used for command-line testing and previews).
    pub fn scrub_str(&self, s: &str, counts: &mut Counts) -> String {
        let mut out = Vec::with_capacity(s.len());
        self.scrub(s.as_bytes(), &mut out, counts, self.masker.mask_char());
        String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    }

    /// Scrubs an entry name/path inside an archive. A leading `/` is added so home-directory rules apply.
    pub fn scrub_name(&self, name: &str, counts: &mut Counts) -> String {
        let leading = name.starts_with('/');
        let hay = if leading { name.to_string() } else { format!("/{name}") };
        let mut found = Vec::new();
        self.find(hay.as_bytes(), &mut found);
        if found.is_empty() {
            return name.to_string();
        }
        let mut out = Vec::with_capacity(hay.len());
        self.name_masker.apply(hay.as_bytes(), &found, &mut out, counts, self.masker.mask_char());
        let s = String::from_utf8_lossy(&out).into_owned();
        if leading { s } else { s.strip_prefix('/').map(str::to_string).unwrap_or(s) }
    }

    /// Runs only the "learning" rules and collects the values.
    pub fn learn(&self, hay: &[u8], out: &mut HashSet<(Category, String)>) {
        for c in self.rules.iter().filter(|c| c.rule.learn) {
            let cat = c.rule.category;
            self.run_rule(c, hay, &[], &mut |s, e| {
                let v = as_str(&hay[s..e]).trim_matches(|ch: char| ch == '\'' || ch == '"').to_string();
                if !v.is_empty() && v.len() <= 253 {
                    out.insert((cat, v));
                }
            });
        }
    }

    pub fn has_learn_rules(&self) -> bool {
        self.rules.iter().any(|c| c.rule.learn)
    }

    /// Sets the "learned identifiers" used in the second pass. Filters out values that are too short, purely numeric,
    /// generic names, or on the allow list.
    pub fn set_learned(&mut self, values: impl IntoIterator<Item = (Category, String)>) -> Result<()> {
        let mut uniq: Vec<(Category, String)> = Vec::new();
        let mut seen = HashSet::new();
        let mut push = |cat: Category, v: String, uniq: &mut Vec<(Category, String)>| {
            let key = v.to_ascii_lowercase();
            if v.chars().count() < 3
                || v.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b':')
                || GENERIC_HOSTNAMES.contains(&key.as_str())
                || self.allow.allowed(cat, &v)
                || !seen.insert(key)
            {
                return;
            }
            uniq.push((cat, v));
        };
        for (cat, v) in values {
            // Also learn the first label of an FQDN (the short hostname)
            if cat == Category::Hostname
                && v.contains('.')
                && !v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && let Some(short) = v.split('.').next()
            {
                push(cat, short.to_string(), &mut uniq);
            }
            push(cat, v, &mut uniq);
        }
        uniq.sort_by(|a, b| a.1.len().cmp(&b.1.len()).reverse().then_with(|| a.1.cmp(&b.1)));
        uniq.truncate(20_000);
        self.learned_count = [0; Category::COUNT];
        for (c, _) in &uniq {
            self.learned_count[c.index()] += 1;
        }
        if uniq.is_empty() {
            self.learned = None;
            return Ok(());
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(uniq.iter().map(|(_, v)| v.as_str()))
            .map_err(|e| Error::Other(crate::t!("config.learned_build", err = e)))?;
        self.learned = Some(Learned { ac, cats: uniq.into_iter().map(|(c, _)| c).collect() });
        Ok(())
    }
}

impl Scanner for Engine {
    fn find(&self, hay: &[u8], out: &mut Vec<Found>) {
        Engine::find(self, hay, out)
    }
}

#[cfg(test)]
mod tests;
