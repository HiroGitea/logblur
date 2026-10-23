//! Keyword prefilter: decides, per haystack, which rules to run and where.
//!
//! Most rules start with a boundary class such as `(?:^|[^A-Za-z0-9])` followed by case-insensitive keywords, which
//! defeats the literal prefilter inside the regex engine, so every rule would walk the whole haystack with its DFA.
//! Instead, each pattern is parsed once and a set of *required* literals is extracted: every match of the pattern
//! contains at least one of them. A single Aho-Corasick pass (SIMD-accelerated Teddy where the CPU supports it) then
//! finds where those literals occur. A pattern whose literals are all absent is skipped; a pattern that cannot match
//! across lines is searched only on the lines holding one of its literals, as long as those lines are a small part of
//! the haystack.
//!
//! The analysis only ever errs towards searching more: anything it cannot prove (optional parts, wide classes, Unicode
//! case folds such as the Kelvin sign, classes that include a newline) ends a literal or falls back to a full search.

use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use memchr::{memchr, memmem, memrchr};
use regex_syntax::ParserBuilder;
use regex_syntax::hir::{Class, Hir, HirKind};

/// Shortest literal worth filtering on; shorter ones occur almost everywhere.
const MIN_LITERAL: usize = 3;
/// More literals than this per pattern make the filter slower than just running the pattern.
const MAX_LITERALS: usize = 64;
/// Line windows are used while they cover less than 1/WINDOW_SHARE of the haystack; beyond that one full DFA pass is
/// cheaper than many short searches.
const WINDOW_SHARE: usize = 4;

/// How one pattern is searched in one haystack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// None of its required literals occur, so the pattern cannot match.
    Skip,
    /// Search the whole haystack.
    Full,
    /// Search only these sorted, non-overlapping ranges. Each covers whole lines and starts at the newline before
    /// its first line (if any), so a leading boundary class sees the same byte as in a full search.
    Windows(Vec<Range<usize>>),
}

struct Pattern {
    /// Aho-Corasick ids of the required literals; empty means there are none and the pattern always runs in full.
    literals: Vec<usize>,
    /// Matches never contain a newline, except possibly as their first byte, so each lies within one line.
    line_bounded: bool,
}

pub(crate) struct Prefilter {
    ac: Option<AhoCorasick>,
    literal_count: usize,
    patterns: Vec<Pattern>,
}

impl Prefilter {
    /// Builds the filter for `patterns`, parsed with the same flags as the scan engine (multi-line, CRLF).
    pub(crate) fn new<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Prefilter {
        let mut literals: Vec<Vec<u8>> = Vec::new();
        let mut out = Vec::new();
        for p in patterns {
            let hir = parse(p);
            let lits = hir.as_ref().and_then(required).filter(|l| usable(l)).unwrap_or_default();
            let ids = lits
                .into_iter()
                .map(|lit| match literals.iter().position(|l| *l == lit) {
                    Some(id) => id,
                    None => {
                        literals.push(lit);
                        literals.len() - 1
                    }
                })
                .collect();
            out.push(Pattern { literals: ids, line_bounded: hir.as_ref().is_some_and(line_bounded) });
        }
        let ac = if literals.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new().ascii_case_insensitive(true).match_kind(MatchKind::Standard).build(&literals).ok()
        };
        if ac.is_none() {
            out.iter_mut().for_each(|p| p.literals.clear());
        }
        Prefilter { ac, literal_count: literals.len(), patterns: out }
    }

    /// How each pattern should be searched in `hay`.
    pub(crate) fn plan(&self, hay: &[u8]) -> Vec<Plan> {
        let Some(ac) = &self.ac else { return vec![Plan::Full; self.patterns.len()] };
        // Literals assume ASCII case folding; with `ſ` or the Kelvin sign present, a match may not contain them.
        if FOLDS.iter().any(|(c, _)| memmem::find(hay, c.encode_utf8(&mut [0; 4]).as_bytes()).is_some()) {
            return vec![Plan::Full; self.patterns.len()];
        }
        // Positions of each literal; a literal seen this often is only recorded as present.
        let dense_after = hay.len() / 64 + 16;
        let mut positions: Vec<Vec<usize>> = vec![Vec::new(); self.literal_count];
        let mut dense = vec![false; self.literal_count];
        for m in ac.find_overlapping_iter(hay) {
            let id = m.pattern().as_usize();
            if !dense[id] {
                positions[id].push(m.start());
                if positions[id].len() > dense_after {
                    dense[id] = true;
                    positions[id] = Vec::new();
                }
            }
        }
        self.patterns
            .iter()
            .map(|p| {
                if p.literals.is_empty() {
                    return Plan::Full;
                }
                if !p.literals.iter().any(|&id| dense[id] || !positions[id].is_empty()) {
                    return Plan::Skip;
                }
                if !p.line_bounded || p.literals.iter().any(|&id| dense[id]) {
                    return Plan::Full;
                }
                let mut at: Vec<usize> = p.literals.iter().flat_map(|&id| positions[id].iter().copied()).collect();
                at.sort_unstable();
                line_windows(hay, &at).map_or(Plan::Full, Plan::Windows)
            })
            .collect()
    }
}

/// Windows covering the lines of the sorted positions `at`, or `None` if they would cover too much of `hay`.
fn line_windows(hay: &[u8], at: &[usize]) -> Option<Vec<Range<usize>>> {
    let mut wins: Vec<Range<usize>> = Vec::new();
    let mut covered = 0usize;
    for &p in at {
        if wins.last().is_some_and(|w| p < w.end) {
            continue;
        }
        let line_start = memrchr(b'\n', &hay[..p]).map_or(0, |i| i + 1);
        let line_end = memchr(b'\n', &hay[p..]).map_or(hay.len(), |i| p + i);
        let start = line_start.saturating_sub(1);
        covered += line_end - start;
        if covered * WINDOW_SHARE > hay.len() {
            return None;
        }
        match wins.last_mut() {
            Some(w) if start <= w.end => w.end = line_end,
            _ => wins.push(start..line_end),
        }
    }
    Some(wins)
}

fn parse(pattern: &str) -> Option<Hir> {
    ParserBuilder::new().utf8(false).multi_line(true).crlf(true).build().parse(pattern).ok()
}

/// Whether no match of `h` contains a newline, other than as the byte consumed by a leading one-character item.
fn line_bounded(h: &Hir) -> bool {
    match h.kind() {
        HirKind::Capture(c) => line_bounded(&c.sub),
        HirKind::Concat(items) => match items.split_first() {
            Some((first, rest)) => {
                (one_char_or_look(first) || !may_match_newline(first)) && !rest.iter().any(may_match_newline)
            }
            None => true,
        },
        _ => one_char_or_look(h) || !may_match_newline(h),
    }
}

/// Matches at most one character.
fn one_char_or_look(h: &Hir) -> bool {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(_) => true,
        HirKind::Capture(c) => one_char_or_look(&c.sub),
        HirKind::Alternation(alts) => alts.iter().all(one_char_or_look),
        _ => false,
    }
}

fn may_match_newline(h: &Hir) -> bool {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(lit) => lit.0.contains(&b'\n'),
        HirKind::Class(Class::Unicode(c)) => c.ranges().iter().any(|r| r.start() <= '\n' && '\n' <= r.end()),
        HirKind::Class(Class::Bytes(c)) => c.ranges().iter().any(|r| r.start() <= b'\n' && b'\n' <= r.end()),
        HirKind::Repetition(r) => may_match_newline(&r.sub),
        HirKind::Capture(c) => may_match_newline(&c.sub),
        HirKind::Concat(items) | HirKind::Alternation(items) => items.iter().any(may_match_newline),
    }
}

/// Lower-cased literals of which every match of `pattern` contains at least one, or `None` if there is no
/// selective set.
#[cfg(test)]
fn required_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    let lits = required(&parse(pattern)?)?;
    usable(&lits).then_some(lits)
}

fn usable(lits: &[Vec<u8>]) -> bool {
    !lits.is_empty() && lits.len() <= MAX_LITERALS && lits.iter().all(|l| l.len() >= MIN_LITERAL)
}

/// Required literal set of `h`, choosing the most selective one where there are several.
fn required(h: &Hir) -> Option<Vec<Vec<u8>>> {
    match h.kind() {
        HirKind::Literal(lit) => Some(vec![lit.0.to_ascii_lowercase()]),
        HirKind::Capture(c) => required(&c.sub),
        HirKind::Repetition(r) if r.min >= 1 => required(&r.sub),
        HirKind::Alternation(alts) => {
            let mut all = Vec::new();
            for a in alts {
                all.extend(required(a)?);
            }
            all.sort();
            all.dedup();
            Some(all)
        }
        HirKind::Concat(items) => {
            let mut best: Option<Vec<Vec<u8>>> = None;
            let mut consider = |cand: Vec<Vec<u8>>| {
                if usable(&cand) && best.as_ref().is_none_or(|b| better(&cand, b)) {
                    best = Some(cand);
                }
            };
            // Runs of single characters (or ASCII case pairs) form literals; other items are tried on their own.
            let mut run = Vec::new();
            for item in items {
                if let Some(b) = single_byte(item) {
                    run.push(b);
                    continue;
                }
                if let HirKind::Literal(lit) = item.kind() {
                    run.extend(lit.0.to_ascii_lowercase());
                    continue;
                }
                if !run.is_empty() {
                    consider(vec![std::mem::take(&mut run)]);
                }
                if let Some(sub) = required(item) {
                    consider(sub);
                }
            }
            if !run.is_empty() {
                consider(vec![run]);
            }
            best
        }
        _ => None,
    }
}

/// Prefers longer shortest literals, then fewer literals.
fn better(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    let min = |s: &[Vec<u8>]| s.iter().map(Vec::len).min().unwrap_or(0);
    (min(a), std::cmp::Reverse(a.len())) > (min(b), std::cmp::Reverse(b.len()))
}

/// The characters whose simple case fold is an ASCII letter: under `(?i)`, `s` also matches `ſ` and `k` also matches
/// the Kelvin sign. Literals are kept across them; [`Prefilter::plan`] falls back to full searches when they occur.
const FOLDS: [(char, u8); 2] = [('\u{17F}', b's'), ('\u{212A}', b'k')];

/// A class that matches exactly one ASCII byte, or one ASCII letter in either case (plus its non-ASCII fold, if any),
/// as that byte lower-cased.
fn single_byte(h: &Hir) -> Option<u8> {
    let HirKind::Class(class) = h.kind() else { return None };
    let mut chars = Vec::new();
    match class {
        Class::Unicode(c) => {
            for r in c.ranges() {
                for ch in r.start()..=r.end() {
                    if chars.len() >= 3 {
                        return None;
                    }
                    chars.push(ch);
                }
            }
        }
        Class::Bytes(c) => {
            for r in c.ranges() {
                for b in r.start()..=r.end() {
                    if !b.is_ascii() || chars.len() >= 2 {
                        return None;
                    }
                    chars.push(b as char);
                }
            }
        }
    }
    let (ascii, other): (Vec<char>, Vec<char>) = chars.into_iter().partition(char::is_ascii);
    let fold_ok = |lower: u8| match other[..] {
        [] => true,
        [c] => FOLDS.contains(&(c, lower)),
        _ => false,
    };
    match ascii[..] {
        [c] if other.is_empty() => Some((c as u8).to_ascii_lowercase()),
        [a, b] if a.is_ascii_alphabetic() && a.eq_ignore_ascii_case(&b) && a != b => {
            let lower = (a as u8).to_ascii_lowercase();
            fold_ok(lower).then_some(lower)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lits(p: &str) -> Option<Vec<String>> {
        required_literals(p).map(|v| v.into_iter().map(|l| String::from_utf8(l).unwrap()).collect())
    }

    #[test]
    fn keywords_behind_boundary_class() {
        assert_eq!(lits(r"(?i)(?:^|[^A-Za-z0-9])bearer[ \t]+([A-Za-z0-9]{8,})"), Some(vec!["bearer".into()]));
    }

    #[test]
    fn alternations_union() {
        assert_eq!(lits(r"(?:password|passwd)=(\S+)"), Some(vec!["passwd".into(), "password".into()]));
    }

    #[test]
    fn unicode_case_folds_are_kept_in_literals() {
        // (?i)k also matches the Kelvin sign; the literal stays whole and the plan checks for the fold instead.
        assert_eq!(lits(r"(?i)cookie:"), Some(vec!["cookie:".into()]));
        let pf = Prefilter::new([r"(?i)(?:^|[^a-z])cookie:([^;\n]*)"]);
        let filler = b"x\n".repeat(20);
        assert_eq!(pf.plan(&[&b"none here\n"[..], &filler].concat())[0], Plan::Skip);
        assert_eq!(pf.plan(&["coo\u{212A}ie: a\n".as_bytes(), &filler].concat())[0], Plan::Full);
    }

    #[test]
    fn optional_or_short_parts_are_not_required() {
        assert_eq!(lits(r"(?:token)?[0-9]{16}"), None);
        assert_eq!(lits(r"(?:sn|serial)=([0-9]+)"), None);
        assert_eq!(lits(r"[2-6][0-9](?:[ \-]?[0-9]){11,17}"), None);
    }

    #[test]
    fn non_ascii_literals() {
        // The alternation (6 bytes each) is more selective than the trailing 3-byte "号".
        assert_eq!(lits(r"(?:手机|电话)号"), Some(vec!["手机".into(), "电话".into()]));
    }

    #[test]
    fn plans() {
        let pf =
            Prefilter::new([r"(?i)(?:^|[^a-z])bearer (\S+)", r"(?i)cookie:([^;]*)", r"[0-9]{4}", r"(?s)begin(.*)"]);
        let hay = [&b"one\ntwo BEARER abc\n"[..], &b"filler\n".repeat(20)].concat();
        let plans = pf.plan(&hay);
        assert_eq!(plans[0], Plan::Windows(std::iter::once(3..18).collect()));
        assert_eq!(plans[1], Plan::Skip);
        assert_eq!(plans[2], Plan::Full);
        assert_eq!(plans[3], Plan::Skip);
        // `[^;]*` can match a newline, so the cookie rule is searched in full once its literal is present.
        assert_eq!(pf.plan(b"a\nset-cookie:x\nb")[1], Plan::Full);
    }

    #[test]
    fn dense_lines_fall_back_to_full() {
        let pf = Prefilter::new([r"(?i)bearer (\S+)"]);
        assert_eq!(pf.plan(b"bearer a\nbearer b\nx\n")[0], Plan::Full);
    }

    #[test]
    fn line_bounds() {
        let b = |p: &str| line_bounded(&parse(p).unwrap());
        assert!(b(r"(?:^|[^A-Za-z0-9])bearer[ \t]+([A-Za-z0-9]{8,})"));
        assert!(!b(r"x[^;]*"));
        assert!(!b(r"(?s)a.b"));
        assert!(!b(r"a\sb"));
    }
}
