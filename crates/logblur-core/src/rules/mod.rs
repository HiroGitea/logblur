//! Rule definitions: category, level, regex, capture group to mask, validator, boundary check.
//!
//! The `regex` crate does not support lookaround, so "context + target" are written in a single regex and
//! `group` selects the capture group holding the target to mask; the trailing boundary is checked afterwards by an
//! `after` function, so separators are not consumed and two adjacent targets can both match.

pub mod allow;
pub mod protect;
pub mod table;
pub mod validators;

use std::borrow::Cow;

use crate::category::Category;

/// Candidate hit, handed to the validator for a decision.
pub struct Cand<'a> {
    /// The text to mask.
    pub payload: &'a str,
    /// The whole regex match (including context).
    pub whole: &'a str,
    /// Up to 64 bytes before the payload, within the same line.
    pub before: &'a [u8],
    /// Up to 64 bytes after the payload.
    pub after: &'a [u8],
}

pub type Validator = fn(&Cand) -> bool;
/// Trailing boundary check: the argument is the remaining bytes after the payload; returns true if the boundary is
/// valid.
pub type AfterCheck = fn(&[u8]) -> bool;

/// When `group` is set to this value, it means "the first capture group that participated in the match".
pub const FIRST_GROUP: usize = usize::MAX;

#[derive(Clone)]
pub struct Rule {
    pub id: Cow<'static, str>,
    pub category: Category,
    /// The secrecy level from which the rule takes effect.
    pub level: u8,
    pub desc: Cow<'static, str>,
    pub pattern: Cow<'static, str>,
    /// Capture group to mask: 0 = the whole match, `FIRST_GROUP` = the first group that participated in the match.
    pub group: usize,
    pub validator: Option<Validator>,
    pub after: Option<AfterCheck>,
    /// Whether to avoid protected ranges (version numbers, timestamps, etc.).
    pub protect: bool,
    /// Whether matched values are added to the "learned identifiers", which are scrubbed throughout the text in the
    /// second pass.
    pub learn: bool,
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("id", &self.id)
            .field("category", &self.category)
            .field("level", &self.level)
            .finish()
    }
}

impl Rule {
    /// Constructor for built-in rules.
    pub fn new(id: &'static str, category: Category, level: u8, desc: &'static str, pattern: &'static str) -> Rule {
        Rule {
            id: Cow::Borrowed(id),
            category,
            level,
            desc: Cow::Borrowed(desc),
            pattern: Cow::Borrowed(pattern),
            group: 1,
            validator: None,
            after: None,
            protect: false,
            learn: false,
        }
    }

    /// Masks the whole match.
    pub fn whole(mut self) -> Self {
        self.group = 0;
        self
    }

    pub fn group(mut self, g: usize) -> Self {
        self.group = g;
        self
    }

    pub fn first_group(mut self) -> Self {
        self.group = FIRST_GROUP;
        self
    }

    pub fn check(mut self, v: Validator) -> Self {
        self.validator = Some(v);
        self
    }

    pub fn after(mut self, a: AfterCheck) -> Self {
        self.after = Some(a);
        self
    }

    pub fn protect(mut self) -> Self {
        self.protect = true;
        self
    }

    pub fn learn(mut self) -> Self {
        self.learn = true;
        self
    }
}
