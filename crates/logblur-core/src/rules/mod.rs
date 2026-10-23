//! 规则定义：类别、等级、正则、打码的捕获组、校验函数、边界检查。
//!
//! `regex` crate 不支持环视，所以「上下文 + 目标」写在同一个正则里，
//! 再用 `group` 指定只打码目标所在的捕获组；尾部边界用 `after` 函数事后检查，
//! 这样分隔符不会被吃掉，相邻的两个目标都能命中。

pub mod allow;
pub mod protect;
pub mod table;
pub mod validators;

use std::borrow::Cow;

use crate::category::Category;

/// 候选命中，交给校验函数判断。
pub struct Cand<'a> {
    /// 要打码的文本。
    pub payload: &'a str,
    /// 整个正则匹配（含上下文）。
    pub whole: &'a str,
    /// payload 之前同一行内最多 64 字节。
    pub before: &'a [u8],
    /// payload 之后最多 64 字节。
    pub after: &'a [u8],
}

pub type Validator = fn(&Cand) -> bool;
/// 尾部边界检查：参数是 payload 之后的剩余字节，返回 true 表示边界合法。
pub type AfterCheck = fn(&[u8]) -> bool;

/// `group` 取这个值表示「第一个参与匹配的捕获组」。
pub const FIRST_GROUP: usize = usize::MAX;

#[derive(Clone)]
pub struct Rule {
    pub id: Cow<'static, str>,
    pub category: Category,
    /// 从哪个保密等级开始生效。
    pub level: u8,
    pub desc: Cow<'static, str>,
    pub pattern: Cow<'static, str>,
    /// 打码的捕获组：0 = 整段匹配，`FIRST_GROUP` = 第一个参与匹配的组。
    pub group: usize,
    pub validator: Option<Validator>,
    pub after: Option<AfterCheck>,
    /// 是否避开保护区间（版本号、时间戳等）。
    pub protect: bool,
    /// 命中的值是否加入「已学习标识」，在第二遍中全文清洗。
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
    /// 内置规则构造器。
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

    /// 打码整段匹配。
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
