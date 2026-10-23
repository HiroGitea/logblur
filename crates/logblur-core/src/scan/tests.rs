//! Rule fixture tests (data in tests/fixtures/rules.toml) and engine unit tests.

use std::collections::HashSet;

use serde::Deserialize;

use super::*;
use crate::category::Counts;
use crate::config::{JobConfig, MaskMode};

#[derive(Deserialize)]
struct Fixtures {
    case: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    level: u8,
    input: String,
    #[serde(default)]
    masked: Vec<String>,
    #[serde(default)]
    kept: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    keep_private_ips: bool,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

fn cfg_for(c: &Case, mask: MaskMode) -> JobConfig {
    JobConfig {
        level: c.level,
        mask,
        keep_private_ips: c.keep_private_ips,
        allow: c.allow.clone(),
        deny: c.deny.clone(),
        salt: Some("test-salt".into()),
        ..Default::default()
    }
}

fn is_masked(s: &str) -> bool {
    s.chars().all(|ch| ch == '░' || ch == '\n' || ch == '\r')
}

#[test]
fn rule_fixtures() {
    let fx: Fixtures = toml::from_str(include_str!("../../tests/fixtures/rules.toml")).expect("夹具文件应能解析");
    assert!(fx.case.len() >= 40);
    let mut failures = Vec::new();
    for c in &fx.case {
        let engine = Engine::new(&cfg_for(c, MaskMode::Tag)).expect("引擎");
        let out = engine.scrub_str(&c.input, &mut Counts::default());
        for m in &c.masked {
            if out.contains(m.as_str()) {
                failures.push(format!("[{}] 仍包含 {m:?}\n    {out}", c.name));
            }
        }
        for k in &c.kept {
            if !out.contains(k.as_str()) {
                failures.push(format!("[{}] 误删了 {k:?}\n    {out}", c.name));
            }
        }
        for t in &c.tags {
            if !out.contains(&format!("[{t}]")) {
                failures.push(format!("[{}] 缺少标签 [{t}]\n    {out}", c.name));
            }
        }

        // block 模式：字符数不变；再扫描一遍只会命中已经打码的部分
        let block = Engine::new(&cfg_for(c, MaskMode::Block)).expect("引擎");
        let masked = block.scrub_str(&c.input, &mut Counts::default());
        if masked.chars().count() != c.input.chars().count() {
            failures.push(format!("[{}] block 模式改变了字符数", c.name));
        }
        let mut again = Vec::new();
        block.find(masked.as_bytes(), &mut again);
        for f in again {
            let text = String::from_utf8_lossy(&masked.as_bytes()[f.start..f.end]).into_owned();
            if !is_masked(&text) {
                failures.push(format!("[{}] 再次扫描命中 {text:?}（{}）", c.name, block.rule_id(f.rule)));
            }
        }
    }
    assert!(failures.is_empty(), "{} 处失败：\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn every_builtin_rule_compiles_at_level_4_with_timestamps() {
    let cfg = JobConfig { level: 4, enable: vec![Category::Timestamp], ..Default::default() };
    let e = Engine::new(&cfg).expect("所有规则都应能编译");
    assert_eq!(e.active_rule_count(), crate::rules::table::builtin().len());
}

#[test]
fn rule_ids_are_unique() {
    let mut seen = HashSet::new();
    for r in crate::rules::table::builtin() {
        assert!(seen.insert(r.id.to_string()), "重复的规则 id {}", r.id);
    }
}

#[test]
fn learned_identifiers_are_masked_everywhere() {
    let cfg = JobConfig { level: 3, mask: MaskMode::Tag, ..Default::default() };
    let mut e = Engine::new(&cfg).unwrap();
    let mut set = HashSet::new();
    e.learn(
        b"Oct 23 11:12:13 alice-pc sshd[1]: Accepted publickey for alice from 203.0.113.5 port 22 ssh2\n",
        &mut set,
    );
    assert!(set.contains(&(Category::Hostname, "alice-pc".to_string())));
    assert!(set.contains(&(Category::Username, "alice".to_string())));
    e.set_learned(set).unwrap();
    let out = e.scrub_str("backup of alice-pc finished for ALICE; malice and alicex unchanged", &mut Counts::default());
    assert_eq!(out, "backup of [HOST] finished for [USER]; malice and alicex unchanged");
}

#[test]
fn generic_names_are_not_learned() {
    let cfg = JobConfig::default();
    let mut e = Engine::new(&cfg).unwrap();
    e.set_learned([(Category::Hostname, "debian".to_string()), (Category::Username, "ab".to_string())]).unwrap();
    assert_eq!(e.learned_counts().iter().sum::<usize>(), 0);
}

#[test]
fn scrubs_entry_names() {
    let cfg = JobConfig::default();
    let e = Engine::new(&cfg).unwrap();
    let mut c = Counts::default();
    assert_eq!(e.scrub_name("home/alice/.bash_history", &mut c), "home/░░░░░/.bash_history");
    assert_eq!(e.scrub_name("var/log/syslog", &mut c), "var/log/syslog");
    assert_eq!(c.total(), 1);
}

#[test]
fn remove_mode_uses_tags_for_names() {
    let cfg = JobConfig { mask: MaskMode::Remove, ..Default::default() };
    let e = Engine::new(&cfg).unwrap();
    assert_eq!(e.scrub_name("home/alice/x.log", &mut Counts::default()), "home/[USER]/x.log");
}

#[test]
fn pseudonyms_are_stable_with_salt() {
    let cfg = JobConfig { mask: MaskMode::Pseudo, salt: Some("s".into()), ..Default::default() };
    let a = Engine::new(&cfg).unwrap().scrub_str("from 203.0.113.5 and 203.0.113.5", &mut Counts::default());
    let b = Engine::new(&cfg).unwrap().scrub_str("peer 203.0.113.5", &mut Counts::default());
    let tok = a.split_whitespace().nth(1).unwrap().to_string();
    assert!(tok.starts_with("IP_"));
    assert_eq!(a, format!("from {tok} and {tok}"));
    assert_eq!(b, format!("peer {tok}"));
}

#[test]
fn custom_rules() {
    let cfg = JobConfig {
        level: 1,
        mask: MaskMode::Tag,
        custom_rules: vec![
            crate::config::CustomRule {
                id: "order".into(),
                pattern: "ORD-[0-9]{10}".into(),
                group: None,
                category: None,
                level: None,
            },
            crate::config::CustomRule {
                id: "emp".into(),
                pattern: "(?i)emp_id=([A-Z0-9]{6,})".into(),
                group: None,
                category: Some(Category::Username),
                level: Some(3),
            },
        ],
        ..Default::default()
    };
    let e = Engine::new(&cfg).unwrap();
    // emp 规则属于第 3 级的类别，在第 1 级不启用
    assert_eq!(e.scrub_str("ORD-0123456789 emp_id=AB12345", &mut Counts::default()), "[REDACTED] emp_id=AB12345");
    let cfg3 = JobConfig { level: 3, ..cfg };
    let e3 = Engine::new(&cfg3).unwrap();
    assert_eq!(e3.scrub_str("emp_id=AB12345", &mut Counts::default()), "emp_id=[USER]");
}

#[test]
fn counts_by_category() {
    let cfg = JobConfig { level: 3, ..Default::default() };
    let e = Engine::new(&cfg).unwrap();
    let mut c = Counts::default();
    e.scrub_str("a 203.0.113.1 b 203.0.113.2 c 52:54:00:12:34:56", &mut c);
    assert_eq!(c.0[Category::Ipv4.index()], 2);
    assert_eq!(c.0[Category::Mac.index()], 1);
}
