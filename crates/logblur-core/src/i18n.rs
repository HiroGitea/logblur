//! 多语言。英文是源语言和回退语言，内置简体中文；可以从外部目录加载更多语言或覆盖译文。
//!
//! 语言选择顺序：显式指定（`--lang`）> `LOGBLUR_LANG` > `LANGUAGE`（冒号分隔的列表）
//! > `LC_ALL` > `LC_MESSAGES` > `LANG` > 系统区域（调用方传入）> `en`。`C` / `POSIX` 视为英文。
//!
//! 语言文件是 TOML：表名和键名拼成点分键（`[error] cancelled = "…"` → `error.cancelled`），
//! `[meta] tag` / `name` 给出语言标签和本地名称。占位符写作 `{name}`，没有对应参数的 `{…}` 原样保留。
//! 外部语言文件目录（后者优先级更低）：`$LOGBLUR_LOCALE_DIR`、`$XDG_DATA_HOME/logblur/locales`
//!（或 `~/.local/share/logblur/locales`）、`/usr/local/share/logblur/locales`、`/usr/share/logblur/locales`。
//!
//! 机器可读的输出（JSON 报告的键、类别 id、配置键、退出码）不翻译。

use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// 内置语言文件。
const BUILTIN: &[(&str, &str)] = &[("en", include_str!("../locales/en.toml")), ("zh-CN", include_str!("../locales/zh-CN.toml"))];

#[derive(Debug, Clone)]
struct Catalog {
    tag: String,
    name: String,
    map: HashMap<String, String>,
}

#[derive(Debug)]
struct State {
    catalogs: Arc<Vec<Catalog>>,
    current: usize,
}

static STATE: RwLock<Option<Arc<State>>> = RwLock::new(None);

fn flatten(prefix: &str, table: &toml::Table, out: &mut HashMap<String, String>) {
    for (k, v) in table {
        let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match v {
            toml::Value::String(s) => {
                out.insert(key, s.clone());
            }
            toml::Value::Table(t) => flatten(&key, t, out),
            _ => {}
        }
    }
}

fn parse_catalog(hint: &str, text: &str) -> Option<Catalog> {
    let table: toml::Table = toml::from_str(text).ok()?;
    let mut map = HashMap::new();
    flatten("", &table, &mut map);
    let tag = map.get("meta.tag").cloned().unwrap_or_else(|| hint.to_string());
    let name = map.get("meta.name").cloned().unwrap_or_else(|| tag.clone());
    Some(Catalog { tag, name, map })
}

fn external_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(d) = std::env::var_os("LOGBLUR_LOCALE_DIR") {
        if !d.is_empty() {
            v.push(PathBuf::from(d));
        }
    }
    match std::env::var_os("XDG_DATA_HOME") {
        Some(d) if !d.is_empty() => v.push(PathBuf::from(d).join("logblur").join("locales")),
        _ => {
            if let Some(h) = std::env::var_os("HOME") {
                v.push(PathBuf::from(h).join(".local").join("share").join("logblur").join("locales"));
            }
        }
    }
    if cfg!(unix) {
        v.push(PathBuf::from("/usr/local/share/logblur/locales"));
        v.push(PathBuf::from("/usr/share/logblur/locales"));
    }
    v
}

fn load_all() -> Vec<Catalog> {
    let mut cats: Vec<Catalog> = BUILTIN.iter().filter_map(|(tag, text)| parse_catalog(tag, text)).collect();
    // 低优先级的目录先加载，高优先级的后加载覆盖
    for dir in external_dirs().into_iter().rev() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for p in files {
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            let hint = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let Some(c) = parse_catalog(&hint, &text) else { continue };
            match cats.iter_mut().find(|x| x.tag.eq_ignore_ascii_case(&c.tag)) {
                Some(existing) => {
                    existing.name = c.name;
                    existing.map.extend(c.map);
                }
                None => cats.push(c),
            }
        }
    }
    cats
}

/// `zh_CN.UTF-8@euro` → `zh-cn`；`C`、`POSIX` → `en`。
fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim();
    let s = s.split(['.', '@']).next().unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    if s.eq_ignore_ascii_case("c") || s.eq_ignore_ascii_case("posix") {
        return Some("en".into());
    }
    Some(s.replace('_', "-").to_ascii_lowercase())
}

fn find(cats: &[Catalog], raw: &str) -> Option<usize> {
    let want = normalize(raw)?;
    if let Some(i) = cats.iter().position(|c| c.tag.to_ascii_lowercase() == want) {
        return Some(i);
    }
    // 只有主语言相同也算（zh-TW、zh-Hans → zh-CN；en-GB → en）
    let primary = want.split('-').next().unwrap_or(&want).to_string();
    cats.iter().position(|c| c.tag.to_ascii_lowercase().split('-').next() == Some(primary.as_str()))
}

fn candidates(explicit: Option<&str>, system: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Some(e) = explicit {
        v.push(e.to_string());
    }
    if let Ok(e) = std::env::var("LOGBLUR_LANG") {
        v.push(e);
    }
    if let Ok(l) = std::env::var("LANGUAGE") {
        v.extend(l.split(':').filter(|s| !s.is_empty()).map(str::to_string));
    }
    for k in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(x) = std::env::var(k) {
            if !x.is_empty() {
                v.push(x);
            }
        }
    }
    if let Some(s) = system {
        v.push(s.to_string());
    }
    v
}

/// 初始化：加载语言文件并按优先级选择语言。可以重复调用。
pub fn init(explicit: Option<&str>, system_locale: Option<&str>) {
    let cats = load_all();
    let current = candidates(explicit, system_locale)
        .iter()
        .find_map(|c| find(&cats, c))
        .or_else(|| find(&cats, "en"))
        .unwrap_or(0);
    let st = State { catalogs: Arc::new(cats), current };
    *STATE.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(st));
}

fn state() -> Arc<State> {
    if let Some(s) = STATE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return s.clone();
    }
    init(None, None);
    STATE.read().unwrap_or_else(|e| e.into_inner()).as_ref().cloned().expect("i18n 已初始化")
}

/// 切换语言；没有这种语言时返回 false。
pub fn set_language(tag: &str) -> bool {
    let st = state();
    match find(&st.catalogs, tag) {
        Some(i) => {
            let new = State { catalogs: st.catalogs.clone(), current: i };
            *STATE.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(new));
            true
        }
        None => false,
    }
}

/// 当前语言标签，如 `en`、`zh-CN`。
pub fn language() -> String {
    let st = state();
    st.catalogs.get(st.current).map(|c| c.tag.clone()).unwrap_or_else(|| "en".into())
}

/// 可用语言：(标签, 本地名称)。
pub fn languages() -> Vec<(String, String)> {
    state().catalogs.iter().map(|c| (c.tag.clone(), c.name.clone())).collect()
}

fn lookup(st: &State, key: &str) -> Option<String> {
    st.catalogs
        .get(st.current)
        .and_then(|c| c.map.get(key))
        .or_else(|| st.catalogs.iter().find(|c| c.tag == "en").and_then(|c| c.map.get(key)))
        .cloned()
}

/// 翻译；找不到时返回键本身。
pub fn tr(key: &str) -> String {
    lookup(&state(), key).unwrap_or_else(|| key.to_string())
}

/// 翻译；找不到时返回 `default`。
pub fn tr_or(key: &str, default: &str) -> String {
    lookup(&state(), key).unwrap_or_else(|| default.to_string())
}

/// 翻译并填入命名参数。
pub fn trf(key: &str, args: &[(&str, &dyn Display)]) -> String {
    fill(&tr(key), args)
}

/// 把 `{name}` 替换成参数；没有对应参数的 `{…}` 原样保留。
pub fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('}') {
            Some(j) => {
                let name = &after[..j];
                match args.iter().find(|(n, _)| *n == name) {
                    Some((_, v)) => {
                        let _ = write!(out, "{v}");
                        rest = &after[j + 1..];
                    }
                    None => {
                        out.push('{');
                        rest = after;
                    }
                }
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// 翻译宏：`t!("error.cancelled")`、`t!("io.open", path = p.display())`。
#[macro_export]
macro_rules! t {
    ($key:expr $(,)?) => {
        $crate::i18n::tr($key)
    };
    ($key:expr, $($name:ident = $val:expr),+ $(,)?) => {
        $crate::i18n::trf($key, &[$((stringify!($name), &$val as &dyn ::std::fmt::Display)),+])
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn builtin(tag: &str) -> Catalog {
        let (t, text) = BUILTIN.iter().find(|(t, _)| *t == tag).expect("内置语言");
        parse_catalog(t, text).unwrap_or_else(|| panic!("{tag} 语言文件无法解析"))
    }

    #[test]
    fn builtin_catalogs_parse_and_match() {
        let en = builtin("en");
        let zh = builtin("zh-CN");
        let en_keys: BTreeSet<_> = en.map.keys().filter(|k| !k.starts_with("rule.")).collect();
        let zh_keys: BTreeSet<_> = zh.map.keys().filter(|k| !k.starts_with("rule.")).collect();
        let missing: Vec<_> = en_keys.difference(&zh_keys).collect();
        let extra: Vec<_> = zh_keys.difference(&en_keys).collect();
        assert!(missing.is_empty(), "zh-CN 缺少: {missing:?}");
        assert!(extra.is_empty(), "zh-CN 多出: {extra:?}");
    }

    #[test]
    fn every_rule_has_chinese_description() {
        let zh = builtin("zh-CN");
        for r in crate::rules::table::builtin() {
            assert!(zh.map.contains_key(&format!("rule.{}", r.id)), "zh-CN 缺少 rule.{}", r.id);
        }
    }

    #[test]
    fn config_templates_parse() {
        for tag in ["en", "zh-CN"] {
            let c = builtin(tag);
            let tpl = c.map.get("config.template").expect("模板");
            let fc: crate::config::FileConfig = toml::from_str(tpl).unwrap_or_else(|e| panic!("{tag} 模板: {e}"));
            let mut cfg = crate::config::JobConfig::default();
            cfg.apply(fc).unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn normalize_tags() {
        assert_eq!(normalize("zh_CN.UTF-8").as_deref(), Some("zh-cn"));
        assert_eq!(normalize("C").as_deref(), Some("en"));
        assert_eq!(normalize("en_US@euro").as_deref(), Some("en-us"));
        assert_eq!(normalize(""), None);
        let cats = vec![builtin("en"), builtin("zh-CN")];
        assert_eq!(find(&cats, "zh_TW.UTF-8"), Some(1));
        assert_eq!(find(&cats, "en_GB"), Some(0));
        assert_eq!(find(&cats, "fr_FR"), None);
    }

    #[test]
    fn fill_placeholders() {
        let n = 3;
        assert_eq!(fill("{a} and {b}", &[("a", &"x"), ("b", &n)]), "x and 3");
        assert_eq!(fill("keep {unknown} and [0-9]{10}", &[]), "keep {unknown} and [0-9]{10}");
        assert_eq!(fill("unclosed {", &[]), "unclosed {");
    }
}
