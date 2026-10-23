//! Merging of overlapping hits: overlapping ranges are unioned (never masking less), and the category is taken from
//! the longest of the hits (the higher-priority one on ties), so a hostname inside a URL merges into a single `[URL]`.

use super::Found;

/// `prio`: a lower value means higher priority.
pub fn resolve(found: &mut Vec<Found>, prio: impl Fn(&Found) -> u32) {
    if found.len() <= 1 {
        return;
    }
    found.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)).then(prio(a).cmp(&prio(b))));
    let mut out: Vec<Found> = Vec::with_capacity(found.len());
    // (length, priority) of the "representative hit" in each merged range
    let mut best: Vec<(usize, u32)> = Vec::with_capacity(found.len());
    for f in found.drain(..) {
        let len = f.end - f.start;
        let p = prio(&f);
        if let Some(last) = out.last_mut()
            && f.start < last.end
        {
            last.end = last.end.max(f.end);
            let b = best.last_mut().expect("kept in sync with out");
            if len > b.0 || (len == b.0 && p < b.1) {
                *b = (len, p);
                last.category = f.category;
                last.rule = f.rule;
            }
            continue;
        }
        best.push((len, p));
        out.push(f);
    }
    *found = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;

    fn f(s: usize, e: usize, c: Category, r: u16) -> Found {
        Found { start: s, end: e, category: c, rule: r }
    }

    #[test]
    fn merges_overlaps() {
        let mut v = vec![f(10, 20, Category::Hostname, 5), f(0, 30, Category::Url, 9), f(40, 45, Category::Ipv4, 1)];
        resolve(&mut v, |x| x.rule as u32);
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].start, v[0].end, v[0].category), (0, 30, Category::Url));
        assert_eq!((v[1].start, v[1].end), (40, 45));
    }

    #[test]
    fn keeps_touching_separate() {
        let mut v = vec![f(0, 5, Category::Email, 1), f(5, 9, Category::Ipv4, 2)];
        resolve(&mut v, |x| x.rule as u32);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn equal_length_prefers_priority() {
        let mut v = vec![f(0, 8, Category::Email, 7), f(0, 8, Category::Password, 2)];
        resolve(&mut v, |x| x.rule as u32);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].category, Category::Password);
    }
}
