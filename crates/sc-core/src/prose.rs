//! Text a model wrote into a parameter value: generation loops, prose
//! with a small offline guess at its language (script, then common words;
//! no dictionaries, no models), and prose from one template in several
//! clusters ([`prompt_echo_pairs`]), a soft link that never scores or links.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// At most this many words of a value are read.
const MAX_WORDS: usize = 200;
/// A loop is a word or phrase repeated this many times in a row.
pub const LOOP_REPEATS: usize = 5;

/// Whether `v` holds one word (three or more characters, with a letter) or a
/// phrase of two or three words repeated [`LOOP_REPEATS`] times or more in a
/// row, ignoring case: what a model stuck in a generation loop writes. A run
/// of a short syllable (`na na na`) or one long word (`aaaa`) is not a loop,
/// and neither is a phrase that is itself one word repeated.
pub fn repeated_token(v: &str) -> bool {
    let w: Vec<&str> = v.split_whitespace().take(MAX_WORDS).collect();
    let same =
        |a: usize, b: usize, p: usize| (0..p).all(|k| w[a + k].eq_ignore_ascii_case(w[b + k]));
    for p in 1..=3 {
        for i in 0..w.len() {
            let block = &w[i..(i + p).min(w.len())];
            let ok = block.len() == p
                && block.iter().any(|t| t.chars().any(char::is_alphabetic))
                && if p == 1 {
                    block[0].chars().count() >= 3
                } else {
                    block.iter().any(|t| !t.eq_ignore_ascii_case(block[0]))
                };
            if !ok {
                continue;
            }
            let mut n = 1;
            while i + (n + 1) * p <= w.len() && same(i, i + n * p, p) {
                n += 1;
            }
            if n >= LOOP_REPEATS {
                return true;
            }
        }
    }
    false
}

/// A value is prose when it has at least this many words with letters.
pub const PROSE_MIN_WORDS: usize = 6;

/// Prose found in a cluster's parameter values ([`prose_stats`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Prose {
    /// Distinct prose values over the members.
    pub values: usize,
    /// Prose values per guessed language (ISO 639-1); values whose language
    /// is unclear are not counted here.
    pub languages: BTreeMap<String, usize>,
    /// Prose values whose language differs from the language of their
    /// target's country domain (`.de` German, `.jp` Japanese ...), where both
    /// are known.
    pub mismatched: usize,
}

impl Prose {
    pub fn is_empty(&self) -> bool {
        self.values == 0
    }
}

/// Whether `v` reads as prose: [`PROSE_MIN_WORDS`] or more words with
/// letters, most of its words; in Chinese, Japanese or Thai, which are
/// written without spaces, twice that many characters.
pub fn is_prose(v: &str) -> bool {
    let (mut words, mut lettered) = (0, 0);
    for w in v.split_whitespace().take(MAX_WORDS) {
        words += 1;
        if w.chars().any(char::is_alphabetic) {
            lettered += 1;
        }
    }
    // Scripts written without spaces: count characters, two per word.
    let unspaced = v
        .chars()
        .filter(|&c| matches!(c as u32, 0xe00..=0xe7f | 0x3040..=0x30ff | 0x4e00..=0x9fff))
        .count();
    (lettered >= PROSE_MIN_WORDS && lettered * 10 >= words * 7) || unspaced >= 2 * PROSE_MIN_WORDS
}

const STOPWORDS: &[(&str, &[&str])] = &[
    (
        "en",
        &[
            "the", "and", "of", "to", "is", "for", "with", "that", "on", "are", "this", "you",
            "what", "how",
        ],
    ),
    (
        "es",
        &[
            "el", "los", "las", "que", "y", "en", "por", "para", "con", "una", "es", "del", "como",
        ],
    ),
    (
        "fr",
        &[
            "le", "les", "des", "et", "est", "pour", "une", "dans", "qui", "sur", "pas", "du", "au",
        ],
    ),
    (
        "de",
        &[
            "der", "die", "das", "und", "ist", "nicht", "mit", "für", "ein", "eine", "zu", "von",
            "auf", "den",
        ],
    ),
    (
        "pt",
        &[
            "os", "as", "que", "e", "em", "para", "com", "uma", "não", "do", "da", "é", "dos",
        ],
    ),
    (
        "it",
        &[
            "il", "gli", "di", "che", "e", "per", "con", "una", "non", "è", "del", "della", "sono",
        ],
    ),
    (
        "nl",
        &[
            "het", "een", "van", "en", "is", "niet", "met", "voor", "op", "dat", "zijn", "de",
        ],
    ),
];

/// A guess at the language of `text`: its script, then for Latin script
/// the language whose common words it uses most (at least two of them).
/// `None` when unclear.
pub fn language(text: &str) -> Option<&'static str> {
    let mut counts = [0usize; 11];
    const NAMES: [&str; 11] = [
        "latin", "ru", "uk", "el", "he", "ar", "th", "hi", "ko", "ja", "zh",
    ];
    for c in text.chars() {
        let i = match c as u32 {
            0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f => 0,
            0x404 | 0x406 | 0x407 | 0x454 | 0x456 | 0x457 | 0x490 | 0x491 => 2,
            0x400..=0x4ff => 1,
            0x370..=0x3ff => 3,
            0x590..=0x5ff => 4,
            0x600..=0x6ff => 5,
            0xe00..=0xe7f => 6,
            0x900..=0x97f => 7,
            0xac00..=0xd7af | 0x1100..=0x11ff => 8,
            0x3040..=0x30ff => 9,
            0x4e00..=0x9fff => 10,
            _ => continue,
        };
        counts[i] += 1;
    }
    let letters: usize = counts.iter().sum();
    if letters == 0 {
        return None;
    }
    // Kana marks Japanese even beside Han; Ukrainian letters mark
    // Ukrainian among Cyrillic.
    if counts[9] > 0 && counts[9] + counts[10] >= letters / 2 {
        return Some("ja");
    }
    if counts[2] > 0 && counts[1] + counts[2] >= letters / 2 {
        return Some("uk");
    }
    let (top, n) = counts
        .iter()
        .enumerate()
        .max_by_key(|&(i, n)| (*n, std::cmp::Reverse(i)))?;
    if n * 2 < letters {
        return None;
    }
    if top != 0 {
        return Some(NAMES[top]);
    }
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    let mut best: Option<(&str, usize)> = None;
    let mut tie = false;
    for (lang, stop) in STOPWORDS {
        let n = words.iter().filter(|w| stop.contains(&w.as_str())).count();
        match best {
            Some((_, b)) if n == b => tie = true,
            Some((_, b)) if n < b => {}
            _ => {
                best = Some((lang, n));
                tie = false;
            }
        }
    }
    match best {
        Some((lang, n)) if n >= 2 && !tie => Some(lang),
        _ => None,
    }
}

/// The language a country-code domain's sites are usually written in, for
/// the countries with one clear language.
pub fn cctld_language(host: &str) -> Option<&'static str> {
    let tld = host.rsplit('.').next()?;
    Some(match tld {
        "de" | "at" => "de",
        "fr" => "fr",
        "es" | "mx" | "ar" | "cl" | "co" | "pe" => "es",
        "it" => "it",
        "nl" => "nl",
        "pt" | "br" => "pt",
        "ru" => "ru",
        "ua" => "uk",
        "gr" => "el",
        "il" => "he",
        "sa" | "eg" | "ae" => "ar",
        "th" => "th",
        "jp" => "ja",
        "kr" => "ko",
        "cn" | "tw" => "zh",
        "uk" | "au" | "nz" | "ie" => "en",
        _ => return None,
    })
}

/// Prose over records: each record's parameter values with its target host.
pub fn prose_stats<'a>(
    records: impl IntoIterator<Item = (Option<&'a str>, Vec<&'a str>)>,
) -> Prose {
    let mut out = Prose::default();
    let mut seen = std::collections::BTreeSet::new();
    for (host, values) in records {
        let want = host.and_then(cctld_language);
        for v in values {
            if !is_prose(v) || !seen.insert(v) {
                continue;
            }
            out.values += 1;
            if let Some(lang) = language(v) {
                *out.languages.entry(lang.to_string()).or_default() += 1;
                if want.is_some_and(|w| w != lang) {
                    out.mismatched += 1;
                }
            }
        }
    }
    out
}

/// Prompt echo settings (`[prompt_echo]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptEchoOptions {
    /// Words a prose value must keep once slotted.
    pub min_words: usize,
    /// Estimated similarity of two values' word shingles that makes them
    /// one template, when a MinHash band agrees.
    pub min_similarity: f64,
    /// A template carried by more senders than this (clusters above noise,
    /// and records outside them) ties none.
    pub max_holders: usize,
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs compared.
    pub fdr: f64,
    /// Published query lists (dork lists, benchmark prompts): a template
    /// matching one of these is public and ties none. `{site}` stands for
    /// the target's name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_templates: Vec<String>,
}

impl Default for PromptEchoOptions {
    fn default() -> Self {
        Self {
            min_words: 6,
            min_similarity: 0.6,
            max_holders: 5,
            max_chance: 0.01,
            fdr: 0.05,
            common_templates: Vec::new(),
        }
    }
}

/// Pairs kept, most unlikely first.
const MAX_ECHO_PAIRS: usize = 200;
/// Earlier values in one MinHash band each value is compared with.
const BAND_COMPARE: usize = 64;
/// The word `{site}` becomes in a published template, slotted as a target
/// name is.
pub(crate) const COMMON_SITE: &str = "commonsiteslot";
/// Characters of slotted template a pair shows.
const ECHO_EXCERPT: usize = 80;

/// Two clusters writing prose from one template beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptEchoPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// Usable templates the two share.
    pub templates: usize,
    /// The start of the rarest one, slotted (target names, numbers, URLs
    /// and identifiers replaced).
    pub excerpt: String,
    /// Clusters above noise writing it, the comparable clusters (those
    /// writing prose at all), and records outside them carrying it.
    pub holders: usize,
    pub clusters: usize,
    pub outside: usize,
    /// Its base rate: other holders and outside records over the other
    /// comparable clusters.
    pub base_rate: f64,
    /// The chance that an unrelated cluster shares as many template
    /// families with one side as the other does, each family at its base
    /// rate (a Poisson-binomial tail); the larger of the two sides.
    pub chance: f64,
    /// Pairs compared, and pairs this unlikely expected among them.
    pub tested: usize,
    pub expected_pairs: f64,
}

impl PromptEchoPair {
    pub fn detail(&self) -> String {
        format!(
            "{} prose template(s) in both, the rarest in {} of {} clusters writing prose and {} record(s) outside them, a base rate of {:.1e} (chance {:.1e}; {:.2} such pairs expected among {} compared): one prompt may drive both: \"{}\"",
            self.templates,
            self.holders,
            self.clusters,
            self.outside,
            self.base_rate,
            self.chance,
            self.expected_pairs,
            self.tested,
            self.excerpt
        )
    }
}

/// Who carries a prose value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Holder {
    /// A cluster above noise, by position.
    Cluster(usize),
    /// A record outside them, by index.
    Outside(usize),
    /// A published template from the rules.
    Common,
}

/// A record's parameter values: its layers' when kept, else its URL's.
pub(crate) fn param_values(r: &crate::analyze::ObsResult) -> Vec<String> {
    if r.layers.is_empty() {
        crate::weburl::WebUrl::parse(&r.obs.url)
            .map(|u| u.query_pairs().into_iter().map(|(_, v)| v).collect())
            .unwrap_or_default()
    } else {
        r.layers
            .iter()
            .flat_map(|l| l.params.iter().map(|(_, v)| v.clone()))
            .collect()
    }
}

/// Words of a target host that name it, slotted out of prose: the host
/// and its labels of three letters or more, the top-level one and `www`
/// aside, and for a label with hyphens its parts of three letters or more
/// and the parts joined (`acme-corp` gives `acme`, `corp` and `acmecorp`),
/// as prose writes the name.
pub(crate) fn host_words(host: Option<&str>) -> Vec<String> {
    let Some(h) = host else {
        return Vec::new();
    };
    let labels: Vec<&str> = h.split('.').collect();
    let mut out = vec![h.to_string()];
    for l in &labels[..labels.len().saturating_sub(1)] {
        if l.len() < 3 || *l == "www" {
            continue;
        }
        out.push(l.to_string());
        if l.contains('-') {
            out.extend(l.split('-').filter(|p| p.len() >= 3).map(str::to_string));
            out.push(l.replace('-', ""));
        }
    }
    out
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

fn union(parent: &mut [usize], x: usize, y: usize) {
    let (a, b) = (find(parent, x), find(parent, y));
    if a != b {
        parent[a.max(b)] = a.min(b);
    }
}

/// Pairs of clusters above noise whose prose parameter values come from one
/// template beyond chance, most unlikely first, and the family's
/// multiplicity budget. Each prose value of `min_words` slotted words
/// ([`crate::platform::text::slot_tokens`], the target host's words as
/// slots) is sketched; two values are one template when their slotted
/// templates are equal, or a MinHash band agrees and the estimated
/// similarity reaches `min_similarity`. A template matching one of
/// `common_templates` is public and ties none; one carried by more than
/// `max_holders` senders (clusters, and records outside them) or
/// `max_shared` clusters is common. A template's base rate is its other
/// holders and outside records over the other clusters writing prose.
/// Templates carried by the same clusters count as one family, at its
/// highest rate, and a pair's chance is that an unrelated cluster shares as
/// many of one side's families as the other does, the larger of the two
/// sides, as for scaffold lineage: the rarest shared template's rate
/// squared reads the chance of that one template, not of any of the many a
/// cluster writes, and lets a few unrelated clusters copying one prompt
/// pass among a few dozen writers. Kept at `max_chance`, then cut at false
/// discovery rate `fdr`.
pub(crate) fn prompt_echo_pairs(
    clusters: &[crate::analyze::Cluster],
    results: &[crate::analyze::ObsResult],
    max_shared: usize,
    opts: &PromptEchoOptions,
) -> (Vec<PromptEchoPair>, crate::chance::TestFamily) {
    use crate::chance::TestFamily;
    use crate::platform::text::{BANDS, TextSketch, slot_tokens, token_sketch};
    let family = "prompt_echo";
    let shown: Vec<&crate::analyze::Cluster> = clusters
        .iter()
        .filter(|c| c.tier > crate::model::Tier::Noise)
        .collect();
    if shown.len() < 3 {
        return (Vec::new(), TestFamily::cut(family, &[], 0, opts.fdr));
    }
    let mut owner: Vec<Option<usize>> = vec![None; results.len()];
    for (ci, c) in shown.iter().enumerate() {
        for &m in &c.members {
            owner[m] = Some(ci);
        }
    }
    let mut nodes: Vec<(Holder, TextSketch)> = Vec::new();
    let min_words = opts.min_words.max(2);
    let mut seen: BTreeSet<(Holder, u64, Vec<u32>)> = BTreeSet::new();
    let mut add = |holder: Holder, tokens: Vec<String>, nodes: &mut Vec<(Holder, TextSketch)>| {
        if tokens.len() < min_words {
            return;
        }
        if let Some(sk) = token_sketch(&tokens)
            && seen.insert((holder, sk.skeleton, sk.minhash.clone()))
        {
            nodes.push((holder, sk));
        }
    };
    for (i, r) in results.iter().enumerate() {
        let values: Vec<String> = param_values(r)
            .into_iter()
            .filter(|v| is_prose(v))
            .collect();
        if values.is_empty() {
            continue;
        }
        let words = host_words(r.target_host.as_deref());
        let ctx: Vec<&str> = words.iter().map(String::as_str).collect();
        let holder = owner[i].map_or(Holder::Outside(i), Holder::Cluster);
        for v in values {
            add(holder, slot_tokens(&v, &ctx), &mut nodes);
        }
    }
    let comparable = nodes
        .iter()
        .filter_map(|(h, _)| match h {
            Holder::Cluster(c) => Some(*c),
            _ => None,
        })
        .collect::<BTreeSet<usize>>()
        .len();
    if comparable < 2 {
        return (Vec::new(), TestFamily::cut(family, &[], 0, opts.fdr));
    }
    // `{site}` in a published template stands for the target's name.
    for t in &opts.common_templates {
        let t = t.replace("{site}", COMMON_SITE);
        add(Holder::Common, slot_tokens(&t, &[COMMON_SITE]), &mut nodes);
    }

    // Templates: values joined by an equal slotted template, or by a band
    // and their estimated similarity.
    let mut parent: Vec<usize> = (0..nodes.len()).collect();
    let mut by_skeleton: BTreeMap<u64, usize> = BTreeMap::new();
    let mut by_band: BTreeMap<(usize, u64), Vec<usize>> = BTreeMap::new();
    for (i, (_, sk)) in nodes.iter().enumerate() {
        match by_skeleton.get(&sk.skeleton) {
            Some(&j) => union(&mut parent, i, j),
            None => {
                by_skeleton.insert(sk.skeleton, i);
            }
        }
        for b in 0..BANDS {
            let Some(h) = sk.band(b) else { continue };
            let earlier = by_band.entry((b, h)).or_default();
            for &j in earlier.iter().rev().take(BAND_COMPARE) {
                if find(&mut parent, i) != find(&mut parent, j)
                    && sk.similarity(&nodes[j].1) >= opts.min_similarity
                {
                    union(&mut parent, i, j);
                }
            }
            earlier.push(i);
        }
    }
    // Per template: its clusters, its outside records, whether it is public,
    // and a node to show.
    #[derive(Default)]
    struct Group {
        clusters: BTreeSet<usize>,
        outside: BTreeSet<usize>,
        common: bool,
        shown: Option<usize>,
    }
    let mut groups: BTreeMap<usize, Group> = BTreeMap::new();
    for (i, (holder, _)) in nodes.iter().enumerate() {
        let root = find(&mut parent, i);
        let g = groups.entry(root).or_default();
        match *holder {
            Holder::Cluster(c) => {
                g.clusters.insert(c);
                g.shown.get_or_insert(i);
            }
            Holder::Outside(r) => {
                g.outside.insert(r);
            }
            Holder::Common => g.common = true,
        }
    }
    let usable = |g: &Group| {
        !g.common
            && g.clusters.len() >= 2
            && g.clusters.len() <= max_shared
            && g.clusters.len() + g.outside.len() <= opts.max_holders
    };
    let rate = |g: &Group| {
        ((g.clusters.len() - 1 + g.outside.len()) as f64 / (comparable - 1).max(1) as f64).min(1.0)
    };
    let mut shared: BTreeMap<(usize, usize), Vec<&Group>> = BTreeMap::new();
    for g in groups.values().filter(|g| usable(g)) {
        let ids: Vec<usize> = g.clusters.iter().copied().collect();
        for (n, &x) in ids.iter().enumerate() {
            for &y in &ids[n + 1..] {
                shared.entry((x, y)).or_default().push(g);
            }
        }
    }
    let tested = shared.len();
    // Each cluster's usable templates as families: templates carried by
    // the same clusters are one prompt seen several times and count once,
    // at the family's highest base rate.
    let mut families: Vec<BTreeMap<Vec<usize>, f64>> = vec![BTreeMap::new(); shown.len()];
    for g in groups.values().filter(|g| usable(g)) {
        let ids: Vec<usize> = g.clusters.iter().copied().collect();
        for &c in &ids {
            let e = families[c].entry(ids.clone()).or_insert(0.0);
            *e = e.max(rate(g));
        }
    }
    // Conditioned on one side's families, the chance that an unrelated
    // cluster meets it in as many of them as the other does.
    let both = |c: usize, o: usize| {
        crate::scaffold::family_chance(
            families[c].iter().map(|(ids, r)| (ids.as_slice(), *r)),
            c,
            o,
        )
    };
    let mut out = Vec::new();
    for ((x, y), gs) in shared {
        let Some(rarest) = gs.iter().min_by(|p, q| rate(p).total_cmp(&rate(q))) else {
            continue;
        };
        let r = rate(rarest);
        let chance = both(x, y).max(both(y, x));
        if chance > opts.max_chance {
            continue;
        }
        let excerpt = rarest
            .shown
            .map(|i| nodes[i].1.excerpt.chars().take(ECHO_EXCERPT).collect())
            .unwrap_or_default();
        out.push(PromptEchoPair {
            a: shown[x].id.clone(),
            b: shown[y].id.clone(),
            templates: gs.len(),
            excerpt,
            holders: rarest.clusters.len(),
            clusters: comparable,
            outside: rarest.outside.len(),
            base_rate: r,
            chance,
            tested,
            expected_pairs: chance * tested as f64,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let fam = TestFamily::cut(family, &ps, tested, opts.fdr);
    out.retain(|p| fam.keeps(p.chance));
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_ECHO_PAIRS);
    (out, fam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prose_and_its_language() {
        for (v, lang) in [
            (
                "what is the population of the largest city in this region",
                Some("en"),
            ),
            (
                "cuál es la población de la ciudad más grande para el año",
                Some("es"),
            ),
            (
                "quelle est la population de la plus grande ville dans le pays",
                Some("fr"),
            ),
            (
                "wie viele Einwohner hat die größte Stadt und das Land",
                Some("de"),
            ),
            (
                "какова численность населения самого большого города страны",
                Some("ru"),
            ),
            (
                "яка чисельність населення найбільшого міста країни зараз",
                Some("uk"),
            ),
            (
                "この地域で最も大きな都市の人口は何人ですか 教えて ください 今 すぐ",
                Some("ja"),
            ),
            ("lorem ipsum dolor sit amet consectetur adipiscing", None),
        ] {
            assert!(is_prose(v), "{v}");
            assert_eq!(language(v), lang, "{v}");
        }
        for v in ["population", "a b", "1 2 3 4 5 6 7 8", "id=5&x=7", ""] {
            assert!(!is_prose(v), "{v}");
        }
    }

    #[test]
    fn prose_against_the_target_country() {
        let p = prose_stats([
            (
                Some("www.stadt.example.de"),
                vec!["what is the population of the largest city in this region"],
            ),
            (
                Some("www.ville.fr"),
                vec![
                    "quelle est la population de la plus grande ville dans le pays",
                    "x",
                ],
            ),
            (
                Some("data.example"),
                vec!["what is the population of the largest city in this region"],
            ),
        ]);
        assert_eq!(p.values, 2, "{p:?}");
        assert_eq!(p.languages.get("en"), Some(&1));
        assert_eq!(p.languages.get("fr"), Some(&1));
        assert_eq!(p.mismatched, 1);
        assert_eq!(cctld_language("a.example.jp"), Some("ja"));
        assert_eq!(cctld_language("a.example"), None);
    }

    #[test]
    fn target_names_are_slotted_as_prose_writes_them() {
        use crate::platform::text::slot_tokens;
        let slotted = |host: &str, v: &str| {
            let words = host_words(Some(host));
            let ctx: Vec<&str> = words.iter().map(String::as_str).collect();
            slot_tokens(v, &ctx).join(" ")
        };
        let want = "list every staff page on <user> site and its login form";
        for (host, v) in [
            (
                "www.acme-corp.example",
                "list every staff page on Acme Corp site and its login form",
            ),
            (
                "www.acme-corp.example",
                "list every staff page on AcmeCorp's site and its login form",
            ),
            (
                "shop.brightway.example",
                "list every staff page on brightway\u{2019}s site and its login form",
            ),
            (
                "shop.brightway.example",
                "list every staff page on brightway's site and its login form",
            ),
        ] {
            let t = slotted(host, v);
            assert_eq!(t, want, "{host}: {v}");
        }
        // Other possessives stay words as written.
        let other = slotted("www.acme-corp.example", "the company's own staff list page");
        assert!(other.contains("company's"), "{other}");
    }

    #[test]
    fn loops_and_near_misses() {
        for v in [
            "building permit permit permit permit permit permit records",
            "latest news latest news latest news latest news latest news",
            "Find the The THE the the the end",
            "a b c a b c a b c a b c a b c",
        ] {
            assert!(repeated_token(v), "{v}");
        }
        for v in [
            "na na na na na na na na batman",
            "aaaaaaaaaaaaaaaa test",
            "hey hey hey hey",
            "1 1 1 1 1 1 1",
            "the quick brown fox jumps over the lazy dog",
            "",
        ] {
            assert!(!repeated_token(v), "{v}");
        }
    }

    const VOCAB: [&str; 40] = [
        "river", "mountain", "garden", "violin", "engine", "harbor", "pepper", "lantern", "meadow",
        "copper", "falcon", "orchard", "glacier", "pillow", "saddle", "thunder", "velvet",
        "walnut", "candle", "desert", "feather", "goblet", "hammer", "island", "jacket", "kettle",
        "ladder", "marble", "needle", "oyster", "parrot", "quiver", "ribbon", "spider", "timber",
        "umbrella", "vessel", "window", "yogurt", "zephyr",
    ];

    const SITES: [&str; 6] = [
        "alphacorp",
        "brightway",
        "cobaltinc",
        "dunmore",
        "everleaf",
        "foxglen",
    ];

    /// `echo` clusters searching their own site with one prompt's query,
    /// and `others` clusters each writing its own prose.
    fn echo_records(echo: usize, others: usize) -> Vec<crate::model::Observation> {
        let t0 = 1_791_000_000;
        let inbox = |n: usize| format!("{n:08x}-3333-4c2a-9a55-3f2e1d0c9b8a");
        let mut obs = Vec::new();
        let mut push = |id: String, t: i64, host: String, q: String, n: usize| {
            obs.push(crate::model::Observation {
                id,
                ts: t,
                url: format!(
                    "https://{host}/search?id=1%27%20OR%201=1--&q={}&hook=https://webhook.site/{}",
                    q.replace(' ', "%20"),
                    inbox(n)
                ),
                ..Default::default()
            });
        };
        for (c, &site) in SITES.iter().enumerate().take(echo) {
            for k in 0..2 {
                push(
                    format!("e{c}{k}"),
                    t0 + c as i64 * 86_400 + k * 60,
                    format!("www.{site}.example"),
                    format!(
                        "find the staff login portal for {site} and list every exposed admin page"
                    ),
                    c,
                );
            }
        }
        for b in 0..others {
            // Eight words of the vocabulary in an order of its own.
            let mut seed = b as u64 * 2_654_435_761 + 1;
            let mut pool: Vec<&str> = VOCAB.to_vec();
            let words: Vec<&str> = (0..8)
                .map(|_| {
                    seed = seed
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    pool.remove((seed >> 33) as usize % pool.len())
                })
                .collect();
            for k in 0..2 {
                push(
                    format!("o{b}{k}"),
                    t0 + (b as i64 + 20) * 86_400 + k * 60,
                    format!("h{k}.other{b}.example"),
                    words.join(" "),
                    100 + b,
                );
            }
        }
        obs
    }

    #[test]
    fn one_prompt_across_clusters_is_an_echo_pair() {
        let rules = crate::rules::Rules::default_rules();
        let a = crate::analyze::analyze(echo_records(2, 150), &rules);
        assert_eq!(a.clusters.len(), 152, "{}", a.clusters.len());
        let p = &a.prompt_echo_pairs;
        assert_eq!(p.len(), 1, "{p:?}");
        let rate = 1.0 / 151.0;
        for x in p {
            assert_eq!(
                (x.holders, x.clusters, x.outside, x.tested),
                (2, 152, 0, 1),
                "{x:?}"
            );
            assert!((x.base_rate - rate).abs() < 1e-12, "{x:?}");
            assert!((x.chance - rate).abs() < 1e-12, "{x:?}");
            assert!(
                x.excerpt
                    .starts_with("find the staff login portal for <user>"),
                "{}",
                x.excerpt
            );
            assert!(!x.detail().contains("alphacorp"), "{}", x.detail());
        }
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::PromptEcho),
            "{:?}",
            a.soft_links
        );
        let f = a.multiplicity.iter().find(|f| f.family == "prompt_echo");
        assert_eq!(f.map(|f| (f.kept, f.tested)), Some((1, 1)), "{f:?}");

        // A published query ties nobody.
        let mut rules = crate::rules::Rules::default_rules();
        rules.set.prompt_echo.common_templates =
            vec!["Find the staff login portal for {site} and list every exposed admin page".into()];
        let b = crate::analyze::analyze(echo_records(2, 150), &rules);
        assert!(b.prompt_echo_pairs.is_empty(), "{:?}", b.prompt_echo_pairs);
        // Nor does one prompt three clusters copy among a few dozen writing
        // prose: each meets the others at a base rate of 2 in 42, though
        // that rate squared is under the limit.
        let v = crate::analyze::analyze(echo_records(3, 40), &crate::rules::Rules::default_rules());
        assert!(v.prompt_echo_pairs.is_empty(), "{:?}", v.prompt_echo_pairs);
        // Nor does one six clusters write.
        let c = crate::analyze::analyze(echo_records(6, 40), &crate::rules::Rules::default_rules());
        assert!(c.prompt_echo_pairs.is_empty(), "{:?}", c.prompt_echo_pairs);
    }
}
