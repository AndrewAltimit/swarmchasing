//! Text a model wrote into a parameter value: generation loops, and prose
//! with a small offline guess at its language (script, then common words;
//! no dictionaries, no models).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
}
