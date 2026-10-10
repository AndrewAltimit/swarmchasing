//! Text a model wrote into a parameter value: generation loops.

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

#[cfg(test)]
mod tests {
    use super::*;

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
