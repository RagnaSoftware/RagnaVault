//! Passwort-Generator ohne Modulo-Bias (Rejection Sampling über OsRng).

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    #[serde(default)]
    pub avoid_ambiguous: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    pub password: String,
    pub entropy_bits: f64,
}

/// Gleichverteilte Zahl in `0..n`. Werte oberhalb des größten Vielfachen von `n` werden verworfen,
/// damit kleine Reste nicht häufiger gezogen werden.
fn uniform(n: u32) -> u32 {
    assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let r = OsRng.next_u32();
        if r < zone {
            return r % n;
        }
    }
}

pub fn generate(opts: &GenOptions) -> Result<Generated> {
    if !(4..=128).contains(&opts.length) {
        return Err(Error::invalid("Länge muss zwischen 4 und 128 liegen"));
    }
    let filter = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !opts.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    };
    let classes: Vec<Vec<char>> = [
        (opts.lower, LOWER),
        (opts.upper, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| filter(set))
    .collect();
    if classes.is_empty() {
        return Err(Error::invalid("Mindestens eine Zeichenart auswählen"));
    }

    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let pick = |set: &[char]| set[uniform(set.len() as u32) as usize];

    // Je ein Zeichen aus jeder gewählten Klasse, Rest aus dem Gesamtpool, dann mischen.
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(classes.iter().map(|c| pick(c)).collect());
    while chars.len() < opts.length {
        chars.push(pick(&pool));
    }
    for i in (1..chars.len()).rev() {
        let j = uniform(i as u32 + 1) as usize;
        chars.swap(i, j);
    }

    Ok(Generated {
        password: chars.iter().collect(),
        entropy_bits: opts.length as f64 * (pool.len() as f64).log2(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(length: usize) -> GenOptions {
        GenOptions { length, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: false }
    }

    #[test]
    fn respects_length_and_classes() {
        for _ in 0..200 {
            let p = generate(&opts(12)).unwrap().password;
            assert_eq!(p.chars().count(), 12);
            assert!(p.chars().any(|c| LOWER.contains(c)));
            assert!(p.chars().any(|c| UPPER.contains(c)));
            assert!(p.chars().any(|c| DIGITS.contains(c)));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn avoids_ambiguous() {
        let o = GenOptions { avoid_ambiguous: true, ..opts(128) };
        for _ in 0..50 {
            assert!(!generate(&o).unwrap().password.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn uniform_stays_in_range_and_covers_it() {
        let mut seen = [false; 7];
        for _ in 0..2000 {
            seen[uniform(7) as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn rejects_bad_options() {
        assert!(generate(&opts(2)).is_err());
        let none = GenOptions { lower: false, upper: false, digits: false, symbols: false, ..opts(16) };
        assert!(generate(&none).is_err());
    }
}
