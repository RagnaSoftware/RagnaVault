//! Grobe Passwortstärke-Schätzung (0–4) für Anzeige und Sicherheitsbericht.
//! Bewusst konservativ: Wiederholungen und Folgen zählen kaum, bekannte Passwörter gar nicht.

use serde::Serialize;

const COMMON: &[&str] = &[
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "qwertz", "1234567",
    "111111", "123123", "abc123", "1234567890", "password1", "iloveyou", "000000", "passwort",
    "hallo", "hallo123", "schatz", "sommer", "letmein", "welcome", "willkommen", "monkey",
    "dragon", "master", "admin", "login", "test", "secret", "geheim", "qwerty123", "1q2w3e4r",
    "asdfgh", "asdf", "654321", "666666", "121212", "football", "fussball", "sunshine",
    "princess", "shadow", "superman", "trustno1", "hello", "freedom", "whatever", "passw0rd",
    "p@ssw0rd", "changeme", "default", "lol123", "killer", "computer",
];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    pub score: u8,
    pub bits: f64,
}

pub fn estimate(pw: &str) -> Strength {
    let chars: Vec<char> = pw.chars().collect();
    if chars.is_empty() {
        return Strength { score: 0, bits: 0.0 };
    }

    let lower = pw.to_lowercase();
    let stem = lower.trim_end_matches(|c: char| c.is_ascii_digit() || "!?.#*".contains(c));
    if COMMON.contains(&lower.as_str()) || (stem.chars().count() >= 4 && COMMON.contains(&stem)) {
        return Strength { score: 0, bits: 8.0 };
    }

    let has = |f: fn(&char) -> bool| chars.iter().any(f);
    let mut pool = 0u32;
    if has(|c| c.is_ascii_lowercase()) { pool += 26; }
    if has(|c| c.is_ascii_uppercase()) { pool += 26; }
    if has(|c| c.is_ascii_digit()) { pool += 10; }
    if has(|c| c.is_ascii_punctuation() || *c == ' ') { pool += 33; }
    if has(|c| !c.is_ascii()) { pool += 60; }

    // Wiederholte und aufeinanderfolgende Zeichen (aaa, abc, 123) tragen kaum Entropie bei.
    let mut effective = 1.0;
    for w in chars.windows(2) {
        let step = w[1] as i64 - w[0] as i64;
        effective += match step {
            0 => 0.2,
            -1 | 1 => 0.4,
            _ => 1.0,
        };
    }

    let bits = effective * f64::from(pool.max(1)).log2();
    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    };
    Strength { score, bits }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_obvious_cases() {
        assert_eq!(estimate("").score, 0);
        assert_eq!(estimate("password").score, 0);
        assert_eq!(estimate("Passwort123!").score, 0);
        assert_eq!(estimate("aaaaaaaaaaaa").score, 0);
        assert!(estimate("abcdefgh").score <= 1);
        assert!(estimate("Tr0ub4dor&3").score >= 2);
        assert_eq!(estimate("k8#Vq2!mZp$Lw9xR@n4T").score, 4);
        assert!(estimate("korrekt pferd batterie heftklammer").score >= 3);
    }
}
