//! TOTP nach RFC 6238 und Parsing von otpauth://-Links.

use std::sync::OnceLock;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TotpConfig {
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: String,
    pub account: String,
}

impl Default for TotpConfig {
    fn default() -> Self {
        TotpConfig {
            secret: String::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: String::new(),
            account: String::new(),
        }
    }
}

impl TotpConfig {
    /// Kein `Drop`, damit `..Default::default()` und serde-Defaults funktionieren;
    /// `Entry` ruft das beim Verwerfen auf.
    pub fn wipe(&mut self) {
        self.secret.zeroize();
        self.issuer.zeroize();
        self.account.zeroize();
    }

    /// Prüft die Parameter und bringt das Secret in kanonische Base32-Form.
    pub fn normalized(&self) -> Result<TotpConfig> {
        if !(6..=8).contains(&self.digits) {
            return Err(Error::invalid("2FA: Es werden 6 bis 8 Ziffern unterstützt"));
        }
        if !(1..=300).contains(&self.period) {
            return Err(Error::invalid("2FA: Intervall muss zwischen 1 und 300 Sekunden liegen"));
        }
        decode_secret(&self.secret)?;
        Ok(TotpConfig {
            secret: clean_secret(&self.secret),
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period,
            issuer: self.issuer.trim().to_string(),
            account: self.account.trim().to_string(),
        })
    }

    pub fn display_name(&self) -> String {
        match (self.issuer.is_empty(), self.account.is_empty()) {
            (false, _) => self.issuer.clone(),
            (true, false) => self.account.clone(),
            (true, true) => String::new(),
        }
    }

    pub fn remaining(&self, unix: u64) -> u64 {
        self.period - unix % self.period
    }
}

fn base32() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = Specification::new();
        spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        // Manche Dienste liefern Secrets mit nicht-null Restbits – tolerant sein.
        spec.check_trailing_bits = false;
        spec.encoding().expect("gültige Base32-Spezifikation")
    })
}

fn clean_secret(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase()
}

pub fn decode_secret(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned = Zeroizing::new(clean_secret(s));
    let bytes = base32()
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::invalid("2FA: Secret ist kein gültiges Base32"))?;
    if bytes.len() < 5 {
        return Err(Error::invalid("2FA: Secret ist zu kurz"));
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
pub fn encode_secret(bytes: &[u8]) -> String {
    base32().encode(bytes)
}

fn hmac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC akzeptiert jede Schlüssellänge");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn generate(cfg: &TotpConfig, unix: u64) -> Result<String> {
    let key = decode_secret(&cfg.secret)?;
    let counter = (unix / cfg.period.max(1)).to_be_bytes();
    let mac = Zeroizing::new(match cfg.algorithm {
        Algorithm::Sha1 => hmac::<Hmac<Sha1>>(&key, &counter),
        Algorithm::Sha256 => hmac::<Hmac<Sha256>>(&key, &counter),
        Algorithm::Sha512 => hmac::<Hmac<Sha512>>(&key, &counter),
    });
    // Dynamische Trunkierung (RFC 4226, Abschnitt 5.3)
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    let digits = cfg.digits.clamp(6, 8);
    Ok(format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize))
}

/// otpauth://totp/Issuer:konto?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30
pub fn parse_otpauth(uri: &str) -> Result<TotpConfig> {
    let bad = || Error::invalid("Kein gültiger otpauth://-Link");
    let url = Url::parse(uri.trim()).map_err(|_| bad())?;
    if !url.scheme().eq_ignore_ascii_case("otpauth") {
        return Err(bad());
    }
    match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case("totp") => {}
        Some(h) if h.eq_ignore_ascii_case("hotp") => {
            return Err(Error::invalid("HOTP (zählerbasiert) wird nicht unterstützt"))
        }
        _ => return Err(bad()),
    }

    let label = percent_decode_str(url.path().trim_start_matches('/'))
        .decode_utf8_lossy()
        .to_string();
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let mut cfg = TotpConfig { account, issuer: label_issuer, ..Default::default() };
    for (key, value) in url.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            "secret" => cfg.secret = value.to_string(),
            "issuer" if !value.trim().is_empty() => cfg.issuer = value.trim().to_string(),
            "algorithm" => {
                cfg.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(Error::invalid("2FA: Unbekannter Algorithmus")),
                }
            }
            "digits" => cfg.digits = value.parse().map_err(|_| bad())?,
            "period" => cfg.period = value.parse().map_err(|_| bad())?,
            _ => {}
        }
    }
    if cfg.secret.is_empty() {
        return Err(Error::invalid("Der Link enthält kein Secret"));
    }
    cfg.normalized()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(secret: &[u8], algorithm: Algorithm) -> TotpConfig {
        TotpConfig { secret: encode_secret(secret), algorithm, digits: 8, ..Default::default() }
    }

    // Testvektoren aus RFC 6238, Anhang B
    #[test]
    fn rfc6238_vectors() {
        let sha1 = cfg(b"12345678901234567890", Algorithm::Sha1);
        let sha256 = cfg(b"12345678901234567890123456789012", Algorithm::Sha256);
        let sha512 = cfg(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            Algorithm::Sha512,
        );
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, a, b, c) in cases {
            assert_eq!(generate(&sha1, t).unwrap(), a, "SHA1 @ {t}");
            assert_eq!(generate(&sha256, t).unwrap(), b, "SHA256 @ {t}");
            assert_eq!(generate(&sha512, t).unwrap(), c, "SHA512 @ {t}");
        }
    }

    #[test]
    fn parses_otpauth_link() {
        let c = parse_otpauth(
            "otpauth://totp/ACME%20Co:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(c.issuer, "ACME Co");
        assert_eq!(c.account, "jane@example.com");
        assert_eq!(c.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(c.digits, 6);
    }

    #[test]
    fn rejects_hotp_and_garbage() {
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=!!!").is_err());
    }

    #[test]
    fn secret_is_normalized() {
        let c = TotpConfig { secret: "jbsw y3dp ehpk 3pxp".into(), ..Default::default() };
        assert_eq!(c.normalized().unwrap().secret, "JBSWY3DPEHPK3PXP");
    }
}
