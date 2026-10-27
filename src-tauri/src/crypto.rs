//! Schlüsselableitung und authentifizierte Verschlüsselung.
//!
//! Master-Passwort + Salt --Argon2id--> KEK --XChaCha20-Poly1305--> DEK --XChaCha20-Poly1305--> Tresor

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub algorithm: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Argon2id, 64 MiB, 3 Durchläufe, frisches Salt.
    pub fn generate() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        KdfParams {
            algorithm: "argon2id".into(),
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
            salt,
        }
    }

    /// Schutz gegen manipulierte Dateien, die absurde Parameter vorgeben (Speicher-/Zeit-DoS).
    fn validate(&self) -> Result<()> {
        let ok = self.algorithm == "argon2id"
            && (8 * 1024..=1024 * 1024).contains(&self.m_cost_kib)
            && (1..=10).contains(&self.t_cost)
            && (1..=8).contains(&self.p_cost)
            && self.salt.len() >= SALT_LEN;
        if ok {
            Ok(())
        } else {
            Err(Error::Corrupt("ungültige KDF-Parameter".into()))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sealed {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

pub fn derive_kek(password: &str, kdf: &KdfParams) -> Result<SecretKey> {
    kdf.validate()?;
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|_| Error::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), &kdf.salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

pub fn random_key() -> SecretKey {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

pub fn key_from_slice(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() != KEY_LEN {
        return Err(Error::Corrupt("Schlüssellänge".into()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

/// Verschlüsselt mit frischer 192-Bit-Nonce; `aad` wird mit authentifiziert.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)?;
    Ok(Sealed { nonce: nonce.to_vec(), ciphertext })
}

/// `None`, wenn der Auth-Tag nicht passt (falscher Schlüssel oder manipulierte Daten).
/// Der Aufrufer entscheidet, welcher Fehler daraus wird – es gibt bewusst kein Klartext-Orakel.
pub fn open(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != NONCE_LEN {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload { msg: &sealed.ciphertext, aad },
        )
        .ok()
        .map(Zeroizing::new)
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let sealed = seal(&key, b"geheim", b"aad").unwrap();
        assert_eq!(open(&key, &sealed, b"aad").unwrap().as_slice(), b"geheim");
    }

    #[test]
    fn open_rejects_wrong_key_aad_and_tampering() {
        let key = random_key();
        let sealed = seal(&key, b"geheim", b"aad").unwrap();
        assert!(open(&random_key(), &sealed, b"aad").is_none());
        assert!(open(&key, &sealed, b"andere").is_none());
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(open(&key, &tampered, b"aad").is_none());
    }

    #[test]
    fn kdf_is_deterministic_per_salt() {
        let kdf = KdfParams::generate();
        assert_eq!(*derive_kek("pw", &kdf).unwrap(), *derive_kek("pw", &kdf).unwrap());
        assert_ne!(*derive_kek("pw", &kdf).unwrap(), *derive_kek("pw2", &kdf).unwrap());
    }

    #[test]
    fn kdf_rejects_hostile_params() {
        let mut kdf = KdfParams::generate();
        kdf.m_cost_kib = 64 * 1024 * 1024;
        assert!(derive_kek("pw", &kdf).is_err());
    }
}
