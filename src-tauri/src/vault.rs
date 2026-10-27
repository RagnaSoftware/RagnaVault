//! Tresor-Datei (`*.rvault`) und entsperrte Sitzung.
//!
//! Auf der Platte liegen nur KDF-Parameter, der verpackte DEK, der verschlüsselte Inhalt und
//! eine Revision. Die Revision steckt in den AAD des Inhalts, kann also nicht unbemerkt
//! verändert werden – und eignet sich später als Konfliktzähler für eine Synchronisierung.
//!
//! Dazu kommt immer ein zweites Schlüssel-Fach (`alt`) für das Notfall-Passwort (Duress).
//! Ist keins eingerichtet, enthält es gleich lange Zufallsdaten – an der Datei ist also nicht
//! erkennbar, ob es ein Notfall-Passwort gibt. Beide Fächer hängen am selben KDF-Salt, so dass
//! jeder Entsperrversuch genau eine Argon2-Ableitung kostet, egal welches Fach passt.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KdfParams, Sealed, SecretKey};
use crate::error::{Error, Result};
use crate::totp::TotpConfig;

const FORMAT_VERSION: u32 = 1;
// Die AAD-Kennungen stammen aus der Zeit vor der Umbenennung zu RagnaVault. Sie sind Teil jeder
// verschlüsselten Datei und dürfen sich nicht ändern, sonst lassen sich bestehende Tresore nicht mehr öffnen.
const AAD_DEK: &[u8] = b"tresor/v1/dek";
const AAD_DATA: &[u8] = b"tresor/v1/vault";
const AAD_DURESS: &[u8] = b"tresor/v1/duress";
pub const MIN_MASTER_LEN: usize = 10;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultFile {
    format: u32,
    revision: u64,
    kdf: KdfParams,
    wrapped_dek: Sealed,
    /// Notfall-Fach; fehlt nur in Dateien von vor der Duress-Funktion.
    #[serde(default)]
    alt: Option<Sealed>,
    vault: Sealed,
}

/// Was zum Prüfen und Neuverpacken von Passwörtern gebraucht wird – ohne den DEK selbst.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub kdf: KdfParams,
    pub wrapped_dek: Sealed,
    pub alt: Sealed,
}

/// Ein leeres Notfall-Fach: gleiche Längen wie ein echtes (24 Byte Nonce, 32 Byte + 16 Byte Tag).
fn dummy_slot() -> Sealed {
    let random = |n: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(crypto::random_key().as_slice());
        }
        v.truncate(n);
        v
    };
    Sealed { nonce: random(24), ciphertext: random(32 + 16) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Login,
    Note,
    Totp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub kind: EntryKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub password_changed_at: u64,
    /// Frühere Passwörter, neuestes zuerst.
    #[serde(default)]
    pub history: Vec<PasswordHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    pub password: String,
    pub replaced_at: u64,
}

pub const MAX_HISTORY: usize = 10;

// Jede Kopie eines Eintrags (auch Backups beim Rollback) wird beim Verwerfen überschrieben.
impl Drop for Entry {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        if let Some(t) = self.totp.as_mut() {
            t.wipe();
        }
    }
}

impl Drop for PasswordHistory {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryInput {
    pub id: Option<String>,
    pub kind: Option<EntryKind>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: Option<TotpConfig>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VaultData {
    entries: Vec<Entry>,
    /// Steht verschlüsselt im Tresor, damit die Datei selbst nichts verrät.
    #[serde(default)]
    duress_set: bool,
}

pub struct Session {
    path: PathBuf,
    kdf: KdfParams,
    wrapped_dek: Sealed,
    alt: Sealed,
    dek: SecretKey,
    data: VaultData,
    revision: u64,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn data_aad(revision: u64) -> Vec<u8> {
    let mut aad = AAD_DATA.to_vec();
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

fn validate_master(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_LEN {
        return Err(Error::invalid(format!(
            "Das Master-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein"
        )));
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<VaultFile> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoVault),
        Err(e) => return Err(e.into()),
    };
    let file: VaultFile =
        serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    if file.format != FORMAT_VERSION {
        return Err(Error::Corrupt(format!("unbekannte Formatversion {}", file.format)));
    }
    Ok(file)
}

/// Schreibt erst in eine temporäre Datei und ersetzt dann atomar; die vorige Version bleibt als `.bak`.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("rvault.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if path.exists() {
        fs::copy(path, path.with_extension("rvault.bak"))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Überschreibt Tresor-Datei, Backup und Zwischenstand mit Zufallsdaten und löscht sie.
/// (Auf SSDs garantiert das Überschreiben nicht, dass alte Blöcke physisch weg sind.)
fn wipe_files(path: &Path) -> Result<()> {
    for p in [path.to_owned(), path.with_extension("rvault.bak"), path.with_extension("rvault.tmp")] {
        let Ok(meta) = fs::metadata(&p) else { continue };
        {
            let mut f = fs::OpenOptions::new().write(true).open(&p)?;
            let mut left = meta.len() as usize;
            while left > 0 {
                let chunk = crypto::random_key();
                let n = left.min(chunk.len());
                f.write_all(&chunk[..n])?;
                left -= n;
            }
            f.sync_all()?;
        }
        fs::remove_file(&p)?;
    }
    Ok(())
}

/// Entsperrt den DEK mit dem alten Passwort und verpackt ihn unter einem neuen.
/// Salt und KDF-Parameter bleiben, damit ein eingerichtetes Notfall-Passwort gültig bleibt.
/// Läuft ohne Sitzungs-Lock, weil Argon2 zweimal rechnen muss.
pub fn rewrap(old: &str, new: &str, km: &KeyMaterial) -> Result<Sealed> {
    validate_master(new)?;
    let old_kek = crypto::derive_kek(old, &km.kdf)?;
    let dek = crypto::open(&old_kek, &km.wrapped_dek, AAD_DEK).ok_or(Error::WrongPassword)?;
    let new_kek = crypto::derive_kek(new, &km.kdf)?;
    if crypto::open(&new_kek, &km.alt, AAD_DURESS).is_some() {
        return Err(Error::invalid("Das neue Master-Passwort darf nicht dem Notfall-Passwort entsprechen"));
    }
    crypto::seal(&new_kek, &dek, AAD_DEK)
}

/// Prüft das Master-Passwort und verpackt einen Prüfwert unter dem Notfall-Passwort.
pub fn seal_duress(master: &str, duress: &str, km: &KeyMaterial) -> Result<Sealed> {
    verify_master(master, km)?;
    if duress.chars().count() < MIN_MASTER_LEN {
        return Err(Error::invalid(format!("Das Notfall-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein")));
    }
    if duress == master {
        return Err(Error::invalid("Das Notfall-Passwort muss sich vom Master-Passwort unterscheiden"));
    }
    let kek = crypto::derive_kek(duress, &km.kdf)?;
    crypto::seal(&kek, crypto::random_key().as_ref(), AAD_DURESS)
}

pub fn verify_master(master: &str, km: &KeyMaterial) -> Result<()> {
    let kek = crypto::derive_kek(master, &km.kdf)?;
    crypto::open(&kek, &km.wrapped_dek, AAD_DEK).map(|_| ()).ok_or(Error::WrongPassword)
}

impl Session {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(path: &Path, password: &str) -> Result<Self> {
        if path.exists() {
            return Err(Error::VaultExists);
        }
        validate_master(password)?;
        let kdf = KdfParams::generate();
        let kek = crypto::derive_kek(password, &kdf)?;
        let dek = crypto::random_key();
        let wrapped_dek = crypto::seal(&kek, dek.as_ref(), AAD_DEK)?;
        let mut session = Session {
            path: path.to_owned(),
            kdf,
            wrapped_dek,
            alt: dummy_slot(),
            dek,
            data: VaultData::default(),
            revision: 0,
        };
        session.save()?;
        Ok(session)
    }

    /// Entsperrt mit dem Master-Passwort. Passt stattdessen das Notfall-Passwort, wird der Tresor
    /// vernichtet und an seiner Stelle ein leerer angelegt, der sich mit genau diesem Passwort öffnet.
    pub fn unlock(path: &Path, password: &str) -> Result<Self> {
        let file = read_file(path)?;
        let kek = crypto::derive_kek(password, &file.kdf)?;
        let Some(dek_bytes) = crypto::open(&kek, &file.wrapped_dek, AAD_DEK) else {
            if file.alt.as_ref().is_some_and(|alt| crypto::open(&kek, alt, AAD_DURESS).is_some()) {
                drop(file);
                wipe_files(path)?;
                return Session::create(path, password);
            }
            return Err(Error::WrongPassword);
        };
        let dek = crypto::key_from_slice(&dek_bytes)?;
        let plain = crypto::open(&dek, &file.vault, &data_aad(file.revision))
            .ok_or_else(|| Error::Corrupt("Inhalt lässt sich nicht authentifizieren".into()))?;
        let data: VaultData =
            serde_json::from_slice(&plain).map_err(|e| Error::Corrupt(e.to_string()))?;
        Ok(Session {
            path: path.to_owned(),
            kdf: file.kdf,
            wrapped_dek: file.wrapped_dek,
            alt: file.alt.unwrap_or_else(dummy_slot),
            dek,
            data,
            revision: file.revision,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn duress_set(&self) -> bool {
        self.data.duress_set
    }

    fn save(&mut self) -> Result<()> {
        let next = self.revision + 1;
        let plain = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let file = VaultFile {
            format: FORMAT_VERSION,
            revision: next,
            kdf: self.kdf.clone(),
            wrapped_dek: self.wrapped_dek.clone(),
            alt: Some(self.alt.clone()),
            vault: crypto::seal(&self.dek, &plain, &data_aad(next))?,
        };
        write_atomic(&self.path, &serde_json::to_vec_pretty(&file)?)?;
        self.revision = next;
        Ok(())
    }

    /// Ändert die Daten und speichert; schlägt das Speichern fehl, wird der Speicherstand zurückgesetzt.
    fn mutate<T>(&mut self, f: impl FnOnce(&mut VaultData) -> Result<T>) -> Result<T> {
        let backup = self.data.clone();
        let result = f(&mut self.data).and_then(|v| self.save().map(|_| v));
        if result.is_err() {
            self.data = backup;
        }
        result
    }

    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    pub fn entry(&self, id: &str) -> Result<&Entry> {
        self.data.entries.iter().find(|e| e.id == id).ok_or(Error::NotFound)
    }

    pub fn key_material(&self) -> KeyMaterial {
        KeyMaterial { kdf: self.kdf.clone(), wrapped_dek: self.wrapped_dek.clone(), alt: self.alt.clone() }
    }

    fn ensure_unchanged(&self, expected: &KeyMaterial) -> Result<()> {
        if self.wrapped_dek != expected.wrapped_dek || self.alt != expected.alt {
            return Err(Error::invalid("Der Tresor wurde zwischenzeitlich geändert – bitte erneut versuchen"));
        }
        Ok(())
    }

    pub fn apply_rewrap(&mut self, expected: &KeyMaterial, wrapped: Sealed) -> Result<()> {
        self.ensure_unchanged(expected)?;
        let old = std::mem::replace(&mut self.wrapped_dek, wrapped);
        if let Err(e) = self.save() {
            self.wrapped_dek = old;
            return Err(e);
        }
        Ok(())
    }

    /// Notfall-Fach setzen (`Some`) oder wieder mit Zufall füllen (`None`).
    pub fn apply_duress(&mut self, expected: &KeyMaterial, slot: Option<Sealed>) -> Result<()> {
        self.ensure_unchanged(expected)?;
        let set = slot.is_some();
        let old = std::mem::replace(&mut self.alt, slot.unwrap_or_else(dummy_slot));
        let result = self.mutate(|data| {
            data.duress_set = set;
            Ok(())
        });
        if result.is_err() {
            self.alt = old;
        }
        result
    }

    pub fn upsert(&mut self, input: &EntryInput) -> Result<Entry> {
        let kind = input.kind.unwrap_or(EntryKind::Login);
        let totp = match &input.totp {
            Some(t) if !t.secret.trim().is_empty() => Some(t.normalized()?),
            _ => None,
        };
        if kind == EntryKind::Totp && totp.is_none() {
            return Err(Error::invalid("Für einen 2FA-Eintrag wird ein Secret benötigt"));
        }
        let mut title = input.title.trim().to_string();
        if title.is_empty() {
            title = totp.as_ref().map(TotpConfig::display_name).unwrap_or_default();
        }
        if title.is_empty() {
            return Err(Error::invalid("Bitte einen Titel angeben"));
        }
        // Notizen haben keine Login-Felder; so landen keine versteckten Reste im Tresor.
        let is_note = kind == EntryKind::Note;
        let pick = |s: &str| if is_note { String::new() } else { s.to_string() };
        let totp = if is_note { None } else { totp };
        let ts = now();

        self.mutate(|data| match input.id.as_deref().filter(|s| !s.is_empty()) {
            Some(id) => {
                let e = data.entries.iter_mut().find(|e| e.id == id).ok_or(Error::NotFound)?;
                let password = pick(&input.password);
                if e.password != password {
                    if !e.password.is_empty() {
                        let old = std::mem::take(&mut e.password);
                        e.history.insert(0, PasswordHistory { password: old, replaced_at: ts });
                        e.history.truncate(MAX_HISTORY);
                    }
                    e.password_changed_at = ts;
                }
                e.kind = kind;
                e.title = title;
                e.username = pick(input.username.trim());
                e.password = password;
                e.url = pick(input.url.trim());
                e.notes = input.notes.clone();
                e.totp = totp;
                e.favorite = input.favorite;
                e.updated_at = ts;
                Ok(e.clone())
            }
            None => {
                let e = Entry {
                    id: uuid::Uuid::new_v4().to_string(),
                    kind,
                    title,
                    username: pick(input.username.trim()),
                    password: pick(&input.password),
                    url: pick(input.url.trim()),
                    notes: input.notes.clone(),
                    totp,
                    favorite: input.favorite,
                    created_at: ts,
                    updated_at: ts,
                    password_changed_at: ts,
                    history: Vec::new(),
                };
                data.entries.push(e.clone());
                Ok(e)
            }
        })
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.mutate(|data| {
            let before = data.entries.len();
            data.entries.retain(|e| e.id != id);
            if data.entries.len() == before {
                Err(Error::NotFound)
            } else {
                Ok(())
            }
        })
    }

    pub fn toggle_favorite(&mut self, id: &str) -> Result<bool> {
        self.mutate(|data| {
            let e = data.entries.iter_mut().find(|e| e.id == id).ok_or(Error::NotFound)?;
            e.favorite = !e.favorite;
            Ok(e.favorite)
        })
    }

    /// Mehrere 2FA-Einträge auf einmal anlegen (ein Speichervorgang).
    pub fn import_totp(&mut self, configs: Vec<TotpConfig>) -> Result<usize> {
        let ts = now();
        self.mutate(|data| {
            let n = configs.len();
            for cfg in configs {
                let title = match cfg.display_name() {
                    t if t.is_empty() => "2FA-Code".to_string(),
                    t => t,
                };
                data.entries.push(Entry {
                    id: uuid::Uuid::new_v4().to_string(),
                    kind: EntryKind::Totp,
                    title,
                    username: String::new(),
                    password: String::new(),
                    url: String::new(),
                    notes: String::new(),
                    totp: Some(cfg),
                    favorite: false,
                    created_at: ts,
                    updated_at: ts,
                    password_changed_at: 0,
                    history: Vec::new(),
                });
            }
            Ok(n)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ragnavault-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("vault.rvault")
    }

    fn login(title: &str) -> EntryInput {
        EntryInput {
            kind: Some(EntryKind::Login),
            title: title.into(),
            username: "jane".into(),
            password: "s3cret!".into(),
            ..Default::default()
        }
    }

    #[test]
    fn create_save_unlock_roundtrip() {
        let path = temp_path();
        let mut s = Session::create(&path, "korrekt-pferd").unwrap();
        let e = s.upsert(&login("Mail")).unwrap();
        drop(s);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("s3cret!") && !raw.contains("Mail"), "Klartext in der Datei");

        let s = Session::unlock(&path, "korrekt-pferd").unwrap();
        assert_eq!(s.entry(&e.id).unwrap().password, "s3cret!");
        assert_eq!(s.revision, 2);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let path = temp_path();
        Session::create(&path, "korrekt-pferd").unwrap();
        assert!(matches!(Session::unlock(&path, "falsch-pferd"), Err(Error::WrongPassword)));
    }

    #[test]
    fn tampered_revision_is_detected() {
        let path = temp_path();
        Session::create(&path, "korrekt-pferd").unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        fs::write(&path, raw.replace("\"revision\": 1", "\"revision\": 7")).unwrap();
        assert!(matches!(Session::unlock(&path, "korrekt-pferd"), Err(Error::Corrupt(_))));
    }

    #[test]
    fn change_master_password_keeps_data() {
        let path = temp_path();
        let mut s = Session::create(&path, "altes-passwort").unwrap();
        let e = s.upsert(&login("Bank")).unwrap();
        let km = s.key_material();
        assert!(matches!(rewrap("falsch-falsch-falsch", "neues-passwort", &km), Err(Error::WrongPassword)));
        let new_wrapped = rewrap("altes-passwort", "neues-passwort", &km).unwrap();
        s.apply_rewrap(&km, new_wrapped).unwrap();
        drop(s);

        assert!(Session::unlock(&path, "altes-passwort").is_err());
        let s = Session::unlock(&path, "neues-passwort").unwrap();
        assert_eq!(s.entry(&e.id).unwrap().title, "Bank");
    }

    fn with_duress(path: &Path) -> Session {
        let mut s = Session::create(path, "master-passwort").unwrap();
        s.upsert(&login("Bank")).unwrap();
        let km = s.key_material();
        let slot = seal_duress("master-passwort", "notfall-passwort", &km).unwrap();
        s.apply_duress(&km, Some(slot)).unwrap();
        s
    }

    #[test]
    fn duress_password_wipes_and_opens_empty_vault() {
        let path = temp_path();
        drop(with_duress(&path));
        let bak = path.with_extension("rvault.bak");
        assert!(bak.exists());

        let s = Session::unlock(&path, "notfall-passwort").unwrap();
        assert!(s.entries().is_empty(), "nach Duress ist der Tresor leer");
        assert!(!s.duress_set());
        assert!(!bak.exists(), "Backup mit den echten Daten ist weg");
        drop(s);

        assert!(matches!(Session::unlock(&path, "master-passwort"), Err(Error::WrongPassword)));
        assert!(Session::unlock(&path, "notfall-passwort").unwrap().entries().is_empty());
    }

    #[test]
    fn master_still_works_with_duress_set_and_survives_master_change() {
        let path = temp_path();
        let mut s = with_duress(&path);
        assert!(s.duress_set());
        let km = s.key_material();
        assert!(rewrap("master-passwort", "notfall-passwort", &km).is_err(), "darf nicht gleich sein");
        let w = rewrap("master-passwort", "neuer-master-1", &km).unwrap();
        s.apply_rewrap(&km, w).unwrap();
        drop(s);

        assert_eq!(Session::unlock(&path, "neuer-master-1").unwrap().entries().len(), 1);
        assert!(Session::unlock(&path, "notfall-passwort").unwrap().entries().is_empty());
    }

    #[test]
    fn duress_rules_and_removal() {
        let path = temp_path();
        let mut s = with_duress(&path);
        let km = s.key_material();
        assert!(matches!(seal_duress("falsch-falsch", "noch-ein-notfall", &km), Err(Error::WrongPassword)));
        assert!(seal_duress("master-passwort", "master-passwort", &km).is_err());
        assert!(seal_duress("master-passwort", "kurz", &km).is_err());
        s.apply_duress(&km, None).unwrap();
        drop(s);
        assert!(matches!(Session::unlock(&path, "notfall-passwort"), Err(Error::WrongPassword)));
        assert_eq!(Session::unlock(&path, "master-passwort").unwrap().entries().len(), 1);
    }

    #[test]
    fn empty_duress_slot_looks_like_a_real_one() {
        let real = {
            let km = with_duress(&temp_path()).key_material();
            km.alt
        };
        let dummy = dummy_slot();
        assert_eq!(real.nonce.len(), dummy.nonce.len());
        assert_eq!(real.ciphertext.len(), dummy.ciphertext.len());
    }

    #[test]
    fn update_delete_favorite() {
        let path = temp_path();
        let mut s = Session::create(&path, "korrekt-pferd").unwrap();
        let e = s.upsert(&login("A")).unwrap();
        let mut edit = login("B");
        edit.id = Some(e.id.clone());
        s.upsert(&edit).unwrap();
        assert_eq!(s.entry(&e.id).unwrap().title, "B");
        assert!(s.entry(&e.id).unwrap().history.is_empty(), "gleiches Passwort erzeugt keinen Verlauf");
        edit.password = "neu!".into();
        s.upsert(&edit).unwrap();
        let hist = &s.entry(&e.id).unwrap().history;
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].password, "s3cret!");
        assert!(s.toggle_favorite(&e.id).unwrap());
        s.delete(&e.id).unwrap();
        assert!(s.entries().is_empty());
        assert!(matches!(s.delete(&e.id), Err(Error::NotFound)));
    }

    #[test]
    fn totp_entry_requires_valid_secret() {
        let path = temp_path();
        let mut s = Session::create(&path, "korrekt-pferd").unwrap();
        let mut input = EntryInput { kind: Some(EntryKind::Totp), ..Default::default() };
        assert!(s.upsert(&input).is_err());
        input.totp = Some(TotpConfig { secret: "jbsw y3dp ehpk 3pxp".into(), issuer: "GitHub".into(), ..Default::default() });
        let e = s.upsert(&input).unwrap();
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.totp.as_ref().unwrap().secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn short_master_password_is_rejected() {
        assert!(matches!(Session::create(&temp_path(), "kurz"), Err(Error::Invalid(_))));
    }
}
