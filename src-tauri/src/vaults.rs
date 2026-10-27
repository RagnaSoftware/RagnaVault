//! Liste der Tresore (`vaults.json`): Name und Dateiname je Tresor, dazu der zuletzt gewählte.
//! Die Namen liegen unverschlüsselt vor – sie erscheinen ja schon auf dem Sperrbildschirm.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const FILE: &str = "vaults.json";
const LEGACY_FILE: &str = "vault.rvault";
const MAX_NAME: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRef {
    pub id: String,
    pub name: String,
    pub file: String,
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub vaults: Vec<VaultRef>,
    pub current: Option<String>,
}

pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::invalid("Bitte einen Namen für den Tresor angeben"));
    }
    if name.chars().count() > MAX_NAME {
        return Err(Error::invalid(format!("Der Name darf höchstens {MAX_NAME} Zeichen lang sein")));
    }
    Ok(name.to_string())
}

impl Registry {
    /// Lädt die Liste; ein einzelner Tresor aus der Zeit vor der Mehrfach-Unterstützung wird übernommen.
    pub fn load(dir: &Path, now: u64) -> Registry {
        let mut reg: Registry = fs::read(dir.join(FILE))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        if reg.vaults.is_empty() && dir.join(LEGACY_FILE).exists() {
            let id = uuid::Uuid::new_v4().to_string();
            reg.vaults.push(VaultRef { id: id.clone(), name: "Mein Tresor".into(), file: LEGACY_FILE.into(), created_at: now });
            reg.current = Some(id);
            let _ = reg.save(dir);
        }
        reg
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let tmp = dir.join("vaults.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(tmp, dir.join(FILE))?;
        Ok(())
    }

    pub fn current(&self) -> Option<&VaultRef> {
        self.current
            .as_deref()
            .and_then(|id| self.get(id))
            .or_else(|| self.vaults.first())
    }

    pub fn get(&self, id: &str) -> Option<&VaultRef> {
        self.vaults.iter().find(|v| v.id == id)
    }

    pub fn path(dir: &Path, v: &VaultRef) -> PathBuf {
        dir.join(&v.file)
    }

    /// Neuer Eintrag (noch nicht in der Liste – erst nach erfolgreichem Anlegen hinzufügen).
    pub fn new_ref(name: String, now: u64) -> VaultRef {
        let id = uuid::Uuid::new_v4().to_string();
        VaultRef { file: format!("vault-{id}.rvault"), id, name, created_at: now }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ragnavault-reg-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn adopts_legacy_vault_and_roundtrips() {
        let dir = temp_dir();
        fs::write(dir.join(LEGACY_FILE), b"{}").unwrap();
        let reg = Registry::load(&dir, 1);
        assert_eq!(reg.vaults.len(), 1);
        assert_eq!(reg.current().unwrap().file, LEGACY_FILE);

        let mut reg = Registry::load(&dir, 2);
        assert_eq!(reg.vaults.len(), 1, "nicht doppelt übernehmen");
        let v = Registry::new_ref("Arbeit".into(), 3);
        reg.vaults.push(v.clone());
        reg.current = Some(v.id.clone());
        reg.save(&dir).unwrap();
        assert_eq!(Registry::load(&dir, 4).current().unwrap().name, "Arbeit");
    }

    #[test]
    fn validates_names() {
        assert!(validate_name("  ").is_err());
        assert!(validate_name(&"x".repeat(41)).is_err());
        assert_eq!(validate_name("  Privat ").unwrap(), "Privat");
    }
}
