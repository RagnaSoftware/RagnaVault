//! Zustimmung zur RagnaSoftware Generallizenz.
//!
//! Gespeichert wird die zugestimmte Lizenzversion. Erscheint eine neue Version,
//! fragt die App erneut (Generallizenz § 13: wesentliche Änderungen brauchen Zustimmung).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

pub const LICENSE_VERSION: &str = "1.0";
pub const LICENSE_DATE: &str = "25. Oktober 2026";
pub const LICENSE_URL: &str = "https://ragnasoftware.net/lizenz/";
const FILE: &str = "license.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Acceptance {
    pub version: String,
    pub accepted_at: u64,
}

pub fn load(dir: &Path) -> Option<Acceptance> {
    let raw = fs::read(dir.join(FILE)).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub fn is_accepted(dir: &Path) -> bool {
    load(dir).is_some_and(|a| a.version == LICENSE_VERSION)
}

pub fn accept(dir: &Path, now: u64) -> Result<()> {
    let a = Acceptance { version: LICENSE_VERSION.into(), accepted_at: now };
    fs::write(dir.join(FILE), serde_json::to_vec_pretty(&a)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptance_is_tied_to_version() {
        let dir = std::env::temp_dir().join(format!("ragnavault-lic-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_accepted(&dir));
        accept(&dir, 1).unwrap();
        assert!(is_accepted(&dir));
        fs::write(dir.join(FILE), r#"{"version":"0.9","acceptedAt":1}"#).unwrap();
        assert!(!is_accepted(&dir), "ältere Version erfordert erneute Zustimmung");
    }
}
