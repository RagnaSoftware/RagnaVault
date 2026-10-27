use serde::{Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Falsches Master-Passwort")]
    WrongPassword,
    #[error("Es existiert noch kein Tresor")]
    NoVault,
    #[error("Es existiert bereits ein Tresor")]
    VaultExists,
    #[error("Zu viele Fehlversuche – bitte {0} s warten")]
    Throttled(u64),
    #[error("Der Tresor ist gesperrt")]
    Locked,
    #[error("Eintrag nicht gefunden")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("Tresor-Datei beschädigt: {0}")]
    Corrupt(String),
    #[error("Dateifehler: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialisierung fehlgeschlagen: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Kryptografiefehler")]
    Crypto,
    #[error("Zwischenablage: {0}")]
    Clipboard(String),
    #[error("Interner Fehler: {0}")]
    Internal(String),
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }
}

// Tauri gibt Fehler als Promise-Rejection an das Frontend weiter – dort reicht der Text.
impl Serialize for Error {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
