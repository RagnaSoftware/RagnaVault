//! Tauri-Befehle.
//!
//! Die Oberfläche bekommt für Listen nur Zusammenfassungen ohne Passwörter, Secrets und Notizen.
//! Geheime Felder werden einzeln angefordert (anzeigen/kopieren) – oder gar nicht erst ausgeliefert,
//! weil das Kopieren direkt aus Rust heraus passiert.
//! Alles, was Argon2 rechnet, läuft auf einem Blocking-Thread, damit die Oberfläche flüssig bleibt.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::generator::{self, GenOptions, Generated};
use crate::license;
use crate::strength::{self, Strength};
use crate::totp::{self, TotpConfig};
use crate::vault::{self, Entry, EntryInput, EntryKind, Session};
use crate::vaults::{self, Registry};

/// Ab dem dritten Fehlversuch wächst die Wartezeit exponentiell (2 s, 4 s, 8 s … max. 5 min).
#[derive(Default)]
struct Throttle {
    failures: u32,
    until: Option<Instant>,
}

impl Throttle {
    fn check(&self) -> Result<()> {
        match self.until {
            Some(until) if Instant::now() < until => {
                Err(Error::Throttled((until - Instant::now()).as_secs() + 1))
            }
            _ => Ok(()),
        }
    }

    fn fail(&mut self) {
        self.failures += 1;
        if self.failures >= 3 {
            let secs = (2u64 << (self.failures - 3).min(8)).min(300);
            self.until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }
}

pub struct AppState {
    pub data_dir: PathBuf,
    registry: Mutex<Registry>,
    pub session: Arc<Mutex<Option<Session>>>,
    // Gilt für alle Tresore gemeinsam – ein Wechsel des Tresors setzt die Wartezeit nicht zurück.
    throttle: Mutex<Throttle>,
    pub lock_on_minimize: AtomicBool,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        AppState {
            registry: Mutex::new(Registry::load(&data_dir, vault::now())),
            data_dir,
            session: Arc::new(Mutex::new(None)),
            throttle: Mutex::new(Throttle::default()),
            lock_on_minimize: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Session>> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current_path(&self) -> Option<PathBuf> {
        self.registry().current().map(|v| Registry::path(&self.data_dir, v))
    }

    fn throttle(&self) -> MutexGuard<'_, Throttle> {
        self.throttle.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_session<T>(&self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        let mut guard = self.lock();
        f(guard.as_mut().ok_or(Error::Locked)?)
    }

    /// Sperrt sofort; `true`, wenn vorher entsperrt war.
    pub fn lock_now(&self) -> bool {
        self.lock().take().is_some()
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| Error::Internal(e.to_string()))?
}

// ---------- App & Lizenz ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: String,
    license_version: &'static str,
    license_date: &'static str,
    license_url: &'static str,
    license_accepted: bool,
    license_accepted_at: Option<u64>,
}

#[tauri::command]
pub fn app_info(app: AppHandle, state: State<AppState>) -> AppInfo {
    let acceptance = license::load(&state.data_dir);
    AppInfo {
        version: app.package_info().version.to_string(),
        license_version: license::LICENSE_VERSION,
        license_date: license::LICENSE_DATE,
        license_url: license::LICENSE_URL,
        license_accepted: license::is_accepted(&state.data_dir),
        license_accepted_at: acceptance.map(|a| a.accepted_at),
    }
}

#[tauri::command]
pub fn accept_license(state: State<AppState>) -> Result<()> {
    license::accept(&state.data_dir, vault::now())
}

#[tauri::command]
pub fn quit(app: AppHandle, state: State<AppState>) {
    state.lock_now();
    app.exit(0);
}

/// Öffnet http(s)-Links im Standardbrowser – andere Schemata (file:, javascript: …) werden abgelehnt.
#[tauri::command]
pub fn open_url(app: AppHandle, url: String) -> Result<()> {
    let parsed = url::Url::parse(&url).map_err(|_| Error::invalid("Ungültiger Link"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(Error::invalid("Nur http- und https-Links können geöffnet werden"));
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(|e| Error::Internal(e.to_string()))
}

// ---------- Tresor ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    exists: bool,
    unlocked: bool,
    path: String,
    vault_name: Option<String>,
    vault_count: usize,
}

#[tauri::command]
pub fn status(state: State<AppState>) -> Status {
    let reg = state.registry();
    let current = reg.current();
    let path = current.map(|v| Registry::path(&state.data_dir, v));
    Status {
        exists: path.as_deref().is_some_and(Session::exists),
        unlocked: state.lock().is_some(),
        path: path.unwrap_or_else(|| state.data_dir.clone()).display().to_string(),
        vault_name: current.map(|v| v.name.clone()),
        vault_count: reg.vaults.len(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    id: String,
    name: String,
    exists: bool,
    current: bool,
    created_at: u64,
}

#[tauri::command]
pub fn list_vaults(state: State<AppState>) -> Vec<VaultInfo> {
    let reg = state.registry();
    let current = reg.current().map(|v| v.id.clone());
    reg.vaults
        .iter()
        .map(|v| VaultInfo {
            id: v.id.clone(),
            name: v.name.clone(),
            exists: Registry::path(&state.data_dir, v).exists(),
            current: current.as_deref() == Some(v.id.as_str()),
            created_at: v.created_at,
        })
        .collect()
}

/// Wechselt den Tresor; ein entsperrter wird dabei gesperrt.
#[tauri::command]
pub fn select_vault(state: State<AppState>, id: String) -> Result<()> {
    let mut reg = state.registry();
    if reg.get(&id).is_none() {
        return Err(Error::NotFound);
    }
    state.lock_now();
    reg.current = Some(id);
    reg.save(&state.data_dir)
}

#[tauri::command]
pub fn rename_vault(state: State<AppState>, id: String, name: String) -> Result<()> {
    let name = vaults::validate_name(&name)?;
    let mut reg = state.registry();
    let v = reg.vaults.iter_mut().find(|v| v.id == id).ok_or(Error::NotFound)?;
    v.name = name;
    reg.save(&state.data_dir)
}

/// Entfernt einen Tresor nur aus der Liste – die Datei bleibt liegen.
#[tauri::command]
pub fn forget_vault(state: State<AppState>, id: String) -> Result<()> {
    let mut reg = state.registry();
    let v = reg.get(&id).ok_or(Error::NotFound)?;
    let path = Registry::path(&state.data_dir, v);
    if state.lock().as_ref().is_some_and(|s| s.path() == path) {
        return Err(Error::invalid("Ein geöffneter Tresor kann nicht entfernt werden – bitte zuerst sperren"));
    }
    reg.vaults.retain(|v| v.id != id);
    if reg.current.as_deref() == Some(id.as_str()) {
        reg.current = reg.vaults.first().map(|v| v.id.clone());
    }
    reg.save(&state.data_dir)
}

#[tauri::command]
pub async fn create_vault(state: State<'_, AppState>, name: String, password: String) -> Result<()> {
    let password = Zeroizing::new(password);
    let entry = Registry::new_ref(vaults::validate_name(&name)?, vault::now());
    let path = Registry::path(&state.data_dir, &entry);
    let session = blocking(move || Session::create(&path, &password)).await?;
    {
        let mut reg = state.registry();
        reg.current = Some(entry.id.clone());
        reg.vaults.push(entry);
        reg.save(&state.data_dir)?;
    }
    *state.lock() = Some(session);
    Ok(())
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<()> {
    state.throttle().check()?;
    let password = Zeroizing::new(password);
    let path = state.current_path().ok_or(Error::NoVault)?;
    match blocking(move || Session::unlock(&path, &password)).await {
        Ok(session) => {
            *state.throttle() = Throttle::default();
            *state.lock() = Some(session);
            Ok(())
        }
        Err(Error::WrongPassword) => {
            state.throttle().fail();
            Err(Error::WrongPassword)
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub fn lock(state: State<AppState>) {
    // Drop der Sitzung überschreibt DEK und alle Einträge.
    state.lock_now();
}

#[tauri::command]
pub async fn change_master(state: State<'_, AppState>, current: String, new: String) -> Result<()> {
    let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
    let km = state.with_session(|s| Ok(s.key_material()))?;
    let expected = km.clone();
    let wrapped = blocking(move || vault::rewrap(&current, &new, &km)).await?;
    state.with_session(|s| s.apply_rewrap(&expected, wrapped))
}

// ---------- Notfall-Passwort (Duress) ----------

#[tauri::command]
pub fn duress_status(state: State<AppState>) -> Result<bool> {
    state.with_session(|s| Ok(s.duress_set()))
}

#[tauri::command]
pub async fn set_duress(state: State<'_, AppState>, master: String, duress: String) -> Result<()> {
    let (master, duress) = (Zeroizing::new(master), Zeroizing::new(duress));
    let km = state.with_session(|s| Ok(s.key_material()))?;
    let expected = km.clone();
    let slot = blocking(move || vault::seal_duress(&master, &duress, &km)).await?;
    state.with_session(|s| s.apply_duress(&expected, Some(slot)))
}

#[tauri::command]
pub async fn remove_duress(state: State<'_, AppState>, master: String) -> Result<()> {
    let master = Zeroizing::new(master);
    let km = state.with_session(|s| Ok(s.key_material()))?;
    let expected = km.clone();
    blocking(move || vault::verify_master(&master, &km)).await?;
    state.with_session(|s| s.apply_duress(&expected, None))
}

// ---------- Einträge ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpInfo {
    issuer: String,
    account: String,
    digits: u32,
    period: u64,
}

/// Was die Liste braucht – ohne Passwort, TOTP-Secret, Notizen und Verlauf.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    id: String,
    kind: EntryKind,
    title: String,
    username: String,
    url: String,
    has_password: bool,
    has_notes: bool,
    totp: Option<TotpInfo>,
    favorite: bool,
    created_at: u64,
    updated_at: u64,
    password_changed_at: u64,
    history: Vec<u64>,
    strength: Option<u8>,
    reused: bool,
}

fn summarize(entries: &[Entry]) -> Vec<EntrySummary> {
    let mut uses: HashMap<&str, usize> = HashMap::new();
    for e in entries.iter().filter(|e| !e.password.is_empty()) {
        *uses.entry(e.password.as_str()).or_default() += 1;
    }
    entries
        .iter()
        .map(|e| {
            let has_password = !e.password.is_empty();
            EntrySummary {
                id: e.id.clone(),
                kind: e.kind,
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                has_password,
                has_notes: !e.notes.trim().is_empty(),
                totp: e.totp.as_ref().map(|t| TotpInfo {
                    issuer: t.issuer.clone(),
                    account: t.account.clone(),
                    digits: t.digits,
                    period: t.period,
                }),
                favorite: e.favorite,
                created_at: e.created_at,
                updated_at: e.updated_at,
                password_changed_at: e.password_changed_at,
                history: e.history.iter().map(|h| h.replaced_at).collect(),
                strength: has_password.then(|| strength::estimate(&e.password).score),
                reused: has_password && uses.get(e.password.as_str()).copied().unwrap_or(0) > 1,
            }
        })
        .collect()
}

#[tauri::command]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntrySummary>> {
    state.with_session(|s| Ok(summarize(s.entries())))
}

/// Vollständiger Eintrag – nur für den Editor.
#[tauri::command]
pub fn get_entry(state: State<AppState>, id: String) -> Result<Entry> {
    state.with_session(|s| s.entry(&id).cloned())
}

#[tauri::command]
pub fn save_entry(state: State<AppState>, entry: EntryInput) -> Result<String> {
    state.with_session(|s| s.upsert(&entry).map(|e| e.id.clone()))
}

#[tauri::command]
pub fn delete_entry(state: State<AppState>, id: String) -> Result<()> {
    state.with_session(|s| s.delete(&id))
}

#[tauri::command]
pub fn toggle_favorite(state: State<AppState>, id: String) -> Result<bool> {
    state.with_session(|s| s.toggle_favorite(&id))
}

fn field_value(e: &Entry, field: &str, index: Option<usize>) -> Result<Zeroizing<String>> {
    let v = match field {
        "username" => e.username.clone(),
        "password" => e.password.clone(),
        "url" => e.url.clone(),
        "notes" => e.notes.clone(),
        "totp" => {
            let cfg = e.totp.as_ref().ok_or(Error::NotFound)?;
            totp::generate(cfg, vault::now())?
        }
        "history" => {
            let h = index.and_then(|i| e.history.get(i)).ok_or(Error::NotFound)?;
            h.password.clone()
        }
        _ => return Err(Error::invalid("Unbekanntes Feld")),
    };
    Ok(Zeroizing::new(v))
}

/// Gibt ein einzelnes geheimes Feld zum Anzeigen heraus.
#[tauri::command]
pub fn reveal_field(state: State<AppState>, id: String, field: String, index: Option<usize>) -> Result<String> {
    state.with_session(|s| field_value(s.entry(&id)?, &field, index).map(|v| v.to_string()))
}

/// Kopiert ein Feld direkt aus dem Tresor, ohne dass der Wert durch die Oberfläche läuft.
#[tauri::command]
pub fn copy_field(
    state: State<AppState>,
    id: String,
    field: String,
    index: Option<usize>,
    clear_after: u64,
) -> Result<()> {
    let value = state.with_session(|s| field_value(s.entry(&id)?, &field, index))?;
    copy_to_clipboard(value, clear_after)
}

// ---------- 2FA ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    id: String,
    code: String,
    remaining: u64,
    period: u64,
}

#[tauri::command]
pub fn totp_codes(state: State<AppState>) -> Result<Vec<TotpCode>> {
    let t = vault::now();
    state.with_session(|s| {
        Ok(s.entries()
            .iter()
            .filter_map(|e| {
                let cfg = e.totp.as_ref()?;
                Some(TotpCode {
                    id: e.id.clone(),
                    code: totp::generate(cfg, t).ok()?,
                    remaining: cfg.remaining(t),
                    period: cfg.period,
                })
            })
            .collect())
    })
}

/// Aktueller Code für eine noch nicht gespeicherte Konfiguration (Vorschau im Editor).
#[tauri::command]
pub fn totp_preview(config: TotpConfig) -> Result<String> {
    let mut cfg = config.normalized()?;
    let code = totp::generate(&cfg, vault::now());
    cfg.wipe();
    code
}

#[tauri::command]
pub fn parse_otpauth(uri: String) -> Result<TotpConfig> {
    totp::parse_otpauth(&uri)
}

/// Text mit einem oder mehreren otpauth://-Links (je Zeile einer).
#[tauri::command]
pub fn import_otpauth(state: State<AppState>, text: String) -> Result<usize> {
    let text = Zeroizing::new(text);
    let configs = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .enumerate()
        .map(|(i, line)| {
            totp::parse_otpauth(line).map_err(|e| Error::invalid(format!("Zeile {}: {e}", i + 1)))
        })
        .collect::<Result<Vec<_>>>()?;
    if configs.is_empty() {
        return Err(Error::invalid("Keine otpauth://-Links gefunden"));
    }
    state.with_session(|s| s.import_totp(configs))
}

// ---------- Werkzeuge ----------

#[tauri::command]
pub fn generate_password(options: GenOptions) -> Result<Generated> {
    generator::generate(&options)
}

#[tauri::command]
pub fn password_strength(password: String) -> Strength {
    strength::estimate(&Zeroizing::new(password))
}

#[tauri::command]
pub fn copy_text(text: String, clear_after: u64) -> Result<()> {
    copy_to_clipboard(Zeroizing::new(text), clear_after)
}

#[tauri::command]
pub fn clear_clipboard() -> Result<()> {
    CLIP_GENERATION.fetch_add(1, Ordering::SeqCst);
    arboard::Clipboard::new().and_then(|mut cb| cb.clear()).map_err(clip_err)
}

/// Fensterinhalt für Screenshots, Bildschirmaufnahmen und Fernwartung unsichtbar machen.
#[tauri::command]
pub fn set_content_protected(window: tauri::WebviewWindow, enabled: bool) -> Result<()> {
    window
        .set_content_protected(enabled)
        .map_err(|e| Error::Internal(e.to_string()))
}

#[tauri::command]
pub fn set_lock_on_minimize(state: State<AppState>, enabled: bool) {
    state.lock_on_minimize.store(enabled, Ordering::SeqCst);
}

// ---------- Zwischenablage ----------

/// Jede Kopie erhöht den Zähler; ein Lösch-Timer greift nur, wenn seit ihm nichts Neues kopiert wurde.
static CLIP_GENERATION: AtomicU64 = AtomicU64::new(0);

fn clip_err(e: arboard::Error) -> Error {
    Error::Clipboard(e.to_string())
}

fn copy_to_clipboard(text: Zeroizing<String>, clear_after: u64) -> Result<()> {
    if text.is_empty() {
        return Err(Error::invalid("Das Feld ist leer"));
    }
    let mut cb = arboard::Clipboard::new().map_err(clip_err)?;
    set_private(&mut cb, &text)?;
    let generation = CLIP_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    if clear_after > 0 {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(clear_after));
            if CLIP_GENERATION.load(Ordering::SeqCst) != generation {
                return;
            }
            if let Ok(mut cb) = arboard::Clipboard::new() {
                // Nur löschen, wenn der Nutzer nicht inzwischen selbst etwas anderes kopiert hat.
                let current = cb.get_text().map(Zeroizing::new);
                if matches!(&current, Ok(c) if c.as_str() == text.as_str()) {
                    let _ = cb.clear();
                }
            }
        });
    }
    Ok(())
}

#[cfg(windows)]
fn set_private(cb: &mut arboard::Clipboard, text: &str) -> Result<()> {
    use arboard::SetExtWindows;
    // Nicht im Windows-Zwischenablageverlauf (Win+V) und nicht in der Cloud-Synchronisierung landen.
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(text)
        .map_err(clip_err)
}

#[cfg(not(windows))]
fn set_private(cb: &mut arboard::Clipboard, text: &str) -> Result<()> {
    cb.set_text(text).map_err(clip_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_backs_off_after_three_failures() {
        let mut t = Throttle::default();
        t.fail();
        t.fail();
        assert!(t.check().is_ok());
        t.fail();
        assert!(matches!(t.check(), Err(Error::Throttled(s)) if s >= 2));
    }
}
