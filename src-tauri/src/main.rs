#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod crypto;
mod error;
mod generator;
mod license;
mod strength;
mod totp;
mod vault;
mod vaults;

use std::path::Path;
use std::sync::atomic::Ordering;

use tauri::{Emitter, Manager, WindowEvent};

/// Vor der Umbenennung lag der Tresor unter `de.tresor.desktop`. Einmalig kopieren, nie verschieben.
fn migrate_legacy_vault(data_dir: &Path) -> std::io::Result<()> {
    let target = data_dir.join("vault.rvault");
    let Some(legacy) = data_dir.parent().map(|p| p.join("de.tresor.desktop").join("vault.rvault")) else {
        return Ok(());
    };
    if !target.exists() && legacy.exists() {
        std::fs::copy(legacy, target)?;
    }
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            migrate_legacy_vault(&dir)?;
            app.manage(commands::AppState::new(dir));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Beim Minimieren optional sofort sperren – unabhängig davon, ob die Oberfläche noch reagiert.
            if let WindowEvent::Resized(_) = event {
                if window.is_minimized().unwrap_or(false) {
                    let state = window.state::<commands::AppState>();
                    if state.lock_on_minimize.load(Ordering::SeqCst) && state.lock_now() {
                        let _ = window.emit("vault-locked", "minimized");
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::accept_license,
            commands::quit,
            commands::open_url,
            commands::status,
            commands::list_vaults,
            commands::select_vault,
            commands::rename_vault,
            commands::forget_vault,
            commands::duress_status,
            commands::set_duress,
            commands::remove_duress,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::change_master,
            commands::list_entries,
            commands::get_entry,
            commands::save_entry,
            commands::delete_entry,
            commands::toggle_favorite,
            commands::reveal_field,
            commands::copy_field,
            commands::totp_codes,
            commands::totp_preview,
            commands::parse_otpauth,
            commands::import_otpauth,
            commands::generate_password,
            commands::password_strength,
            commands::copy_text,
            commands::clear_clipboard,
            commands::set_content_protected,
            commands::set_lock_on_minimize,
        ])
        .run(tauri::generate_context!())
        .expect("RagnaVault konnte nicht gestartet werden");
}
