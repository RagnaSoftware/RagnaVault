# RagnaVault

Passwort-Manager und 2FA-Authenticator für Windows von RagnaSoftware, gebaut mit Rust und Tauri 2.
Alles bleibt lokal; die Tresor-Datei verlässt das Gerät nicht.

Version 3.0.0 · Nutzung unter der [RagnaSoftware Generallizenz](https://ragnasoftware.net/lizenz/).
Beim ersten Start muss der Lizenz zugestimmt werden; bei einer neuen Lizenzversion fragt die App erneut.

## Funktionen

- Logins (Benutzername, Passwort, URL, Notizen), sichere Notizen, eigenständige 2FA-Einträge
- TOTP nach RFC 6238 (SHA-1/256/512, 6–8 Ziffern, frei wählbares Intervall), Import per `otpauth://`-Link
- Passwort-Generator ohne Modulo-Bias (Rejection Sampling über den OS-Zufall)
- Suche, Favoriten, Filter, Schnellkopie direkt aus der Liste, vollständige Tastaturbedienung
- Sicherheitsbericht: schwache, mehrfach verwendete und alte Passwörter, Logins ohne 2FA
- Passwortverlauf (die letzten 10 Passwörter je Eintrag)
- Zwischenablage wird nach einstellbarer Zeit geleert und nicht in den Windows-Verlauf (Win+V) übernommen
- Automatische Sperre bei Inaktivität, optional beim Minimieren, Sperren mit Strg+L
- Fensterinhalt ist für Screenshots, Aufnahmen und Fernwartung gesperrt (abschaltbar)
- Nach drei falschen Master-Passwörtern wachsende Wartezeit (2 s … 5 min)
- Master-Passwort ändern, ohne den Tresor neu zu verschlüsseln
- Mehrere Tresore mit eigenen Master-Passwörtern; wählen, umbenennen, anlegen über den Sperrbildschirm
- Notfall-Passwort (Duress) pro Tresor: löscht den Tresor unwiderruflich und öffnet einen leeren

## Kryptografie

```
Master-Passwort + Salt ──Argon2id (64 MiB, 3 Durchläufe)──► KEK
KEK ──XChaCha20-Poly1305──► verpackter DEK (32 Byte, einmalig zufällig erzeugt)
DEK ──XChaCha20-Poly1305──► Tresor-Inhalt
```

- Ein falsches Passwort scheitert am Auth-Tag des verpackten DEK – kein Klartext-Orakel.
- Die Revision liegt unverschlüsselt in der Datei, ist aber Teil der AAD des Inhalts und damit manipulationssicher.
  Sie dient später als Konfliktzähler für eine Synchronisierung.
- Speichern ist atomar (temporäre Datei + Umbenennen); die vorige Version bleibt als `vault.rvault.bak`.
- Entschlüsselte Einträge und Schlüssel werden beim Sperren im Speicher überschrieben (`zeroize`).
- Die Oberfläche bekommt für die Liste nur Zusammenfassungen. Passwörter, TOTP-Secrets und Notizen
  werden einzeln angefordert, wenn man sie anzeigt; Kopieren passiert direkt in Rust. Angezeigte
  Passwörter verschwinden nach 20 s wieder.
- Links öffnen nur über Rust im Standardbrowser, und nur `http`/`https`.
- **Notfall-Passwort:** Jede Datei enthält ein zweites Schlüssel-Fach (`alt`), ohne Notfall-Passwort
  mit gleich langen Zufallsdaten gefüllt – ob eins existiert, ist der Datei nicht anzusehen. Beide Fächer
  hängen am selben Salt, ein Entsperrversuch kostet also immer genau eine Argon2-Ableitung. Passt das
  Notfall-Passwort, werden `*.rvault`, `.bak` und `.tmp` mit Zufall überschrieben und gelöscht, dann wird
  ein leerer Tresor mit diesem Passwort angelegt. Grenzen: Auf SSDs garantiert Überschreiben nicht, dass
  alte Blöcke physisch weg sind, und eine vorher kopierte Datei bleibt natürlich lesbar.
  Beim Ändern des Master-Passworts bleibt das Salt erhalten, damit das Notfall-Passwort gültig bleibt.
- Das Master-Passwort ist **nicht wiederherstellbar**.

Speicherort: `%APPDATA%\net.ragnasoftware.ragnavault\` – `vaults.json` (Liste mit Namen),
je Tresor eine `vault-<id>.rvault` (der erste heißt `vault.rvault`), dazu `license.json`.
Ein Tresor aus der Zeit vor der Umbenennung (`%APPDATA%\de.tresor.desktop\`) wird beim ersten Start kopiert.

## Entwickeln

Voraussetzungen: Rust (stable), Node.js, WebView2 (in Windows 10/11 enthalten).

```sh
npm install
npx tauri dev     # App im Entwicklungsmodus
npm test          # Rust-Unit-Tests (u. a. RFC-6238-Testvektoren)
npx tauri build   # portable exe + Installer
```

Ergebnis: `src-tauri/target/release/ragnavault.exe` (portabel) und
`src-tauri/target/release/bundle/nsis/RagnaVault_3.0.0_x64-setup.exe`.

Hinweis: In PowerShell mit eingeschränktem Sprachmodus funktioniert `npm.ps1` nicht –
dann `npx.cmd` verwenden oder Git Bash.

## Logos

Quelldateien liegen in `assets/logo/`. Daraus erzeugt:
`src/logo-icon.png`, `src/logo-text-dark.png` (helles „Ragna“, dunkles Design),
`src/logo-text-light.png` (schwarzes „Ragna“, helles Design) und die App-Icons unter `src-tauri/icons/`
(`npx tauri icon <quadratisches PNG>`).

## Aufbau

| Datei | Inhalt |
|---|---|
| `src-tauri/src/crypto.rs` | Argon2id, XChaCha20-Poly1305, Schlüsseltypen |
| `src-tauri/src/vault.rs` | Dateiformat, Sitzung, Einträge, Notfall-Passwort |
| `src-tauri/src/vaults.rs` | Liste der Tresore |
| `src-tauri/src/totp.rs` | TOTP-Berechnung, otpauth-Parser |
| `src-tauri/src/generator.rs` | Passwort-Generator |
| `src-tauri/src/strength.rs` | Stärke-Schätzung für Anzeige und Bericht |
| `src-tauri/src/license.rs` | Zustimmung zur Generallizenz |
| `src-tauri/src/commands.rs` | Tauri-Befehle, Zwischenablage |
| `src/` | Oberfläche (HTML/CSS/JS ohne Build-Schritt, strikte CSP, kein `innerHTML`) |
