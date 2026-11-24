# Abnahmeprotokoll, Sicherheitsnachweise und offene Grenzen

> **Freigabestatus: TESTVERSION (nicht freigegeben)**  
> Die sicherheitskritischen Code-Befunde (Schlüsselauswahl, Wipe-Sicherheit bei laufenden Dateioperationen, Budget für anonyme PKESK-Versuche) wurden behoben und durch automatisierte Regressionstests nachgewiesen. Solange die externen Freigabetests (GitHub Pages Live-Start, Tor Browser, GnuPG/Kleopatra-Interoperabilität, externe Release-Signierung und Zwei-Umgebungen-Buildvergleich) offen sind, gilt dieser Stand ausdrücklich als **Testversion**.

## 1. Gebautes Artefakt (aktueller Stand)

- **Toolchain:** Rust `1.99.1` (`rust-toolchain.toml`, Target `wasm32-unknown-unknown`)
- **rPGP:** `pgp = "=0.21.1"` (eingecheckte `Cargo.lock`, gebaut mit `--locked`)
- **Wasm-Binary (`vault_wasm.wasm`):** `2,614,597` Bytes · SHA-256 `f5a7f75dfdb3787754fba113a947c777d6356e9c00ce3f78d54a50551134c479`
- **Standalone HTML (`dist/index.html`):** `3,549,731` Bytes · SHA-256 `8dcad2931b1583fdcf8500532291d0639ac3204c9b505c448985ced0abe5f0d7`

## 2. Behobene Sicherheitsbefunde und Regressionstests

| Befund | Reproduktion & Ursache | Behebung | Regressionstest |
|---|---|---|---|
| **1. OpenPGP-Schlüsselauswahl** | `select_encryption_subkey` und `select_signing_key` prüften nur `algorithm().can_encrypt()/can_sign()`; `sign_detached` nutzte fest `primary_key` ohne Prüfung auf Widerruf, Ablauf, Bindungssignaturen oder Key Flags. | Neues Modul `crates/vault-wasm/src/key_select.rs`: prüft Primärschlüssel-Selbstsignaturen, `KeyRevocation`, `KeyExpirationTime`, `SubkeyBinding`, `SubkeyRevocation`, explizite `KeyFlags` und eingebettete `Primary Key Binding`-Rücksignaturen; durchsucht alle Unterschlüssel; Altschlüssel ohne explizites `KeyFlags`-Subpaket werden fail-closed abgelehnt. | `test_key_selection_rejects_expired_revoked_wrong_flags_and_missing_flags`, `test_key_selection_skips_unsuitable_first_subkey_and_picks_later_valid_subkey` (**PASS**) |
| **2. Notfall-Wipe vs. laufende Dateioperationen** | Asynchrone `readFileAsBytes()`-Aufrufe in `web/app.js` waren nicht an `sessionEpoch` gebunden und wurden beim Wipe nicht abgebrochen; verspätete `onload`-Ergebnisse konnten nach dem Worker-Neustart in der neuen Sitzung `rpc()` aufrufen. | Jede Operation (Import, Encrypt, Decrypt, Sign, Verify, Keygen) bindet `opEpoch = sessionEpoch` beim Start; aktive `FileReader` werden beim Wipe per `reader.abort()` abgebrochen; verspätete Puffer werden per `.fill(0)` genullt und vor jedem Worker-Aufruf, UI-Update oder Download (`lastDecEpoch`/`lastEncEpoch`/`lastSignEpoch`) verworfen. | `node scripts/test-wipe-regression.mjs` gegen `file:///…/dist/index.html` in Chrome: verzögerter Import + Wipe (`abortCalled=true`, `bufferWasZeroized=true`, `0 Schlüssel`) und verzögerte Entschlüsselung + Wipe (`decAbortCalled=true`, `decBufZeroized=true`, `decResultHidden=true`, `decOutputEmpty=true`, `downloadBlobCreated=false`) (**PASS**) |
| **3. Budget für anonyme Entschlüsselungsversuche** | `audit.pkesk_count * store.secret_keys.len()` zählte nur Schlüssel-Bundles, während rPGP (`TheRing::find_session_key`) bei jedem anonymen PKESK sowohl den Primärschlüssel als auch alle Unterschlüssel über `match_identity` prüft. | `packet_check::estimate_pkesk_decrypt_budget` berechnet vorab die konservative Obergrenze `anonyme_PKESKs × Σ(1 + subkeys.len())` (entspricht rPGPs tatsächlichem Suchraum) und lehnt oberhalb von `MAX_ANON_DECRYPT_ATTEMPTS = 32` ab. | `test_anon_pkesk_budget_multi_subkey_below_at_and_above_limit`: 30 (< 32, PASS), 32 (== 32, PASS), 33 (> 32, REJECT), 34 (> 32, REJECT), 3×11 = 33 (> 32, REJECT) (**PASS**) |

## 3. Praktisch geprüfte Abnahmepunkte

| # | Prüfung | Ergebnis | Nachweis / Details |
|---|---|---|---|
| 1 | Rust-Tests mit `Cargo.lock` (`cargo test --locked --offline`) | **PASS (11/11)** | Alle 8 Kern- und Paket-Audit-Tests + 3 neue Sicherheits-Regressionstests (Schlüsselauswahl & PKESK-Budget) bestanden. |
| 2 | Wasm-Release-Build (`--locked`) & Single-File-HTML-Build | **PASS** | Zwei Läufe von `scripts/build.py` erzeugten byte-identisches `dist/index.html` (`8dcad2931b1583fdcf8500532291d0639ac3204c9b505c448985ced0abe5f0d7`); statische Prüfung auf strenge CSP, kein `unsafe-inline`, keine externen URLs, keine Browser-Storage-APIs bestanden. |
| 3 | Deterministischer Browser-Wipe-Regressionstest (`file://`, Chrome) | **PASS** | `node scripts/test-wipe-regression.mjs` gegen `file:///…/dist/index.html`: Worker startet unter `file://`, verzögerter Datei-Import und verzögerte Datei-Entschlüsselung nach Wipe vollständig verworfen & genullt. |
| 4 | End-to-End-Browser-Test über HTTP (`http://127.0.0.1:8765/`) | **PASS (5/5)** | Worker + Wasm bereit, genau 1 Netzwerkabruf (`GET /`), 0 Konsolen-/CSP-Fehler, v6-Keygen, RFC-9580-Verschlüsselung (`SEIPD v2 · 1 anonyme PKESK (v6)`, ohne `Version:`/`Comment:`), Entschlüsselung mit Integritätsprüfung, Notfall-Wipe. |

## 4. Offene Abnahmepunkte und konkrete Blocker

Folgende Punkte konnten auf dieser Arbeitsumgebung **nicht** ausgeführt werden und bleiben vor einer Produktiv-Freigabe zwingend offen:

1. **GitHub Pages Live-Start (`https://cclol.github.io/pgp/`):**
   - **Blocker:** Repository-Stand ist lokal; GitHub Pages und der Push/Workflow-Lauf auf `cclol/pgp` sind von dieser lokalen Umgebung aus nicht aktiviert/abgerufen worden.
2. **Tor Browser (Online-URL und lokale `dist/index.html` offline):**
   - **Blocker:** Tor Browser ist auf diesem macOS-Host nicht installiert (`/Applications` enthält Chrome, Firefox, Brave, Safari, aber keinen Tor Browser).
3. **Bidirektionale Interoperabilität mit GnuPG und Kleopatra (beide Richtungen, je Profil):**
   - **Blocker:** Weder `gpg` (GnuPG) noch `Kleopatra` sind auf diesem Host installiert (`gpg not found`).
   - **Bekannte Profil-Einschränkung:** GnuPG 2.4.x / ältere Kleopatra-Versionen unterstützen RFC-9580-v6/v2-SEIPD nicht durchgängig; dafür ist das explizit wählbare Profil `Kompatibilität (v1-SEIPD + MDC + anonyme v3-PKESK)` ohne stillen Fallback vorhanden und muss gegen die konkreten Zielversionen geprüft werden.
4. **Externe Release-Signaturprüfung der tatsächlichen `dist/index.html` und Ablehnung einer manipulierten Kopie:**
   - **Blocker:** Kein externer Release-Signaturschlüssel vorhanden (bewusst außerhalb von Repo und CI) und kein externes Verifikationswerkzeug (`gpg` / `sq`) auf diesem Host installiert. Eine interne rPGP-Simulation (`test_release_html_detached_signature_and_tamper_rejection`) lief erfolgreich, ersetzt aber nicht den externen Prüflauf mit unabhängigem Tool und Prüfschlüssel.
5. **SHA-256-Vergleich zweier sauberer Build-Umgebungen:**
   - **Blocker:** Nur eine lokale Build-Umgebung (`aarch64-apple-darwin`) verfügbar; der zweite saubere Vergleichs-Build (z. B. GitHub Actions `ubuntu-24.04`) steht erst nach Push/CI-Ausführung zur Verfügung.

## 5. Systembedingte Sicherheitsgrenzen

- Unveränderliche JS-Strings im Browser-Heap, Browser-Caches, Swap/Auslagerungsspeicher, Absturzabbilder, Browser-Erweiterungen und die Betriebssystem-Zwischenablage liegen außerhalb der Kontrolle einer Web-App.
- `worker.terminate()` beendet den Worker-Thread, garantiert aber auf OS-/Browser-Ebene kein sofortiges physisches Überschreiben aller Speicherseiten.
- Online-Nutzung über GitHub Pages setzt Vertrauen in Server/Auslieferung und Endgerät voraus; für sensible Daten ist die extern signaturgeprüfte, offline geöffnete `dist/index.html` vorgesehen.
