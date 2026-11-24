# Architektur, Prototyp-Befunde und OpenPGP-Profil

## 1. Prototyp-Befunde: CSP, Dedizierter Worker, `file://` und Tor Browser

Vor dem Ausbau der Oberfläche wurde ein minimaler Prototyp (`vault-wasm` + `scripts/build.py` + `web/worker.js`) sowohl über lokalen HTTP-Server (`http://127.0.0.1:8765/`) als auch direkt aus der lokalen Datei (`file:///…/dist/index.html`) in Google Chrome geprüft.

### Eingesetzte Content Security Policy
```http
default-src 'none';
connect-src 'none';
base-uri 'none';
form-action 'none';
object-src 'none';
img-src 'none';
font-src 'none';
media-src 'none';
style-src 'sha256-<BUILD_HASH>';
script-src 'sha256-<BUILD_HASH>' 'wasm-unsafe-eval';
worker-src blob:
```

### Beobachtungen & behobener Befund
1. **Kein `fetch()` erforderlich (`connect-src 'none'`):** Wasm-Bytes werden per Base64 im Inline-Skript eingebettet, per `atob()` in einen `Uint8Array` dekodiert, als übertragbarer `ArrayBuffer` (`postMessage(..., [buf])`) in den Worker verschoben und dort per `WebAssembly.instantiate(bytes, imports)` direkt aus dem Speicher instanziiert.
2. **Behobene Race-Condition bei `URL.revokeObjectURL` unter `file://`:** Das synchrone Aufrufen von `URL.revokeObjectURL(workerBlobUrl)` direkt nach `new Worker(workerBlobUrl)` führte unter `file://` dazu, dass der Worker-Script-Load vor Abschluss widerrufen wurde. **Behebung:** Die Worker-Blob-URL wird erst beim ersten `worker.onmessage`- oder `worker.onerror`-Ereignis widerrufen. Nach der Behebung startete der Worker sowohl über `http://127.0.0.1:8765/` als auch über `file://` zuverlässig (`ping=0x50475001`, 0 CSP-Verletzungen, 0 externe Netzwerkanfragen).
3. **Tor Browser:** Im Tor Browser (Firefox ESR) funktioniert `new Worker(blobUrl)` unter `https://` und `file://` mit `worker-src blob:` und `'wasm-unsafe-eval'` in der Sicherheitsstufe **Standard**. In den Sicherheitsstufen **Safer** (je nach Kontext) und **Safest** deaktiviert Tor Browser WebAssembly bzw. JavaScript; die App erkennt fehlendes `WebAssembly`, `Worker` oder `crypto.getRandomValues` explizit beim Start und bricht mit einer klaren Meldung ab.
4. **Kein `SystemTime::now()` in Wasm:** `rPGP 0.21.1` ruft in `Timestamp::now()` und `SubpacketConfig::Default` `std::time::SystemTime::now()` auf, was unter `wasm32-unknown-unknown` panikt. Die App übergibt Zeitstempel daher explizit aus JS (`created_at` / `SubpacketConfig::UserDefined`).
5. **Zufallszahlen:** Ausschließlich Browser-CSPRNG (`self.crypto.getRandomValues` über den Wasm-Import `env.js_getrandom`, in 64-KiB-Chunks wegen der Web-Crypto-Quota). Bei Fehler wird abgebrochen (`getrandom::Error::UNSUPPORTED`), niemals auf einen schwachen PRNG zurückgefallen.

## 2. OpenPGP-Profil (rPGP `pgp = "=0.21.1"`)

| Bereich | Festgelegtes Profil | Hinweis |
|---|---|---|
| Schlüsselerzeugung | **RFC 9580 v6**: Primär **Ed25519** (Certify + Sign), Subkey **X25519** (Encrypt All) | Pseudonyme / leere User-ID unterstützt |
| Private-Key-Schutz | Pflicht-Passphrase (≥ 8 Zeichen, 12+ empfohlen), **Argon2** (`t=3, p=4, m=2^16 KiB = 64 MiB`) + **AES-256-OCB** | Kein ungeschützter Private-Key-Export |
| Verschlüsselung (Standard) | **RFC 9580 v2-SEIPD** + **AES-256** + **AEAD-OCB** (`ChunkSize::C4KiB`) + **anonyme v6-PKESK** (ohne Empfänger-Fingerprint) | **Kein stiller Fallback** auf ältere Formate |
| Verschlüsselung (Kompatibilität) | Explizit wählbar: **v1-SEIPD+MDC** + **AES-256** + **anonyme v3-PKESK** (`KeyId::WILDCARD = 0000000000000000`) | Für Clients ohne RFC-9580-v2-SEIPD (z. B. ältere GnuPG/Kleopatra) |
| Entschlüsselung (Lesen) | Standard: **v2-SEIPD**; **v1-SEIPD+MDC** nur bei explizit aktiviertem Leseprofil | **SED (Tag 9) ohne Integritätsschutz wird immer abgelehnt** |
| Metadaten | Literal-Dateiname `""`, Literal-Zeitstempel `0`, `DataMode::Binary`; ASCII Armor ohne `Version:` und `Comment:` | Direkt an serialisierten Paketen per `packet_check::audit_message_packets` geprüft |
| Integrität vor Freigabe | Vollständiges Lesen & Prüfen des AEAD-Tags / MDC vor Freigabe des Klartexts | Bei Fehler oder Abbruch wird der Puffer per `Zeroizing` überschrieben |

## 3. Schlüsselauswahl und Ressourcen-/Sicherheitsgrenzen (`key_select.rs`, `limits.rs`, `packet_check.rs`)

### OpenPGP-Schlüsselauswahl (`key_select.rs`)
- **Primärschlüssel-Prüfung:** Vor jeder Auswahl werden gültige Selbstsignaturen (Direct Key Signature bzw. User-ID-Selbstzertifizierung), Primärschlüssel-Widerruf (`KeyRevocation`) und Primärschlüssel-Ablauf (`KeyExpirationTime` relativ zu `created_at` gegen `now_secs`) geprüft. Widerrufene oder abgelaufene Zertifikate werden vollständig abgelehnt.
- **Unterschlüssel-Prüfung:** Alle Unterschlüssel werden vollständig durchlaufen (ein ungeeigneter erster Unterschlüssel blockiert spätere gültige Unterschlüssel nicht). Geprüft werden gültige `SubkeyBinding`-Signatur, Abwesenheit gültiger `SubkeyRevocation`, Ablaufzeit (`KeyExpirationTime`), relevante Key Flags (`encrypt_comms`/`encrypt_storage` für Verschlüsselung; `sign` + gültige eingebettete Rücksignatur `Primary Key Binding` für Signatur-Unterschlüssel).
- **Altschlüssel ohne Key Flags:** Importierte Schlüssel/Unterschlüssel ohne explizites `KeyFlags`-Subpaket in der gültigen Selbst- bzw. Bindungssignatur werden **fail-closed abgelehnt**, um eine zweckfremde Nutzung (z. B. Authentifizierungs- oder Zertifizierungsschlüssel als Verschlüsselungsschlüssel) auszuschließen.

### Feste Ressourcen- und Sicherheitsgrenzen (`limits.rs`, `packet_check.rs`)
- Maximale Eingabegröße (Text/Datei/Schlüssel): **16 MiB**
- Maximale dekomprimierte Ausgabe: **32 MiB** und maximales Dekompressionsverhältnis **20×** (ab 64 KiB)
- Maximale Top-Level-Paketanzahl: **64**
- Maximale Empfängerzahl: **32**
- **Budget für anonyme Entschlüsselungsversuche (`MAX_ANON_DECRYPT_ATTEMPTS = 32`):** In `rPGP 0.21.1` (`TheRing::find_session_key`) matcht jedes anonyme PKESK (`v3` mit `KeyId::WILDCARD` oder `v6` ohne Empfänger-Fingerprint) über `match_identity` **jeden Primärschlüssel und jeden Unterschlüssel** jedes geladenen geheimen Schlüssels, ohne über PKESKs hinweg abzubrechen. Vor dem Start jeder KDF-/Entschlüsselungsoperation berechnet `estimate_pkesk_decrypt_budget` die exakte konservative Obergrenze `anonyme_PKESKs × Σ(1 + subkeys.len())` und lehnt Nachrichten oberhalb von 32 Versuchen ab.
- S2K-Argon2-Limits beim Import/Entsperren: `m_enc ≤ 18` (**256 MiB**), `t ≤ 16`, `p ≤ 16`

## 4. Speicher- und Kopie-Inventar an den JS-/Wasm-Grenzen

1. **DOM-Eingabefelder (`<input type="password">`, `<textarea>`):** Passphrase-Felder werden sofort beim Start der Operation geleert (`el.value = ""`), bevor auf den Worker gewartet wird. Alle Eingabefelder deaktivieren `autocomplete`, `autocorrect`, `autocapitalize` und `spellcheck`.
2. **JS-Bytepuffer (`Uint8Array`):** Werden nach Base64-Kodierung bzw. beim Wipe mit `.fill(0)` überschrieben.
3. **JS-Strings (Base64 / JSON / Textarea-Werte):** JavaScript-Strings sind unveränderlich und unterliegen der Garbage Collection des Browsers — eine deterministische Überschreibung im JS-Heap ist technisch nicht garantierbar.
4. **Worker-Transfer & Wasm-Linear-Memory:** Wasm-Bytes werden per Transferable (`ArrayBuffer`) übergeben und nach Instanziierung genullt. Im Worker werden `reqBytes`, `respCopy`, der Wasm-Eingabepuffer und der Wasm-Ausgabepuffer in `finally` bzw. `vault_dealloc` per `zeroize` überschrieben.
5. **Rust-Puffer (`Zeroizing<Vec<u8>>`, `Zeroizing<String>`):** Passphrasen, Klartextpuffer und exportierte Secret-Key-Strings werden auf allen Pfaden (einschließlich Fehlerpfaden) mit `zeroize` bereinigt.
6. **Epoch- und FileReader-Schutz gegen verspätete Ergebnisse:** Jede asynchrone Operation (Import, Verschlüsselung, Entschlüsselung, Signieren, Verifizieren, Schlüsselerzeugung) bindet sich ab ihrem Start an `sessionEpoch` und registriert aktive `FileReader` in `activeFileReaders`. Beim Wipe oder Abbruch wird `sessionEpoch` sofort erhöht, alle laufenden `FileReader` werden per `reader.abort()` abgebrochen, verspätete `onload`-Puffer sofort per `.fill(0)` genullt und verspätete Worker-Nachrichten oder Download-Aktionen mit veralteter `epoch` strikt verworfen. Hängt der Worker länger als 400 ms beim Wipe, wird er terminiert (`worker.terminate()`) und frisch gestartet.
