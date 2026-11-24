# Zero-Trace Wasm PGP Vault

Ein vollständig lokaler, selbstständiger OpenPGP-Vault im Browser auf Basis von **Rust/WebAssembly**, **rPGP (`pgp = 0.21.1`)** und **Vanilla JavaScript**. Die gesamte Anwendung wird in eine einzige HTML-Datei (`dist/index.html`) ohne externe Skripte, CDNs, Fonts oder Analytik eingebettet.

- **Online-Einstieg (GitHub Pages):** `https://cclol.github.io/pgp/`
- **Bevorzugter Einstieg für sensible Daten:** Heruntergeladene, extern signaturgeprüfte `index.html` aus GitHub Releases, offline direkt als `file://` im Browser geöffnet.
- **Spezifikation:** [KONZEPT.md](KONZEPT.md) · **Architektur & Befunde:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · **Abnahme & Grenzen:** [docs/VERIFICATION.md](docs/VERIFICATION.md)

## Sicherheitsgrenzen („Zero Trace“)

**Zero Trace** beschreibt das Entwicklungsziel der appseitigen Spurenminimierung:
- Kein `localStorage`, kein `sessionStorage`, kein `IndexedDB`, keine Cookies, kein Service Worker, keine Cache API.
- Kryptokern läuft isoliert in einem dedizierten Web Worker; kontrollierte sensible Rust-Puffer werden mit `zeroize` überschrieben (auch auf Fehlerpfaden).
- Strenge CSP (`default-src 'none'; connect-src 'none'; ...`) per Build-SHA-256-Hash.
- **Keine Garantie gegen OS-/Browser-Spuren:** Browser-Cache, Auslagerungsspeicher (Swap), Absturzabbilder, Browser-Erweiterungen und die Betriebssystem-Zwischenablage liegen außerhalb der Kontrolle einer Web-App.

## Build (lokal & deterministisch)

Voraussetzungen: Rust-Toolchain gemäß `rust-toolchain.toml` (`1.99.1` inkl. Target `wasm32-unknown-unknown`) und Python 3.

```bash
# 1. Rust-Tests inkl. Paket- und Metadatenprüfung
cargo test --locked

# 2. Wasm-Kryptokern bauen
cargo build --target wasm32-unknown-unknown --release --locked

# 3. Selbstständige Single-File-HTML inkl. SHA-256-CSP-Hashes erzeugen
python3 scripts/build.py
```

Ergebnis: `dist/index.html` (identisch für GitHub Pages und GitHub Releases).

## Externe Release-Signierung (außerhalb der CI)

Der Release-Signaturschlüssel bleibt **außerhalb** von GitHub Actions / Pages:

```bash
# Auf dem Offline-/Signatur-System über die vollständige HTML-Datei:
gpg --armor --detach-sign --output index.html.asc dist/index.html
# oder mit Sequoia (sq):
sq sign --detached --signer-file release-key.pgp --output index.html.asc dist/index.html
```

Anschließend `dist/index.html` und `index.html.asc` gemeinsam im GitHub Release veröffentlichen.

## Offline-Prüfung und Nutzung

1. Release-Prüfschlüssel über einen **unabhängigen Kanal** beziehen und dessen Fingerprint verifizieren.
2. `index.html` und `index.html.asc` herunterladen und **vor dem Öffnen** prüfen:
   ```bash
   gpg --import release-signing-key.asc
   gpg --verify index.html.asc index.html
   ```
   Bei manipulierter oder unvollständiger Datei schlägt `gpg --verify` fehl — Datei dann nicht öffnen.
3. Optional Netzwerkverbindung trennen und `index.html` direkt lokal im Browser (`file:///…/index.html`) öffnen.
