# Zero-Trace Wasm PGP Vault

A fully local, self-contained OpenPGP vault in the browser built with **Rust/WebAssembly**, **rPGP (`pgp = 0.21.1`)**, and **Vanilla JavaScript**. The entire application is bundled into a single HTML file (`dist/index.html`) with no external scripts, CDNs, fonts, or analytics.

- **Online entry point (GitHub Pages):** `https://cclol.github.io/pgp/`
- **Preferred entry point for sensitive data:** Downloaded, externally signature-verified `index.html` from GitHub Releases, opened offline directly via `file://` in the browser.
- **Specification:** [CONCEPT.md](CONCEPT.md) · **Architecture & Findings:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · **Verification & Limits:** [docs/VERIFICATION.md](docs/VERIFICATION.md)

## Security Boundaries ("Zero Trace")

**Zero Trace** describes the design goal of minimizing app-controlled traces and persistent session data:
- No `localStorage`, no `sessionStorage`, no `IndexedDB`, no cookies, no Service Worker, and no app-managed Cache API.
- The crypto core runs isolated in a dedicated Web Worker; controlled sensitive Rust buffers are overwritten with `zeroize` (including on error paths).
- Strict CSP (`default-src 'none'; connect-src 'none'; ...`) using build-time SHA-256 hashes.
- **No guarantee against OS/browser copies:** browser caches, swap space, crash dumps, browser extensions, and the operating-system clipboard are outside a web app's control.

## Build (Local & Deterministic)

Prerequisites: Rust toolchain matching `rust-toolchain.toml` (`1.99.1` including the `wasm32-unknown-unknown` target) and Python 3.

```bash
# 1. Run Rust tests including packet, key-selection, and metadata checks
cargo test --locked

# 2. Build the Wasm crypto core
cargo build --target wasm32-unknown-unknown --release --locked

# 3. Build the standalone single-file HTML with SHA-256 CSP hashes
python3 scripts/build.py
```

Output: `dist/index.html` (same artifact format for GitHub Pages and GitHub Releases).

## External Release Signing (Outside CI)

The release signing key stays **outside** GitHub Actions and GitHub Pages:

```bash
# On an offline signing machine, sign the complete HTML file:
gpg --armor --detach-sign --output index.html.asc dist/index.html
# or with Sequoia (sq):
sq sign --detached --signer-file release-key.pgp --output index.html.asc dist/index.html
```

Publish `dist/index.html` and `index.html.asc` together in the GitHub Release.

## Offline Verification and Usage

1. Obtain the release verification public key over an **independent channel** and verify its fingerprint.
2. Download `index.html` and `index.html.asc` and verify the signature **before opening** the file:
   ```bash
   gpg --import release-signing-key.asc
   gpg --verify index.html.asc index.html
   ```
   If the file is modified or truncated, `gpg --verify` fails — do not open the file.
   *(Note: a local rebuild checks your own build pipeline; an independent reproducibility check compares hashes across two clean environments; external signature verification validates the actual distributed release artifact against the trusted release key.)*
3. Optionally disconnect from the network and open `index.html` locally in the browser (`file:///…/index.html`).
