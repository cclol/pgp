# Verification Log, Security Review, and Open Boundaries

> **Release status: TEST BUILD (not yet released)**
>
> All confirmed code-level security findings from both the initial and fresh reviews have been fixed and verified with automated Rust and browser regression tests. Because external release gates (Tor Browser, GnuPG/Kleopatra interoperability, independent two-environment reproducibility check, external detached signature verification, and live Pages deployment of the updated English build) remain open, this build is explicitly marked as a **test build**.

## 1. Environment & Tool Versions

- **OS / Architecture:** macOS (`aarch64-apple-darwin`)
- **Rust / Cargo:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1 (5f94df478 2026-08-27)` (`rust-toolchain.toml`, target `wasm32-unknown-unknown`)
- **rPGP:** `pgp = "=0.21.1"` (checked-in `Cargo.lock`, built with `--locked --offline`)
- **Python:** `Python 3.14.7`
- **Node.js:** `v20.20.2`
- **Browsers tested locally:**
  - **Google Chrome:** `158.0.8127.88`
  - **Mozilla Firefox:** `158.0.1`
- **Tools not installed on this host:** `gpg` (GnuPG), `Kleopatra`, `sq` (Sequoia), `Tor Browser`

## 2. Built Local Artifact (Current Workspace)

- **Wasm binary (`target/wasm32-unknown-unknown/release/vault_wasm.wasm`):** `2,632,814` bytes · SHA-256 `87208772647712cc5340db87fba5205c3ef16576eb4fcbfea43272ca011f34ae`
- **Standalone HTML (`dist/index.html`):** `3,579,073` bytes · SHA-256 `860aaa0412249164ee3aad980efed85747629f699fc257d7ba5883097eea7346`
- **CSP hashes embedded in `dist/index.html`:**
  - `style-src 'sha256-rqK/7OxggKjW+nXJM44BSaAudDQnfCdiXxr/yb6Vs0k='`
  - `script-src 'sha256-ZfaFTUcnQ9siV4ayD//NlGnjt0GweGK550q1gvIhuoc=' 'wasm-unsafe-eval'`
  - `worker-src blob:`

## 2b. Key Generation Profiles, Private-Key Protection, and Signature Hashes

| Profile | Packet Version & Algorithms | Key Flags & Self-Signatures | Private-Key Protection (Passphrase Required) | Signing & Verification Hash Behavior |
|---|---|---|---|---|
| **Modern (default)** (`modern`) | **OpenPGP v6 (RFC 9580):** Primary **Ed25519** + Subkey **X25519** | v6 Direct Key Signature (`Certify + Sign` = `0x03`), optional v6 `CertPositive` User ID self-signature, v6 `SubkeyBinding` (`EncryptComms + EncryptStorage` = `0x0C`) | **S2K Usage 253 (AEAD)** + **Argon2** (`t=3, p=4, m_enc=16` / `64 MiB`) + **AES-256-OCB** | **Vault signing:** always **SHA-256** (v6 signature with random salt and hashed `IssuerFingerprint`). **Verification:** SHA-256 / SHA-512 supported. |
| **Compatibility (Kleopatra / GnuPG)** (`compat_rsa4096`) | **OpenPGP v4 (RFC 4880):** Primary **RSA-4096** (4096-bit modulus) + Subkey **RSA-4096** (4096-bit modulus) | Non-empty User ID required; v4 `CertPositive` User ID self-signature (`Certify + Sign` = `0x03`, `IsPrimary=true`, `Features: SEIPD v1`, preferred sym/hash/compression, hashed `IssuerFingerprint` + unhashed `IssuerKeyId`); v4 `SubkeyBinding` (`EncryptComms + EncryptStorage` = `0x0C`, hashed `IssuerFingerprint` + unhashed `IssuerKeyId`) | **S2K Usage 254 (CFB + 20-octet SHA-1 checksum)** + **Iterated & Salted S2K** (Type 3, `SHA-256`, coded `count=224` / `65,536,000` octets) + **AES-256-CFB** (16-octet IV) | **Vault signing:** always **SHA-256** (v4 signature with hashed `IssuerFingerprint` and unhashed `IssuerKeyId`). **Verification:** both **SHA-256** and **SHA-512** (plus SHA-384) verified and tested on RSA-4096 keys. |

## 3. Confirmed Security Findings Fixed & Regression Tests

### Previous Findings (Re-verified)

| Finding | Cause | Fix | Regression Test |
|---|---|---|---|
| **1. OpenPGP encryption/signing key selection** | Previous selection only checked `algorithm().can_encrypt()/can_sign()` without validating revocations, expirations, bindings, or `KeyFlags`. | `crates/vault-wasm/src/key_select.rs` validates primary self-signatures, `KeyRevocation`, `KeyExpirationTime`, `SubkeyBinding`, `SubkeyRevocation`, explicit `KeyFlags`, and signing-subkey `Primary Key Binding` backsignatures; rejects legacy keys without `KeyFlags` fail-closed. | `test_key_selection_rejects_expired_revoked_wrong_flags_and_missing_flags`, `test_key_selection_skips_unsuitable_first_subkey_and_picks_later_valid_subkey` (**PASS**) |
| **2. Emergency Wipe vs. in-flight file operations** | `FileReader` reads were not bound to `sessionEpoch` or aborted on wipe. | Operations bind to `opEpoch = sessionEpoch`; active `FileReader`s are aborted on wipe; late buffers are zeroized and discarded before RPC, UI update, or download. | `node scripts/test-wipe-regression.mjs` Tests 1 & 2 (**PASS**) |
| **3. Anonymous PKESK decryption budget** | Counting only key bundles undercounted rPGP's actual search space across primary keys and subkeys. | `packet_check::estimate_pkesk_decrypt_budget` computes `anon_PKESKs × Σ(1 + subkeys.len())` before decryption and rejects above `MAX_ANON_DECRYPT_ATTEMPTS = 32`. | `test_anon_pkesk_budget_multi_subkey_below_at_and_above_limit` (**PASS**) |

### New Findings Identified & Fixed in Fresh Review

| Finding & Severity | Impact & Location | Fix | Regression Test |
|---|---|---|---|
| **4. Signature verification bypassed key eligibility checks (HIGH)** | `verify_inline_signatures` and `verify_detached` in `crates/vault-wasm/src/crypto.rs` verified signatures against raw primary keys and all subkeys without checking revocations, expirations, `SubkeyBinding`, explicit `Sign` Key Flags, signing-subkey `Primary Key Binding` backsignatures, or data signature expiration. A revoked/expired key or spoofed/unflagged subkey could display as `VALID`. | Added `select_verifying_keys` and exported `is_signature_active` in `crates/vault-wasm/src/key_select.rs`; passed `now_secs` in `DecryptRequest` and `VerifyDetachedRequest` (`web/app.js`, `crates/vault-wasm/src/crypto.rs`); tightened backsignature type & active-window checks in `select_signing_target`. | `test_signature_verification_rejects_revoked_expired_and_unbacksigged_keys` (**PASS**) |
| **5. Resource-limit & packet-audit gaps (MEDIUM)** | `crates/vault-wasm/src/crypto.rs`, `limits.rs`, `packet_check.rs`: (a) Base64 inputs were decoded before checking size; (b) SKESK packets were not checked for excessive S2K Argon2 parameters in `inspect_raw_packets`; (c) multiple SEIPD packets overwrote `seipd_version`, allowing v1-SEIPD smuggling behind v2-SEIPD; (d) nested compressed packets were not explicitly rejected; (e) total matched PKESK attempts were not capped alongside anonymous attempts. | Added `check_base64_input_size` before `B64.decode`; added SKESK S2K parameter checks in `inspect_raw_packets`; added `seipd_count` to `PacketAudit` and enforced `seipd_count == 1`; rejected nested `Message::Compressed`; capped total PKESK attempts at `MAX_TOTAL_DECRYPT_ATTEMPTS = 64`. | `test_rejects_v1_seipd_tamper_truncation_and_multi_seipd_smuggling` + all 13 Rust tests (**PASS**) |
| **6. `performWipe` re-entrancy & `btn-abort` state desync (MEDIUM)** | `web/app.js`: (a) `performWipe` temporarily overwrote `worker.onmessage` and restored `prevHandler` on `wiped`; a rapid double-wipe captured the temporary handler and permanently broke `worker.onmessage` while leaking stale fallback timers. (b) `btn-abort` respawned the Worker (clearing Rust's `SessionStore`) without clearing `sessionKeys` or UI fields. (c) Keygen download buttons did not zeroize temporary `Uint8Array` buffers. | Handled `wiped` inside the single `worker.onmessage` handler using `pendingWipeEpoch` and a single `wipeFallbackTimer`; routed `btn-abort` through `performWipe(..., true)`; zeroized temporary `Uint8Array` buffers on keygen download; guarded `ConfirmIdentity`/`RemoveKey` clicks with `opEpoch`. | `node scripts/test-wipe-regression.mjs` Tests 3, 4 & 5 (**PASS**) |

## 4. Executed Verification Runs

| # | Check | Command / Target | Result | Details |
|---|---|---|---|---|
| 1 | Locked Rust unit, key-selection, integrity, packet-audit & RSA-4096 compatibility tests | `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --offline` | **PASS (14/14)** | All 13 prior tests + `test_compat_rsa4096_keygen_packet_inspection_and_sha256_sha512_interop`: verifies Modern v6 (`Ed25519` + `X25519`, Argon2 + AES-256-OCB) and Compatibility v4 (`RSA-4096` primary + `RSA-4096` subkey, 4096-bit MPI moduli, `Certify+Sign` & `EncryptComms+EncryptStorage` Key Flags, S2K Usage 254 CFB + 20-byte SHA-1 checksum + Iterated & Salted SHA-256 `count=224` + AES-256-CFB), explicit rejection of missing passphrase / empty v4 User ID / unknown profile, SHA-256 signing, SHA-256 and SHA-512 RSA-4096 signature verification, `compat_seipd_v1` encryption/decryption, and simulated external Kleopatra/GnuPG v4 RSA-4096 secret key import + non-anonymous v3-PKESK decryption + inline SHA-512 signature verification. |
| 2 | Locked Wasm release build & local deterministic single-file HTML rebuild | `cargo build --target wasm32-unknown-unknown --release --locked --offline && python3 scripts/build.py` (×2) | **PASS** | Two consecutive local builds produced identical `dist/index.html` (`860aaa0412249164ee3aad980efed85747629f699fc257d7ba5883097eea7346`). Static checks confirmed strict CSP, no `unsafe-inline`, no `http://`/`https://` URLs, `lang="en"`, and 0 German UI strings. |
| 3 | Chrome Wipe, Cancel & session-isolation regression suite (`file://`) | `node scripts/test-wipe-regression.mjs` (Chrome `158.0.8127.88`) | **PASS (6/6)** | Verified delayed `FileReader` import + Wipe, delayed `FileReader` decrypt + Wipe, delayed Worker `rpc_result` import after Wipe + Worker restart, delayed Worker `rpc_result` decrypt (with real plaintext) after Wipe + Worker restart, rapid double Emergency Wipe, and delayed Worker `rpc_result` for `GenerateKey` arriving after `Abort operation` (`btn-abort`) / Wipe (confirming no keys are restored and `btn-kg-pub-dl` / `btn-kg-sec-dl` create no download Blob). |
| 4 | Chrome E2E crypto, CSP, storage & English UI check — Modern v6 & Compatibility v4 RSA-4096 (`file://`) | Chrome `158.0.8127.88` via CDP against `file:///…/dist/index.html` | **PASS** | Verified default `modern` profile (RFC 9580 v6 keygen, v2-SEIPD encrypt+sign, decrypt+verify, detached sign+verify) and `compat_rsa4096` profile: explicit UI error on empty v4 User ID, RSA-4096 + RSA-4096 generation inside Wasm Worker (`14,682 ms`, `587` main-thread 25 ms UI timer ticks proving UI responsiveness, `Abort operation` button visible during generation, passphrase fields cleared immediately), `V4 · RSA` badge, 40-hex-char v4 fingerprint, no `Version:`/`Comment:` armor headers, `compat_seipd_v1` (`SEIPD v1 · 1 anonymous PKESK (v3)`) encrypt+sign, decrypt+verify with `allow_legacy_seipd_v1`, and detached sign+verify. |
| 5 | Firefox E2E crypto, CSP, storage & English UI check (`file://`) | Firefox `158.0.1` via WebDriver BiDi against `file:///…/dist/index.html` | **PASS** | `lang="en"`, 0 German matches, strict CSP, 0 CSP violations, 0 storage items, full RFC 9580 v6 keygen, encrypt+sign, decrypt+verify, detached sign+verify, password fields cleared, Emergency Wipe verified. |
| 6 | Live GitHub Pages deployment audit (synthetic data only) | `https://cclol.github.io/pgp/` (currently deployed build) | **PASS (with drift noted)** | HTTP 200, 1 total network request (`GET https://cclol.github.io/pgp/`), 0 third-party requests, strict CSP (`default-src 'none'`, `connect-src 'none'`, `worker-src blob:`), 0 console errors, synthetic keygen/encrypt/decrypt/wipe succeeded. **Note:** Live site still serves the earlier German build (`Wasm SHA-256: cd21bcbfec53b53d29a93ba023543784695d335da7116c0774e77b7a6da1a9bd`) pending explicit publish approval; browser storage APIs could not be queried in the webview harness on the live origin. |

## 5. Remaining Findings & Open Blockers

### Remaining Non-Critical Findings
1. **Low — Pages workflow deploys on every push to `main` (`.github/workflows/pages.yml#L3-L9`, `#L69`):** `CONCEPT.md` specifies binding deployments to a verified release state. Currently, `deploy` runs on pushes to `main` as well as `v*` tags, and CI does not yet run `scripts/test-wipe-regression.mjs`. Permissions are otherwise minimal (`contents: read` on `build`; `pages: write` + `id-token: write` on `deploy`) and all GitHub Actions are pinned to full commit SHAs.
2. **Low — Live GitHub Pages deployment drift (`https://cclol.github.io/pgp/`):** The public site currently serves the pre-translation German build (`cd21bcbf…`) without the new security fixes or the Compatibility RSA-4096 key generation profile. Publishing is intentionally left for explicit user approval.

### Open Acceptance Blockers (Not Verified in This Environment)
1. **Tor Browser (online URL and offline `dist/index.html`):** Not tested — Tor Browser is not installed on this macOS host (`/Applications` contains Chrome, Firefox, Brave, and Safari only).
2. **Live Kleopatra and GnuPG CLI/GUI bidirectional execution:** Could not be executed against a live `kleopatra` or `gpg` binary on this host because neither `Kleopatra` nor `gpg` (GnuPG) nor `sq` (Sequoia) is installed (`which gpg kleopatra sq` returned not found; `/Applications`, `/opt`, and `/usr/local` contain no GnuPG/Kleopatra bundle).
   - **What was verified locally:** Packet-level inspection of the vault's `Compatibility (OpenPGP v4 RSA-4096)` export confirmed exact RFC 4880 v4 packet version, 4096-bit RSA moduli on both primary and subkey, v4 `CertPositive` (`Certify + Sign`) and `SubkeyBinding` (`EncryptComms + EncryptStorage`) signatures with hashed `IssuerFingerprint` and unhashed `IssuerKeyId`, and S2K Usage 254 (`AES-256-CFB` + 20-byte SHA-1 checksum + Iterated & Salted SHA-256 `count=224`). In addition, a passphrase-protected v4 RSA-4096 secret key locked with standard GnuPG/Kleopatra S2K Usage 254 parameters and a non-anonymous v3-PKESK + v1-SEIPD message signed with SHA-512 were imported, unlocked, decrypted, and verified in the vault's Rust test suite (`test_compat_rsa4096_keygen_packet_inspection_and_sha256_sha512_interop`).
   - **What remains to run on a host with Kleopatra/GnuPG installed:** Import the vault-exported `vault-secret-key.asc` into Kleopatra, unlock it with its passphrase, sign and decrypt a test message in Kleopatra, and export a passphrase-protected RSA-4096 key from Kleopatra into the vault.
3. **Independent reproducibility check across two clean environments:** Not verified — a **local rebuild** was verified deterministic on `aarch64-apple-darwin` (identical SHA-256 across repeated runs), but an **independent reproducibility check** comparing `dist/index.html` against a second clean environment (such as GitHub Actions `ubuntu-24.04`) has not been performed for this commit.
4. **External detached release signature verification of the actual release artifact:** Not verified — no external release signing key (kept outside the repo and CI by design) and no external verification CLI (`gpg` / `sq`) are present on this host. The internal Rust test (`test_release_html_detached_signature_and_tamper_rejection`) validates rPGP's detached signing/tamper rejection logic only and does not replace external verification of the actual release `dist/index.html` with an independently obtained key.

## 6. Inherent Security Boundaries

- **Zero Trace** minimizes app-controlled traces and persistent session data; immutable JS strings in the browser heap, browser caches, swap space, crash dumps, browser extensions, and the operating-system clipboard remain outside a web app's control.
- `worker.terminate()` terminates the Worker thread, but does not guarantee immediate physical overwriting of memory pages by the browser or OS.
- Online usage via GitHub Pages requires trusting the served code, GitHub Pages, and the endpoint device; for sensitive data, verify the external release signature of `index.html` and open it offline.
