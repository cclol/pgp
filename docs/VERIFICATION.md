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

- **Wasm binary (`target/wasm32-unknown-unknown/release/vault_wasm.wasm`):** `2,618,240` bytes · SHA-256 `8bd3157bcfd78f2079863ea3515dc32181e818be3486276b50d75646173fa7ec`
- **Standalone HTML (`dist/index.html`):** `3,555,293` bytes · SHA-256 `18745f7af62ee3d9f3cb136a47038517e564e2705e72b4acad36e2646237ba00`
- **CSP hashes embedded in `dist/index.html`:**
  - `style-src 'sha256-rqK/7OxggKjW+nXJM44BSaAudDQnfCdiXxr/yb6Vs0k='`
  - `script-src 'sha256-ukjQbownz3F/TMCpZR6BMMv2T82bAlZTwE81oTCg+i4=' 'wasm-unsafe-eval'`
  - `worker-src blob:`

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
| 1 | Locked Rust unit, key-selection, integrity & packet-audit tests | `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --offline` | **PASS (13/13)** | All 11 prior tests + 2 new security regression tests (verifying-key eligibility; v1-SEIPD tamper/truncation + multi-SEIPD smuggling). |
| 2 | Locked Wasm release build & local deterministic single-file HTML rebuild | `cargo build --target wasm32-unknown-unknown --release --locked --offline && python3 scripts/build.py` (×2) | **PASS** | Two consecutive local builds produced identical `dist/index.html` (`18745f7af62ee3d9f3cb136a47038517e564e2705e72b4acad36e2646237ba00`). Static checks confirmed strict CSP, no `unsafe-inline`, no `http://`/`https://` URLs, `lang="en"`, and 0 German UI strings. |
| 3 | Chrome Wipe & session-isolation regression suite (`file://`) | `node scripts/test-wipe-regression.mjs` (Chrome `158.0.8127.88`) | **PASS (5/5)** | Verified delayed `FileReader` import + Wipe, delayed `FileReader` decrypt + Wipe, delayed Worker `rpc_result` import after Wipe + Worker restart, delayed Worker `rpc_result` decrypt (with real plaintext) after Wipe + Worker restart, and rapid double Emergency Wipe. |
| 4 | Chrome E2E crypto, CSP, storage & English UI check (`file://`) | Chrome `158.0.8127.88` via CDP against `file:///…/dist/index.html` | **PASS** | `lang="en"`, 0 German matches, strict CSP, 0 CSP violations, 0 storage items (`localStorage=0`, `sessionStorage=0`, `cookie=""`), full RFC 9580 v6 keygen, encrypt+sign (`SEIPD v2 · 1 anonymous PKESK (v6)`, no `Version:`/`Comment:`), decrypt+verify, detached sign+verify, password fields cleared, Emergency Wipe verified. |
| 5 | Firefox E2E crypto, CSP, storage & English UI check (`file://`) | Firefox `158.0.1` via WebDriver BiDi against `file:///…/dist/index.html` | **PASS** | Identical full pass: `lang="en"`, 0 German matches, strict CSP, 0 CSP violations, 0 storage items, full RFC 9580 v6 keygen, encrypt+sign, decrypt+verify, detached sign+verify, password fields cleared, Emergency Wipe verified. |
| 6 | Live GitHub Pages deployment audit (synthetic data only) | `https://cclol.github.io/pgp/` (currently deployed build) | **PASS (with drift noted)** | HTTP 200, 1 total network request (`GET https://cclol.github.io/pgp/`), 0 third-party requests, strict CSP (`default-src 'none'`, `connect-src 'none'`, `worker-src blob:`), 0 console errors, synthetic keygen/encrypt/decrypt/wipe succeeded. **Note:** Live site still serves the earlier German build (`Wasm SHA-256: cd21bcbfec53b53d29a93ba023543784695d335da7116c0774e77b7a6da1a9bd`) pending explicit publish approval; browser storage APIs could not be queried in the webview harness on the live origin. |

## 5. Remaining Findings & Open Blockers

### Remaining Non-Critical Findings
1. **Low — Pages workflow deploys on every push to `main` (`.github/workflows/pages.yml#L3-L9`, `#L69`):** `CONCEPT.md` specifies binding deployments to a verified release state. Currently, `deploy` runs on pushes to `main` as well as `v*` tags, and CI does not yet run `scripts/test-wipe-regression.mjs`. Permissions are otherwise minimal (`contents: read` on `build`; `pages: write` + `id-token: write` on `deploy`) and all GitHub Actions are pinned to full commit SHAs.
2. **Low — Live GitHub Pages deployment drift (`https://cclol.github.io/pgp/`):** The public site currently serves the pre-translation German build (`cd21bcbf…`) without the new security fixes from Section 3. Publishing is intentionally left for explicit user approval.

### Open Acceptance Blockers (Not Verified in This Environment)
1. **Tor Browser (online URL and offline `dist/index.html`):** Not tested — Tor Browser is not installed on this macOS host (`/Applications` contains Chrome, Firefox, Brave, and Safari only).
2. **GnuPG and Kleopatra bidirectional interoperability:** Not tested — neither `gpg` nor `Kleopatra` is installed on this host. Known profile note: GnuPG 2.4.x / older Kleopatra releases may not support RFC 9580 v6 keys / v2-SEIPD; the explicit `Compatibility (v1-SEIPD + MDC + AES-256 + anonymous v3-PKESK)` profile exists for this purpose and still requires live bidirectional testing against exact target versions.
3. **Independent reproducibility check across two clean environments:** Not verified — a **local rebuild** was verified deterministic on `aarch64-apple-darwin` (identical SHA-256 across repeated runs), but an **independent reproducibility check** comparing `dist/index.html` against a second clean environment (such as GitHub Actions `ubuntu-24.04`) has not been performed for this commit.
4. **External detached release signature verification of the actual release artifact:** Not verified — no external release signing key (kept outside the repo and CI by design) and no external verification CLI (`gpg` / `sq`) are present on this host. The internal Rust test (`test_release_html_detached_signature_and_tamper_rejection`) validates rPGP's detached signing/tamper rejection logic only and does not replace external verification of the actual release `dist/index.html` with an independently obtained key.

## 6. Inherent Security Boundaries

- **Zero Trace** minimizes app-controlled traces and persistent session data; immutable JS strings in the browser heap, browser caches, swap space, crash dumps, browser extensions, and the operating-system clipboard remain outside a web app's control.
- `worker.terminate()` terminates the Worker thread, but does not guarantee immediate physical overwriting of memory pages by the browser or OS.
- Online usage via GitHub Pages requires trusting the served code, GitHub Pages, and the endpoint device; for sensitive data, verify the external release signature of `index.html` and open it offline.
