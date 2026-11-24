# Architecture, Prototype Findings, and OpenPGP Profile

## 1. Prototype Findings: CSP, Dedicated Worker, `file://`, and Tor Browser

Before building out the full interface, a minimal prototype (`vault-wasm` + `scripts/build.py` + `web/worker.js`) was verified both over a local HTTP server (`http://127.0.0.1:8765/`) and directly from the local file (`file:///…/dist/index.html`) in Google Chrome.

### Content Security Policy
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

### Observations & Resolved Issues
1. **No `fetch()` required (`connect-src 'none'`):** Wasm bytes are embedded as Base64 in the inline script, decoded via `atob()` into a `Uint8Array`, moved into the Worker as a transferable `ArrayBuffer` (`postMessage(..., [buf])`), and instantiated directly from memory via `WebAssembly.instantiate(bytes, imports)`.
2. **Resolved `URL.revokeObjectURL` race condition under `file://`:** Calling `URL.revokeObjectURL(workerBlobUrl)` synchronously right after `new Worker(workerBlobUrl)` revoked the Worker script before it finished loading under `file://`. **Fix:** Revoke the Worker Blob URL on the first `worker.onmessage` or `worker.onerror` event. After this fix, the Worker started reliably over both `http://127.0.0.1:8765/` and `file://` (`ping=0x50475001`, 0 CSP violations, 0 external network requests).
3. **Tor Browser:** In Tor Browser (Firefox ESR), `new Worker(blobUrl)` works under `https://` and `file://` with `worker-src blob:` and `'wasm-unsafe-eval'` at the **Standard** security level. At **Safer** (depending on context) and **Safest**, Tor Browser disables WebAssembly or JavaScript; the app explicitly checks for `WebAssembly`, `Worker`, and `crypto.getRandomValues` at startup and aborts with a clear message if unavailable.
4. **No `SystemTime::now()` in Wasm:** `rPGP 0.21.1` calls `std::time::SystemTime::now()` in `Timestamp::now()` and `SubpacketConfig::Default`, which panics on `wasm32-unknown-unknown`. The app therefore passes explicit timestamps from JS (`now_secs` / `SubpacketConfig::UserDefined`).
5. **Randomness:** Drawn exclusively from the browser CSPRNG (`self.crypto.getRandomValues` via the Wasm import `env.js_getrandom`, in 64 KiB chunks to respect the Web Crypto quota). On failure, the call aborts (`getrandom::Error::UNSUPPORTED`) and never falls back to a weak PRNG.

## 2. OpenPGP Profile (rPGP `pgp = "=0.21.1"`)

| Area | Selected Profile | Notes |
|---|---|---|
| Key generation | **RFC 9580 v6**: Primary **Ed25519** (Certify + Sign), Subkey **X25519** (Encrypt All) | Pseudonymous / empty User ID supported |
| Private key protection | Mandatory passphrase (≥ 8 chars, 12+ recommended), **Argon2** (`t=3, p=4, m=2^16 KiB = 64 MiB`) + **AES-256-OCB** | No unprotected private key export |
| Encryption (default) | **RFC 9580 v2-SEIPD** + **AES-256** + **AEAD-OCB** (`ChunkSize::C4KiB`) + **anonymous v6-PKESK** (omitted recipient fingerprint) | **No silent fallback** to legacy formats |
| Encryption (compatibility) | Explicitly selectable: **v1-SEIPD+MDC** + **AES-256** + **anonymous v3-PKESK** (`KeyId::WILDCARD = 0000000000000000`) | For clients lacking RFC 9580 v2-SEIPD (e.g., older GnuPG/Kleopatra) |
| Decryption (read) | Default: **v2-SEIPD**; **v1-SEIPD+MDC** only with explicit read-profile opt-in | **Unauthenticated SED (Tag 9) and multi-SEIPD packets are always rejected** |
| Metadata | Literal filename `""`, literal timestamp `0`, `DataMode::Binary`; ASCII Armor without `Version:` or `Comment:` headers | Audited directly on serialized packets via `packet_check::audit_message_packets` |
| Integrity before release | Full read & verification of the AEAD tag / MDC before releasing plaintext | On error or abort, partial buffers are zeroized via `Zeroizing` |

## 3. Key Selection, Signature Verification, and Resource Limits (`key_select.rs`, `limits.rs`, `packet_check.rs`)

### OpenPGP Key Selection & Verification Eligibility (`key_select.rs`)
- **Primary key validation:** Before any encryption, signing, or signature verification, the app validates primary self-signatures (Direct Key Signature or non-revoked User-ID self-certification), primary key revocation (`KeyRevocation`), and primary key expiration (`KeyExpirationTime` relative to `created_at` against `now_secs`). Revoked or expired certificates are rejected completely.
- **Subkey validation:** All subkeys are scanned (an unsuitable first subkey never masks a later valid subkey). Each candidate subkey is checked for a valid active `SubkeyBinding`, absence of `SubkeyRevocation`, expiration (`KeyExpirationTime`), explicit `KeyFlags` (`encrypt_comms`/`encrypt_storage` for encryption; `sign` + valid active embedded `Primary Key Binding` backsignature for signing and verifying subkeys).
- **Signature verification eligibility:** Both inline signature verification (`verify_inline_signatures`) and detached signature verification (`verify_detached`) only accept signatures verified against keys returned by `select_verifying_keys` and only if the data signature itself is active (not expired and not future-dated at `now_secs`).
- **Legacy keys without Key Flags:** Imported keys or subkeys lacking an explicit `KeyFlags` subpacket in their valid self-signature or binding signature are **rejected fail-closed** to prevent cross-purpose key misuse (such as using an authentication or certification key for encryption or signing).

### Hard Resource and Security Limits (`limits.rs`, `packet_check.rs`)
- Maximum input size (text/file/key): **16 MiB** (pre-checked on Base64 length before decoding, and again on decoded bytes)
- Maximum decompressed output: **32 MiB** and maximum decompression ratio **20×** (above a 64 KiB floor); nested compressed packets are rejected
- Maximum top-level packet count: **64**
- Maximum recipient count: **32**
- **Anonymous & total PKESK decryption attempt budget (`MAX_ANON_DECRYPT_ATTEMPTS = 32`, `MAX_TOTAL_DECRYPT_ATTEMPTS = 64`):** In `rPGP 0.21.1` (`TheRing::find_session_key`), every anonymous PKESK (`v3` with `KeyId::WILDCARD` or `v6` with omitted fingerprint) matches every primary key and every subkey of every loaded secret key via `match_identity`. Before running any KDF or asymmetric decryption, `estimate_pkesk_decrypt_budget` computes the exact conservative upper bound `anon_PKESKs × Σ(1 + subkeys.len())` (and total matched PKESK attempts) and rejects messages exceeding the budget.
- S2K Argon2 limits on secret keys and SKESK packets: `m_enc ≤ 18` (**256 MiB**), `t ≤ 16`, `p ≤ 16`

## 4. Memory and Copy Inventory Across JS/Wasm Boundaries

1. **DOM inputs (`<input type="password">`, `<textarea>`):** Passphrase fields are cleared immediately when an operation starts (`el.value = ""`) before awaiting the Worker. All inputs disable `autocomplete`, `autocorrect`, `autocapitalize`, and `spellcheck`.
2. **JS byte buffers (`Uint8Array`):** Overwritten with `.fill(0)` after Base64 encoding, download Blob creation, or wipe.
3. **JS strings (Base64 / JSON / textarea values):** JavaScript strings are immutable and managed by the browser's garbage collector — deterministic overwriting in the JS heap cannot be guaranteed.
4. **Worker transfer & Wasm linear memory:** Wasm bytes are transferred via a transferable `ArrayBuffer` and zeroized after instantiation. Inside the Worker, `reqBytes`, `respCopy`, the Wasm input buffer, and the Wasm output buffer are overwritten with `zeroize` in `finally` / `vault_dealloc`.
5. **Rust buffers (`Zeroizing<Vec<u8>>`, `Zeroizing<String>`):** Passphrases, plaintext buffers, and exported secret key strings are cleaned up with `zeroize` across all paths (including error paths).
6. **Epoch, FileReader, and Worker isolation against late results:** Every asynchronous operation binds to `sessionEpoch` at start and registers active `FileReader` instances in `activeFileReaders`. On wipe or abort, `sessionEpoch` is incremented immediately, any prior wipe fallback timer is cancelled, all active `FileReader`s are aborted (`reader.abort()`), late `onload` buffers are zeroized with `.fill(0)`, and stale Worker `rpc_result` messages or download actions with an outdated `epoch` are strictly discarded. A single `worker.onmessage` handler processes all Worker events (preventing double-wipe handler corruption). If the Worker does not acknowledge a wipe within 400 ms, it is terminated (`worker.terminate()`) and respawned fresh.
