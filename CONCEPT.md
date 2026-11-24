# Zero-Trace Wasm PGP Vault

## Goal and Security Boundaries

The Vault encrypts, decrypts, signs, and verifies OpenPGP data locally in the browser. The GitHub repository `cclol/pgp` is the intended distribution channel. GitHub Pages serves the web app directly. For sensitive data, opening a pre-verified release file offline in the browser is the preferred entry point.

**Zero Trace is the design goal for app-controlled traces.** The app stores no persistent session data and overwrites sensitive buffers that it controls. The browser, operating system, and extensions can still leave traces, for example in caches, swap space, crash dumps, or the clipboard. Downloaded files are explicit user exports.

Online use requires trusting the served code and the endpoint device. GitHub may observe connection metadata when the page is fetched. Tor Browser can shield the source IP address from GitHub. Offline use additionally relies on independent release signature verification.

## Distribution via GitHub

- **GitHub Pages.** A static page at `https://cclol.github.io/pgp/` once Pages is enabled. It loads no CDNs, external fonts, analytics, or other third-party content. Before the first input, the online page explains the trust assumptions of launching over the web.
- **GitHub Releases.** Publish the same self-contained HTML file as a release download accompanied by a detached signature. The signature covers the entire file, including JavaScript, Wasm, and styles. Users verify the file before opening it using an independently obtained public verification key, and then open it offline as needed. A hash displayed on the same website serves at most as a build identifier.
- **Build and release.** Pin the Rust toolchain, dependencies, Wasm tooling, and CI actions to exact versions or commit SHAs. Build with the checked-in `Cargo.lock`. Run build jobs with minimal permissions, bind deployments to a verified release state, and keep the signing key outside the Pages workflow. Verify comparable builds from two clean environments against the full artifact.

## Browser Architecture

Vanilla JavaScript handles the user interface, file inputs, and downloads. Rust/Wasm handles OpenPGP parsing and cryptography via rPGP. The build embeds the Wasm bytes in the HTML artifact and instantiates them directly from memory. A dedicated Web Worker separates the crypto core from the UI thread and can be terminated on demand. The prototype must first demonstrate that the chosen Worker embedding works under the CSP and over `file://` in the target browsers.

The CSP appears before any executable content. Its baseline is `default-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`. Inline script and styles are allowed via build-time SHA-256 hashes. Wasm compilation receives the required permission via `'wasm-unsafe-eval'`. Any `blob:` allowance applies specifically to Workers (`worker-src blob:`). The CSP restricts resource fetches by the intended program. Offline execution additionally prevents network traffic during processing, and the external signature protects against undetected modification of the distributed file.

## Session Data and Cleanup

- Prefer reading keys and files as byte buffers. Use transferable buffers when moving data into the Worker and still account for all remaining copies across the JS/Wasm boundaries. Request passphrases only for the operation at hand, clear input fields immediately, and disable browser autocomplete and spellcheck where supported.
- Clean up controlled sensitive Rust buffers with `zeroize`, including on error paths. Keep unlocked keys in Worker memory only for the active session. On an explicit wipe, immediately clear the UI, discard results from in-flight operations, and ask the Worker to clear its state. If it hangs, terminate the Worker. Terminating a Worker is not a guarantee that the OS or browser immediately overwrites its memory.
- Trigger the same session cleanup on inactivity and, on a best-effort basis, on page unload or tab hide. Re-check the timeout on return from the background, since timers may pause while hidden. Remove decrypted plaintext from display after a short interval. Revoke Blob URLs after use. Browser lifecycle events are supplementary safeguards.
- No `localStorage`, no `sessionStorage`, no IndexedDB, no cookies, no Service Worker, and no app-managed Cache API for session data. Plaintext downloads and clipboard copy occur only on explicit user action. The app does not automatically overwrite the clipboard.

## OpenPGP and Metadata

- Use RFC 9580 as the modern write profile, with Ed25519 and X25519 for key generation and v2-SEIPD with AES-256 and AEAD. Finalize the concrete AEAD mode, key version, and supported combinations based on the pinned rPGP version and interoperability tests before release. Draw randomness exclusively from the browser CSPRNG and abort on failure.
- Support legacy integrity-protected v1-SEIPD messages with MDC only through an explicit read profile. Reject unauthenticated encrypted messages (SED / Tag 9). Release plaintext only after complete message integrity verification. Clearly distinguish signature status on combined encrypted-and-signed messages.
- Anonymize recipient identifiers in PKESK packets: set the wildcard Key ID (`0000000000000000`) for v3, and omit the recipient fingerprint for v6. Verify the chosen implementation directly on serialized packets. The number of recipient packets, algorithms, and approximate length may remain visible.
- Write an empty filename (`""`) and timestamp `0` in the encrypted Literal Data packet. Use neutral filenames for exported files. Emit ASCII Armor without `Version:` or `Comment:` headers. Support pseudonymous User IDs. Handle key and signature timestamps according to format and validity rules. Published keys and signatures may still contain identifying attributes.
- Display recipient fingerprints before encryption. Display signature validity, the signing fingerprint, and user-confirmed identity separately. Export private keys passphrase-protected only. Validate the concrete S2K profile and its resource limits against target clients.

## Scope and Acceptance Criteria

The initial release covers text and file operations, multiple recipients, key import, signing and verification, and offline key generation with passphrase-protected export. File size, packet count, decompression, and S2K resource usage have hard limits. Bound the number of decryption attempts for anonymous recipient packets. On abort or integrity failure, plaintext display and plaintext download remain locked.

1. **Browser and network.** Test on the GitHub Pages URL and directly from the downloaded local file, including Tor Browser. After launch, execute all core functions with the network disconnected. During online tests, capture all requests triggered by the document and Worker and verify that only expected fetches occur.
2. **Memory and UI.** Test wipe, timeout, resume from background, error paths, and cancellation. Check input fields, output views, controlled buffers, and Blob URLs. A Worker result arriving after a wipe must never restore plaintext or keys.
3. **Cryptography and interoperability.** Document exact versions of GnuPG and Kleopatra. Test supported operations in both directions. Inspect serialized packets for metadata. Test tampered, truncated, and oversized messages. If the modern profile conflicts with a target client, document the limitation openly or specify an explicitly selectable and separately tested compatibility profile.
4. **Release.** An independent verification run validates the detached signature of the downloaded file and demonstrates that a modified copy fails verification. The verified file must start completely offline.

## References

- [OpenPGP — RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)
- [rPGP source code and documentation](https://github.com/rpgp/rpgp)
- [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [MDN: CSP `connect-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)
