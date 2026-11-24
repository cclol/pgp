#!/usr/bin/env python3
"""Deterministic single-file HTML builder for Zero-Trace Wasm PGP Vault."""

import base64
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WASM_PATH = ROOT / "target" / "wasm32-unknown-unknown" / "release" / "vault_wasm.wasm"
WEB_DIR = ROOT / "web"
DIST_DIR = ROOT / "dist"
OUT_HTML = DIST_DIR / "index.html"


def sha256_csp(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def main() -> int:
    if not WASM_PATH.exists():
        print(f"ERROR: Wasm binary not found at {WASM_PATH}", file=sys.stderr)
        print(
            "Run: cargo build --target wasm32-unknown-unknown --release --locked",
            file=sys.stderr,
        )
        return 1

    wasm_bytes = WASM_PATH.read_bytes()
    wasm_b64 = base64.b64encode(wasm_bytes).decode("ascii")
    wasm_sha256 = hashlib.sha256(wasm_bytes).hexdigest()

    template = (WEB_DIR / "index.template.html").read_text(encoding="utf-8")
    css = (WEB_DIR / "styles.css").read_text(encoding="utf-8")
    worker_js = (WEB_DIR / "worker.js").read_text(encoding="utf-8")
    app_js = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    # Escape </script> inside JSON strings defensively
    worker_json = json.dumps(worker_js).replace("</", "<\\/")
    wasm_b64_json = json.dumps(wasm_b64)

    inline_script = (
        f"const __VAULT_WASM_SHA256__ = {json.dumps(wasm_sha256)};\n"
        f"const __VAULT_WASM_B64__ = {wasm_b64_json};\n"
        f"const __VAULT_WORKER_SRC__ = {worker_json};\n"
        f"{app_js}"
    )

    style_hash = sha256_csp(css)
    script_hash = sha256_csp(inline_script)

    csp = (
        "default-src 'none'; "
        "connect-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "object-src 'none'; "
        "img-src 'none'; "
        "font-src 'none'; "
        "media-src 'none'; "
        f"style-src {style_hash}; "
        f"script-src {script_hash} 'wasm-unsafe-eval'; "
        "worker-src blob:"
    )

    html = (
        template.replace("__CSP__", csp)
        .replace("__INLINE_CSS__", css)
        .replace("__INLINE_JS__", inline_script)
        .replace("__WASM_SHA256__", wasm_sha256)
    )

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8", newline="\n")

    out_bytes = OUT_HTML.read_bytes()
    out_sha256 = hashlib.sha256(out_bytes).hexdigest()
    print(f"Built: {OUT_HTML}")
    print(f"  Wasm size:   {len(wasm_bytes):,} bytes (sha256: {wasm_sha256})")
    print(f"  HTML size:   {len(out_bytes):,} bytes (sha256: {out_sha256})")
    print(f"  Style hash:  {style_hash}")
    print(f"  Script hash: {script_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
