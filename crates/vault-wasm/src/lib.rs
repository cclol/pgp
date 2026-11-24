pub mod crypto;
pub mod key_select;
pub mod limits;
pub mod packet_check;
pub mod session;

#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::slice;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::session::SessionStore;

thread_local! {
    static SESSION: RefCell<SessionStore> = RefCell::new(SessionStore::default());
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn js_getrandom(ptr: *mut u8, len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    if len == 0 {
        return Ok(());
    }
    let rc = unsafe { js_getrandom(dest, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(getrandom::Error::UNSUPPORTED)
    }
}

#[cfg(target_arch = "wasm32")]
fn custom_getrandom_v02(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
    if buf.is_empty() {
        return Ok(());
    }
    let rc = unsafe { js_getrandom(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(getrandom02::Error::UNSUPPORTED)
    }
}

#[cfg(target_arch = "wasm32")]
getrandom02::register_custom_getrandom!(custom_getrandom_v02);

#[derive(Deserialize)]
#[serde(tag = "op", content = "payload")]
enum RpcRequest {
    ListKeys,
    Wipe,
    GenerateKey(crypto::KeyGenRequest),
    ImportKeys(crypto::ImportKeyRequest),
    ConfirmIdentity { fingerprint: String, confirmed: bool },
    RemoveKey { fingerprint: String },
    Encrypt(crypto::EncryptRequest),
    Decrypt(crypto::DecryptRequest),
    SignDetached(crypto::SignDetachedRequest),
    VerifyDetached(crypto::VerifyDetachedRequest),
}

#[derive(Serialize)]
struct RpcResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn dispatch_json(req_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let resp = match serde_json::from_slice::<RpcRequest>(req_bytes) {
        Err(e) => RpcResponse {
            ok: false,
            data: None,
            error: Some(format!("Invalid request: {e}")),
        },
        Ok(req) => SESSION.with(|cell| {
            let mut store = cell.borrow_mut();
            let res: Result<serde_json::Value, String> = match req {
                RpcRequest::ListKeys => {
                    serde_json::to_value(store.list_keys()).map_err(|e| e.to_string())
                }
                RpcRequest::Wipe => {
                    store.wipe();
                    Ok(serde_json::json!({ "wiped": true }))
                }
                RpcRequest::GenerateKey(r) => crypto::generate_key(&mut store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::ImportKeys(r) => crypto::import_keys(&mut store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::ConfirmIdentity {
                    fingerprint,
                    confirmed,
                } => store
                    .confirm_identity(&fingerprint, confirmed)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::RemoveKey { fingerprint } => {
                    let removed = store.remove_key(&fingerprint);
                    Ok(serde_json::json!({ "removed": removed }))
                }
                RpcRequest::Encrypt(r) => crypto::encrypt_message(&store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::Decrypt(r) => crypto::decrypt_message(&store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::SignDetached(r) => crypto::sign_detached(&store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
                RpcRequest::VerifyDetached(r) => crypto::verify_detached(&store, r)
                    .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
            };
            match res {
                Ok(data) => RpcResponse {
                    ok: true,
                    data: Some(data),
                    error: None,
                },
                Err(err) => RpcResponse {
                    ok: false,
                    data: None,
                    error: Some(err),
                },
            }
        }),
    };

    Zeroizing::new(serde_json::to_vec(&resp).unwrap_or_else(|_| {
        br#"{"ok":false,"error":"Serialization error"}"#.to_vec()
    }))
}

#[no_mangle]
pub extern "C" fn vault_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn vault_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
        zeroize::Zeroize::zeroize(slice);
        let _ = unsafe { Vec::from_raw_parts(ptr, 0, len) };
    }
}

#[no_mangle]
pub extern "C" fn vault_ping() -> u32 {
    0x50475001
}

#[no_mangle]
pub extern "C" fn vault_wipe() {
    SESSION.with(|cell| cell.borrow_mut().wipe());
}

#[no_mangle]
pub unsafe extern "C" fn vault_call(
    req_ptr: *mut u8,
    req_len: usize,
    out_len_ptr: *mut usize,
) -> *mut u8 {
    let req_slice = if req_ptr.is_null() || req_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(req_ptr, req_len) }
    };

    let resp = dispatch_json(req_slice);

    // Zeroize the incoming request buffer immediately after parsing
    if !req_ptr.is_null() && req_len > 0 {
        let mut_slice = unsafe { slice::from_raw_parts_mut(req_ptr, req_len) };
        zeroize::Zeroize::zeroize(mut_slice);
    }

    let out_len = resp.len();
    let out_ptr = vault_alloc(out_len);
    if !out_ptr.is_null() && out_len > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(resp.as_ptr(), out_ptr, out_len);
        }
    }
    if !out_len_ptr.is_null() {
        unsafe {
            *out_len_ptr = out_len;
        }
    }
    out_ptr
}
