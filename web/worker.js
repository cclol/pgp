"use strict";

let wasmInstance = null;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

function fillRandom(ptr, len) {
  try {
    if (!self.crypto || typeof self.crypto.getRandomValues !== "function") {
      return -1;
    }
    const mem = new Uint8Array(wasmInstance.exports.memory.buffer, ptr, len);
    let offset = 0;
    while (offset < len) {
      const chunk = Math.min(65536, len - offset);
      self.crypto.getRandomValues(mem.subarray(offset, offset + chunk));
      offset += chunk;
    }
    return 0;
  } catch (_) {
    return -1;
  }
}

function callWasmJson(reqObj) {
  if (!wasmInstance) {
    throw new Error("Crypto core is not initialized.");
  }
  const ex = wasmInstance.exports;
  const reqBytes = encoder.encode(JSON.stringify(reqObj));
  const reqPtr = ex.vault_alloc(reqBytes.length);
  const outLenPtr = ex.vault_alloc(4);
  let outPtr = 0;
  let outLen = 0;

  try {
    new Uint8Array(ex.memory.buffer, reqPtr, reqBytes.length).set(reqBytes);
    reqBytes.fill(0);

    outPtr = ex.vault_call(reqPtr, reqBytes.length, outLenPtr);
    outLen = new DataView(ex.memory.buffer).getUint32(outLenPtr, true);

    const respCopy = new Uint8Array(outLen);
    respCopy.set(new Uint8Array(ex.memory.buffer, outPtr, outLen));
    const text = decoder.decode(respCopy);
    respCopy.fill(0);
    return JSON.parse(text);
  } finally {
    reqBytes.fill(0);
    if (reqPtr) ex.vault_dealloc(reqPtr, reqBytes.length);
    if (outLenPtr) ex.vault_dealloc(outLenPtr, 4);
    if (outPtr && outLen) ex.vault_dealloc(outPtr, outLen);
  }
}

self.onmessage = async (ev) => {
  const msg = ev.data;
  if (!msg || typeof msg.type !== "string") return;

  if (msg.type === "init") {
    try {
      const bytes = new Uint8Array(msg.wasmBuffer);
      const { instance } = await WebAssembly.instantiate(bytes, {
        env: { js_getrandom: fillRandom },
      });
      wasmInstance = instance;
      bytes.fill(0);
      const ping = wasmInstance.exports.vault_ping();
      self.postMessage({ type: "ready", ping, epoch: msg.epoch });
    } catch (err) {
      self.postMessage({ type: "error", message: String(err), epoch: msg.epoch });
    }
    return;
  }

  if (msg.type === "wipe") {
    try {
      if (wasmInstance && wasmInstance.exports.vault_wipe) {
        wasmInstance.exports.vault_wipe();
      }
      self.postMessage({ type: "wiped", epoch: msg.epoch });
    } catch (err) {
      self.postMessage({ type: "error", message: String(err), epoch: msg.epoch });
    }
    return;
  }

  if (msg.type === "rpc") {
    try {
      const result = callWasmJson(msg.req);
      self.postMessage({
        type: "rpc_result",
        id: msg.id,
        epoch: msg.epoch,
        result,
      });
    } catch (err) {
      self.postMessage({
        type: "rpc_result",
        id: msg.id,
        epoch: msg.epoch,
        result: { ok: false, error: String(err) },
      });
    }
  }
};
