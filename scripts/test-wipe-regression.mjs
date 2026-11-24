#!/usr/bin/env node
/**
 * Deterministic Browser Regression Test for Emergency Wipe & Session Isolation:
 *   1. Delayed FileReader import + Emergency Wipe + late onload -> vault stays empty & buffer zeroized.
 *   2. Delayed FileReader decrypt + Emergency Wipe + late onload -> no plaintext shown & no download created.
 *   3. Delayed Worker RPC response (ImportKeys) arriving after Emergency Wipe & Worker restart -> vault stays empty.
 *   4. Delayed Worker RPC response (Decrypt) arriving after Emergency Wipe & Worker restart -> no plaintext shown & no download created.
 *   5. Rapid double Emergency Wipe -> Worker handler remains intact and subsequent operations succeed.
 *
 * Runs directly against the built standalone `dist/index.html` over `file://` in headless Chrome via CDP pipe.
 */

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HTML_URL = "file://" + path.resolve(__dirname, "..", "dist", "index.html");
const CHROME_BIN =
  process.env.CHROME_BIN ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

function runChromeTest() {
  return new Promise((resolve, reject) => {
    const chrome = spawn(
      CHROME_BIN,
      [
        "--headless=new",
        "--user-data-dir=/tmp/chrome-wipe-reg-" + Date.now(),
        "--remote-debugging-pipe",
        HTML_URL,
      ],
      { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] }
    );

    let buf = "";
    let nextId = 1;
    const waiters = new Map();
    const send = (method, params = {}, sessionId) => {
      const id = nextId++;
      const msg = sessionId ? { id, sessionId, method, params } : { id, method, params };
      chrome.stdio[3].write(JSON.stringify(msg) + "\0");
      return new Promise((res, rej) => waiters.set(id, { res, rej }));
    };

    chrome.stdio[4].on("data", (chunk) => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf("\0")) !== -1) {
        const msg = JSON.parse(buf.slice(0, idx));
        buf = buf.slice(idx + 1);
        if (msg.id && waiters.has(msg.id)) {
          const { res, rej } = waiters.get(msg.id);
          waiters.delete(msg.id);
          if (msg.error) rej(new Error(JSON.stringify(msg.error)));
          else res(msg.result);
        }
      }
    });

    const timeout = setTimeout(() => {
      chrome.kill();
      reject(new Error("Browser regression test timed out after 45s"));
    }, 45000);

    setTimeout(async () => {
      try {
        const { targetInfos } = await send("Target.getTargets");
        const page = targetInfos.find((t) => t.type === "page");
        if (!page) throw new Error("No page target found");
        const { sessionId } = await send("Target.attachToTarget", {
          targetId: page.targetId,
          flatten: true,
        });

        const evalRes = await send(
          "Runtime.evaluate",
          {
            awaitPromise: true,
            returnByValue: true,
            expression: `(async () => {
              const sleep = (ms) => new Promise(r => setTimeout(r, ms));
              const waitFor = async (fn, ms = 15000) => {
                const start = Date.now();
                while (Date.now() - start < ms) {
                  if (fn()) return true;
                  await sleep(50);
                }
                throw new Error("waitFor timeout");
              };

              const isWorkerReady = () => {
                const el = document.getElementById("worker-badge");
                return Boolean(el && el.dataset && el.dataset.state === "ready");
              };
              const keyCount = () => {
                const el = document.getElementById("key-count");
                return el && el.dataset ? el.dataset.count : null;
              };

              await waitFor(isWorkerReady);

              // Step A: Generate a real v6 key to get a valid armored public/secret key and ciphertext
              document.querySelector('[data-tab="keygen"]').click();
              document.getElementById("kg-uid").value = "reg-test";
              document.getElementById("kg-pw").value = "regression-pass-99";
              document.getElementById("kg-pw2").value = "regression-pass-99";
              document.getElementById("btn-keygen").click();
              await waitFor(() => !document.getElementById("kg-result").hidden);
              const validPubKey = document.getElementById("kg-pub").value;
              const validSecKey = document.getElementById("kg-sec").value;

              // Encrypt a known secret message
              document.querySelector('[data-tab="encrypt"]').click();
              document.getElementById("enc-text").value = "TOP_SECRET_MUST_NOT_LEAK_AFTER_WIPE";
              document.getElementById("btn-encrypt").click();
              await waitFor(() => !document.getElementById("enc-result").hidden);
              const validCiphertext = document.getElementById("enc-output").value;

              // Clean slate via Wipe
              document.getElementById("btn-wipe").click();
              await waitFor(() => keyCount() === "0" && isWorkerReady());

              // ------------------------------------------------------------------
              // TEST 1: Delayed FileReader import + Wipe + late onload after wipe
              // ------------------------------------------------------------------
              const OrigFileReader = window.FileReader;
              let heldReader = null;
              let heldBuffer = null;
              let abortCalled = false;

              window.FileReader = function MockDelayedFileReader() {
                this.result = null;
                this.onload = null;
                this.onerror = null;
                this.onabort = null;
                this.abort = () => { abortCalled = true; };
                this.readAsArrayBuffer = (file) => {
                  heldReader = this;
                  file.arrayBuffer().then((ab) => { heldBuffer = ab; });
                };
              };

              const dt = new DataTransfer();
              dt.items.add(new File([validPubKey], "key.asc", { type: "text/plain" }));
              document.getElementById("import-file").files = dt.files;

              document.getElementById("btn-import").click();
              await waitFor(() => heldReader !== null && heldBuffer !== null);

              document.getElementById("btn-wipe").click();
              await waitFor(isWorkerReady);
              await sleep(150);

              heldReader.result = heldBuffer;
              if (typeof heldReader.onload === "function") {
                heldReader.onload();
              }
              await sleep(300);

              const staleBufferBytes = new Uint8Array(heldBuffer);
              const bufferWasZeroized = staleBufferBytes.every((b) => b === 0);
              const keyCountAfterLateImport = keyCount();
              window.FileReader = OrigFileReader;

              // ------------------------------------------------------------------
              // TEST 2: Delayed FileReader Decrypt + Wipe + late onload
              // ------------------------------------------------------------------
              document.getElementById("import-text").value = validSecKey;
              document.getElementById("btn-import").click();
              await waitFor(() => keyCount() === "1");

              let heldDecReader = null;
              let heldDecBuf = null;
              let decAbortCalled = false;
              window.FileReader = function MockDelayedDecReader() {
                this.result = null;
                this.onload = null;
                this.onerror = null;
                this.onabort = null;
                this.abort = () => { decAbortCalled = true; };
                this.readAsArrayBuffer = (file) => {
                  heldDecReader = this;
                  file.arrayBuffer().then((ab) => { heldDecBuf = ab; });
                };
              };

              document.querySelector('[data-tab="decrypt"]').click();
              const dt2 = new DataTransfer();
              dt2.items.add(new File([validCiphertext], "msg.asc", { type: "text/plain" }));
              document.getElementById("dec-file").files = dt2.files;
              document.getElementById("dec-pw").value = "regression-pass-99";

              document.getElementById("btn-decrypt").click();
              await waitFor(() => heldDecReader !== null && heldDecBuf !== null);

              document.getElementById("btn-wipe").click();
              await waitFor(isWorkerReady);
              await sleep(150);

              heldDecReader.result = heldDecBuf;
              if (typeof heldDecReader.onload === "function") {
                heldDecReader.onload();
              }
              await sleep(300);

              let downloadBlobCreated = false;
              const origCreate = URL.createObjectURL;
              URL.createObjectURL = function () {
                downloadBlobCreated = true;
                return origCreate.apply(this, arguments);
              };
              document.getElementById("btn-dec-download").click();
              URL.createObjectURL = origCreate;
              window.FileReader = OrigFileReader;

              const test2 = {
                decAbortCalled,
                decBufZeroized: new Uint8Array(heldDecBuf).every((b) => b === 0),
                decResultHidden: document.getElementById("dec-result").hidden,
                decOutputEmpty: document.getElementById("dec-output").value === "",
                downloadBlobCreated,
                keyCountAfterWipe: keyCount(),
              };

              // ------------------------------------------------------------------
              // TEST 3 & 4: Delayed Worker rpc_result (Import & Decrypt) arriving
              //             AFTER Emergency Wipe + Worker restart
              // ------------------------------------------------------------------
              const OrigWorker = window.Worker;
              const workers = [];
              let holdNextRpcResult = false;
              let heldRpcEvents = [];

              window.Worker = function InterceptedWorker(url) {
                const real = new OrigWorker(url);
                let userOnMessage = null;
                const wrapper = {
                  postMessage(data, transfer) {
                    return transfer ? real.postMessage(data, transfer) : real.postMessage(data);
                  },
                  terminate() {
                    return real.terminate();
                  },
                  set onmessage(fn) {
                    userOnMessage = fn;
                    real.onmessage = (ev) => {
                      if (holdNextRpcResult && ev.data && ev.data.type === "rpc_result") {
                        holdNextRpcResult = false;
                        heldRpcEvents.push({ ev, targetWrapper: wrapper });
                        return;
                      }
                      if (userOnMessage) userOnMessage(ev);
                    };
                  },
                  get onmessage() {
                    return userOnMessage;
                  },
                  set onerror(fn) {
                    real.onerror = fn;
                  },
                  get onerror() {
                    return real.onerror;
                  },
                };
                workers.push(wrapper);
                return wrapper;
              };

              // Force a fresh Worker restart through our intercepted Worker constructor
              // by triggering Abort/Wipe via pagehide or rapid wipe after loading a key:
              // First click Abort? Better: trigger pagehide (forceRestartWorker = true)
              window.dispatchEvent(new Event("pagehide"));
              await waitFor(() => workers.length >= 1 && isWorkerReady());

              // TEST 3: Hold Worker rpc_result for ImportKeys, wipe & restart Worker, then deliver stale rpc_result
              holdNextRpcResult = true;
              heldRpcEvents = [];
              document.getElementById("import-text").value = validPubKey;
              document.getElementById("btn-import").click();
              await waitFor(() => heldRpcEvents.length === 1);

              // Wipe AND restart Worker (via pagehide -> forceRestartWorker=true)
              const prevWorkerCount = workers.length;
              window.dispatchEvent(new Event("pagehide"));
              await waitFor(() => workers.length > prevWorkerCount && isWorkerReady());
              const newWorkerAfterImportWipe = workers[workers.length - 1];

              // Deliver the old rpc_result to BOTH the old handler and the new Worker handler
              const staleImportEv = heldRpcEvents[0].ev;
              if (heldRpcEvents[0].targetWrapper.onmessage) {
                heldRpcEvents[0].targetWrapper.onmessage(staleImportEv);
              }
              if (newWorkerAfterImportWipe.onmessage) {
                newWorkerAfterImportWipe.onmessage(staleImportEv);
              }
              await sleep(250);
              const test3KeyCount = keyCount();

              // TEST 4: Load secret key, start real Decrypt, hold Worker rpc_result (real plaintext!),
              //         wipe & restart Worker, then deliver stale Decrypt rpc_result
              document.getElementById("import-text").value = validSecKey;
              document.getElementById("btn-import").click();
              await waitFor(() => keyCount() === "1");

              holdNextRpcResult = true;
              heldRpcEvents = [];
              document.querySelector('[data-tab="decrypt"]').click();
              document.getElementById("dec-text").value = validCiphertext;
              document.getElementById("dec-pw").value = "regression-pass-99";
              document.getElementById("btn-decrypt").click();
              await waitFor(() => heldRpcEvents.length === 1);

              const staleDecryptEv = heldRpcEvents[0].ev;
              const staleHadRealPlaintext = Boolean(
                staleDecryptEv.data &&
                staleDecryptEv.data.result &&
                staleDecryptEv.data.result.ok === true &&
                staleDecryptEv.data.result.data &&
                staleDecryptEv.data.result.data.plaintext_b64
              );

              // Wipe & restart Worker
              const prevWorkerCount2 = workers.length;
              window.dispatchEvent(new Event("pagehide"));
              await waitFor(() => workers.length > prevWorkerCount2 && isWorkerReady());
              const newWorkerAfterDecWipe = workers[workers.length - 1];

              // Deliver stale Decrypt rpc_result to both old and new Worker handlers
              if (heldRpcEvents[0].targetWrapper.onmessage) {
                heldRpcEvents[0].targetWrapper.onmessage(staleDecryptEv);
              }
              if (newWorkerAfterDecWipe.onmessage) {
                newWorkerAfterDecWipe.onmessage(staleDecryptEv);
              }
              await sleep(250);

              let test4DownloadCreated = false;
              URL.createObjectURL = function () {
                test4DownloadCreated = true;
                return origCreate.apply(this, arguments);
              };
              document.getElementById("btn-dec-download").click();
              URL.createObjectURL = origCreate;

              const test4 = {
                staleHadRealPlaintext,
                decResultHidden: document.getElementById("dec-result").hidden,
                decOutputEmpty: document.getElementById("dec-output").value === "",
                downloadBlobCreated: test4DownloadCreated,
                keyCountAfterWipe: keyCount(),
              };

              window.Worker = OrigWorker;

              // ------------------------------------------------------------------
              // TEST 5: Rapid double Emergency Wipe does not corrupt worker.onmessage
              // ------------------------------------------------------------------
              document.getElementById("import-text").value = validPubKey;
              document.getElementById("btn-import").click();
              await waitFor(() => keyCount() === "1");

              // Double-click Emergency Wipe immediately
              document.getElementById("btn-wipe").click();
              document.getElementById("btn-wipe").click();
              await sleep(500);
              await waitFor(isWorkerReady);

              // Verify subsequent RPC still works cleanly
              document.getElementById("import-text").value = validPubKey;
              document.getElementById("btn-import").click();
              await waitFor(() => keyCount() === "1");
              const test5Recovered = keyCount() === "1" && isWorkerReady();

              return {
                test1: {
                  abortCalled,
                  bufferWasZeroized,
                  keyCountAfterLateImport,
                },
                test2,
                test3: {
                  keyCountAfterStaleRpcImport: test3KeyCount,
                },
                test4,
                test5: {
                  recoveredAfterDoubleWipe: test5Recovered,
                },
              };
            })()`,
          },
          sessionId
        );

        clearTimeout(timeout);
        chrome.kill();
        if (evalRes.exceptionDetails) {
          reject(new Error("Page exception: " + JSON.stringify(evalRes.exceptionDetails)));
          return;
        }
        resolve(evalRes.result.value);
      } catch (err) {
        clearTimeout(timeout);
        chrome.kill();
        reject(err);
      }
    }, 1500);
  });
}

runChromeTest()
  .then((res) => {
    console.log("WIPE_REGRESSION_RESULT:", JSON.stringify(res, null, 2));
    const ok =
      res.test1.abortCalled === true &&
      res.test1.bufferWasZeroized === true &&
      res.test1.keyCountAfterLateImport === "0" &&
      res.test2.decAbortCalled === true &&
      res.test2.decBufZeroized === true &&
      res.test2.decResultHidden === true &&
      res.test2.decOutputEmpty === true &&
      res.test2.downloadBlobCreated === false &&
      res.test2.keyCountAfterWipe === "0" &&
      res.test3.keyCountAfterStaleRpcImport === "0" &&
      res.test4.staleHadRealPlaintext === true &&
      res.test4.decResultHidden === true &&
      res.test4.decOutputEmpty === true &&
      res.test4.downloadBlobCreated === false &&
      res.test4.keyCountAfterWipe === "0" &&
      res.test5.recoveredAfterDoubleWipe === true;
    if (!ok) {
      console.error("FAIL: One or more wipe regression assertions failed!");
      process.exit(1);
    }
    console.log("PASS: All delayed-FileReader, delayed-Worker-RPC, and double-Wipe regression assertions passed!");
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
