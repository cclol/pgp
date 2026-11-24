#!/usr/bin/env node
/**
 * Deterministic Browser Regression Test for Finding 2:
 *   1. Delayed FileReader import + Emergency Wipe + late onload after Worker restart -> vault stays empty & buffer zeroized.
 *   2. Delayed Decrypt result (both FileReader and Worker rpc_result) arriving after Emergency Wipe -> no plaintext shown & no download created.
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
      reject(new Error("Browser regression test timed out after 35s"));
    }, 35000);

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

              await waitFor(() => document.getElementById("worker-badge").textContent.includes("bereit"));

              // Step A: Generate a real v6 key to get a valid armored public key and a valid ciphertext
              document.querySelector('[data-tab="keygen"]').click();
              document.getElementById("kg-uid").value = "reg-test";
              document.getElementById("kg-pw").value = "regression-pass-99";
              document.getElementById("kg-pw2").value = "regression-pass-99";
              document.getElementById("btn-keygen").click();
              await waitFor(() => !document.getElementById("kg-result").hidden);
              const validPubKey = document.getElementById("kg-pub").value;

              // Encrypt a known secret message
              document.querySelector('[data-tab="encrypt"]').click();
              document.getElementById("enc-text").value = "TOP_SECRET_MUST_NOT_LEAK_AFTER_WIPE";
              document.getElementById("btn-encrypt").click();
              await waitFor(() => !document.getElementById("enc-result").hidden);
              const validCiphertext = document.getElementById("enc-output").value;

              // Clean slate via Wipe
              document.getElementById("btn-wipe").click();
              await waitFor(() => document.getElementById("key-count").textContent === "0 Schlüssel");
              await waitFor(() => document.getElementById("worker-badge").textContent.includes("bereit"));

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

              // Start async import (now suspended in FileReader)
              document.getElementById("btn-import").click();
              await waitFor(() => heldReader !== null && heldBuffer !== null);

              // Trigger Emergency Wipe while file read is still in-flight!
              document.getElementById("btn-wipe").click();
              await waitFor(() => document.getElementById("worker-badge").textContent.includes("bereit"));
              await sleep(150);

              // Now force the stale FileReader onload to fire AFTER wipe & worker ready!
              heldReader.result = heldBuffer;
              if (typeof heldReader.onload === "function") {
                heldReader.onload();
              }
              await sleep(400);

              const staleBufferBytes = new Uint8Array(heldBuffer);
              const bufferWasZeroized = staleBufferBytes.every((b) => b === 0);
              const keyCountAfterLateImport = document.getElementById("key-count").textContent;

              // Restore real FileReader
              window.FileReader = OrigFileReader;

              // ------------------------------------------------------------------
              // TEST 2: Delayed Decrypt (FileReader + Worker rpc_result) + Wipe
              // ------------------------------------------------------------------
              // First import the secret key by generating fresh key + ciphertext so we can test real Decrypt
              document.querySelector('[data-tab="keygen"]').click();
              document.getElementById("kg-uid").value = "reg-dec";
              document.getElementById("kg-pw").value = "regression-pass-99";
              document.getElementById("kg-pw2").value = "regression-pass-99";
              document.getElementById("btn-keygen").click();
              await waitFor(() => !document.getElementById("kg-result").hidden);

              document.querySelector('[data-tab="encrypt"]').click();
              document.getElementById("enc-text").value = "SECRET_DECRYPT_WIPE_TEST";
              document.getElementById("btn-encrypt").click();
              await waitFor(() => !document.getElementById("enc-result").hidden);
              const ct2 = document.getElementById("enc-output").value;

              // Delay FileReader for Decrypt
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
              dt2.items.add(new File([ct2], "msg.asc", { type: "text/plain" }));
              document.getElementById("dec-file").files = dt2.files;
              document.getElementById("dec-pw").value = "regression-pass-99";

              document.getElementById("btn-decrypt").click();
              await waitFor(() => heldDecReader !== null && heldDecBuf !== null);

              // Wipe BEFORE file read finishes
              document.getElementById("btn-wipe").click();
              await waitFor(() => document.getElementById("worker-badge").textContent.includes("bereit"));
              await sleep(150);

              // Deliver late FileReader onload after wipe
              heldDecReader.result = heldDecBuf;
              if (typeof heldDecReader.onload === "function") {
                heldDecReader.onload();
              }
              await sleep(400);

              // Track whether clicking #btn-dec-download creates any Blob URL
              let downloadBlobCreated = false;
              const origCreate = URL.createObjectURL;
              URL.createObjectURL = function () {
                downloadBlobCreated = true;
                return origCreate.apply(this, arguments);
              };
              document.getElementById("btn-dec-download").click();
              URL.createObjectURL = origCreate;
              window.FileReader = OrigFileReader;

              return {
                test1: {
                  abortCalled,
                  bufferWasZeroized,
                  keyCountAfterLateImport,
                },
                test2: {
                  decAbortCalled,
                  decBufZeroized: new Uint8Array(heldDecBuf).every((b) => b === 0),
                  decResultHidden: document.getElementById("dec-result").hidden,
                  decOutputEmpty: document.getElementById("dec-output").value === "",
                  downloadBlobCreated,
                  keyCountAfterWipe: document.getElementById("key-count").textContent,
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
      res.test1.keyCountAfterLateImport === "0 Schlüssel" &&
      res.test2.decAbortCalled === true &&
      res.test2.decBufZeroized === true &&
      res.test2.decResultHidden === true &&
      res.test2.decOutputEmpty === true &&
      res.test2.downloadBlobCreated === false &&
      res.test2.keyCountAfterWipe === "0 Schlüssel";
    if (!ok) {
      console.error("FAIL: One or more wipe regression assertions failed!");
      process.exit(1);
    }
    console.log("PASS: All delayed-file Wipe & late-Decrypt regression assertions passed!");
    process.exit(0);
  })
  .catch((err) => {
    console.error("ERROR:", err);
    process.exit(1);
  });
