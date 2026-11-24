"use strict";

(function () {
  const MAX_INPUT_BYTES = 16 * 1024 * 1024;
  const PLAINTEXT_AUTOCLEAR_SEC = 90;

  let worker = null;
  let workerReady = false;
  let workerBlobUrl = null;
  let sessionEpoch = 1;
  let nextReqId = 1;
  const pending = new Map();
  const activeBlobUrls = new Set();
  const activeFileReaders = new Set();

  let sessionKeys = [];
  let lastEncBytes = null;
  let lastEncEpoch = 0;
  let lastEncIsArmor = true;
  let lastDecBytes = null;
  let lastDecEpoch = 0;
  let lastSignBytes = null;
  let lastSignEpoch = 0;
  let lastSignIsArmor = true;

  function makeStaleError() {
    const err = new Error("Vorgang durch Sitzungs-Wipe verworfen.");
    err.staleEpoch = true;
    return err;
  }

  function abortActiveFileReaders() {
    for (const reader of activeFileReaders) {
      try { reader.abort(); } catch (_) {}
    }
    activeFileReaders.clear();
  }

  let timeoutSec = 300;
  let lastActivityAt = Date.now();
  let plaintextClearAt = 0;

  const $ = (id) => document.getElementById(id);

  function setStatus(text, kind) {
    const el = $("status-bar");
    el.textContent = text;
    el.className = "status-bar" + (kind ? " " + kind : "");
  }

  function formatFp(fp) {
    return (fp || "").replace(/(.{4})/g, "$1 ").trim();
  }

  function decodeBase64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function encodeBytesToBase64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function zeroizeUint8(arr) {
    if (arr && arr.fill) {
      try { arr.fill(0); } catch (_) {}
    }
  }

  function revokeAllBlobUrls() {
    for (const u of activeBlobUrls) {
      try { URL.revokeObjectURL(u); } catch (_) {}
    }
    activeBlobUrls.clear();
  }

  function downloadBytes(bytes, filename, mime) {
    const blob = new Blob([bytes], { type: mime || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    activeBlobUrls.add(url);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch (_) {}
      activeBlobUrls.delete(url);
    }, 5000);
  }

  async function copyExplicit(text, label) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setStatus(label + " in Zwischenablage kopiert (wird von der App nicht automatisch überschrieben).", "ok");
    } catch (_) {
      setStatus("Zwischenablage nicht verfügbar — bitte manuell markieren und kopieren.", "err");
    }
  }

  function readFileAsBytes(file, opEpoch) {
    return new Promise((resolve, reject) => {
      if (opEpoch !== sessionEpoch) {
        reject(makeStaleError());
        return;
      }
      if (file.size > MAX_INPUT_BYTES) {
        reject(new Error("Datei überschreitet das Limit von 16 MiB."));
        return;
      }
      const reader = new FileReader();
      activeFileReaders.add(reader);
      const cleanup = () => activeFileReaders.delete(reader);

      reader.onload = () => {
        cleanup();
        const bytes = new Uint8Array(reader.result);
        if (opEpoch !== sessionEpoch) {
          zeroizeUint8(bytes);
          reject(makeStaleError());
          return;
        }
        resolve(bytes);
      };
      reader.onerror = () => {
        cleanup();
        reject(opEpoch !== sessionEpoch ? makeStaleError() : new Error("Datei konnte nicht gelesen werden."));
      };
      reader.onabort = () => {
        cleanup();
        reject(makeStaleError());
      };
      reader.readAsArrayBuffer(file);
    });
  }

  function touchActivity() {
    lastActivityAt = Date.now();
  }

  function setBusy(busy) {
    $("btn-abort").hidden = !busy;
    for (const id of ["btn-import", "btn-encrypt", "btn-decrypt", "btn-sign", "btn-verify", "btn-keygen"]) {
      const btn = $(id);
      if (btn) btn.disabled = busy || !workerReady;
    }
  }

  function spawnWorker() {
    if (worker) {
      try { worker.terminate(); } catch (_) {}
      worker = null;
    }
    if (workerBlobUrl) {
      try { URL.revokeObjectURL(workerBlobUrl); } catch (_) {}
      workerBlobUrl = null;
    }
    workerReady = false;
    $("worker-badge").textContent = "Worker startet…";
    $("worker-badge").className = "badge";

    const epochAtSpawn = sessionEpoch;
    try {
      const blob = new Blob([__VAULT_WORKER_SRC__], { type: "application/javascript" });
      workerBlobUrl = URL.createObjectURL(blob);
      worker = new Worker(workerBlobUrl);
    } catch (err) {
      showEnvError("Dedizierter Worker konnte nicht gestartet werden: " + String(err));
      return;
    }

    const revokeWorkerScript = () => {
      if (workerBlobUrl) {
        try { URL.revokeObjectURL(workerBlobUrl); } catch (_) {}
        workerBlobUrl = null;
      }
    };

    worker.onmessage = (ev) => {
      revokeWorkerScript();
      const msg = ev.data;
      if (!msg) return;
      // Ignore any stale message from a wiped/aborted epoch!
      if (msg.epoch !== sessionEpoch) {
        return;
      }
      if (msg.type === "ready") {
        workerReady = true;
        $("worker-badge").textContent = "Worker + Wasm bereit";
        $("worker-badge").className = "badge badge-ok";
        setBusy(false);
        setStatus("Kryptokern bereit (isoliert im Worker, kein Netzwerkverkehr).", "ok");
      } else if (msg.type === "wiped") {
        setStatus("Sitzung vollständig bereinigt.", "ok");
      } else if (msg.type === "rpc_result") {
        const entry = pending.get(msg.id);
        if (entry) {
          pending.delete(msg.id);
          setBusy(pending.size > 0);
          entry.resolve(msg.result);
        }
      } else if (msg.type === "error") {
        showEnvError("Worker-Fehler: " + msg.message);
      }
    };

    worker.onerror = (err) => {
      revokeWorkerScript();
      showEnvError("Worker-Laufzeitfehler: " + (err.message || "unbekannt"));
    };

    const wasmBytes = decodeBase64ToBytes(__VAULT_WASM_B64__);
    worker.postMessage(
      { type: "init", wasmBuffer: wasmBytes.buffer, epoch: epochAtSpawn },
      [wasmBytes.buffer]
    );
  }

  function rpc(op, payload, opEpoch) {
    touchActivity();
    const epoch = opEpoch === undefined ? sessionEpoch : opEpoch;
    if (epoch !== sessionEpoch) {
      return Promise.reject(makeStaleError());
    }
    if (!worker || !workerReady) {
      return Promise.reject(new Error("Kryptokern ist nicht bereit."));
    }
    const id = nextReqId++;
    setBusy(true);
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, epoch });
      worker.postMessage({
        type: "rpc",
        id,
        epoch,
        req: payload === undefined ? { op } : { op, payload },
      });
    });
  }

  function clearPlaintextDisplay() {
    $("dec-output").value = "";
    $("dec-result").hidden = true;
    $("dec-meta").textContent = "";
    $("dec-sig-box").textContent = "";
    zeroizeUint8(lastDecBytes);
    lastDecBytes = null;
    lastDecEpoch = 0;
    plaintextClearAt = 0;
  }

  function clearAllUiFields() {
    for (const id of [
      "import-text", "enc-text", "enc-output", "enc-sign-pw",
      "dec-text", "dec-output", "dec-pw",
      "sign-text", "sign-output", "sign-pw",
      "ver-text", "ver-sig-text",
      "kg-uid", "kg-pw", "kg-pw2", "kg-pub", "kg-sec",
    ]) {
      const el = $(id);
      if (el) el.value = "";
    }
    for (const id of ["import-file", "enc-file", "dec-file", "sign-file", "ver-file", "ver-sig-file"]) {
      const el = $(id);
      if (el) el.value = "";
    }
    for (const id of ["enc-result", "dec-result", "sign-result", "ver-result", "kg-result"]) {
      const el = $(id);
      if (el) el.hidden = true;
    }
    zeroizeUint8(lastEncBytes);
    zeroizeUint8(lastDecBytes);
    zeroizeUint8(lastSignBytes);
    lastEncBytes = null;
    lastEncEpoch = 0;
    lastDecBytes = null;
    lastDecEpoch = 0;
    lastSignBytes = null;
    lastSignEpoch = 0;
    plaintextClearAt = 0;
    sessionKeys = [];
    renderKeys();
  }

  function performWipe(reason, forceRestartWorker) {
    // Bump epoch FIRST and abort all active FileReaders so no late file read or Worker
    // result can ever trigger a Worker RPC, UI update, or plaintext download!
    sessionEpoch++;
    abortActiveFileReaders();
    for (const [, entry] of pending) {
      entry.reject(makeStaleError());
    }
    pending.clear();

    clearAllUiFields();
    revokeAllBlobUrls();
    touchActivity();
    setStatus(reason || "Notfall-Wipe ausgeführt…", "ok");

    if (forceRestartWorker || !workerReady) {
      spawnWorker();
      setStatus(reason || "Notfall-Wipe ausgeführt (Worker neu gestartet).", "ok");
      return;
    }

    // Request cooperative zeroize in Worker; terminate & restart if it does not reply within 400ms
    const wipeEpoch = sessionEpoch;
    let acked = false;
    const prevHandler = worker.onmessage;
    const fallbackTimer = setTimeout(() => {
      if (!acked) {
        spawnWorker();
        setStatus((reason || "Wipe") + " — Worker beendet und frisch gestartet.", "ok");
      }
    }, 400);

    worker.onmessage = (ev) => {
      if (ev.data && ev.data.type === "wiped" && ev.data.epoch === wipeEpoch) {
        acked = true;
        clearTimeout(fallbackTimer);
        worker.onmessage = prevHandler;
        setBusy(false);
        setStatus(reason || "Notfall-Wipe abgeschlossen (Puffer & Oberfläche geleert).", "ok");
      }
    };
    worker.postMessage({ type: "wipe", epoch: wipeEpoch });
  }

  function showEnvError(msg) {
    const el = $("env-error");
    el.textContent = msg;
    el.hidden = false;
    $("worker-badge").textContent = "Nicht verfügbar";
    $("worker-badge").className = "badge badge-err";
    setBusy(false);
  }

  function renderSignatureBox(container, sig) {
    container.textContent = "";
    container.className = "sig-box";

    const addLine = (label, value, cls) => {
      const div = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = label + ": ";
      const span = document.createElement("span");
      span.textContent = value;
      if (cls) span.className = cls;
      div.appendChild(strong);
      div.appendChild(span);
      container.appendChild(div);
    };

    if (!sig || sig.status === "none") {
      addLine("Signaturstatus", "Keine Signatur vorhanden");
      return;
    }

    if (sig.status === "valid") {
      container.classList.add("valid");
      addLine("Signaturgültigkeit", "GÜLTIG (kryptografisch verifiziert)");
      addLine("Signatur-Fingerprint", formatFp(sig.signer_fingerprint), "mono");
      addLine(
        "Schlüssel-User-IDs (unbestätigt)",
        sig.signer_user_ids && sig.signer_user_ids.length ? sig.signer_user_ids.join(", ") : "(keine User-ID)"
      );
      addLine(
        "Nutzerbestätigte Identität",
        sig.signer_identity_confirmed
          ? "BESTÄTIGT (Fingerprint in dieser Sitzung manuell bestätigt)"
          : "NICHT BESTÄTIGT — bitte Fingerprint unabhängig prüfen!",
        sig.signer_identity_confirmed ? "badge badge-ok" : "badge badge-warn"
      );
      if (sig.created_at) {
        addLine("Signatur-Zeitstempel", new Date(sig.created_at * 1000).toISOString());
      }
    } else if (sig.status === "unknown_signer") {
      container.classList.add("invalid");
      addLine("Signaturgültigkeit", "UNBEKANNTER ABSENDER (kein passender öffentlicher Schlüssel geladen)");
    } else {
      container.classList.add("invalid");
      addLine("Signaturgültigkeit", "UNGÜLTIG (Signatur passt nicht zu Daten oder geladenen Schlüsseln)");
    }
  }

  function renderKeys() {
    $("key-count").textContent = sessionKeys.length + (sessionKeys.length === 1 ? " Schlüssel" : " Schlüssel");

    const listEl = $("key-list");
    listEl.textContent = "";
    if (sessionKeys.length === 0) {
      const p = document.createElement("p");
      p.className = "muted small";
      p.textContent = "Noch keine Schlüssel geladen.";
      listEl.appendChild(p);
    } else {
      for (const k of sessionKeys) {
        const card = document.createElement("div");
        card.className = "key-card";

        const head = document.createElement("div");
        head.className = "row";
        const uid = document.createElement("strong");
        uid.textContent = k.user_ids.length ? k.user_ids[0] : "(ohne User-ID / pseudonym)";
        head.appendChild(uid);

        const typeBadge = document.createElement("span");
        typeBadge.className = "badge " + (k.has_secret ? "badge-ok" : "");
        typeBadge.textContent = (k.has_secret ? "Secret+Public" : "Public") + " · " + k.version;
        head.appendChild(typeBadge);
        card.appendChild(head);

        const fpEl = document.createElement("div");
        fpEl.className = "key-fp";
        fpEl.textContent = formatFp(k.fingerprint);
        card.appendChild(fpEl);

        const idStatus = document.createElement("div");
        idStatus.className = "row";
        const confBadge = document.createElement("span");
        confBadge.className = "badge " + (k.identity_confirmed ? "badge-ok" : "badge-warn");
        confBadge.textContent = k.identity_confirmed ? "Identität bestätigt" : "Identität unbestätigt";
        idStatus.appendChild(confBadge);

        const btnConf = document.createElement("button");
        btnConf.type = "button";
        btnConf.className = "btn btn-sm";
        btnConf.textContent = k.identity_confirmed ? "Bestätigung aufheben" : "Fingerprint bestätigen";
        btnConf.addEventListener("click", async () => {
          try {
            const res = await rpc("ConfirmIdentity", {
              fingerprint: k.fingerprint,
              confirmed: !k.identity_confirmed,
            });
            if (res.ok) await refreshKeys();
          } catch (e) { setStatus(String(e), "err"); }
        });
        idStatus.appendChild(btnConf);

        const btnDel = document.createElement("button");
        btnDel.type = "button";
        btnDel.className = "btn btn-sm btn-danger";
        btnDel.textContent = "Entfernen";
        btnDel.addEventListener("click", async () => {
          try {
            await rpc("RemoveKey", { fingerprint: k.fingerprint });
            await refreshKeys();
          } catch (e) { setStatus(String(e), "err"); }
        });
        idStatus.appendChild(btnDel);

        card.appendChild(idStatus);
        listEl.appendChild(card);
      }
    }

    // Update recipients checklist
    const recEl = $("enc-recipients");
    const checkedBefore = new Set(
      Array.from(recEl.querySelectorAll("input[type=checkbox]:checked")).map((c) => c.value)
    );
    recEl.textContent = "";
    const encKeys = sessionKeys.filter((k) => k.can_encrypt);
    if (encKeys.length === 0) {
      const s = document.createElement("span");
      s.className = "muted small";
      s.textContent = "Kein verschlüsselungsfähiger Schlüssel geladen.";
      recEl.appendChild(s);
    } else {
      for (const k of encKeys) {
        const lbl = document.createElement("label");
        lbl.className = "check-item";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.value = k.fingerprint;
        if (checkedBefore.has(k.fingerprint) || encKeys.length === 1) cb.checked = true;
        const info = document.createElement("span");
        const title = k.user_ids.length ? k.user_ids[0] : "(ohne User-ID)";
        const conf = k.identity_confirmed ? " [bestätigt]" : " [unbestätigt]";
        info.textContent = title + conf + " — " + formatFp(k.fingerprint);
        lbl.appendChild(cb);
        lbl.appendChild(info);
        recEl.appendChild(lbl);
      }
    }

    // Update signer dropdowns
    const signKeys = sessionKeys.filter((k) => k.has_secret && k.can_sign);
    for (const [selId, emptyLabel] of [
      ["enc-signer", "— Nicht signieren —"],
      ["sign-key", "— Signaturschlüssel wählen —"],
    ]) {
      const sel = $(selId);
      const prev = sel.value;
      sel.textContent = "";
      const opt0 = document.createElement("option");
      opt0.value = "";
      opt0.textContent = emptyLabel;
      sel.appendChild(opt0);
      for (const k of signKeys) {
        const opt = document.createElement("option");
        opt.value = k.fingerprint;
        const label = k.user_ids.length ? k.user_ids[0] : "(ohne User-ID)";
        opt.textContent = label + " (" + k.fingerprint.slice(-16) + ")";
        sel.appendChild(opt);
      }
      if (signKeys.some((k) => k.fingerprint === prev)) {
        sel.value = prev;
      } else if (selId === "sign-key" && signKeys.length === 1) {
        sel.value = signKeys[0].fingerprint;
      }
    }
    $("enc-sign-pw-row").hidden = !$("enc-signer").value;
  }

  async function refreshKeys(opEpoch) {
    const epoch = opEpoch === undefined ? sessionEpoch : opEpoch;
    if (epoch !== sessionEpoch) return;
    const res = await rpc("ListKeys", undefined, epoch);
    if (epoch !== sessionEpoch) return;
    if (res.ok) {
      sessionKeys = res.data || [];
      renderKeys();
    }
  }

  function initTrustBanner() {
    const isFile = location.protocol === "file:";
    const badge = $("mode-badge");
    const trust = $("trust-text");
    if (isFile) {
      badge.textContent = "Offline-Datei (file://)";
      badge.className = "badge badge-ok";
      trust.textContent =
        "Lokaler Offline-Start (file://): Die App führt alle OpenPGP-Operationen lokal ohne Netzwerkverbindungen aus. Stellen Sie sicher, dass diese HTML-Datei vor dem Öffnen extern signaturgeprüft wurde.";
    } else {
      badge.textContent = "Online (" + location.origin + ")";
      badge.className = "badge badge-warn";
      trust.textContent =
        "Online-Start über Webserver: Diese Nutzung setzt Vertrauen in den ausgelieferten Code, den Webserver (GitHub Pages) und das Endgerät voraus; beim Seitenabruf können Verbindungsdaten anfallen. Für hochsensible Daten laden Sie die signierte Release-HTML-Datei herunter, prüfen deren Signatur extern und öffnen sie offline.";
    }
  }

  function initTabs() {
    const tabs = document.querySelectorAll(".tab");
    tabs.forEach((btn) => {
      btn.addEventListener("click", () => {
        touchActivity();
        const target = btn.getAttribute("data-tab");
        tabs.forEach((t) => {
          const active = t === btn;
          t.classList.toggle("active", active);
          t.setAttribute("aria-selected", active ? "true" : "false");
        });
        document.querySelectorAll(".tab-pane").forEach((pane) => {
          const match = pane.id === "tab-" + target;
          pane.hidden = !match;
          pane.classList.toggle("active", match);
        });
      });
    });
  }

  function initTimersAndLifecycle() {
    const activityEvents = ["pointerdown", "keydown", "input", "change"];
    for (const ev of activityEvents) {
      window.addEventListener(ev, touchActivity, { passive: true });
    }

    $("timeout-select").addEventListener("change", (e) => {
      timeoutSec = parseInt(e.target.value, 10) || 300;
      touchActivity();
    });

    setInterval(() => {
      const now = Date.now();
      const elapsedSec = Math.floor((now - lastActivityAt) / 1000);
      const remaining = Math.max(0, timeoutSec - elapsedSec);
      const mm = String(Math.floor(remaining / 60)).padStart(2, "0");
      const ss = String(remaining % 60).padStart(2, "0");
      $("timeout-badge").textContent = "Timeout: " + mm + ":" + ss;

      if (remaining === 0) {
        performWipe("Inaktivitäts-Timeout erreicht — Sitzung bereinigt.", false);
        return;
      }

      if (plaintextClearAt > 0) {
        const ptRem = Math.max(0, Math.ceil((plaintextClearAt - now) / 1000));
        $("dec-autoclear").textContent = "Klartext leert in " + ptRem + "s";
        if (ptRem === 0) {
          clearPlaintextDisplay();
          setStatus("Klartext-Anzeige nach Schutzfrist automatisch geleert.", "ok");
        }
      }
    }, 1000);

    // Check timeout upon returning from background (timers may pause while hidden)
    const checkAfterResume = () => {
      const now = Date.now();
      if (document.visibilityState === "hidden") {
        if ($("wipe-on-hide").checked) {
          performWipe("Tab ausgeblendet — Sitzung bereinigt.", true);
        }
        return;
      }
      if (now - lastActivityAt >= timeoutSec * 1000) {
        performWipe("Sperrfrist im Hintergrund abgelaufen — Sitzung bereinigt.", true);
      } else if (plaintextClearAt > 0 && now >= plaintextClearAt) {
        clearPlaintextDisplay();
      }
    };

    document.addEventListener("visibilitychange", checkAfterResume);
    window.addEventListener("focus", checkAfterResume);
    window.addEventListener("pagehide", () => performWipe("Seite verlassen.", true));
  }

  function wireActions() {
    $("btn-wipe").addEventListener("click", () => {
      performWipe("Notfall-Wipe durch Nutzer ausgelöst.", false);
    });

    $("btn-abort").addEventListener("click", () => {
      sessionEpoch++;
      abortActiveFileReaders();
      for (const [, entry] of pending) {
        entry.reject(makeStaleError());
      }
      pending.clear();
      // Restart worker to stop any heavy computation immediately
      spawnWorker();
      setStatus("Laufender Vorgang abgebrochen; verspätete Ergebnisse werden verworfen.", "ok");
    });

    $("enc-signer").addEventListener("change", () => {
      $("enc-sign-pw-row").hidden = !$("enc-signer").value;
    });

    // IMPORT
    $("btn-import").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      let bytes = null;
      try {
        const file = $("import-file").files[0];
        if (file) {
          bytes = await readFileAsBytes(file, opEpoch);
          if (opEpoch !== sessionEpoch) return;
          $("import-file").value = "";
        } else {
          const text = $("import-text").value.trim();
          if (!text) {
            setStatus("Bitte Schlüsseltext einfügen oder Datei wählen.", "err");
            return;
          }
          bytes = new TextEncoder().encode(text);
          $("import-text").value = "";
        }
        if (opEpoch !== sessionEpoch) return;
        setStatus("Importiere und prüfe Schlüssel…", "busy");
        const b64 = encodeBytesToBase64(bytes);
        zeroizeUint8(bytes);
        bytes = null;
        if (opEpoch !== sessionEpoch) return;
        const res = await rpc("ImportKeys", { data_b64: b64 }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          setStatus("Import fehlgeschlagen: " + res.error, "err");
          return;
        }
        await refreshKeys(opEpoch);
        if (opEpoch !== sessionEpoch) return;
        setStatus(
          res.data.imported.length + " Schlüssel importiert (Identität noch unbestätigt — bitte Fingerprint prüfen).",
          "ok"
        );
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        setStatus("Import-Fehler: " + String(err.message || err), "err");
      } finally {
        zeroizeUint8(bytes);
      }
    });

    // ENCRYPT
    $("btn-encrypt").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      const signPw = $("enc-sign-pw").value;
      $("enc-sign-pw").value = ""; // Immediately clear passphrase field!
      let plainBytes = null;
      try {
        const recipients = Array.from(
          $("enc-recipients").querySelectorAll("input[type=checkbox]:checked")
        ).map((c) => c.value);
        if (recipients.length === 0) {
          setStatus("Bitte mindestens einen Empfänger auswählen.", "err");
          return;
        }
        const armor = $("enc-armor").checked;
        const profile = $("enc-profile").value;
        const signFp = $("enc-signer").value || null;
        const file = $("enc-file").files[0];
        if (file) {
          plainBytes = await readFileAsBytes(file, opEpoch);
          if (opEpoch !== sessionEpoch) return;
        } else {
          const text = $("enc-text").value;
          if (!text) {
            setStatus("Bitte Klartext eingeben oder Datei wählen.", "err");
            return;
          }
          plainBytes = new TextEncoder().encode(text);
        }
        if (opEpoch !== sessionEpoch) return;
        const b64 = encodeBytesToBase64(plainBytes);
        zeroizeUint8(plainBytes);
        plainBytes = null;
        if (opEpoch !== sessionEpoch) return;

        setStatus("Verschlüssele im Worker…", "busy");
        const res = await rpc("Encrypt", {
          plaintext_b64: b64,
          recipient_fingerprints: recipients,
          sign_fingerprint: signFp,
          sign_passphrase: signFp ? signPw : null,
          profile,
          armor,
          now_secs: Math.floor(Date.now() / 1000),
        }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          setStatus("Verschlüsselung fehlgeschlagen: " + res.error, "err");
          return;
        }
        const outBytes = decodeBase64ToBytes(res.data.output_b64);
        if (opEpoch !== sessionEpoch) {
          zeroizeUint8(outBytes);
          return;
        }
        zeroizeUint8(lastEncBytes);
        lastEncBytes = outBytes;
        lastEncEpoch = opEpoch;
        lastEncIsArmor = armor;
        $("enc-output").value = armor
          ? res.data.output_armored
          : "[Binäre OpenPGP-Ausgabe: " + lastEncBytes.length + " Bytes — bitte über Herunterladen speichern]";
        const a = res.data.packet_audit;
        $("enc-audit-badge").textContent =
          "SEIPD v" + a.seipd_version + " · " + a.pkesk_count + " anonyme PKESK (v" + a.pkesk_versions.join(",v") + ")";
        $("enc-result").hidden = false;
        setStatus("Verschlüsselung abgeschlossen: " + res.data.profile_used, "ok");
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        setStatus("Verschlüsselungsfehler: " + String(err.message || err), "err");
      } finally {
        zeroizeUint8(plainBytes);
      }
    });

    $("btn-enc-copy").addEventListener("click", () => {
      if (lastEncIsArmor && lastEncEpoch === sessionEpoch) copyExplicit($("enc-output").value, "Verschlüsselte Nachricht");
    });
    $("btn-enc-download").addEventListener("click", () => {
      if (!lastEncBytes || lastEncEpoch !== sessionEpoch) return;
      downloadBytes(
        lastEncBytes,
        lastEncIsArmor ? "vault-output.asc" : "vault-output.pgp",
        lastEncIsArmor ? "text/plain;charset=utf-8" : "application/pgp-encrypted"
      );
    });
    $("btn-enc-clear").addEventListener("click", () => {
      $("enc-output").value = "";
      $("enc-result").hidden = true;
      zeroizeUint8(lastEncBytes);
      lastEncBytes = null;
      lastEncEpoch = 0;
    });

    // DECRYPT
    $("btn-decrypt").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      const pw = $("dec-pw").value;
      $("dec-pw").value = ""; // Immediately clear passphrase field!
      clearPlaintextDisplay();
      let inBytes = null;
      try {
        const allowV1 = $("dec-allow-v1").checked;
        const file = $("dec-file").files[0];
        if (file) {
          inBytes = await readFileAsBytes(file, opEpoch);
          if (opEpoch !== sessionEpoch) return;
        } else {
          const text = $("dec-text").value.trim();
          if (!text) {
            setStatus("Bitte verschlüsselte Nachricht einfügen oder Datei wählen.", "err");
            return;
          }
          inBytes = new TextEncoder().encode(text);
        }
        if (opEpoch !== sessionEpoch) return;
        const b64 = encodeBytesToBase64(inBytes);
        zeroizeUint8(inBytes);
        inBytes = null;
        if (opEpoch !== sessionEpoch) return;

        setStatus("Entschlüssele und prüfe Nachrichtenintegrität…", "busy");
        const res = await rpc("Decrypt", {
          input_b64: b64,
          passphrase: pw,
          allow_legacy_seipd_v1: allowV1,
        }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          clearPlaintextDisplay();
          setStatus("Entschlüsselung abgelehnt: " + res.error, "err");
          return;
        }
        const ptBytes = decodeBase64ToBytes(res.data.plaintext_b64);
        if (opEpoch !== sessionEpoch) {
          zeroizeUint8(ptBytes);
          return;
        }
        lastDecBytes = ptBytes;
        lastDecEpoch = opEpoch;
        const textPreview = new TextDecoder("utf-8", { fatal: false }).decode(lastDecBytes);
        $("dec-output").value = textPreview;

        const meta = $("dec-meta");
        meta.textContent = "";
        for (const label of [
          "SEIPD v" + res.data.seipd_version,
          "Größe: " + lastDecBytes.length + " Bytes",
          "Literal-Dateiname: " + (res.data.literal_filename || "(leer)"),
          "Literal-Zeitstempel: " + res.data.literal_timestamp,
        ]) {
          const b = document.createElement("span");
          b.className = "badge";
          b.textContent = label;
          meta.appendChild(b);
        }

        renderSignatureBox($("dec-sig-box"), res.data.signature);
        plaintextClearAt = Date.now() + PLAINTEXT_AUTOCLEAR_SEC * 1000;
        $("dec-autoclear").textContent = "Klartext leert in " + PLAINTEXT_AUTOCLEAR_SEC + "s";
        $("dec-result").hidden = false;
        setStatus("Entschlüsselung und Integritätsprüfung erfolgreich.", "ok");
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        clearPlaintextDisplay();
        setStatus("Entschlüsselungsfehler: " + String(err.message || err), "err");
      } finally {
        zeroizeUint8(inBytes);
      }
    });

    $("btn-dec-copy").addEventListener("click", () => {
      if (lastDecEpoch === sessionEpoch) copyExplicit($("dec-output").value, "Klartext");
    });
    $("btn-dec-download").addEventListener("click", () => {
      if (!lastDecBytes || lastDecEpoch !== sessionEpoch) return;
      downloadBytes(lastDecBytes, "vault-plaintext.bin", "application/octet-stream");
    });
    $("btn-dec-clear").addEventListener("click", () => {
      clearPlaintextDisplay();
      setStatus("Klartext-Anzeige geleert.", "ok");
    });

    // SIGN DETACHED
    $("btn-sign").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      const pw = $("sign-pw").value;
      $("sign-pw").value = "";
      let dataBytes = null;
      try {
        const signFp = $("sign-key").value;
        if (!signFp) {
          setStatus("Bitte einen Signaturschlüssel auswählen.", "err");
          return;
        }
        const armor = $("sign-armor").checked;
        const file = $("sign-file").files[0];
        if (file) {
          dataBytes = await readFileAsBytes(file, opEpoch);
          if (opEpoch !== sessionEpoch) return;
        } else {
          const text = $("sign-text").value;
          if (!text) {
            setStatus("Bitte Text eingeben oder Datei wählen.", "err");
            return;
          }
          dataBytes = new TextEncoder().encode(text);
        }
        if (opEpoch !== sessionEpoch) return;
        const b64 = encodeBytesToBase64(dataBytes);
        zeroizeUint8(dataBytes);
        dataBytes = null;
        if (opEpoch !== sessionEpoch) return;

        setStatus("Erzeuge abgetrennte Signatur…", "busy");
        const res = await rpc("SignDetached", {
          data_b64: b64,
          sign_fingerprint: signFp,
          passphrase: pw,
          armor,
          now_secs: Math.floor(Date.now() / 1000),
        }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          setStatus("Signierung fehlgeschlagen: " + res.error, "err");
          return;
        }
        const sigOut = decodeBase64ToBytes(res.data.signature_b64);
        if (opEpoch !== sessionEpoch) {
          zeroizeUint8(sigOut);
          return;
        }
        zeroizeUint8(lastSignBytes);
        lastSignBytes = sigOut;
        lastSignEpoch = opEpoch;
        lastSignIsArmor = armor;
        $("sign-output").value = armor
          ? res.data.signature_armored
          : "[Binäre Signatur: " + lastSignBytes.length + " Bytes]";
        $("sign-result").hidden = false;
        setStatus("Abgetrennte Signatur erzeugt.", "ok");
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        setStatus("Signaturfehler: " + String(err.message || err), "err");
      } finally {
        zeroizeUint8(dataBytes);
      }
    });

    $("btn-sign-copy").addEventListener("click", () => {
      if (lastSignIsArmor && lastSignEpoch === sessionEpoch) copyExplicit($("sign-output").value, "Signatur");
    });
    $("btn-sign-download").addEventListener("click", () => {
      if (!lastSignBytes || lastSignEpoch !== sessionEpoch) return;
      downloadBytes(
        lastSignBytes,
        lastSignIsArmor ? "vault-signature.asc" : "vault-signature.sig",
        lastSignIsArmor ? "text/plain;charset=utf-8" : "application/pgp-signature"
      );
    });

    // VERIFY DETACHED
    $("btn-verify").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      let dataBytes = null;
      let sigBytes = null;
      try {
        const dFile = $("ver-file").files[0];
        if (dFile) {
          dataBytes = await readFileAsBytes(dFile, opEpoch);
          if (opEpoch !== sessionEpoch) return;
        } else {
          const text = $("ver-text").value;
          if (!text) {
            setStatus("Bitte zu prüfende Daten angeben.", "err");
            return;
          }
          dataBytes = new TextEncoder().encode(text);
        }

        const sFile = $("ver-sig-file").files[0];
        if (sFile) {
          sigBytes = await readFileAsBytes(sFile, opEpoch);
          if (opEpoch !== sessionEpoch) return;
        } else {
          const text = $("ver-sig-text").value.trim();
          if (!text) {
            setStatus("Bitte Signatur angeben.", "err");
            return;
          }
          sigBytes = new TextEncoder().encode(text);
        }
        if (opEpoch !== sessionEpoch) return;

        const dataB64 = encodeBytesToBase64(dataBytes);
        const sigB64 = encodeBytesToBase64(sigBytes);
        zeroizeUint8(dataBytes);
        zeroizeUint8(sigBytes);
        dataBytes = null;
        sigBytes = null;
        if (opEpoch !== sessionEpoch) return;

        setStatus("Prüfe Signatur…", "busy");
        const res = await rpc("VerifyDetached", {
          data_b64: dataB64,
          signature_b64: sigB64,
        }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          setStatus("Verifikation fehlgeschlagen: " + res.error, "err");
          return;
        }
        renderSignatureBox($("ver-sig-box"), res.data);
        $("ver-result").hidden = false;
        setStatus("Signaturprüfung abgeschlossen.", res.data.status === "valid" ? "ok" : "err");
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        setStatus("Verifikationsfehler: " + String(err.message || err), "err");
      } finally {
        zeroizeUint8(dataBytes);
        zeroizeUint8(sigBytes);
      }
    });

    // KEYGEN
    $("btn-keygen").addEventListener("click", async () => {
      const opEpoch = sessionEpoch;
      const pw = $("kg-pw").value;
      const pw2 = $("kg-pw2").value;
      const uid = $("kg-uid").value;
      $("kg-pw").value = "";
      $("kg-pw2").value = "";
      try {
        if (pw !== pw2) {
          setStatus("Passphrasen stimmen nicht überein.", "err");
          return;
        }
        if (pw.length < 8) {
          setStatus("Passphrase muss mindestens 8 Zeichen lang sein (12+ empfohlen).", "err");
          return;
        }
        setStatus("Erzeuge RFC-9580-v6-Schlüssel (Argon2 + Ed25519 + X25519)…", "busy");
        const res = await rpc("GenerateKey", {
          user_id: uid.trim() ? uid.trim() : null,
          passphrase: pw,
          now_secs: Math.floor(Date.now() / 1000),
        }, opEpoch);
        if (opEpoch !== sessionEpoch) return;
        if (!res.ok) {
          setStatus("Schlüsselerzeugung fehlgeschlagen: " + res.error, "err");
          return;
        }
        $("kg-fp").textContent = formatFp(res.data.summary.fingerprint);
        $("kg-pub").value = res.data.public_key_armored;
        $("kg-sec").value = res.data.secret_key_armored;
        $("kg-result").hidden = false;
        await refreshKeys(opEpoch);
        if (opEpoch !== sessionEpoch) return;
        setStatus("Schlüssel erzeugt (" + res.data.profile + ") und in Sitzung geladen.", "ok");
      } catch (err) {
        if (opEpoch !== sessionEpoch || (err && err.staleEpoch)) return;
        setStatus("Schlüsselerzeugungsfehler: " + String(err.message || err), "err");
      }
    });

    $("btn-kg-pub-copy").addEventListener("click", () => copyExplicit($("kg-pub").value, "Öffentlicher Schlüssel"));
    $("btn-kg-sec-copy").addEventListener("click", () => copyExplicit($("kg-sec").value, "Geheimer Schlüssel"));
    $("btn-kg-pub-dl").addEventListener("click", () => {
      const text = $("kg-pub").value;
      if (text) downloadBytes(new TextEncoder().encode(text), "vault-public-key.asc", "text/plain;charset=utf-8");
    });
    $("btn-kg-sec-dl").addEventListener("click", () => {
      const text = $("kg-sec").value;
      if (text) downloadBytes(new TextEncoder().encode(text), "vault-secret-key.asc", "text/plain;charset=utf-8");
    });
  }

  // Startup checks (CSP, WebAssembly, Worker, CSPRNG)
  window.addEventListener("securitypolicyviolation", (e) => {
    setStatus("CSP-Verletzung blockiert: " + e.violatedDirective, "err");
  });

  initTrustBanner();
  initTabs();
  initTimersAndLifecycle();
  wireActions();

  if (typeof WebAssembly !== "object" || typeof Worker !== "function" || !(self.crypto && self.crypto.getRandomValues)) {
    showEnvError(
      "Erforderliche Browser-Funktionen (WebAssembly, Web Worker oder crypto.getRandomValues) sind deaktiviert — z. B. im Tor Browser auf Sicherheitsstufe „Safest“ oder „Safer“. Ohne CSPRNG und WebAssembly startet der Kryptokern nicht."
    );
    return;
  }

  spawnWorker();
})();
