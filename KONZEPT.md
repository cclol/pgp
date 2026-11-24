# Zero-Trace Wasm PGP Vault

## Ziel und Sicherheitsgrenzen

Der Vault verschlüsselt, entschlüsselt, signiert und prüft OpenPGP-Daten lokal im Browser. Das GitHub-Repository `cclol/pgp` ist der vorgesehene Veröffentlichungskanal. GitHub Pages liefert die Web-App direkt aus. Für sensible Daten ist eine vorab geprüfte, offline im Browser geöffnete Release-Datei der bevorzugte Einstieg.

**Zero Trace ist das Entwicklungsziel für appseitige Spuren.** Die App speichert keine Sitzungsdaten dauerhaft und überschreibt sensible Puffer, soweit sie diese kontrolliert. Browser, Betriebssystem und Erweiterungen können dennoch Spuren hinterlassen, etwa im Cache, im Auslagerungsspeicher, in Absturzabbildern oder in der Zwischenablage. Heruntergeladene Dateien sind bewusste Exporte.

Die Online-Nutzung setzt Vertrauen in den ausgelieferten Code und das Endgerät voraus. GitHub kann beim Seitenabruf Verbindungsdaten erhalten. Tor Browser kann die Quell-IP gegenüber GitHub abschirmen. Für die Offline-Nutzung setzt das Konzept zusätzlich eine unabhängige Release-Verifikation voraus.

## Auslieferung über GitHub

- **GitHub Pages.** Eine statische Seite auf der vorgesehenen Adresse `https://cclol.github.io/pgp/`, sobald Pages eingerichtet ist. Sie lädt keine CDNs, externen Fonts, Analytik oder sonstigen Drittinhalte. Die Online-Seite erklärt vor der ersten Eingabe, welches Vertrauen dieser Startweg voraussetzt.
- **GitHub Releases.** Dieselbe selbstständige HTML-Datei zusätzlich als Release-Download mit abgetrennter Signatur veröffentlichen. Die Signatur deckt die gesamte Datei ab, einschließlich JavaScript, Wasm und Styles. Anwender prüfen die Datei vor dem Öffnen mit einem unabhängig bezogenen öffentlichen Prüfschlüssel und öffnen sie anschließend bei Bedarf ohne Netzwerk. Ein Hash auf derselben Website dient höchstens als Build-Kennung.
- **Build und Freigabe.** Rust-Toolchain, Abhängigkeiten, Wasm-Werkzeuge und CI-Actions auf konkrete Versionen beziehungsweise Commit-SHAs fixieren. Mit eingechecktem `Cargo.lock` bauen. Build-Jobs mit minimalen Berechtigungen ausführen, Deployments an einen geprüften Release-Stand binden und den Signaturschlüssel außerhalb des Pages-Workflows halten. Vergleichbare Builds aus zwei sauberen Umgebungen anhand des vollständigen Artefakts prüfen.

## Browser-Architektur

Vanilla JavaScript übernimmt die Bedienung, Datei-Eingaben und Downloads. Rust/Wasm übernimmt OpenPGP-Parsing und Kryptografie über rPGP. Der Build bettet Wasm-Bytes in die HTML-Auslieferung ein und instanziiert sie direkt aus dem Speicher. Ein dedizierter Worker soll den Kryptokern vom UI-Thread trennen und bei Bedarf beendet werden können. Der Prototyp muss zunächst zeigen, dass die gewählte Worker-Einbettung mit der CSP und unter `file://` in den Zielbrowsern funktioniert.

Die CSP steht vor ausführbarem Inhalt. Ausgangspunkt ist `default-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`. Inline-Skript und Styles werden per Build-Hash freigegeben. Wasm-Kompilierung erhält die nötige Freigabe über `'wasm-unsafe-eval'`. Eine etwaige `blob:`-Freigabe gilt gezielt für Worker. Die CSP begrenzt Ressourcenabrufe des vorgesehenen Programms. Die Offline-Ausführung schützt zusätzlich vor Netzverkehr während der Verarbeitung und die externe Signatur schützt vor einer unbemerkten Änderung der ausgelieferten Datei.

## Sitzungsdaten und Bereinigung

- Schlüssel und Dateien bevorzugt als Bytepuffer einlesen. Beim Transfer in den Worker übertragbare Puffer nutzen und trotzdem alle verbleibenden Kopien an den JS-/Wasm-Grenzen erfassen. Passphrasen nur für den jeweiligen Vorgang anfordern, Eingabefelder sofort leeren und Browser-Autovervollständigung sowie Rechtschreibprüfung deaktivieren, soweit vom Browser unterstützt.
- Kontrollierte, sensible Rust-Puffer mit `zeroize` bereinigen, auch bei Fehlern. Entsperrte Schlüssel nur für die aktive Sitzung im Worker halten. Bei explizitem Wipe sofort die Oberfläche leeren, Ergebnisse laufender Vorgänge verwerfen und den Worker zur Bereinigung auffordern. Falls er hängt, Worker beenden. Worker-Beendigung ist keine Zusage über das Überschreiben seines Speichers.
- Dieselbe Sitzungsbereinigung bei Inaktivität und bestmöglich bei Seitenwechsel oder Ausblenden auslösen. Sperrfrist bei Rückkehr prüfen, da Timer im Hintergrund pausieren können. Den Klartext nach kurzer Frist aus der Anzeige entfernen. Blob-URLs nach Benutzung widerrufen. Browser-Lebenszyklusereignisse sind Zusatzmaßnahmen.
- Kein `localStorage`, kein `sessionStorage`, kein IndexedDB, keine Cookies, kein Service Worker und keine appseitige Cache API für Sitzungsdaten. Klartext-Downloads und Kopieren nur als explizite Aktionen. Die App überschreibt die Zwischenablage nicht automatisch.

## OpenPGP und Metadaten

- Als modernes Schreibprofil RFC 9580 mit Ed25519 und X25519 für die Schlüsselerzeugung sowie v2-SEIPD mit AES-256 und AEAD vorsehen. Konkreten AEAD-Modus, Schlüsselversion und unterstützte Kombinationen anhand der fixierten rPGP-Version und der Interoperabilitätstests vor der Freigabe festlegen. Zufall ausschließlich aus der Browser-CSPRNG beziehen und bei Fehlern abbrechen.
- Ältere integritätsgeschützte v1-SEIPD-Nachrichten mit MDC nur über ein explizites Leseprofil unterstützen. Unauthentifizierte verschlüsselte Nachrichten ablehnen. Klartext erst nach vollständiger Prüfung der Nachrichtenintegrität freigeben. Bei kombinierten Nachrichten den Signaturstatus eindeutig ausweisen.
- Empfängerkennung im PKESK anonymisieren. Bei v3 die Null-Key-ID setzen. Bei v6 die Empfängerkennung weglassen. Die gewählte Implementierung anhand serialisierter Pakete prüfen. Anzahl der Empfängerpakete, Algorithmen und ungefähre Länge können sichtbar bleiben.
- Im verschlüsselten Literal-Paket einen leeren Dateinamen und Zeitstempel `0` schreiben. Ausgabedateien erhalten einen neutralen Dateinamen. ASCII Armor ohne Versions- und Kommentar-Header ausgeben. Pseudonyme User-IDs unterstützen. Schlüssel- und Signaturzeitstempel gemäß Format und Gültigkeitsregeln behandeln. Veröffentlichte Schlüssel und Signaturen können weiterhin Identitätsmerkmale enthalten.
- Empfänger-Fingerprints vor der Verschlüsselung anzeigen. Signaturgültigkeit, verwendeten Fingerprint und die durch den Nutzer bestätigte Identität getrennt anzeigen. Private Schlüssel nur passphrasengeschützt exportieren. Das konkrete S2K-Profil und seine Ressourcenlimits mit den Zielclients prüfen.

## Umfang und Abnahme

Die erste Version umfasst Text- und Dateioperationen, Mehrfachempfänger, Schlüsselimport, Signieren und Verifizieren sowie Offline-Schlüsselerzeugung mit geschütztem Export. Dateigröße, Paketanzahl, Dekompression und S2K-Ressourcenverbrauch erhalten feste Grenzen. Bei anonymen Empfängerpaketen die Zahl der Entschlüsselungsversuche begrenzen. Beim Abbruch oder bei Integritätsfehlern bleiben Klartextansicht und Klartextdownload gesperrt.

1. **Browser und Netz.** Auf der Pages-URL und direkt aus der heruntergeladenen Datei testen, einschließlich Tor Browser. Nach dem Start alle Kernfunktionen bei getrennter Verbindung ausführen. Während der Online-Tests sämtliche vom Dokument und Worker ausgelösten Requests erfassen und auf die vorgesehenen Abrufe prüfen.
2. **Speicher und Oberfläche.** Wipe, Timeout, Wiederaufnahme aus dem Hintergrund, Fehler und Abbruch testen. Eingabefelder, Ausgabeansichten, kontrollierte Puffer und Blob-URLs prüfen. Ein nach dem Wipe eintreffendes Worker-Ergebnis darf keinen Klartext wiederherstellen.
3. **Kryptografie und Austausch.** Konkrete Versionen von GnuPG und Kleopatra dokumentieren. Unterstützte Operationen in beiden Richtungen prüfen. Serialisierte Pakete auf Metadaten kontrollieren. Manipulierte, abgeschnittene und übergroße Nachrichten testen. Falls das moderne Profil mit einem Zielclient kollidiert, die Einschränkung offen dokumentieren oder ein ausdrücklich auswählbares und separat getestetes Kompatibilitätsprofil spezifizieren.
4. **Release.** Ein unabhängiger Prüflauf verifiziert die Signatur der heruntergeladenen Datei und weist nach, dass eine veränderte Datei die Prüfung nicht besteht. Die geprüfte Datei muss vollständig offline starten.

## Referenzen

- [OpenPGP gemäß RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)
- [rPGP-Quellcode und Dokumentation](https://github.com/rpgp/rpgp)
- [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [MDN zu CSP und Verbindungszielen](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)
