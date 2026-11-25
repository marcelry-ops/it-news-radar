# IT News Radar – Qualitätsupdate (25.11.2026)

**Status:** Code-Patch mit Offline-Unit-Tests; kein Commit/Deployment. Der Patch wurde anhand der am 25.11.2026 öffentlich sichtbaren Python-Quelltexte entworfen. Da das Repository aus dieser Laufzeit nicht als vollständiges Git-Checkout geladen werden konnte, muss die Installation in einer lokalen Kopie erfolgen. `apply_upgrade.py` prüft entscheidende Textanker und beendet sich bei Abweichungen, statt still Änderungen vorzunehmen.

## Installation

1. Bestehendes Repository lokal klonen / als ZIP herunterladen und entpacken.
2. `radar_quality.py`, `apply_upgrade.py` und `tests/` aus diesem Paket ins Repository-Hauptverzeichnis kopieren.
3. Im Hauptverzeichnis `python apply_upgrade.py .` ausführen.
4. `python -m unittest discover -s tests -v` ausführen.
5. Sicherstellen, dass `python -m py_compile update_news.py update_cves.py radar_quality.py` erfolgreich ist.
6. Git-Diff manuell kontrollieren. Erst dann committen/pushen. Die bereits veröffentlichten JSON-Dateien bleiben bei der Installation unverändert. Die nächsten GitHub-Actions-Ausführungen erzeugen sie neu.

## Änderungen

- News: Tracking-Parameter aus URLs entfernen; globale Deduplizierung auf URL und Titel; priorisierte Personen-Kategorie ohne Doppelanzeige; differenzierte Schwerpunkt-Suchanfragen und stärkere Gewichtung besonders relevanter Ereignisse.
- CVE: Standard-NVD-Obergrenze 10'000 statt 2'000; Aufnahme neuester historischer CISA-KEV-Treffer über CVE.org (maximal 30 zusätzliche Lookups/Lauf); EPSS-API-Abfrage für erfasste CVEs; Ranking nach Ausnutzung, EPSS, CVSS und priorisierten Produkten; wichtige CVEs mit CVSS unter 9 zulassen.
- Produktzuordnung: keine Priorisierung allein wegen eines beiläufigen Produktbegriffs in einer Beschreibung; statt dessen Matching anhand strukturierter Produktfelder. Bei fehlenden CPE-/CNA-Feldern kann dies zu weniger Treffern führen.
- Qualitätsmetadaten: `knownExploited`, `kevAdded`, `epss`, `epssPercentile`, `kevStats`, `kevError`, `epssError` in Ausgabe.

## Noch zu prüfen / Grenzen

- Das bestehende `cve.html` zeigt möglicherweise statische CVSS-9.0-Beschriftungen. Diese sind im Dashboard vor dem Deployment an die neue Auswahlregel anzupassen. Das Datenformat bleibt abwärtskompatibel, aber die vollständige Frontend-Integration wurde nicht lokal geprüft.
- Die NVD-Suche kann auch bei 10'000 Treffern weiter abgeschnitten werden. `truncated` bleibt dafür als Diagnoseflag bestehen; zuverlässige Vollständigkeit erfordert inkrementelle Synchronisierung und Speicherung des letzten Abrufzeitpunkts.
- CISA KEV enthält bestätigte bekannte Ausnutzung, aber keine vollständige Liste aller weltweit ausgenutzten Schwachstellen. Historische KEV-Anreicherung ist mit 30 API-Lookups/Lauf budgetiert. `kevStats.deferred` weist nicht bearbeitete Kandidaten aus.
- EPSS kann ausfallen oder nur Teilmengen liefern. Bei Fehlern gilt der Score als unbekannt, nicht als nachweislich niedrig.
- Neu gesetzte Suchqueries hängen von externem Google-News-RSS-Index ab; eine vollständige Abdeckung aller Artikel ist nicht belegbar.
- News-Deduplizierung balanciert übersehene Dubletten gegen versehentlich zusammengefasste unterschiedliche Artikel; heuristisch, nicht absolut.
- Die Kosten/Rate-Limits der APIs und die Laufzeit von GitHub Actions sind nach dem ersten produktiven Lauf zu prüfen.

## Erwartete Prüfungen nach Deployment

`news_diagnostics.json`: `rawCandidates`, `uniqueCandidates`, `feedFailures`, `selectedPerCategory` vergleichen. In `news.json` gleiche kanonische URLs und gleiche IDs suchen. `cves.json`: `truncated`, `kevCount`, `epssCount`, `kevStats.deferred`, Fehlermeldungen und Priorisierungsreihenfolge kontrollieren. Besonders CVEs mit `knownExploited=true` und `score<9` im Top-50-Ergebnis prüfen.
