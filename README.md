# IT News Radar – kostenlose Website auf GitHub Pages

## Inbetriebnahme

1. Auf https://github.com/new ein **öffentliches** Repository `it-news-radar` erstellen (GitHub Pages ist für öffentliche Repositories im Gratisangebot verfügbar; Bedingungen beim Anbieter prüfen).
2. Alle Dateien **inklusive `.github/workflows/news.yml`** ins Repository hochladen (GitHub Weboberfläche oder Git).
3. Unter **Settings → Pages → Build and deployment** als Source **Deploy from a branch**, Branch `main`, Verzeichnis `/ (root)` auswählen und speichern.
4. Unter **Actions → IT News aktualisieren → Run workflow** die erste Datenaktualisierung starten. Unter **Settings → Actions → General → Workflow permissions** ggf. `Read and write permissions` für das Committen erlauben (abhängig von Repository- und Organisationsrichtlinien).
5. Die Website ist anschliessend typischerweise unter `https://BENUTZERNAME.github.io/it-news-radar/` erreichbar. Der genaue Link erscheint unter **Settings → Pages**.
6. Optional: Unter **Settings → Secrets and variables → Actions** das Repository-Secret `OPENAI_API_KEY` hinterlegen. Ohne Secret werden RSS-Auszüge als Kurzbeschreibungen angezeigt; mit Secret werden diese per KI verdichtet. API-Nutzung kann Kosten verursachen.

## Aktualisierung und SharePoint

Der GitHub-Workflow läuft ungefähr stündlich (GitHub Actions kann geplante Jobs verzögern). **Bei jedem Seitenaufruf** wird `news.json` neu vom Webserver angefordert. Es werden nicht bei jedem Aufruf neue RSS-Feeds eingelesen. Ein Klick auf «Jetzt aktualisieren» lädt die zuletzt veröffentlichte JSON-Datei erneut.

Die Website kann über einen Link in SharePoint eingebunden werden. Eine iFrame-Einbettung hängt von SharePoint-Administrationsrichtlinien und den Headern des Hosters ab und ist separat zu testen.

## Datenschutz und Betrieb

Die Website ist öffentlich und sollte keine internen Inhalte enthalten. API-Schlüssel gehören nur in GitHub Secrets, nie in JavaScript. Der Aktualisierungsjob liest ausschliesslich drei fest definierte Feeds. Quellen und KI-Ergebnisse sind nicht redaktionell verifiziert. `news.json` ist öffentlich. Prüfen Sie RSS-Nutzungsbedingungen und die Kosten der optionalen KI-API.

## Lokaler Test

`python update_news.py` (benötigt Netzwerkzugriff), anschliessend `python -m http.server 8000` und `http://localhost:8000` öffnen.
