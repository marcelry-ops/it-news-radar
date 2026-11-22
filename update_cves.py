#!/usr/bin/env python3
"""Recent CVEs: NVD plus cve.now, ENISA EUVD and CVE.org enrichment.
Only standard library; source failures are reported in cves.json.
"""
import datetime as dt
import json
import html
import logging
import os
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

UTC = dt.timezone.utc
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EUVD = 'https://euvdservices.enisa.europa.eu/api/search'
NOW = 'https://cve.now/feed?format=json'
CVE_ORG = 'https://cveawg.mitre.org/api/cve/'
DAYS = max(1, min(int(os.getenv('CVE_DAYS', '14')), 120))
MAX_ITEMS = max(50, min(int(os.getenv('CVE_MAX_ITEMS', '2000')), 10000))
TOP_CVES = 50
MIN_CVSS = 9.0
# Separate bounded historical lookups for priority software.
HISTORICAL_RESULTS_PER_TERM = 100
HISTORICAL_PAGES_PER_TERM = max(1, min(int(os.getenv("CVE_HISTORICAL_PAGES", "2")), 5))
VENDOR_DISCOVERY_LIMIT = max(0, min(int(os.getenv("CVE_VENDOR_DISCOVERY_LIMIT", "90")), 300))
# Gemeinsame Konfiguration fuer Frontend und Datenerzeugung.
CONFIG_FILE = Path(__file__).with_name('priority_products.json')

def valid_advisory_domain(domain):
    """Nur DNS-Hostnamen, keine URL, Pfade, Wildcards oder lokalen Hosts."""
    if not isinstance(domain, str) or len(domain) > 253:
        return False
    domain = domain.strip().lower()
    if not re.fullmatch(r'[a-z0-9.-]+', domain) or '..' in domain:
        return False
    parts = domain.split('.')
    return (len(parts) >= 2 and all(0 < len(p) <= 63 and
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', p) for p in parts)
            and not parts[-1].isdigit())

def load_priority_config(path=CONFIG_FILE):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('products'), list):
        raise ValueError('priority_products.json: products muss eine Liste sein')
    result = {}
    search = []
    for entry in data['products']:
        name = str(entry.get('name', '')).strip()
        patterns = entry.get('patterns', [])
        searches = entry.get('searchTerms', [])
        if not name or len(name) > 80 or name in result:
            raise ValueError('Produktname fehlt, ist doppelt oder zu lang: ' + name)
        if not isinstance(patterns, list) or not patterns or len(patterns) > 12:
            raise ValueError('Ungueltige Muster fuer ' + name)
        if not isinstance(searches, list) or not searches or len(searches) > 12:
            raise ValueError('Ungueltige Suchbegriffe fuer ' + name)
        for p in patterns:
            if not isinstance(p, str) or len(p) > 180:
                raise ValueError('Ungueltiger Regex fuer ' + name)
            re.compile(p)
        domain = entry.get('advisoryDomain', '')
        if domain is None: domain = ''
        if not isinstance(domain, str) or (domain.strip() and not valid_advisory_domain(domain.strip().lower())):
            raise ValueError('Ungueltige Herstellerdomain fuer ' + name)
        result[name] = patterns
        search.extend(str(s).strip() for s in searches if str(s).strip())
    return result, list(dict.fromkeys(search))

PRIORITY_TERMS, HISTORICAL_SEARCH_TERMS = load_priority_config()

# Hersteller-/Produktdomains zur Erkennung offizieller Advisories im News-Suchindex.
# Kein Hersteller bietet zwingend einen standardisierten, oeffentlichen CVE-Feed.
# Die Domains sind Kandidaten fuer die Recherche, keine Zusicherung der Abdeckung.
# Herstellerdomains werden ausschliesslich in priority_products.json gepflegt.


def discover_official_cve_ids(config, fetch=None):
    """Find CVE identifiers indexed for official vendor domains; verify later via NVD.

    This is discovery via Google News RSS, NOT a direct vendor advisory API.
    """
    fetch = fetch or get_xml
    result = {}
    errors = []
    for entry in config.get('products', []):
        name = entry['name']
        domain = str(entry.get('advisoryDomain') or '').strip().lower()
        if not domain:
            errors.append(name + ': keine verifizierte offizielle Advisory-Domain konfiguriert')
            continue
        if not valid_advisory_domain(domain):
            errors.append(name + ': ungueltige Domain')
            continue
        query = 'site:' + domain + ' CVE ' + name
        url = 'https://news.google.com/rss/search?' + urllib.parse.urlencode({'q': query, 'hl': 'en', 'gl': 'US', 'ceid': 'US:en'})
        try:
            xml_data = fetch(url)
            root = ET.fromstring(xml_data)
            ids = set()
            for node in root.findall('.//item'):
                text = ' '.join(node.findtext(k, '') for k in ('title', 'description', 'link'))
                ids.update(x.upper() for x in ID_RE.findall(html.unescape(text)))
            result[name] = sorted(ids)
        except Exception as exc:
            errors.append(name + ': ' + str(exc)[:100])
    return result, errors

def get_xml(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'ITNewsDashboard/1.0', 'Accept': 'application/rss+xml, application/xml'})
    with urllib.request.urlopen(req, timeout=25) as response:
        return response.read(1_500_000)



def priority_products(item):
    text = ' '.join([str(item.get('description', '')), ' '.join(item.get('products') or [])]).casefold()
    return [name for name, patterns in PRIORITY_TERMS.items() if any(re.search(pattern, text, re.I) for pattern in patterns)]

def short_title(text):
    text = re.sub(r'\s+', ' ', html.unescape(str(text or ''))).strip()
    first = re.split(r'(?<=[.!?])\s+', text, maxsplit=1)[0]
    return first[:125].rstrip(' ,;:-') + ('…' if len(first) > 125 else '') if first else 'Schwachstelle ohne Titel'

def dedupe_aliases(items):
    # Prefer the CVE as canonical ID if an EUVD row names the same CVE.
    by_id = {x['id']: x for x in items}
    for euvd_id in [k for k in list(by_id) if k.startswith('EUVD-')]:
        row = by_id.get(euvd_id)
        if not row: continue
        aliases = [x for x in row.get('aliases', []) if x.startswith('CVE-')]
        canonical = next((x for x in aliases if x in by_id), None)
        if canonical:
            merge(by_id[canonical], row)
            by_id[canonical]['aliases'] = list(dict.fromkeys(by_id[canonical].get('aliases', []) + [euvd_id]))
            del by_id[euvd_id]
    return list(by_id.values())

def choose_top(items, limit=TOP_CVES):
    ranked = rank(items)
    priority = [x for x in ranked if x.get('priorityProducts')]
    regular = [x for x in ranked if not x.get('priorityProducts')]
    # Prefer relevant software in the 50-record selection, while still showing
    # newest modified timestamp first and severity second in the final list.
    return rank((priority + regular)[:limit])

def translate_descriptions(items):
    # Offline, no API key, no external transmission of article content.
    # Requires argostranslate and en->de model preinstalled by the workflow.
    try:
        import argostranslate.translate as trans
        installed = trans.get_installed_languages()
        en = next((x for x in installed if x.code == 'en'), None)
        de = next((x for x in installed if x.code == 'de'), None)
        translator = en.get_translation(de) if en and de else None
    except Exception as exc:
        print('WARN: German translation unavailable:', str(exc)[:120])
        translator = None
    cache = {}
    for item in items:
        raw = item.get('description', '')
        if not raw or raw == 'Keine Beschreibung vorhanden.':
            item['language'] = 'unknown'; continue
        # Source language metadata is often absent; attempt offline translation
        # on English-looking text; do not label unverified output as translated.
        english = bool(re.search(r'\b(the|allows|vulnerability|affected|could|remote|attacker|arbitrary)\b', raw, re.I))
        if not english:
            item['language'] = 'de'; continue
        if translator:
            try:
                if raw not in cache: cache[raw] = translator.translate(raw[:1600])
                if cache[raw] and cache[raw] != raw:
                    item['descriptionOriginal'] = raw
                    item['description'] = cache[raw]
                    item['language'] = 'de'; continue
            except Exception as exc:
                print('WARN: translation failed:', str(exc)[:100])
        item['language'] = 'en'
    for item in items:
        if not item.get('title'):
            item['title'] = short_title(item.get('description'))
            item['titleLanguage'] = item.get('language', 'unknown')
        elif re.search(r'\b(the|vulnerability|allows|remote|execution|injection|attacker)\b', item['title'], re.I):
            try:
                item['titleOriginal'] = item['title']
                if translator:
                    item['title'] = translator.translate(item['title'][:300])
                item['titleLanguage'] = 'de' if item['title'] != item['titleOriginal'] else 'en'
            except Exception:
                item['titleLanguage'] = 'en'
        elif item.get('title'):
            item['titleLanguage'] = 'de' if re.search(r'\b(und|eine|einer|schwachstelle|ermöglicht|nicht|fehler)\b', item['title'], re.I) else 'en'

PAGE_SIZE = 2000
ID_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
EUVD_RE = re.compile(r'\bEUVD-\d{4}-\d+\b', re.I)


def get_json(url, attempts=2):
    req = urllib.request.Request(url, headers={'User-Agent': 'ITNewsDashboard/1.0 (public vulnerability digest)', 'Accept': 'application/json'})
    for n in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except Exception:
            if n == attempts - 1:
                raise
            time.sleep(3 * (n + 1))


def iso(value):
    if not value:
        return None
    try:
        d = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        return d.astimezone(UTC).isoformat().replace('+00:00', 'Z')
    except (ValueError, TypeError):
        return None


def severity_for(score):
    if score is None:
        return 'UNRATED'
    return 'CRITICAL' if score >= 9 else 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW' if score > 0 else 'NONE'


def numeric_score(value):
    try:
        n = float(value)
        return n if 0 <= n <= 10 else None
    except (TypeError, ValueError):
        return None


def metric(cve):
    metrics = cve.get('metrics') or {}
    for version in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        choices = metrics.get(version) or []
        if choices:
            chosen = next((m for m in choices if m.get('type') == 'Primary'), choices[0])
            data = chosen.get('cvssData') or {}
            score = numeric_score(data.get('baseScore'))
            if score is not None:
                return score, (data.get('baseSeverity') or chosen.get('baseSeverity') or severity_for(score)).upper(), version.replace('cvssMetricV', 'CVSS ')
    return None, 'UNRATED', None


def description(cve):
    ds = cve.get('descriptions') or []
    for lang in ('de', 'en'):
        value = next((x.get('value') for x in ds if x.get('lang') == lang and x.get('value')), None)
        if value:
            return value[:5000]
    return 'Keine Beschreibung vorhanden.'


def products(cve):
    names = []
    def walk(nodes):
        for node in nodes or []:
            for match in node.get('cpeMatch', []):
                cpe = match.get('criteria', '').split(':')
                if len(cpe) > 5 and cpe[3] not in ('*', '-') and cpe[4] not in ('*', '-'):
                    label = f'{cpe[3]} / {cpe[4]}'.replace('_', ' ')
                    if label not in names:
                        names.append(label)
            walk(node.get('children'))
    for config in cve.get('configurations') or []:
        walk(config.get('nodes'))
        if len(names) >= 5:
            break
    return names[:5]


def base(cve_id):
    return {'id': cve_id, 'score': None, 'severity': 'UNRATED', 'cvssVersion': None,
            'published': None, 'modified': None, 'description': 'Keine Beschreibung vorhanden.',
            'products': [], 'references': [], 'sources': [], 'aliases': [], 'title': None,
            'url': ('https://euvd.enisa.europa.eu/enisaid/' + urllib.parse.quote(cve_id)
                    if cve_id.startswith('EUVD-') else 'https://www.cve.org/CVERecord?id=' + cve_id)}


def nvd_item(cve):
    item = base(cve['id'])
    score, severity, version = metric(cve)
    item.update(score=score, severity=severity, cvssVersion=version,
                published=iso(cve.get('published')), modified=iso(cve.get('lastModified')),
                description=description(cve), products=products(cve),
                references=[x.get('url') for x in cve.get('references', []) if str(x.get('url', '')).startswith('https://')][:8],
                sources=['NVD'])
    return item


def merge(target, candidate):
    # Preserve earliest *known* publication timestamp. Different providers may use ingestion dates.
    for field in ('published', 'modified'):
        if candidate.get(field) and (not target.get(field) or (field == 'published' and candidate[field] < target[field]) or (field == 'modified' and candidate[field] > target[field])):
            target[field] = candidate[field]
    if target['score'] is None and candidate.get('score') is not None:
        target['score'] = candidate['score']
        target['severity'] = candidate['severity']
        target['cvssVersion'] = candidate.get('cvssVersion')
    if not target.get('title') and candidate.get('title'):
        target['title'] = candidate['title']
    if target['description'] == 'Keine Beschreibung vorhanden.' and candidate.get('description') and candidate['description'] != 'Keine Beschreibung vorhanden.':
        target['description'] = candidate['description'][:5000]
    target['aliases'] = list(dict.fromkeys(target.get('aliases', []) + candidate.get('aliases', [])))
    target['products'] = list(dict.fromkeys(target['products'] + candidate.get('products', [])))[:5]
    target['references'] = list(dict.fromkeys(target['references'] + candidate.get('references', [])))[:12]
    target['sources'] = list(dict.fromkeys(target['sources'] + candidate.get('sources', [])))
    return target


def extract_id(value):
    match = ID_RE.search(str(value or ''))
    return match.group(0).upper() if match else None


def euvd_candidates(payload):
    # EUVD API results may be paginated as 'items' or 'content'.
    rows = (payload if isinstance(payload, list) else
            payload.get('items', payload.get('content', [])) if isinstance(payload, dict) else [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        euvd_match = EUVD_RE.search(str(row.get('id') or row.get('enisaId') or row.get('euvdId') or ''))
        euvd_id = euvd_match.group(0).upper() if euvd_match else None
        aliases = row.get('aliases') or []
        if not isinstance(aliases, list):
            aliases = [aliases]
        cve_id = (next((extract_id(a) for a in aliases if extract_id(a)), None)
                  or extract_id(row.get('cve')) or extract_id(row.get('cveId')))
        if not euvd_id and not cve_id:
            continue
        published = iso(row.get('datePublished') or row.get('published') or row.get('publicationDate'))
        modified = iso(row.get('dateUpdated') or row.get('lastModified') or
                       row.get('lastModifiedDate') or row.get('dateModified') or row.get('updated'))
        score = numeric_score(row.get('baseScore') if row.get('baseScore') is not None else row.get('cvssScore'))
        for identifier in dict.fromkeys(x for x in (euvd_id, cve_id) if x):
            item = base(identifier)
            item.update(sources=['ENISA EUVD'], published=published, modified=modified,
                        aliases=[x for x in (euvd_id, cve_id) if x and x != identifier],
                        description=str(row.get('description') or item['description'])[:5000],
                        title=str(row.get('title') or row.get('name') or '').strip()[:300] or None)
            if score is not None:
                item['score'], item['severity'] = score, severity_for(score)
            if euvd_id and identifier != euvd_id:
                item['references'].append('https://euvd.enisa.europa.eu/enisaid/' + urllib.parse.quote(euvd_id))
            if cve_id and identifier != cve_id:
                item['references'].append('https://www.cve.org/CVERecord?id=' + urllib.parse.quote(cve_id))
            yield item

def cvenow_candidates(payload):
    # cve.now JSON Feed 1.1. Do not use feed's update timestamp as CVE publication time.
    for row in (payload.get('items', []) if isinstance(payload, dict) else []):
        if not isinstance(row, dict):
            continue
        cid = extract_id(row.get('id')) or extract_id(row.get('url')) or extract_id(row.get('title'))
        if not cid:
            continue
        item = base(cid)
        item['sources'] = ['cve.now']
        title = str(row.get('title') or '').strip()
        if title and title.upper() != cid:
            item['title'] = title[:300]
        item['description'] = str(row.get('summary') or row.get('content_text') or item['description'])[:5000]
        # Feed date_published is an entry date and may differ from CVE original publication date.
        item['published'] = iso(row.get('date_published'))
        item['references'] = ['https://cve.now/' + cid]
        yield item


def cveorg_enrich(item):
    record = get_json(CVE_ORG + urllib.parse.quote(item['id']), attempts=1)
    meta = record.get('cveMetadata') or {}
    if meta.get('state') != 'PUBLISHED':
        return item
    cna = (record.get('containers') or {}).get('cna') or {}
    candidate = base(item['id'])
    candidate['sources'] = ['CVE.org']
    candidate['published'] = iso(meta.get('datePublished'))
    candidate['modified'] = iso(meta.get('dateUpdated'))
    for lang in ('de', 'en'):
        desc = next((d.get('value') for d in cna.get('descriptions', []) if d.get('lang') == lang and d.get('value')), None)
        if desc:
            candidate['description'] = desc[:5000]
            break
    candidate['title'] = str(cna.get('title') or '').strip()[:300] or None
    candidate['references'] = [r.get('url') for r in cna.get('references', []) if str(r.get('url', '')).startswith('https://')][:8]
    return merge(item, candidate)


def rank(items):
    # First last source modification ('Last Check'), then severity (CVSS).
    # Missing modification timestamps rank last, not as if just checked.
    return sorted(items, key=lambda x: (x.get('modified') or '', x['score'] if x.get('score') is not None else -1, x['id']), reverse=True)


def build():
    now = dt.datetime.now(UTC)
    start = now - dt.timedelta(days=DAYS)
    qs = {'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
          'pubEndDate': now.strftime('%Y-%m-%dT%H:%M:%S.000'), 'resultsPerPage': PAGE_SIZE}
    entries = {}
    warnings = []
    total = None
    start_index = 0
    try:
        while start_index < MAX_ITEMS:
            page = get_json(NVD + '?' + urllib.parse.urlencode({**qs, 'startIndex': start_index}))
            total = int(page.get('totalResults', 0))
            batch = page.get('vulnerabilities', [])
            if not batch:
                break
            for row in batch:
                cve = row.get('cve') or {}
                if cve.get('id') and cve.get('vulnStatus') != 'Rejected':
                    item = nvd_item(cve)
                    entries[item['id']] = merge(entries[item['id']], item) if item['id'] in entries else item
            start_index += len(batch)
            if start_index >= total:
                break
            time.sleep(7)
    except Exception as exc:
        warnings.append('NVD nicht vollständig erreichbar: ' + str(exc)[:120])

    for label, url, parser in (
        ('ENISA EUVD', EUVD + '?page=0&size=100', euvd_candidates),
        ('cve.now', NOW, cvenow_candidates),
    ):
        try:
            for item in parser(get_json(url)):
                if item['id'] in entries:
                    merge(entries[item['id']], item)
                else:
                    entries[item['id']] = item
        except Exception as exc:
            warnings.append(label + ' nicht erreichbar: ' + str(exc)[:120])

    # Enrich a small selection of newest CVE entries using authoritative CVE.org records.
    # Keep requests bounded and do not block a successful NVD/EUVD result on failure.
    for item in [x for x in rank(entries.values()) if x['id'].startswith('CVE-')][:20]:
        try:
            cveorg_enrich(item)
        except Exception:
            pass

    # Hersteller-Advisories: offizielle Domains ueber Suchindex entdecken, CVE-ID
    # ausschliesslich ueber NVD validieren. Keine unbestaetigten Treffer anzeigen.
    vendor_hits = {}
    vendor_errors = []
    if os.getenv('CVE_VENDOR_DISCOVERY', '1') == '1':
        vendor_hits, vendor_errors = discover_official_cve_ids(
            json.loads(CONFIG_FILE.read_text(encoding='utf-8')))
    warnings.extend('Herstellerrecherche ' + x for x in vendor_errors)
    discovered_ids = list(dict.fromkeys(cid for ids in vendor_hits.values() for cid in ids))
    discovery_stats = {'discovered': len(discovered_ids), 'verified': 0,
                       'notFoundOrUnrated': 0, 'byProduct': {k: len(v) for k, v in vendor_hits.items()}}
    for cid in discovered_ids[:VENDOR_DISCOVERY_LIMIT]:
        if cid in entries:
            discovery_stats['verified'] += 1
            continue
        try:
            payload = get_json(NVD + '?' + urllib.parse.urlencode({'cveId': cid}), attempts=1)
            for row in payload.get('vulnerabilities', []):
                cve = row.get('cve') or {}
                if cve.get('id', '').upper() != cid or cve.get('vulnStatus') == 'Rejected':
                    continue
                item = nvd_item(cve)
                if item['score'] is not None and item['score'] >= MIN_CVSS:
                    entries[cid] = item
                    discovery_stats['verified'] += 1
            if cid not in entries:
                discovery_stats['notFoundOrUnrated'] += 1
        except Exception as exc:
            warnings.append('Hersteller-CVE ' + cid + ': ' + str(exc)[:70])
        time.sleep(0.7)
    # Historische NVD-Suche mit kontrollierter Pagination statt nur 20 Treffern.
    # Begrenzt, da ein Vollarchiv fuer 31 Hersteller sehr gross sein kann.
    for term in HISTORICAL_SEARCH_TERMS:
        try:
            for page_no in range(HISTORICAL_PAGES_PER_TERM):
                params = {'keywordSearch': term, 'resultsPerPage': HISTORICAL_RESULTS_PER_TERM,
                          'startIndex': page_no * HISTORICAL_RESULTS_PER_TERM}
                page = get_json(NVD + '?' + urllib.parse.urlencode(params))
                for row in page.get('vulnerabilities', []):
                    cve = row.get('cve') or {}
                    if not cve.get('id') or cve.get('vulnStatus') == 'Rejected':
                        continue
                    item = nvd_item(cve)
                    if item['score'] is None or item['score'] < MIN_CVSS:
                        continue
                    if not priority_products(item):
                        continue
                    if item['id'] in entries:
                        merge(entries[item['id']], item)
                    else:
                        entries[item['id']] = item
                if (page_no + 1) * HISTORICAL_RESULTS_PER_TERM >= int(page.get('totalResults', 0)):
                    break
                time.sleep(6)
        except Exception as exc:
            warnings.append('Historische Suche ' + term + ': ' + str(exc)[:80])
        time.sleep(3)

    # Include recently modified entries as well as recently published entries.
    # Never substitute ingestion time for a missing source modification timestamp.
    threshold = iso(start.isoformat())
    selected = [x for x in entries.values() if
                (x.get('modified') and x['modified'] >= threshold) or
                (x.get('published') and x['published'] >= threshold)]
    # Include historical matches only for the explicitly prioritised products.
    selected_ids = {x['id'] for x in selected}
    selected.extend(x for x in entries.values() if x['id'] not in selected_ids and
                    x.get('score') is not None and x['score'] >= MIN_CVSS and priority_products(x))
    selected = dedupe_aliases(selected)
    selected = [x for x in selected if x.get('score') is not None and x['score'] >= MIN_CVSS]
    for item in selected:
        item['priorityProducts'] = priority_products(item)
    # Independent top-50 pools, not limited to the global 50.
    global_top = choose_top(selected)
    product_pools = {name: rank([x for x in selected if name in x.get('priorityProducts', [])])[:TOP_CVES]
                     for name in PRIORITY_TERMS}
    unique = {x['id']: x for x in global_top}
    for pool in product_pools.values():
        unique.update((x['id'], x) for x in pool)
    translate_descriptions(list(unique.values()))
    selected = global_top
    payload = {'updatedAt': iso(now.isoformat()), 'windowDays': DAYS,
               'totalResultsNvd': total, 'count': len(selected),
               'truncated': start_index < (total or 0),
               'source': 'NVD, CVE.org, cve.now, ENISA EUVD',
               'sort': 'modified_desc_score_desc', 'priorityMode': 'prefer_relevant_in_top50', 'minimumCvss': MIN_CVSS,
               'warning': ' | '.join(warnings) if warnings else None,
               'items': selected, 'priorityItems': product_pools, 'priorityNames': list(PRIORITY_TERMS),
               'vendorDiscovery': discovery_stats}
    Path('cves.json').write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    print(f'Wrote {len(selected)} CVEs from {len(entries)} unique candidates')


if __name__ == '__main__':
    build()
