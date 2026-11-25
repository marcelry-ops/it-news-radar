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
import urllib.error
import email.utils
import xml.etree.ElementTree as ET
from pathlib import Path
from radar_guard import guard_dataset
from radar_quality import (load_kev, load_epss, enrich_risks, merge_kev_records,
                           rank_risk, eligible_risk, risk_score)
from nvd_incremental import read_snapshot, modified_query_start, write_snapshot

UTC = dt.timezone.utc
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EUVD = 'https://euvdservices.enisa.europa.eu/api/search'
NOW = 'https://cve.now/feed?format=json'
CVE_ORG = 'https://cveawg.mitre.org/api/cve/'
DAYS = max(1, min(int(os.getenv('CVE_DAYS', '14')), 120))
MAX_ITEMS = max(50, min(int(os.getenv('CVE_MAX_ITEMS', '10000')), 10000))
TOP_CVES = 50
MIN_CVSS = 9.0
# Separate bounded historical lookups for priority software.
HISTORICAL_RESULTS_PER_TERM = 100
HISTORICAL_PAGES_PER_TERM = max(0, min(int(os.getenv("CVE_HISTORICAL_PAGES", "3")), 10))
HISTORICAL_REQUEST_BUDGET = max(0, min(int(os.getenv("CVE_HISTORICAL_REQUEST_BUDGET", "35")), 200))
CVEORG_LOOKUP_BUDGET = max(0, min(int(os.getenv("CVEORG_LOOKUP_BUDGET", "180")), 300))
VENDOR_DISCOVERY_LIMIT = max(0, min(int(os.getenv("CVE_VENDOR_DISCOVERY_LIMIT", "110")), 300))
# Explicit diagnostic lookups: independently of vendor search pagination.
TARGETED_CVE_IDS = tuple(x.strip().upper() for x in os.getenv('CVE_TARGETED_IDS', 'CVE-2026-44756,CVE-2026-58240,CVE-2026-19707').split(',') if re.fullmatch(r'CVE-\d{4}-\d{4,}', x.strip(), re.I))
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

# Konfigurierbare Datenquellen: nur fest definierte Adapter und sichere
# Herstellerrecherche via Google News. Keine beliebigen Server-URL-Aufrufe.
SOURCES_FILE = Path(__file__).with_name('cve_sources.json')
SOURCE_TYPES = {'nvd', 'cveorg', 'euvd', 'cvenow', 'vendor_search'}

def load_sources(path=SOURCES_FILE):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    rows = data.get('sources')
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise ValueError('cve_sources.json: ungueltige Quellenliste')
    seen, validated = set(), []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Ungueltiger Quelleneintrag')
        ident = row.get('id')
        typ = row.get('type')
        name = row.get('name')
        if not isinstance(ident, str) or not re.fullmatch(r'[a-z0-9_-]{2,50}', ident) or ident in seen:
            raise ValueError('Doppelte/ungueltige Quellen-ID')
        if typ not in SOURCE_TYPES or not isinstance(name, str) or not name.strip() or len(name) > 90:
            raise ValueError('Unbekannter Adapter oder Quellenname: ' + ident)
        if not isinstance(row.get('enabled'), bool):
            raise ValueError('enabled muss true/false sein: ' + ident)
        if typ == 'vendor_search' and not valid_advisory_domain(row.get('domain', '')):
            raise ValueError('Ungueltige Domain: ' + ident)
        if typ != 'vendor_search' and ident != {'nvd':'nvd','cveorg':'cveorg','euvd':'euvd','cvenow':'cvenow'}[typ]:
            raise ValueError('Systemadapter haben feste IDs: ' + typ)
        seen.add(ident)
        validated.append(row)
    return validated

def active_sources(rows):
    return {x['type'] for x in rows if x['enabled']}

def discover_extra_sources(rows, fetch=None):
    # Ausschliesslich Google News wird abgerufen, die Herstellerdomain ist ein Suchfilter.
    vendor = [{'name': x['name'], 'advisoryDomain': x['domain']} for x in rows
              if x['enabled'] and x['type'] == 'vendor_search']
    return discover_official_cve_ids({'products': vendor}, fetch=fetch) if vendor else ({}, [])


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
    text = ' '.join(str(x) for x in (item.get('products') or [])).casefold()
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


# NVD limits requests without an API key. Apply a shared pace across all NVD calls.
_LAST_NVD_REQUEST = 0.0
_NVD_INTERVAL = max(6.0, float(os.getenv('CVE_NVD_INTERVAL', '7')))

def get_json(url, attempts=3):
    global _LAST_NVD_REQUEST
    req = urllib.request.Request(url, headers={
        'User-Agent': 'ITNewsDashboard/1.0 (public vulnerability digest)',
        'Accept': 'application/json'})
    for n in range(attempts):
        if url.startswith(NVD):
            wait = _NVD_INTERVAL - (time.monotonic() - _LAST_NVD_REQUEST)
            if wait > 0:
                time.sleep(wait)
            _LAST_NVD_REQUEST = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or n == attempts - 1:
                raise
            raw = exc.headers.get('Retry-After', '')
            try:
                delay = float(raw)
            except ValueError:
                try:
                    delay = (email.utils.parsedate_to_datetime(raw) - dt.datetime.now(UTC)).total_seconds()
                except (ValueError, TypeError, OverflowError):
                    delay = 10 * (2 ** n)
            time.sleep(max(1, min(60, delay)))
        except (TimeoutError, OSError):
            if n == attempts - 1:
                raise
            time.sleep(min(30, 3 * (2 ** n)))


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
            'products': [], 'references': [], 'sources': [], 'aliases': [], 'title': None, 'scoreSource': None,
            'url': ('https://euvd.enisa.europa.eu/enisaid/' + urllib.parse.quote(cve_id)
                    if cve_id.startswith('EUVD-') else 'https://www.cve.org/CVERecord?id=' + cve_id)}


def nvd_item(cve):
    item = base(cve['id'])
    score, severity, version = metric(cve)
    item.update(score=score, severity=severity, cvssVersion=version,
                published=iso(cve.get('published')), modified=iso(cve.get('lastModified')),
                description=description(cve), products=products(cve),
                references=[x.get('url') for x in cve.get('references', []) if str(x.get('url', '')).startswith('https://')][:8],
                sources=['NVD'], scoreSource=('NVD' if score is not None else None))
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
        target['scoreSource'] = candidate.get('scoreSource')
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


def safe_cveorg_lookup(cve_id, fetch=None):
    """Rate-limited CVE.org lookup with a per-run cache and request budget."""
    if cve_id in _CVEORG_CACHE:
        return _CVEORG_CACHE[cve_id]
    if len(_CVEORG_CACHE) >= CVEORG_LOOKUP_BUDGET:
        raise RuntimeError('CVE.org request budget exhausted')
    global _LAST_CVEORG_REQUEST
    delay = 1.0 - (time.monotonic() - _LAST_CVEORG_REQUEST)
    if delay > 0:
        time.sleep(delay)
    _LAST_CVEORG_REQUEST = time.monotonic()
    value = lookup_official_cve(cve_id, fetch=fetch)
    _CVEORG_CACHE[cve_id] = value
    return value

_CVEORG_CACHE = {}
_LAST_CVEORG_REQUEST = 0.0

def cna_cvss(record):
    """Extract published CVSS base score from CNA/ADP CVE 5.x metrics."""
    containers = record.get('containers') or {}
    sources = [('CNA', containers.get('cna') or {})]
    sources += [('ADP', obj) for obj in (containers.get('adp') or []) if isinstance(obj, dict)]
    versions = (('cvssV4_0', 'CVSS 4.0'), ('cvssV3_1', 'CVSS 3.1'),
                ('cvssV3_0', 'CVSS 3.0'))
    for origin, container in sources:
        for metric_row in container.get('metrics') or []:
            if not isinstance(metric_row, dict):
                continue
            for field, version in versions:
                value = metric_row.get(field) or {}
                score = numeric_score(value.get('baseScore')) if isinstance(value, dict) else None
                if score is not None:
                    return score, severity_for(score), version, 'CVE.org ' + origin
    return None, 'UNRATED', None, None


def lookup_official_cve(cve_id, fetch=None):
    """Fetch an official published record even if NVD has no CVSS score."""
    fetch = fetch or get_json
    record = fetch(CVE_ORG + urllib.parse.quote(cve_id))
    metadata = record.get('cveMetadata') or {}
    if metadata.get('state') != 'PUBLISHED' or metadata.get('cveId', '').upper() != cve_id.upper():
        return None
    cna = (record.get('containers') or {}).get('cna') or {}
    item = base(cve_id)
    item['sources'] = ['CVE.org']
    item['published'] = iso(metadata.get('datePublished'))
    item['modified'] = iso(metadata.get('dateUpdated'))
    item['title'] = str(cna.get('title') or '').strip()[:300] or None
    for lang in ('de', 'en'):
        desc = next((x.get('value') for x in cna.get('descriptions', [])
                     if x.get('lang') == lang and x.get('value')), None)
        if desc:
            item['description'] = desc[:5000]
            break
    item['references'] = [x.get('url') for x in cna.get('references', [])
                          if str(x.get('url', '')).startswith('https://')][:8]
    item['products'] = list(dict.fromkeys(
        str(x.get('product', '')).strip() for x in cna.get('affected', [])
        if isinstance(x, dict) and x.get('product')))[:5]
    score, severity, version, source = cna_cvss(record)
    item.update(score=score, severity=severity, cvssVersion=version, scoreSource=source)
    return item


def cveorg_enrich(item):
    official = safe_cveorg_lookup(item['id'])
    if official is None:
        return item
    return merge(item, official)



def rank(items):
    # First last source modification ('Last Check'), then severity (CVSS).
    # Missing modification timestamps rank last, not as if just checked.
    return sorted(items, key=lambda x: (x.get('modified') or '', x['score'] if x.get('score') is not None else -1, x['id']), reverse=True)


def build():
    source_rows = load_sources()
    enabled_sources = active_sources(source_rows)
    if not enabled_sources.intersection({'nvd', 'cveorg', 'euvd', 'cvenow'}):
        raise RuntimeError('Mindestens eine strukturierte CVE-Datenquelle muss aktiv sein')
    now = dt.datetime.now(UTC)
    start = now - dt.timedelta(days=DAYS)
    qs = {'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
          'pubEndDate': now.strftime('%Y-%m-%dT%H:%M:%S.000'), 'resultsPerPage': PAGE_SIZE}
    entries = {}
    warnings = []
    total = None
    start_index = 0
    snapshot = read_snapshot(now) if 'nvd' in enabled_sources else None
    incremental = bool(snapshot)
    nvd_entries = dict(snapshot['entries']) if snapshot else {}
    # First-ever run and expired/invalid snapshots always use the full window.
    if incremental:
        modified_start = modified_query_start(snapshot)
        qs = {'lastModStartDate': modified_start.strftime('%Y-%m-%dT%H:%M:%S.000'),
              'lastModEndDate': now.strftime('%Y-%m-%dT%H:%M:%S.000'), 'resultsPerPage': PAGE_SIZE}
    nvd_complete = False
    try:
        while 'nvd' in enabled_sources and start_index < MAX_ITEMS:
            page = get_json(NVD + '?' + urllib.parse.urlencode({**qs, 'startIndex': start_index}))
            total = int(page.get('totalResults', 0))
            batch = page.get('vulnerabilities', [])
            if not batch:
                nvd_complete = (start_index >= total)
                break
            for row in batch:
                cve = row.get('cve') or {}
                identifier = cve.get('id')
                if identifier and cve.get('vulnStatus') == 'Rejected':
                    nvd_entries.pop(identifier, None)
                elif identifier:
                    nvd_entries[identifier] = nvd_item(cve)
            start_index += len(batch)
            if start_index >= total:
                nvd_complete = True
                break
            time.sleep(7)
        if 'nvd' in enabled_sources and total == 0:
            nvd_complete = True
        if 'nvd' in enabled_sources and not nvd_complete:
            warnings.append('NVD nicht vollständig verarbeitet; Snapshot nicht aktualisiert')
    except Exception as exc:
        warnings.append('NVD nicht vollständig erreichbar: ' + str(exc)[:120])
    # Preserve snapshot records when a modified-only query was used; prune old
    # entries for the display window. Historical high-impact CVEs are separately
    # discovered by KEV and the priority-product searches below.
    threshold_nvd = iso(start.isoformat())
    nvd_entries = {cid:row for cid,row in nvd_entries.items() if
                   (row.get('published') and row['published'] >= threshold_nvd) or
                   (row.get('modified') and row['modified'] >= threshold_nvd)}
    entries.update(nvd_entries)
    if nvd_complete and 'nvd' in enabled_sources:
        try:
            write_snapshot(nvd_entries,now)
        except OSError as exc:
            warnings.append('NVD-Cache konnte nicht geschrieben werden: '+str(exc)[:100])

    for label, url, parser in (
        *((('ENISA EUVD', EUVD + '?page=0&size=100', euvd_candidates),) if 'euvd' in enabled_sources else ()),
        *((('cve.now', NOW, cvenow_candidates),) if 'cvenow' in enabled_sources else ()),
    ):
        try:
            for item in parser(get_json(url)):
                if item['id'] in entries:
                    merge(entries[item['id']], item)
                else:
                    entries[item['id']] = item
        except Exception as exc:
            warnings.append(label + ' nicht erreichbar: ' + str(exc)[:120])

    # Explicit official lookups for historically missed high-impact vendor CVEs.
    # Validate the CVE ID and published state, then accept CNA CVSS >= 9.
    targeted_status = {}
    for cid in (TARGETED_CVE_IDS if 'cveorg' in enabled_sources else []):
        try:
            official = safe_cveorg_lookup(cid)
            if official is None:
                targeted_status[cid] = 'not_published_or_missing'
                continue
            if cid in entries:
                merge(entries[cid], official)
            else:
                entries[cid] = official
            row = entries[cid]
            targeted_status[cid] = ('eligible' if row.get('score') is not None and
                                    row['score'] >= MIN_CVSS else 'no_qualifying_cvss')
        except Exception as exc:
            targeted_status[cid] = 'lookup_failed:' + type(exc).__name__


    # Hersteller-Advisories: offizielle Domains ueber Suchindex entdecken, CVE-ID
    # ausschliesslich ueber NVD validieren. Keine unbestaetigten Treffer anzeigen.
    vendor_hits = {}
    vendor_errors = []
    if 'nvd' in enabled_sources and os.getenv('CVE_VENDOR_DISCOVERY', '1') == '1':
        vendor_hits, vendor_errors = discover_official_cve_ids(
            json.loads(CONFIG_FILE.read_text(encoding='utf-8')))
    # Separate missing configuration from failed lookups; neither category
    # proves that an official advisory feed itself is unavailable.
    vendor_missing = [x for x in vendor_errors if 'keine verifizierte offizielle Advisory-Domain konfiguriert' in x]
    vendor_invalid = [x for x in vendor_errors if 'ungueltige Domain' in x]
    vendor_failed_sources = [x for x in vendor_errors if x not in vendor_missing and x not in vendor_invalid]
    vendor_diagnostics = {
        'configuredCount': sum(bool(str(p.get('advisoryDomain') or '').strip())
                               for p in json.loads(CONFIG_FILE.read_text(encoding='utf-8')).get('products', [])),
        'missingDomains': [x.split(':', 1)[0] for x in vendor_missing],
        'invalidDomains': [x.split(':', 1)[0] for x in vendor_invalid],
        'failedLookups': [{'product': x.split(':', 1)[0], 'reason': x.split(':', 1)[-1].strip()}
                          for x in vendor_failed_sources],
        'note': 'Google News ist eine Discovery-Quelle und keine offizielle Hersteller-API.'
    }
    if vendor_missing:
        warnings.append(f'Herstellerrecherche: {len(vendor_missing)} Advisory-Domains nicht konfiguriert')
    if vendor_invalid:
        warnings.append(f'Herstellerrecherche: {len(vendor_invalid)} ungueltige Advisory-Domains')
    if vendor_failed_sources:
        warnings.append(f'Herstellerrecherche: {len(vendor_failed_sources)} Google-News-Abfragen fehlgeschlagen')
    # Prefer known CVEs and recent vendor discoveries. Never silently discard the
    # rest: diagnostics report how many candidates were deferred by the budget.
    discovered_ids = list(dict.fromkeys(cid for ids in vendor_hits.values() for cid in ids))
    discovered_ids = sorted(discovered_ids, reverse=True)
    discovery_stats = {'discovered': len(discovered_ids), 'verified': 0,
                       'notFoundOrUnrated': 0, 'deferred': 0,
                       'byProduct': {k: len(v) for k, v in vendor_hits.items()}}
    vendor_failed = 0
    for cid in discovered_ids:
        if cid in entries and entries[cid].get('score') is not None:
            discovery_stats['verified'] += 1
            continue
        if discovery_stats['verified'] + discovery_stats['notFoundOrUnrated'] + vendor_failed >= VENDOR_DISCOVERY_LIMIT:
            discovery_stats['deferred'] += 1
            continue
        try:
            # CNA-first for missing NVD scores; do not require NVD enrichment.
            official = safe_cveorg_lookup(cid) if 'cveorg' in enabled_sources else None
            if official is not None:
                entries[cid] = merge(entries[cid], official) if cid in entries else official
            row = entries.get(cid)
            if row is not None and row.get('score') is not None and row['score'] >= MIN_CVSS:
                discovery_stats['verified'] += 1
            else:
                discovery_stats['notFoundOrUnrated'] += 1
        except Exception:
            vendor_failed += 1
    if vendor_failed:
        warnings.append(f'Hersteller-CVE-Abfragen: {vendor_failed} fehlgeschlagen')
    if discovery_stats['deferred']:
        warnings.append(f'Hersteller-CVE-Abfragen: {discovery_stats["deferred"]} auf spaeter verschoben')

    # Historical NVD search: bounded pages and total request budget, with
    # CNA fallback for unscored records relevant to prioritised products.
    historical_failed = 0
    historical_requests = 0
    historical_deferred = 0
    for term in (HISTORICAL_SEARCH_TERMS if 'nvd' in enabled_sources else []):
        for page_no in range(HISTORICAL_PAGES_PER_TERM):
            if historical_requests >= HISTORICAL_REQUEST_BUDGET:
                historical_deferred += 1
                break
            try:
                params = {'keywordSearch': term, 'resultsPerPage': HISTORICAL_RESULTS_PER_TERM,
                          'startIndex': page_no * HISTORICAL_RESULTS_PER_TERM}
                historical_requests += 1
                page = get_json(NVD + '?' + urllib.parse.urlencode(params))
                for record in page.get('vulnerabilities', []):
                    cve = record.get('cve') or {}
                    if not cve.get('id') or cve.get('vulnStatus') == 'Rejected':
                        continue
                    item = nvd_item(cve)
                    if not priority_products(item):
                        continue
                    if item['score'] is None and 'cveorg' in enabled_sources:
                        try:
                            official = safe_cveorg_lookup(item['id'])
                            if official:
                                merge(item, official)
                        except Exception:
                            pass
                    if item['score'] is None:
                        continue
                    if item['id'] in entries:
                        merge(entries[item['id']], item)
                    else:
                        entries[item['id']] = item
                if (page_no + 1) * HISTORICAL_RESULTS_PER_TERM >= int(page.get('totalResults', 0)):
                    break
            except Exception:
                historical_failed += 1
                break
    if historical_failed:
        warnings.append(f'Historische NVD-Suche: {historical_failed} Suchbegriffe fehlgeschlagen')
    if historical_deferred:
        warnings.append('Historische NVD-Suche: Anfragebudget erreicht')
    # Enrich a small selection of newest CVE entries using authoritative CVE.org records.
    # Keep requests bounded and do not block a successful NVD/EUVD result on failure.
    for item in ([x for x in rank(entries.values()) if x['id'].startswith('CVE-') and x.get('score') is None][:20] if 'cveorg' in enabled_sources else []):
        try:
            cveorg_enrich(item)
        except Exception:
            pass

    # Public threat intelligence: active exploitation and exploit probability.
    # A source failure never silently turns existing records into confirmed negatives.
    kev = {}
    kev_error = None
    kev_stats = {}
    try:
        kev = load_kev()
        kev_stats = merge_kev_records(
            entries, kev, lambda cid: safe_cveorg_lookup(cid),
            max_missing=max(0,min(int(os.getenv('CVE_KEV_LOOKUP_LIMIT','30')),100)))
    except Exception as exc:
        kev_error = str(exc)[:160]
        warnings.append('CISA KEV nicht erreichbar: '+kev_error)
    epss = {}
    epss_error = None
    try:
        epss = load_epss([cid for cid in entries if cid.startswith('CVE-')])
    except Exception as exc:
        epss_error = str(exc)[:160]
        warnings.append('FIRST EPSS nicht vollständig erreichbar: '+epss_error)
    enrich_risks(list(entries.values()), kev, epss)
    # Include recently modified entries as well as recently published entries.
    # Never substitute ingestion time for a missing source modification timestamp.
    threshold = iso(start.isoformat())
    selected = [x for x in entries.values() if
                (x.get('modified') and x['modified'] >= threshold) or
                (x.get('published') and x['published'] >= threshold)]
    # Include historical matches only for the explicitly prioritised products.
    selected_ids = {x['id'] for x in selected}
    selected.extend(x for x in entries.values() if x['id'] not in selected_ids and
                    (x.get('knownExploited') or (x.get('score') is not None and x['score'] >= 7 and priority_products(x))))
    selected = dedupe_aliases(selected)
    for item in selected:
        item['priorityProducts'] = priority_products(item)
    selected = [x for x in selected if eligible_risk(x)]
    # Independent top-50 pools, not limited to the global 50.
    for item in selected:
        item['riskScore'] = risk_score(item)
    global_top = rank_risk(selected)[:TOP_CVES]
    product_pools = {name: rank_risk([x for x in selected if name in x.get('priorityProducts', [])])[:TOP_CVES]
                     for name in PRIORITY_TERMS}
    unique = {x['id']: x for x in global_top}
    for pool in product_pools.values():
        unique.update((x['id'], x) for x in pool)
    translate_descriptions(list(unique.values()))
    selected = global_top
    for cid in (TARGETED_CVE_IDS if 'cveorg' in enabled_sources else []):
        if targeted_status.get(cid) == 'eligible':
            targeted_status[cid] = ('in_global_top50' if any(x['id'] == cid for x in global_top)
                                    else 'in_product_pool' if any(x['id'] == cid for pool in product_pools.values() for x in pool)
                                    else 'excluded_by_top50')
    payload = {'updatedAt': iso(now.isoformat()), 'windowDays': DAYS,
               'totalResultsNvd': total, 'count': len(selected),
               'truncated': bool('nvd' in enabled_sources and not nvd_complete),
               'source': ', '.join(x['name'] for x in source_rows if x['enabled']),
               'activeSources': [x['id'] for x in source_rows if x['enabled']],
               'riskScoreMethod': 'heuristic_v2_0_to_100', 'sort': 'risk_desc', 'priorityMode': 'kev_epss_cvss_product', 'minimumCvss': None,
                'nvdIncremental': incremental, 'nvdCacheComplete': nvd_complete,
                'kevStats': kev_stats, 'kevCount': len(kev), 'epssCount': len(epss),
                'kevError': kev_error, 'epssError': epss_error,
               'warning': ' | '.join(warnings) if warnings else None,
               'items': selected, 'priorityItems': product_pools, 'priorityNames': list(PRIORITY_TERMS),
               'vendorDiscovery': discovery_stats, 'vendorSourceDiagnostics': vendor_diagnostics, 'targetedDiagnostics': targeted_status,
                'retrievalDiagnostics': {'nvdIncremental':incremental, 'nvdPagesComplete':nvd_complete,
                                         'nvdRetrieved':start_index,
                                         'historicalRequests': historical_requests,
                                         'historicalFailures': historical_failed,
                                         'historicalBudget': HISTORICAL_REQUEST_BUDGET,
                                         'cveorgRequests': len(_CVEORG_CACHE),
                                         'cveorgBudget': CVEORG_LOOKUP_BUDGET}}
    # Never replace the last valid dataset with an empty/failed run.
    if not selected:
        raise RuntimeError('Keine gueltigen CVE-Daten; bestehende cves.json bleibt unveraendert')
    destination = Path('cves.json')
    guard_dataset(destination, payload)
    temp = destination.with_suffix('.json.tmp')
    temp.write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    temp.replace(destination)
    print(f'Wrote {len(selected)} CVEs from {len(entries)} unique candidates')


if __name__ == '__main__':
    build()
