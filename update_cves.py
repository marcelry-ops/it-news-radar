#!/usr/bin/env python3
"""Recent CVEs: NVD plus cve.now, ENISA EUVD and CVE.org enrichment.
Only standard library; source failures are reported in cves.json.
"""
import datetime as dt
import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

UTC = dt.timezone.utc
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EUVD = 'https://euvdservices.enisa.europa.eu/api/search'
NOW = 'https://cve.now/feed?format=json'
CVE_ORG = 'https://cveawg.mitre.org/api/cve/'
DAYS = max(1, min(int(os.getenv('CVE_DAYS', '14')), 120))
MAX_ITEMS = max(50, min(int(os.getenv('CVE_MAX_ITEMS', '2000')), 10000))
TOP_CVES = 50
PAGE_SIZE = 2000
ID_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)


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
            'products': [], 'references': [], 'sources': [],
            'url': 'https://www.cve.org/CVERecord?id=' + cve_id}


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
    if target['description'] == 'Keine Beschreibung vorhanden.' and candidate.get('description') and candidate['description'] != 'Keine Beschreibung vorhanden.':
        target['description'] = candidate['description'][:5000]
    target['products'] = list(dict.fromkeys(target['products'] + candidate.get('products', [])))[:5]
    target['references'] = list(dict.fromkeys(target['references'] + candidate.get('references', [])))[:12]
    target['sources'] = list(dict.fromkeys(target['sources'] + candidate.get('sources', [])))
    return target


def extract_id(value):
    match = ID_RE.search(str(value or ''))
    return match.group(0).upper() if match else None


def euvd_candidates(payload):
    for row in (payload.get('items', []) if isinstance(payload, dict) else []):
        if not isinstance(row, dict):
            continue
        aliases = row.get('aliases') or []
        cid = next((extract_id(a) for a in aliases if extract_id(a)), None) if isinstance(aliases, list) else extract_id(aliases)
        cid = cid or extract_id(row.get('cve')) or extract_id(row.get('cveId'))
        if not cid:
            continue
        item = base(cid)
        item['sources'] = ['ENISA EUVD']
        item['published'] = iso(row.get('datePublished') or row.get('published'))
        item['description'] = str(row.get('description') or item['description'])[:5000]
        score = numeric_score(row.get('baseScore') or row.get('cvssScore'))
        if score is not None:
            item['score'], item['severity'] = score, severity_for(score)
        enisa_id = row.get('id') or row.get('enisaId')
        if isinstance(enisa_id, str) and enisa_id.startswith('EUVD-'):
            item['references'].append('https://euvd.enisa.europa.eu/enisaid/' + urllib.parse.quote(enisa_id))
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
    candidate['references'] = [r.get('url') for r in cna.get('references', []) if str(r.get('url', '')).startswith('https://')][:8]
    return merge(item, candidate)


def rank(items):
    return sorted(items, key=lambda x: (x.get('published') or '', x['score'] if x.get('score') is not None else -1, x['id']), reverse=True)


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

    # Enrich a small selection of newest entries using authoritative CVE.org records.
    # Keep requests bounded and do not block a successful NVD/EUVD result on failure.
    for item in rank(entries.values())[:20]:
        try:
            cveorg_enrich(item)
        except Exception:
            pass

    # Only original CVE publication dates within the configured window; provider-only
    # entries with ambiguous dates may still reflect ingestion rather than publication.
    selected = [x for x in entries.values() if x.get('published') and x['published'] >= iso(start.isoformat())]
    selected = rank(selected)[:TOP_CVES]
    payload = {'updatedAt': iso(now.isoformat()), 'windowDays': DAYS,
               'totalResultsNvd': total, 'count': len(selected),
               'truncated': start_index < (total or 0),
               'source': 'NVD, CVE.org, cve.now, ENISA EUVD',
               'warning': ' | '.join(warnings) if warnings else None,
               'items': selected}
    Path('cves.json').write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    print(f'Wrote {len(selected)} CVEs from {len(entries)} unique candidates')


if __name__ == '__main__':
    build()
