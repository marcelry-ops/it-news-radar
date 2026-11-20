#!/usr/bin/env python3
"""NVD recent CVEs + CISA KEV; standard library only. No API credentials required."""
import datetime as dt
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

UTC = dt.timezone.utc
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
DAYS = max(1, min(int(os.getenv('CVE_DAYS', '14')), 120))
MAX_ITEMS = max(1, min(int(os.getenv('CVE_MAX_ITEMS', '2000')), 10000))
PAGE_SIZE = 2000


def get_json(url, attempts=3):
    req = urllib.request.Request(url, headers={'User-Agent':'ITNewsDashboard/1.0 (public vulnerability digest)', 'Accept':'application/json'})
    for n in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=40) as response:
                return json.load(response)
        except Exception:
            if n == attempts - 1:
                raise
            time.sleep(10 * (n + 1))


def iso(value):
    if not value:
        return None
    try:
        d = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        return d.astimezone(UTC).isoformat().replace('+00:00', 'Z')
    except ValueError:
        return None


def metric(cve):
    metrics = cve.get('metrics') or {}
    for version in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        choices = metrics.get(version) or []
        if choices:
            chosen = next((m for m in choices if m.get('type') == 'Primary'), choices[0])
            data = chosen.get('cvssData') or {}
            score = data.get('baseScore')
            if isinstance(score, (int, float)):
                severity = (data.get('baseSeverity') or chosen.get('baseSeverity') or '').upper()
                if not severity:
                    severity = 'CRITICAL' if score >= 9 else 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW' if score > 0 else 'NONE'
                return float(score), severity, version.replace('cvssMetricV', 'CVSS ')
    return None, 'UNRATED', None


def english_description(cve):
    descriptions = cve.get('descriptions') or []
    preferred = next((x.get('value') for x in descriptions if x.get('lang') == 'de'), None)
    if not preferred:
        preferred = next((x.get('value') for x in descriptions if x.get('lang') == 'en'), None)
    return (preferred or 'Keine Beschreibung vorhanden.')[:5000]


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


def normalize(cve, kev):
    cve_id = cve.get('id', '')
    score, severity, version = metric(cve)
    refs = [x.get('url') for x in cve.get('references', []) if str(x.get('url', '')).startswith('https://')][:8]
    known = kev.get(cve_id) or {}
    return {'id':cve_id, 'score':score, 'severity':severity, 'cvssVersion':version,
            'published':iso(cve.get('published')), 'modified':iso(cve.get('lastModified')),
            'description':english_description(cve), 'products':products(cve),
            'knownExploited':bool(known), 'kevDateAdded':known.get('dateAdded'),
            'kevVendor':known.get('vendorProject'), 'kevProduct':known.get('product'),
            'kevVulnerability':known.get('vulnerabilityName'),
            'references':refs, 'url':'https://nvd.nist.gov/vuln/detail/' + urllib.parse.quote(cve_id)}


def build():
    now = dt.datetime.now(UTC)
    start = now - dt.timedelta(days=DAYS)
    qs = {'pubStartDate':start.strftime('%Y-%m-%dT%H:%M:%S.000'),
          'pubEndDate':now.strftime('%Y-%m-%dT%H:%M:%S.000'), 'resultsPerPage':PAGE_SIZE}
    try:
        kev_data = get_json(KEV)
        kev = {v['cveID']:v for v in kev_data.get('vulnerabilities', []) if 'cveID' in v}
        kev_warning = None
    except Exception as exc:
        kev = {}
        kev_warning = 'CISA KEV konnte nicht abgerufen werden: ' + str(exc)[:160]
    found = []
    start_index = 0
    total = None
    while len(found) < MAX_ITEMS:
        query = urllib.parse.urlencode({**qs, 'startIndex':start_index})
        page = get_json(NVD + '?' + query)
        total = int(page.get('totalResults', 0))
        entries = page.get('vulnerabilities', [])
        if not entries:
            break
        found.extend(normalize(x['cve'], kev) for x in entries if x.get('cve', {}).get('vulnStatus') != 'Rejected')
        start_index += len(entries)
        if start_index >= total:
            break
        time.sleep(7)
    found.sort(key=lambda x: (x['score'] if x['score'] is not None else -1, x['published'] or ''), reverse=True)
    truncated = start_index < (total or 0)
    payload = {'updatedAt':now.isoformat().replace('+00:00', 'Z'), 'windowDays':DAYS,
               'totalResultsNvd':total, 'count':len(found[:MAX_ITEMS]), 'truncated':truncated,
               'source':'NVD CVE API 2.0', 'kevSource':'CISA KEV',
               'warning':kev_warning, 'items':found[:MAX_ITEMS]}
    Path('cves.json').write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    print(f'Wrote {payload["count"]} CVEs; NVD total={total}, truncated={truncated}')

if __name__ == '__main__':
    build()
