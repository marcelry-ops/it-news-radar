#!/usr/bin/env python3
"""Offline quality report for published IT News Radar JSON files. No external calls."""
import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from radar_quality import canonical_url

UTC = dt.timezone.utc
CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)

def age_hours(value, now):
    try:
        date = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if date.tzinfo is None: date = date.replace(tzinfo=UTC)
        return round((now - date.astimezone(UTC)).total_seconds() / 3600, 1)
    except (ValueError, TypeError):
        return None

def assess(news, cves, now=None):
    now = now or dt.datetime.now(UTC)
    problems = []
    observations = []
    news_rows = news.get('items', [])
    cve_rows = cves.get('items', [])
    urls = [canonical_url(row.get('url','')) for row in news_rows if row.get('url')]
    duplicate_urls = sorted(u for u, n in Counter(urls).items() if n > 1)
    # No fuzzy text-based blocking here; legitimate follow-up stories are not duplicates.
    news_ids = [r.get('id') for r in news_rows]
    duplicated_news_ids = sorted(str(k) for k,n in Counter(news_ids).items() if k and n > 1)
    cve_ids = [str(r.get('id','')).upper() for r in cve_rows]
    duplicate_cves = sorted(k for k,n in Counter(cve_ids).items() if k and n > 1)
    invalid_cve_ids = sorted(set(cid for cid in cve_ids if not CVE_ID.fullmatch(cid)))
    news_age = age_hours(news.get('updatedAt'), now)
    cve_age = age_hours(cves.get('updatedAt'), now)
    news_counts = Counter(r.get('category') for r in news_rows)
    targets = news.get('targets', {})
    below_target = {str(cat): {'actual': news_counts.get(cat,0), 'target': target}
                    for cat,target in targets.items() if isinstance(target,int) and news_counts.get(cat,0) < target}
    feed_failures = (news.get('feedFailures') or [])
    # The news feed failures are stored in a separate diagnostic file, normally.
    nvd_truncated = bool(cves.get('truncated'))
    warnings = [x for x in (cves.get('warning'), news.get('warning')) if x]
    if duplicate_urls: problems.append('duplicate_news_urls')
    if duplicated_news_ids: problems.append('duplicate_news_ids')
    if duplicate_cves: problems.append('duplicate_cve_ids')
    if invalid_cve_ids: problems.append('invalid_cve_ids')
    if not news_rows: problems.append('no_news_items')
    if not cve_rows: problems.append('no_cve_items')
    if news_age is None or news_age > 26: problems.append('stale_news_data')
    if cve_age is None or cve_age > 26: problems.append('stale_cve_data')
    if nvd_truncated: problems.append('nvd_truncated')
    if below_target: observations.append('categories_below_target')
    if warnings: observations.append('source_warnings_present')
    epss_coverage = sum(isinstance(r.get('epss'), (float,int)) for r in cve_rows)
    kev_count = sum(bool(r.get('knownExploited')) for r in cve_rows)
    scored_count = sum(isinstance(r.get('riskScore'),(float,int)) for r in cve_rows)
    return {'checkedAt': now.isoformat(), 'status': 'error' if problems else ('warning' if observations else 'ok'),
            'errors': problems, 'observations': observations,
            'news': {'count':len(news_rows), 'ageHours':news_age, 'duplicateCanonicalUrls':duplicate_urls,
                     'duplicateIds':duplicated_news_ids,'byCategory':dict(news_counts),'belowTarget':below_target,
                     'feedFailures': feed_failures},
            'cves': {'count':len(cve_rows),'ageHours':cve_age, 'duplicateIds':duplicate_cves,
                     'invalidIds':invalid_cve_ids,'nvdTruncated':nvd_truncated,
                     'kevCount':kev_count, 'epssCoverageCount':epss_coverage,
                     'epssCoveragePercent':round(100 * epss_coverage / len(cve_rows),1) if cve_rows else 0,
                     'riskScoreCoverageCount':scored_count,
                     'nvdRetrieval':cves.get('retrievalDiagnostics',{}),
                     'sourceWarnings':cves.get('warning')},
            'note':'Dublettenpruefung nach kanonischer URL und CVE-ID; Vollstaendigkeit der weltweiten Quellen nicht nachweisbar.'}

def run(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--news',default='news.json')
    parser.add_argument('--cves',default='cves.json')
    parser.add_argument('--diagnostics',default='news_diagnostics.json')
    parser.add_argument('--output',default='radar_quality_report.json')
    parser.add_argument('--strict',action='store_true',help='Exit 1 for critical quality problems')
    args = parser.parse_args(argv)
    news=json.loads(Path(args.news).read_text(encoding='utf-8'))
    cves=json.loads(Path(args.cves).read_text(encoding='utf-8'))
    report=assess(news,cves)
    diagnostics=Path(args.diagnostics)
    if diagnostics.exists():
        try:
            data=json.loads(diagnostics.read_text(encoding='utf-8'))
            report['news']['feedFailures']=data.get('feedFailures',[])
            report['news']['rawCandidates']=data.get('rawCandidates')
            report['news']['uniqueCandidates']=data.get('uniqueCandidates')
            if report['news']['feedFailures'] and 'feed_failures' not in report['observations']:
                report['observations'].append('feed_failures')
                if report['status']=='ok': report['status']='warning'
        except (ValueError, OSError) as exc:
            report['observations'].append('invalid_news_diagnostics')
    Path(args.output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Quality report:',report['status'],'errors=',report['errors'],'warnings=',report['observations'])
    return 1 if args.strict and report['errors'] else 0

if __name__=='__main__':
    raise SystemExit(run())
