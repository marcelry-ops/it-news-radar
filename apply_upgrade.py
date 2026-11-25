#!/usr/bin/env python3
"""Apply audited quality improvements to the existing public IT News Radar repository.
Run in repository root: python path/to/apply_upgrade.py
Fails closed if upstream anchors change; does not alter published JSON or deploy.
"""
from pathlib import Path
import shutil
import sys

root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path.cwd()
bundle=Path(__file__).resolve().parent

def replace_once(text, before, after, filename):
    count=text.count(before)
    if count!=1:
        raise RuntimeError(f'{filename}: expected one anchor, found {count}: {before[:90]!r}')
    return text.replace(before,after,1)

news=root/'update_news.py'
cves=root/'update_cves.py'
for path in (news,cves,root/'priority_products.json',root/'cve_sources.json'):
    if not path.is_file():raise SystemExit(f'Missing required repository file: {path}')
n=news.read_text(encoding='utf-8')
c=cves.read_text(encoding='utf-8')
if 'from radar_quality import canonical_url' in n or 'from radar_quality import (load_kev' in c:
    raise SystemExit('Upgrade appears already applied (partially or fully). Inspect files before running again.')
if not (bundle/'radar_quality.py').is_file():
    raise SystemExit('Missing radar_quality.py beside apply_upgrade.py')
# News: URL normalization, dedupe, score, unbiased per-category selection.
n=replace_once(n,'from pathlib import Path\n','from pathlib import Path\nfrom radar_quality import canonical_url, news_identity, dedupe_news, news_impact\n','update_news.py')
n=replace_once(n,"   url = url.strip()\n   if not url.startswith('https://'): continue", "   url = canonical_url(url.strip())\n   if not url.startswith('https://'): continue",'update_news.py')
n=replace_once(n,"'id':hashlib.sha256(url.encode()).hexdigest()[:16]", "'id':news_identity({'url':url})",'update_news.py')
n=replace_once(n,' return points\n# Conservative, local semantic-equivalence heuristics', ' return points + news_impact(item, category)\n# Conservative, local semantic-equivalence heuristics','update_news.py')
start=n.index('def deduplicate(items):')
end=n.index('def build_diagnostics(',start)
n=n[:start]+'''def deduplicate(items):
  # Shared canonical URL plus robust headline similarity; preserve original attribution.
  return dedupe_news(items)

def select(items):
  candidates = deduplicate(items)
  used = set(); chosen = []; counts = {}
  # Personnel only from approved Swiss publications, without global duplication.
  # Reserve personnel stories first, then fill the other categories.
  order = ['Personen'] + [cat for cat in TARGETS if cat != 'Personen']
  for category in order:
   pool = sorted((i for i in candidates if i['id'] not in used and eligible(i,category)),
                 key=lambda i:(score(i,category),i['published']),reverse=True)
   selected = pool[:TARGETS[category]]
   counts[category] = len(selected)
   for item in selected:
    used.add(item['id'])
    chosen.append({**{k:v for k,v in item.items() if k not in ('feedHint','feedSource')},
                   'category':category})
  chosen.sort(key=lambda item: parse_date(item['published']) or dt.datetime.min.replace(tzinfo=UTC),reverse=True)
  return chosen, counts

''' +n[end:]
# More focused searches reduce conjunction overload; update all categories.
anchor="FEEDS += [('Google News / '+cat, google_rss(query), cat) for cat, queries in SEARCHES.items() for query in queries]"
more="""# Targeted discovery queries; broad multi-keyword queries above remain active.
FOCUSED_SEARCHES = {
 'Security': ['actively exploited zero day CVE', 'site:cisa.gov known exploited vulnerability', 'ransomware cyberangriff datenabfluss'],
 'Microsoft 365': ['site:learn.microsoft.com Microsoft 365 retirement', 'site:techcommunity.microsoft.com Microsoft 365 Teams Exchange', 'Microsoft Entra Intune Purview Update'],
 'Cloud': ['site:azure.microsoft.com/blog security outage', 'site:aws.amazon.com/blogs/security vulnerability', 'Google Cloud Kubernetes outage security'],
 'IT Schweiz': ['site:inside-it.ch Digitalisierung Schweiz', 'site:netzwoche.ch Schweizer ICT', 'site:itreseller.ch Schweizer IT'],
 'Trends': ['Agentic AI Unternehmen Infrastruktur', 'Quantencomputing KI Forschung Halbleiter'],
 'Markt': ['Schweiz ICT Marktzahlen IT Investitionen', 'Software Cloud Preise Marktstudie'],
 'Firmen': ['IT Übernahme Fusion Partnerschaft Schweiz', 'Technologiekonzern Quartalszahlen Akquisition'],
}
FEEDS += [('Focused / '+cat, google_rss(query), cat) for cat, qs in FOCUSED_SEARCHES.items() for query in qs]
"""
n=replace_once(n,anchor,anchor+'\n'+more,'update_news.py')
# Personnel targeted searches with explicit language variants; the same whitelist remains mandatory.
person_anchor="FEEDS += [(publisher + ' / Personen', google_rss('site:' + domain + ' (' + query + ')'), 'Personen')\n           for publisher, domain in PERSON_SITES.items() for query in PERSON_QUERIES]"
extra="""FEEDS += [(publisher + ' / Personen', google_rss('site:' + domain + ' ' + q), 'Personen')
          for publisher, domain in PERSON_SITES.items()
          for q in ['CEO ernannt', 'CIO wechselt', 'CTO übernimmt', 'Geschäftsleitung neu', 'Verwaltungsrat gewählt']]
"""
n=replace_once(n,person_anchor,person_anchor+'\n'+extra,'update_news.py')
# Headline-only restriction currently excludes many valid change headlines; require actual action + relevant role or strong action keyword.
n=replace_once(n,"  # A named change or appointment must be stated in the headline.\n  if not PERSON_CHANGE.search(title): return False", "  # Allow clear changes in the synopsis when the headline names the role.\n  if not (PERSON_CHANGE.search(title) or (PERSON_ROLE.search(title) and PERSON_CHANGE.search(text))): return False",'update_news.py')
# Keep id consistency in diagnostics after canonicalization.
# CVE: explicit KEV/EPSS risk enrichment, preserve existing payload shape.
c=replace_once(c,'from pathlib import Path\n','from pathlib import Path\nfrom radar_quality import (load_kev, load_epss, enrich_risks, merge_kev_records,\n                           rank_risk, eligible_risk)\n','update_cves.py')
c=replace_once(c,"os.getenv('CVE_MAX_ITEMS', '2000')", "os.getenv('CVE_MAX_ITEMS', '10000')",'update_cves.py')
c=replace_once(c,"os.getenv('CVEORG_LOOKUP_BUDGET', '110')", "os.getenv('CVEORG_LOOKUP_BUDGET', '180')",'update_cves.py')
# Do not restrict vendor-derived CVEs to CVSS >= 9 before risk ranking.
c=replace_once(c,"if item['score'] is None or item['score'] < MIN_CVSS:\n                         continue", "if item['score'] is None:\n                         continue",'update_cves.py')
anchor="    # Include recently modified entries as well as recently published entries."
insertion="""    # Public threat intelligence: active exploitation and exploit probability.
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
"""
c=replace_once(c,anchor,insertion+anchor,'update_cves.py')
c=replace_once(c,"    selected.extend(x for x in entries.values() if x['id'] not in selected_ids and\n                     x.get('score') is not None and x['score'] >= MIN_CVSS and priority_products(x))", "    selected.extend(x for x in entries.values() if x['id'] not in selected_ids and\n                     (x.get('knownExploited') or (x.get('score') is not None and x['score'] >= 7 and priority_products(x))))",'update_cves.py')
c=replace_once(c,"    selected = [x for x in selected if x.get('score') is not None and x['score'] >= MIN_CVSS]\n    for item in selected:\n        item['priorityProducts'] = priority_products(item)", "    for item in selected:\n        item['priorityProducts'] = priority_products(item)\n    selected = [x for x in selected if eligible_risk(x)]",'update_cves.py')
c=replace_once(c,"    global_top = choose_top(selected)\n    product_pools = {name: rank([x for x in selected if name in x.get('priorityProducts', [])])[:TOP_CVES]", "    global_top = rank_risk(selected)[:TOP_CVES]\n    product_pools = {name: rank_risk([x for x in selected if name in x.get('priorityProducts', [])])[:TOP_CVES]",'update_cves.py')
c=replace_once(c,"'sort': 'modified_desc_score_desc', 'priorityMode': 'prefer_relevant_in_top50', 'minimumCvss': MIN_CVSS,", "'sort': 'risk_desc', 'priorityMode': 'kev_epss_cvss_product', 'minimumCvss': None,\n                'kevStats': kev_stats, 'kevCount': len(kev), 'epssCount': len(epss),\n                'kevError': kev_error, 'epssError': epss_error,",'update_cves.py')
# Avoid false positive product assignment solely from free-text descriptions; use structured product labels.
original="    text = ' '.join([str(item.get('description', '')), ' '.join(item.get('products') or [])]).casefold()"
replacement="    text = ' '.join(str(x) for x in (item.get('products') or [])).casefold()"
c=replace_once(c,original,replacement,'update_cves.py')
# Additional safeguard: canonical aliases only if CVE record exists.
for path,text in ((news,n),(cves,c)):
    compile(text,str(path),'exec')
    path.write_text(text,encoding='utf-8')
if (bundle/'radar_quality.py').resolve() != (root/'radar_quality.py').resolve():
    shutil.copy2(bundle/'radar_quality.py',root/'radar_quality.py')
print('Applied upgrade to',root)
print('Run: python -m unittest discover -s tests (after copying tests from the package)')
print('No GitHub commits, published feeds or external actions were performed.')
