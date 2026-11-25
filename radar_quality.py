"""IT News Radar: deterministic news quality and CVE risk enrichment (stdlib only)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import urllib.parse
import urllib.request
from difflib import SequenceMatcher

UTC = dt.timezone.utc
TRACKERS = {'fbclid', 'gclid', 'dclid', 'mc_cid', 'mc_eid', 'ref', 'ref_src', 'rss', 'source', 'output', 'cmpid'}
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
STOP = set('der die das den dem des ein eine einer einem und oder von mit auf aus fuer für im in am an zu zur zum ueber über als nach bei wegen durch neue neuen neuer neues microsoft meldet meldung berichtet bericht'.split())
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss'


def canonical_url(url):
    """Remove tracking parameters without collapsing meaningful article query parameters."""
    try:
        p = urllib.parse.urlsplit(url.strip())
        host = (p.hostname or '').lower()
        if p.scheme not in ('https', 'http') or not host:
            return url.strip()
        netloc = host + ((':' + str(p.port)) if p.port and p.port not in (80, 443) else '')
        path = re.sub('/+', '/', urllib.parse.unquote(p.path)) or '/'
        if path != '/': path = path.rstrip('/')
        params = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        params = [(k,v) for k,v in params if k.lower() not in TRACKERS and not k.lower().startswith(('utm_', 'pk_', 'wt_'))]
        return urllib.parse.urlunsplit(('https', netloc, urllib.parse.quote(path, safe='/%:@+-._~'), urllib.parse.urlencode(sorted(params)), ''))
    except (ValueError, TypeError):
        return url


def news_identity(item):
    url = canonical_url(item.get('url',''))
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def tokens(title):
    import unicodedata
    s = unicodedata.normalize('NFKD', title.casefold())
    s = ''.join(c for c in s if not unicodedata.combining(c))
    return {t for t in re.findall(r'[a-z0-9]+', s) if len(t)>2 and t not in STOP}


def same_news(a,b):
    if canonical_url(a.get('url','')) == canonical_url(b.get('url','')): return True
    a_ids = set(CVE_RE.findall(a.get('title','')))
    b_ids = set(CVE_RE.findall(b.get('title','')))
    if a_ids and b_ids and a_ids.isdisjoint(b_ids): return False
    ta, tb = tokens(a.get('title','')), tokens(b.get('title',''))
    if not ta or not tb: return False
    overlap = len(ta & tb)/min(len(ta),len(tb))
    if overlap < .78: return False
    # A shared CVE alone is insufficient to merge an advisory and an unrelated follow-up.
    return SequenceMatcher(None, ' '.join(sorted(ta)), ' '.join(sorted(tb))).ratio() >= .78


def dedupe_news(items):
    """Deterministic grouping; preserve the highest-quality representative."""
    groups = []
    by_url = {}
    for item in items:
        item = dict(item)
        item['url'] = canonical_url(item.get('url',''))
        item['id'] = news_identity(item)
        url = item['url']
        index = by_url.get(url)
        if index is None:
            index = next((i for i,g in enumerate(groups) if same_news(g[0],item)),None)
        if index is None:
            index=len(groups); groups.append([])
        groups[index].append(item)
        by_url[url]=index
    def preference(i):
        google = 'news.google.com' in urllib.parse.urlsplit(i.get('url','')).netloc
        return (not google, len(i.get('excerpt','')), i.get('published',''))
    return [max(g,key=preference) for g in groups]


def news_impact(item, category):
    text = (item.get('title','')+' '+item.get('excerpt','')[:400]).casefold()
    points = 0
    patterns = [
        (r'\b(aktiv ausgenutzt|active exploitation|zero.day|notfallpatch|massive störung|grossflächiger ausfall|kritische schwachstelle)\b',65),
        (r'\b(cve-\d{4}-\d{4,}|ransomware|datenleck|datenpanne|sicherheitsvorfall)\b',28),
        (r'\b(eingestellt|abschaltung|end.of.life|end.of.support|abgekündigt|deprecation)\b',40),
        (r'\b(übernahme|fusion|akquisition|übernimmt|rücktritt|ernannt|ceo.wechsel)\b',26),
        (r'\b(störung|ausfall|outage|preiserhöhung|pflicht|regulierung)\b',28),
    ]
    for pattern,weight in patterns:
        if re.search(pattern,text,re.I): points+=weight
    if category == 'Personen' and re.search(r'\b(ernannt|übernimmt|wechselt|verlässt|rücktritt|nachfolge)\b',item.get('title',''),re.I): points+=20
    return points


def fetch_json(url, timeout=25):
    req=urllib.request.Request(url, headers={'User-Agent':'ITNewsRadar/3.0', 'Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=timeout) as resp:
        return json.load(resp)


def load_kev(fetch=fetch_json):
    rows=fetch(KEV_URL).get('vulnerabilities',[])
    return {x['cveID'].upper():x for x in rows if CVE_RE.fullmatch(str(x.get('cveID','')).upper())}


def load_epss(ids, fetch=fetch_json, batch_size=75):
    result={}
    ids=sorted(set(x.upper() for x in ids if CVE_RE.fullmatch(str(x))))
    for start in range(0,len(ids),batch_size):
        query=urllib.parse.urlencode({'cve':','.join(ids[start:start+batch_size])})
        data=fetch(EPSS_URL+'?'+query)
        for item in data.get('data',[]):
            try:
                score=float(item['epss']); percentile=float(item.get('percentile',0))
                if 0<=score<=1: result[item['cve'].upper()]={'epss':score,'epssPercentile':percentile}
            except (ValueError,TypeError,KeyError):
                continue
    return result


def enrich_risks(items, kev, epss):
    for row in items:
        identifier=row.get('id','').upper()
        k=kev.get(identifier)
        row['knownExploited']=bool(k)
        if k:
            row['kevAdded']=k.get('dateAdded')
            row['kevDueDate']=k.get('dueDate')
            row['kevRansomware']=k.get('knownRansomwareCampaignUse')
            row['sources']=list(dict.fromkeys(row.get('sources',[])+['CISA KEV']))
        e=epss.get(identifier,{})
        row['epss']=e.get('epss')
        row['epssPercentile']=e.get('epssPercentile')
    return items


def risk_score(row):
    cvss=row.get('score')
    cvss=cvss if isinstance(cvss,(float,int)) else 0
    epss=row.get('epss') or 0
    score=180 if row.get('knownExploited') else 0
    score+= min(100,epss*100)
    score+=cvss*5
    score+=35 if row.get('priorityProducts') else 0
    if str(row.get('kevRansomware') or '').lower()=='known':score+=15
    return round(score,3)


def rank_risk(items):
    return sorted(items,key=lambda r:(risk_score(r), r.get('modified') or r.get('published') or '',r.get('id','')),reverse=True)


def eligible_risk(row):
    """Accept exploited, priority-product and high-impact/high-probability records."""
    score=row.get('score') or 0
    return bool(row.get('knownExploited') or (row.get('priorityProducts') and score>=7) or score>=9 or (score>=7 and (row.get('epss') or 0)>=.10))


def merge_kev_records(entries, kev, lookup, max_missing=80):
    """Resolve currently exploited historical CVEs via official CVE.org records."""
    missing=[(cid,v) for cid,v in kev.items() if cid not in entries]
    missing.sort(key=lambda p:p[1].get('dateAdded',''),reverse=True)
    stats={'missingKev':len(missing),'attempted':0,'added':0,'failures':0,'deferred':max(0,len(missing)-max_missing)}
    for cid,record in missing[:max_missing]:
        stats['attempted']+=1
        try:
            row=lookup(cid)
            if row and row.get('id','').upper()==cid:
                entries[cid]=row;stats['added']+=1
        except Exception:
            stats['failures']+=1
    return stats
