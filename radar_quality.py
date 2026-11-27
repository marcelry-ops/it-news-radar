"""IT News Radar: deterministic news quality and CVE risk enrichment (stdlib only)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import math
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
                if math.isfinite(score) and math.isfinite(percentile) and 0<=score<=1 and 0<=percentile<=1: result[item['cve'].upper()]={'epss':score,'epssPercentile':percentile}
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


def _published_age_days(row, reference_date):
    """Age is based on publication, never on last-modified or CVE identifier."""
    raw = row.get('published')
    if not raw:
        return None
    try:
        date = dt.date.fromisoformat(str(raw)[:10])
        return max(0, (reference_date-date).days)
    except (ValueError, TypeError):
        return None


def _legacy_cve(row, reference_date, years=3):
    age = _published_age_days(row, reference_date)
    return age is not None and age > years*366


def _current_threat(row, reference_date):
    """Old CVEs recently added to CISA KEV stay current threats."""
    return not _legacy_cve(row, reference_date) or _recent_kev(row, reference_date)


def risk_score(row):
    """0..100 editorial heuristic; source CVSS values and versions are preserved.

    CVSS v2 is NOT treated as a modern v3/v4 severity value. The score does
    not assert the presence of an exploit, asset exposure or business impact.
    """
    raw_cvss=row.get('score')
    cvss=max(0.0,min(10.0,float(raw_cvss))) if isinstance(raw_cvss,(int,float)) and math.isfinite(raw_cvss) else 0.0
    version=str(row.get('cvssVersion') or '').lower()
    # CVSS v2 is not comparable with CVSS v3/v4; reduce its heuristic weight.
    if 'cvss 2' in version: cvss*=0.65
    raw_epss=row.get('epss')
    epss=max(0.0,min(1.0,float(raw_epss))) if isinstance(raw_epss,(int,float)) and math.isfinite(raw_epss) else 0.0
    points=(45 if row.get('knownExploited') else 0)
    points += epss*25 + cvss*1.5 + (10 if row.get('priorityProducts') else 0)
    if str(row.get('kevRansomware') or '').casefold()=='known': points+=5
    # Publish-date bonus avoids letting a new edit to an old NVD record
    # masquerade as a new vulnerability. No date => no bonus.
    age=_published_age_days(row, dt.datetime.now(UTC).date())
    if age is not None:
        points += 12 if age<=30 else 8 if age<=90 else 4 if age<=365 else 0
    return round(min(100.0,points),2)


def attack_prerequisites(row):
    """Derive only documented CVSS vector attributes; unknown stays unknown."""
    vector = str(row.get('cvssVector') or '')
    parts = dict(re.findall(r'\b(AV|PR|UI):([A-Z])\b', vector))
    return {'attackVector': {'N':'network','A':'adjacent','L':'local','P':'physical'}.get(parts.get('AV'),'unknown'),
            'privilegesRequired': {'N':'none','L':'low','H':'high'}.get(parts.get('PR'),'unknown'),
            'userInteraction': {'N':'none','R':'required','P':'passive','A':'active'}.get(parts.get('UI'),'unknown'),
            'source':'CVSS_vector' if parts else 'not_available'}


def rank_risk(items):
    return sorted(items,key=lambda r:(risk_score(r), r.get('published') or '',r.get('id','')),reverse=True)


def _recent_kev(row, reference_date, days=120):
    """Only CISA KEV inclusion confirms exploitation; dates mark additions."""
    if not row.get('knownExploited') or not row.get('kevAdded'): return False
    try:
        age=(reference_date-dt.date.fromisoformat(str(row['kevAdded'])[:10])).days
        return 0 <= age <= days
    except (ValueError,TypeError): return False


def select_operational_top(items, limit=50, reference_date=None):
    """Risk-balanced Top 50 with evidence-backed exploitation first.

    Recent KEV additions are never excluded solely for the age of the CVE.
    Older records not recently added to KEV are moved to a separate legacy
    view. Missing publication dates stay eligible (do not invent dates).
    """
    reference_date=reference_date or dt.datetime.now(UTC).date()
    ranked=rank_risk([x for x in items if _current_threat(x,reference_date)])
    picked=[]; seen=set(); allocations={}
    buckets=(
        ('recentKnownExploited',20,lambda r:_recent_kev(r,reference_date)),
        ('highEpss',15,lambda r:not r.get('knownExploited') and isinstance(r.get('epss'),(int,float)) and r['epss']>=0.15),
        ('priorityProducts',10,lambda r:not r.get('knownExploited') and bool(r.get('priorityProducts'))),
        ('criticalCvss',5,lambda r:not r.get('knownExploited') and isinstance(r.get('score'),(int,float)) and r['score']>=9 and 'cvss 2' not in str(r.get('cvssVersion') or '').lower()),
    )
    for name,quota,condition in buckets:
        count=0
        for row in ranked:
            if len(picked)>=limit or count>=quota: break
            if row['id'] not in seen and condition(row):
                seen.add(row['id']);row['selectionBucket']=name;picked.append(row);count+=1
        allocations[name]=count
    for row in ranked:
        if len(picked)>=limit: break
        if row['id'] not in seen:
            seen.add(row['id']);row['selectionBucket']='remainder';picked.append(row)
    allocations['remainder']=len(picked)-sum(allocations.values())
    return picked,allocations


def select_legacy_top(items, limit=50, reference_date=None):
    """Historical CVEs not newly added to KEV, for a distinct legacy view."""
    reference_date=reference_date or dt.datetime.now(UTC).date()
    old=[x for x in items if _legacy_cve(x,reference_date) and not _recent_kev(x,reference_date)]
    return rank_risk(old)[:limit]


def eligible_risk(row):
    """Accept exploited, priority-product and high-impact/high-probability records."""
    score=row.get('score') or 0
    return bool(row.get('knownExploited') or (row.get('priorityProducts') and score>=7) or score>=9 or (score>=7 and (row.get('epss') or 0)>=.10))


def merge_kev_records(entries, kev, lookup, max_missing=80, previous_backlog=None, reference_date=None):
    """Prioritised, rotating KEV backlog; stored in the committed cves.json.

    Newest catalog additions receive priority. Older pending identifiers rotate
    on each successful run instead of remaining permanently behind new entries.
    The result only marks a CVE exploited after inclusion in CISA KEV.
    """
    reference_date = reference_date or dt.datetime.now(UTC).date()
    missing = {cid: rec for cid, rec in kev.items() if cid not in entries}
    previous = [cid for cid in (previous_backlog or []) if cid in missing]
    new = sorted((cid for cid in missing if cid not in previous),
                 key=lambda cid: (missing[cid].get('dateAdded') or '', cid), reverse=True)
    recent = []
    for cid in sorted(missing, key=lambda key:(missing[key].get('dateAdded') or '',key),reverse=True):
        try:
            days = (reference_date - dt.date.fromisoformat(str(missing[cid].get('dateAdded',''))[:10])).days
        except (ValueError, TypeError):
            continue
        if 0 <= days <= 30:
            recent.append(cid)
    # Carry forward existing work. New catalogue entries get the next chance,
    # then a rotating share goes to earlier entries (including older KEV).
    fresh = list(dict.fromkeys(recent + new))
    ordered = list(dict.fromkeys(fresh + previous))
    ordered += [cid for cid in missing if cid not in set(ordered)]
    quota = max(0,int(max_missing))
    fresh_quota = min(len(fresh), quota//2 + quota%2) if previous else min(len(fresh), quota)
    attempted_ids = list(dict.fromkeys(fresh[:fresh_quota] + previous[:quota-fresh_quota]))
    attempted_ids += [cid for cid in ordered if cid not in attempted_ids][:max(0,quota-len(attempted_ids))]
    stats={'missingKev':len(missing),'attempted':0,'added':0,'failures':0,
           'deferred':max(0,len(missing)-len(attempted_ids)),
           'recentPending':len(recent),'lookups':attempted_ids,
           'backlog':[], 'note':'Aktuelle KEV-Eintraege zuerst, alte Rueckstaende rotierend nachrecherchiert.'}
    failed=[]
    for cid in attempted_ids:
        stats['attempted']+=1
        try:
            row=lookup(cid)
            if row and row.get('id','').upper()==cid:
                entries[cid]=row;stats['added']+=1
            else: failed.append(cid)
        except Exception:
            stats['failures']+=1; failed.append(cid)
    # Put not-yet-attempted entries first next time, then unresolved attempts.
    stats['backlog'] = [cid for cid in ordered if cid not in attempted_ids] + failed
    return stats
