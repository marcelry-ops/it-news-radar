#!/usr/bin/env python3
"""Build a German-language 5/5/5/5 RSS digest for GitHub Pages; stdlib only."""
import datetime as dt
import difflib
import unicodedata
import email.utils
import hashlib
import html
import json
import os
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC)
TARGETS = {'Security': 5, 'Microsoft 365': 5, 'IT Schweiz': 5, 'Cloud': 5}
MAX_AGE_DAYS = int(os.getenv('NEWS_MAX_AGE_DAYS', '7'))
ATOM = '{http://www.w3.org/2005/Atom}'
RSS_NS = '{http://purl.org/rss/1.0/modules/content/}'

# Category-specific news searches supplement established German IT publishers.
# RSS search availability and results are controlled by the external provider.
SEARCHES = {
 'Security': ['Cybersecurity Sicherheitslücke Ransomware Angriff IT Sicherheit', 'CVE Schwachstelle Patch aktiv ausgenutzt'],
 'Microsoft 365': ['Microsoft 365 Teams SharePoint Exchange Entra Copilot Update', 'Microsoft 365 Administration neue Funktionen'],
 'IT Schweiz': ['Schweiz IT Unternehmen Digitalisierung Informatik', 'Schweizer IT Markt Technologie ICT Unternehmen'],
 'Cloud': ['Azure AWS Cloud Kubernetes Rechenzentrum neue Funktionen'],
}

def google_rss(query):
 return 'https://news.google.com/rss/search?' + urllib.parse.urlencode({'q': query + ' when:7d', 'hl':'de-CH', 'gl':'CH', 'ceid':'CH:de'})

FEEDS = [('heise online', 'https://www.heise.de/rss/heise-atom.xml', None),
         ('heise Security', 'https://www.heise.de/security/rss/news-atom.xml', 'Security'),
         ('Golem.de', 'https://rss.golem.de/rss.php?feed=RSS2.0', None)]
# Additional Swiss IT publishers; feed availability is checked at runtime.
FEEDS += [
 ('IT Reseller', 'https://www.itreseller.ch/rss/news.xml', 'IT Schweiz'),
 ('Netzwoche', 'https://www.netzwoche.ch/taxonomy/term/31/feed', 'IT Schweiz'),
 ('Inside IT', 'https://www.inside-it.ch/rss.xml', 'IT Schweiz'),
]
FEEDS += [('Google News / '+cat, google_rss(query), cat) for cat, queries in SEARCHES.items() for query in queries]

BAD = re.compile(r'\b(anzeige|advertorial|sponsored|werbung|promotion|webinar|workshop|seminar|schulung|kurs|ticket|gewinnspiel|rabatt|gutschein|stellenangebot|jobangebot|whitepaper|event-tipp|messe-ticket|partnerinhalt|powered by)\b|\b(?:jetzt anmelden|jetzt buchen|kostenlos anmelden|hier registrieren)\b', re.I)
SECURITY = re.compile(r'\b(cve[- ]?\d{4}|sicherheitslücke|schwachstelle|ransomware|phishing|cyberangriff|cyberattacke|malware|zero.day|exploit|datenleck|datenpanne|hackerangriff|patchday|sicherheitsupdate|ddos|botnetz|security|it.sicherheit|cybersicherheit)\b', re.I)
M365 = re.compile(r'\b(microsoft 365|office 365|m365|teams|sharepoint|exchange online|exchange server|outlook|onedrive|entra(?: id)?|intune|microsoft copilot|copilot studio|power platform|power automate|power apps|purview|defender for office)\b', re.I)
CLOUD = re.compile(r'\b(cloud|azure|aws|amazon web services|google cloud|kubernetes|containerplattform|hyperscaler|rechenzentrum|cloudplattform|cloud.infrastruktur)\b', re.I)
CH = re.compile(r'\b(schweiz|schweizer|schweizerisch|schweizerische|schweizerischen|swiss|zürich|zuerich|bern|basel|genf|lausanne|luzern|st\. gallen|zug|aargau|bundesrat|bundesverwaltung|sbb|swisscom|postfinance|ruag|eth zürich|epfl|ictswitzerland|swico|chf|kanton|kantone)\b', re.I)
IT = re.compile(r'\b(it|ict|informatik|digitalisierung|technologie|software|hardware|ki|künstliche intelligenz|rechenzentrum|daten|netzwerk|telekommunikation|chip|internet|digital|cyber|cloud|startup|start-up)\b', re.I)


def clean(value):
 value = re.sub(r'<[^>]*>', ' ', value or '')
 value = html.unescape(value)
 return re.sub(r'\s+', ' ', value).strip()


def parse_date(value):
 if not value: return None
 try: d = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
 except ValueError:
  try: d = email.utils.parsedate_to_datetime(value)
  except (ValueError, TypeError, IndexError): return None
 return d.replace(tzinfo=UTC) if d.tzinfo is None else d.astimezone(UTC)


def title_valid(title):
 if not (18 <= len(title) <= 175) or BAD.search(title): return False
 # Reject corrupt, long repeated character runs (e.g. AAAAAAAAAAAA).
 if re.search(r'(.)\1{7,}', title, re.I): return False
 return True


def extract(feed):
 name, address, hint = feed
 request = urllib.request.Request(address, headers={'User-Agent':'ITNewsRadar/2.0 (public news digest)', 'Accept':'application/rss+xml, application/atom+xml, application/xml, text/xml'})
 with urllib.request.urlopen(request, timeout=18) as response:
  raw = response.read(2_500_000)
 root = ET.fromstring(raw)
 entries = root.findall(f'{ATOM}entry') if root.tag == f'{ATOM}feed' else root.findall('.//item')
 results = []
 for entry in entries[:65]:
  atom = entry.tag == f'{ATOM}entry'
  def get(tag): return entry.findtext(f'{ATOM}{tag}' if atom else tag, default='')
  title = clean(get('title'))
  if not title_valid(title): continue
  description = clean(get('summary') or get('description') or get('content') or entry.findtext(f'{RSS_NS}encoded', default=''))[:800]
  if BAD.search(description[:160]) and re.search(r'\b(anzeige|advertorial|sponsored|werbung|promotion)\b', description[:160], re.I): continue
  if atom:
   links = entry.findall(f'{ATOM}link')
   url = next((x.get('href', '') for x in links if x.get('rel', 'alternate') == 'alternate'), '')
  else: url = get('link')
  url = url.strip()
  if not url.startswith('https://'): continue
  published = parse_date(get('published') or get('updated') or get('pubDate'))
  if not published or published > NOW + dt.timedelta(hours=4) or published < NOW - dt.timedelta(days=MAX_AGE_DAYS): continue
  # Google News headlines normally end with ' - Publisher'. Keep source attribution separate.
  publisher = name
  if name.startswith('Google News /') and ' - ' in title:
   article, publisher_candidate = title.rsplit(' - ', 1)
   if len(article) > 18 and len(publisher_candidate) < 65:
    title, publisher = article.strip(), publisher_candidate.strip()
  if not title_valid(title): continue
  results.append({'id':hashlib.sha256(url.encode()).hexdigest()[:16], 'title':title, 'excerpt':description,
                  'summary':description[:260] or title, 'source':publisher, 'url':url,
                  'published':published.isoformat(), 'feedHint':hint})
 return results


def eligible(item, category):
 text = item['title'] + ' ' + item['excerpt']
 title = item['title']
 if category == 'Security': return bool(SECURITY.search(text))
 if category == 'Microsoft 365': return bool(M365.search(text))
 if category == 'IT Schweiz':
  swiss_publisher = item.get('source') in {'IT Reseller', 'Netzwoche', 'Inside IT'}
  return bool(IT.search(text) and (CH.search(text) or swiss_publisher))
 if category == 'Cloud': return bool(CLOUD.search(text))
 return False


def score(item, category):
 title = item['title']; text = title + ' ' + item['excerpt']
 hours = max(0, (NOW - parse_date(item['published'])).total_seconds()/3600)
 points = max(0, 70 - hours * .6)
 if item['feedHint'] == category: points += 14
 if category == 'IT Schweiz' and CH.search(title): points += 35
 if category == 'Microsoft 365' and M365.search(title): points += 30
 if category == 'Security' and SECURITY.search(title): points += 22
 if category == 'Cloud' and CLOUD.search(title): points += 25
 if re.search(r'\b(kritisch|aktiv ausgenutzt|zero.day|notfallpatch|cve[- ]?\d{4})\b', text, re.I): points += 12
 if re.search(r'\b(kommentar|meinung|kolumne|testbericht|preisvergleich)\b', title, re.I): points -= 15
 return points


# Conservative, local semantic-equivalence heuristics (no external AI service).
# Match shared CVE IDs or strongly overlapping headline concepts. Avoid grouping
# generic product announcements solely because they mention the same vendor.
STOPWORDS = set('der die das den dem des ein eine einer eines und oder mit von vom zur zum auf im in am an bei fuer für durch gegen nach vor über ueber neue neuen neuer neues jetzt wird sind hat haben als aus zu so wie mehr nicht microsoft security sicherheit update updates meldung bericht'.split())
CVE_PATTERN = re.compile(r'\bcve[-\s]?(\d{4})[-\s]?(\d{4,})\b', re.I)

def headline_tokens(title):
 text = unicodedata.normalize('NFKD', title.casefold())
 text = ''.join(ch for ch in text if not unicodedata.combining(ch))
 return {token for token in re.findall(r'[a-z0-9]+', text) if len(token) >= 3 and token not in STOPWORDS}

def cve_ids(item):
 return set(CVE_PATTERN.findall(item['title'] + ' ' + item.get('excerpt', '')[:250]))

# A shared product is insufficient: compare the actual incident and its action.
PRODUCT_PATTERNS = {
 'outlook': r'\boutlook\b', 'exchange': r'\bexchange\b',
 'teams': r'\bteams\b', 'sharepoint': r'\bsharepoint\b',
 'windows': r'\bwindows\b', 'java': r'\bjava\b',
 'chrome': r'\bchrome\b', 'firefox': r'\bfirefox\b',
 'fortinet': r'\bforti(?:net|os|gate)\b', 'citrix': r'\bcitrix\b',
 'vmware': r'\bvmware\b', 'sap': r'\bsap\b',
}
EVENT_PATTERNS = {
 'spoofing': r'\bspoofing\b|\bidentit[aä]tsf[aä]lschung\b',
 'rce': r'\bremote code execution\b|\brce\b|\bferncodeausf[uü]hrung\b',
 'phishing': r'\bphishing\b',
 'ransomware': r'\bransomware\b|\berpressungstrojaner\b',
 'data_leak': r'\bdatenleck\b|\bdatenpanne\b|\bdatenabfluss\b',
 'dos': r'\bddos\b|\bdenial.of.service\b',
}

def concepts(item, patterns):
 text = (item['title'] + ' ' + item.get('excerpt', '')[:450]).casefold()
 return {name for name, pattern in patterns.items() if re.search(pattern, text, re.I)}

def same_story(a, b):
 ac, bc = cve_ids(a), cve_ids(b)
 if ac and bc:
  return bool(ac & bc)

 def normalized_tokens(item):
  text = unicodedata.normalize('NFKD', item['title'].casefold())
  text = ''.join(ch for ch in text if not unicodedata.combining(ch))
  text = re.sub(r'cve[- ]?\d{4}[- ]?\d{4,}', ' ', text)
  synonyms = {'sicherheitslucke':'schwachstelle', 'lucke':'schwachstelle',
              'genutzte':'ausgenutzt', 'ausgenutzte':'ausgenutzt',
              'schliesst':'patch', 'behoben':'patch'}
  return {synonyms.get(t, t) for t in re.findall(r'[a-z0-9]+', text)
          if len(t) >= 3 and t not in STOPWORDS}

 at, bt = normalized_tokens(a), normalized_tokens(b)
 if not at or not bt: return False
 common = len(at & bt)
 overlap = common / min(len(at), len(bt))
 jaccard = common / len(at | bt)
 pa, pb = concepts(a, PRODUCT_PATTERNS), concepts(b, PRODUCT_PATTERNS)
 ea, eb = concepts(a, EVENT_PATTERNS), concepts(b, EVENT_PATTERNS)
 if pa and pb and not (pa & pb): return False
 if ea and eb and not (ea & eb): return False
 if common >= 5 and overlap >= .80 and jaccard >= .55: return True
 same_source = bool(a.get('source')) and a.get('source', '').casefold() == b.get('source', '').casefold()
 same_product = bool(pa & pb)
 if bool(ac) != bool(bc):
  return ((same_source and same_product and common >= 3 and overlap >= .50)
          or (same_product and bool(ea & eb) and common >= 4 and overlap >= .65))
 return bool(same_source and same_product and common >= 4 and overlap >= .75)

def deduplicate(items):
 # Prefer the most informative and recent representation of a story.
 ranked = sorted(items, key=lambda i: (len(i.get('excerpt', '')) >= 80, len(i.get('excerpt', '')), i['published']), reverse=True)
 groups = []
 for item in ranked:
  for group in groups:
   if any(same_story(item, other) for other in group):
    group.append(item)
    break
  else: groups.append([item])
 return [group[0] for group in groups]

def select(items):
 candidates = deduplicate(items)
 used = set(); chosen = []; counts = {}
 for category, target in TARGETS.items():
  pool = sorted((i for i in candidates if i['id'] not in used and eligible(i, category)), key=lambda i:score(i, category), reverse=True)
  selected = pool[:target]
  counts[category] = len(selected)
  for item in selected:
   used.add(item['id'])
   chosen.append({**{k:v for k,v in item.items() if k != 'feedHint'}, 'category':category})
 # Chronological display across all categories, newest first.
 chosen.sort(key=lambda item: parse_date(item['published']) or dt.datetime.min.replace(tzinfo=UTC), reverse=True)
 return chosen, counts


def main():
 results = []; failures = []
 with ThreadPoolExecutor(max_workers=6) as executor:
  futures = [executor.submit(extract, f) for f in FEEDS]
  for feed, future in zip(FEEDS, futures):
   try: results.extend(future.result())
   except Exception as exc:
    failures.append(feed[0]); print('Feed failed:', feed[0], str(exc)[:150])
 chosen, counts = select(results)
 if not chosen and Path('news.json').exists():
  print('No suitable articles; retaining previous dataset'); return
 missing = [f'{TARGETS[c]-counts[c]} × {c}' for c in TARGETS if counts[c] < TARGETS[c]]
 warnings = []
 if missing: warnings.append('Nicht genügend passende aktuelle Meldungen: ' + ', '.join(missing) + '.')
 if failures: warnings.append(f'{len(failures)} von {len(FEEDS)} RSS-Quellen waren nicht erreichbar.')
 payload = {'items':chosen, 'updatedAt':NOW.isoformat(), 'targets':TARGETS, 'counts':counts,
            'warning':' '.join(warnings), 'aiSummaries':False}
 Path('news.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
 print('Saved', len(chosen), 'items; categories:', counts, 'feed failures:', failures)

if __name__ == '__main__': main()
