#!/usr/bin/env python3
"""Build a German-language 3/3/3/1 RSS digest for GitHub Pages; stdlib only."""
import datetime as dt
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
TARGETS = {'Security': 3, 'Microsoft 365': 3, 'IT Schweiz': 3, 'Cloud': 1}
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
 if category == 'IT Schweiz': return bool(CH.search(text) and IT.search(text))
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


def select(items):
 # Same article can appear in multiple RSS feeds and categories.
 deduped = {}
 for item in items:
  key = re.sub(r'[^a-z0-9äöü]+', '', item['title'].casefold())[:115]
  if key not in deduped or len(item['excerpt']) > len(deduped[key]['excerpt']): deduped[key] = item
 candidates = list(deduped.values()); used = set(); chosen = []; counts = {}
 for category, target in TARGETS.items():
  pool = sorted((i for i in candidates if i['id'] not in used and eligible(i, category)), key=lambda i:score(i, category), reverse=True)
  # Prefer articles with strong category signal; never fill with irrelevant news.
  selected = pool[:target]
  counts[category] = len(selected)
  for item in selected:
   used.add(item['id'])
   chosen.append({**{k:v for k,v in item.items() if k != 'feedHint'}, 'category':category})
 return chosen, counts


def summarize(items):
 key = os.getenv('OPENAI_API_KEY', '').strip()
 if not key or not items: return False
 body = {'model':os.getenv('OPENAI_MODEL', 'gpt-4o-mini'), 'temperature':0.1,
         'response_format':{'type':'json_object'}, 'messages':[
          {'role':'system','content':'Schreibe pro Meldung eine neutrale deutschsprachige Zusammenfassung mit maximal 240 Zeichen, Schweizer Rechtschreibung ohne ß. Nur belegte Angaben aus Titel und RSS-Auszug verwenden. Keine zusätzlichen Fakten. Gib JSON {"summaries":[{"id":"...","summary":"..."}]} zurück.'},
          {'role':'user','content':json.dumps([{'id':i['id'],'title':i['title'],'excerpt':i['excerpt']} for i in items], ensure_ascii=False)}]}
 req = urllib.request.Request('https://api.openai.com/v1/chat/completions', data=json.dumps(body).encode(),
                              headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'}, method='POST')
 try:
  with urllib.request.urlopen(req, timeout=45) as response: data = json.load(response)
  mapping = {x['id']:clean(x['summary'])[:240] for x in json.loads(data['choices'][0]['message']['content']).get('summaries', []) if isinstance(x, dict) and isinstance(x.get('summary'), str)}
  for item in items:
   if item['id'] in mapping and mapping[item['id']]: item['summary'] = mapping[item['id']]
  return bool(mapping)
 except Exception as exc:
  print('AI unavailable:', str(exc)[:200]); return False


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
 ai = summarize(chosen)
 missing = [f'{TARGETS[c]-counts[c]} × {c}' for c in TARGETS if counts[c] < TARGETS[c]]
 warnings = []
 if missing: warnings.append('Nicht genügend passende aktuelle Meldungen: ' + ', '.join(missing) + '.')
 if failures: warnings.append(f'{len(failures)} von {len(FEEDS)} RSS-Quellen waren nicht erreichbar.')
 if not ai: warnings.append('Kurztexte stammen aus RSS-Auszügen; keine KI-Zusammenfassungen aktiv.')
 payload = {'items':chosen, 'updatedAt':NOW.isoformat(), 'targets':TARGETS, 'counts':counts,
            'warning':' '.join(warnings), 'aiSummaries':ai}
 Path('news.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
 print('Saved', len(chosen), 'items; categories:', counts, 'AI:', ai, 'feed failures:', failures)

if __name__ == '__main__': main()
