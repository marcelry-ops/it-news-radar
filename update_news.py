#!/usr/bin/env python3
"""Fetch public RSS feeds, score and optionally summarize using OpenAI API."""
import datetime as dt, email.utils, hashlib, html, json, os, re, urllib.request, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
FEEDS = [('heise online','https://www.heise.de/rss/heise-atom.xml'),('heise Security','https://www.heise.de/security/rss/news-atom.xml'),('Golem.de','https://rss.golem.de/rss.php?feed=RSS2.0')]
ATOM='{http://www.w3.org/2005/Atom}'
def clean(s): return re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]+>',' ',s or ''))).strip()
def cat(s):
 if re.search(r'cve-|sicherheitslücke|ransomware|phishing|cyber|malware|angriff|patch|zero.day|security|hacker|exploit',s,re.I):return 'Security'
 if re.search(r'microsoft 365|teams|sharepoint|exchange|copilot|entra|outlook',s,re.I):return 'Microsoft 365'
 if re.search(r'cloud|azure|aws|kubernetes|google cloud|rechenzentrum',s,re.I):return 'Cloud'
 return 'IT'
def date(s):
 try:
  d=dt.datetime.fromisoformat(s.replace('Z','+00:00'))
 except ValueError:
  d=email.utils.parsedate_to_datetime(s)
 return d.astimezone(dt.timezone.utc)
def fetch(feed):
 name,url=feed
 req=urllib.request.Request(url,headers={'User-Agent':'ITNewsRadar/1.0 (news digest)'})
 with urllib.request.urlopen(req,timeout=18) as resp: root=ET.fromstring(resp.read(2_000_000))
 entries=root.findall(f'{ATOM}entry') if root.tag==f'{ATOM}feed' else root.findall('.//item')
 out=[]
 for e in entries[:35]:
  atom=e.tag==f'{ATOM}entry'
  def get(tag):return e.findtext(f'{ATOM}{tag}' if atom else tag,default='')
  title=clean(get('title')); summary=clean(get('summary') or get('description') or get('content'))[:700]
  linknode=e.find(f'{ATOM}link') if atom else None
  url=(linknode.get('href','') if linknode is not None else get('link')).strip()
  if not url.startswith('https://'):continue
  try: published=date(get('published') or get('updated') or get('pubDate'))
  except Exception:continue
  if not title:continue
  out.append(dict(id=hashlib.sha256(url.encode()).hexdigest()[:16],title=title,excerpt=summary,summary=summary[:260],source=name,url=url,published=published.isoformat(),category=cat(title+' '+summary)))
 return out
def summarize(items):
 key=os.getenv('OPENAI_API_KEY','').strip()
 if not key:return False
 endpoint='https://api.openai.com/v1/chat/completions'
 model=os.getenv('OPENAI_MODEL','gpt-4o-mini')
 payload={'model':model,'temperature':0.1,'response_format':{'type':'json_object'},'messages':[{'role':'system','content':'Du formulierst knappe, neutrale Zusammenfassungen auf Deutsch (Schweizer Schreibweise, kein ß). Nutze ausschliesslich die gelieferten Titel und RSS-Auszüge. Erfinde keine Fakten. Gib JSON {"summaries":[{"id":"...","summary":"..."}]} zurück. Pro Summary maximal 240 Zeichen.'},{'role':'user','content':json.dumps([{'id':x['id'],'title':x['title'],'excerpt':x['excerpt']} for x in items],ensure_ascii=False)}]}
 req=urllib.request.Request(endpoint,data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=45) as resp: data=json.load(resp)
  result=json.loads(data['choices'][0]['message']['content'])
  mapped={x['id']:clean(x['summary'])[:300] for x in result.get('summaries',[]) if isinstance(x,dict) and isinstance(x.get('summary'),str)}
  for item in items:
   if item['id'] in mapped:item['summary']=mapped[item['id']]
  return True
 except Exception as e:
  print('AI summary unavailable:',type(e).__name__,str(e)[:180]);return False
def main():
 items=[];fail=[]
 with ThreadPoolExecutor(max_workers=3) as pool:
  futures=[pool.submit(fetch,f) for f in FEEDS]
  for f,job in zip(FEEDS,futures):
   try:items.extend(job.result())
   except Exception as e:fail.append(f[0]);print('Feed failed:',f[0],str(e)[:180])
 seen=set(); unique=[];now=dt.datetime.now(dt.timezone.utc)
 for x in items:
  key=re.sub(r'\W+','',x['title'].lower())[:85]
  if key not in seen:seen.add(key);unique.append(x)
 def score(x):
  hours=max(0,(now-date(x['published'])).total_seconds()/3600)
  text=x['title']+' '+x['excerpt']
  return (30 if x['category']=='Security' else 0)+(28 if re.search(r'kritisch|aktiv ausgenutzt|zero.day|cve-|ransomware',text,re.I) else 0)+(8 if re.search(r'microsoft|windows|linux|deutschland',text,re.I) else 0)+max(0,35-hours/2)
 unique.sort(key=score,reverse=True);top=unique[:10]
 if not top:
  print('No feeds available; preserving previous data if present')
  if not Path('news.json').exists():Path('news.json').write_text(json.dumps({'items':[],'updatedAt':now.isoformat(),'warning':'Keine Feeds verfügbar.'}),encoding='utf-8')
  return
 ai=summarize(top)
 payload={'items':top,'updatedAt':now.isoformat(),'warning':('Nicht alle Feeds waren erreichbar. ' if fail else '')+('Zusammenfassungen basieren auf RSS-Auszügen (kein KI-Schlüssel konfiguriert oder KI nicht verfügbar).' if not ai else 'KI-Zusammenfassungen basieren ausschliesslich auf RSS-Auszügen.')}
 Path('news.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
 print('Updated',len(top),'items; AI:',ai,'failed:',fail)
if __name__=='__main__':main()
