import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from radar_quality import (canonical_url, news_identity, dedupe_news, same_news,
                           news_impact, load_epss, enrich_risks, merge_kev_records,
                           rank_risk, eligible_risk)

class QualityTests(unittest.TestCase):
    def test_tracking_is_removed(self):
        url='https://www.heise.de/news/abc-11537061.html?utm_source=rss&foo=x#top'
        self.assertEqual(canonical_url(url),'https://www.heise.de/news/abc-11537061.html?foo=x')

    def test_meaningful_parameters_preserved(self):
        self.assertNotEqual(canonical_url('https://example.ch/a?id=1'),canonical_url('https://example.ch/a?id=2'))

    def test_duplicate_story_canonicalized(self):
        a={'url':'https://www.heise.de/news/cia-11537061.html','title':'Cyberangriff auf US-Geheimdienst CIA','excerpt':'Kurzer Text','published':'2026-11-25T01:00:00Z'}
        b={**a,'url':a['url']+'?utm_source=rss','excerpt':'Laengerer, informativerer Text'}
        unique=dedupe_news([a,b])
        self.assertEqual(len(unique),1)
        self.assertEqual(unique[0]['id'],news_identity(a))
        self.assertEqual(unique[0]['excerpt'],b['excerpt'])

    def test_different_cves_not_merged(self):
        a={'url':'https://example.org/1','title':'CVE-2026-11111 Sicherheitsluecke in Produkt X'}
        b={'url':'https://example.org/2','title':'CVE-2026-22222 Sicherheitsluecke in Produkt X'}
        self.assertFalse(same_news(a,b))

    def test_impact_rewards_exploitation(self):
        a={'title':'Zero-Day aktiv ausgenutzt, Notfallpatch veroeffentlicht','excerpt':''}
        b={'title':'Neues Design fuer Software','excerpt':''}
        self.assertGreater(news_impact(a,'Security'),news_impact(b,'Security'))

    def test_epss_parsing(self):
        def fetch(url):
            self.assertIn('cve=',url)
            return {'data':[{'cve':'CVE-2026-11111','epss':'0.819','percentile':'0.98'}]}
        values=load_epss(['CVE-2026-11111'],fetch=fetch)
        self.assertAlmostEqual(values['CVE-2026-11111']['epss'],.819)

    def test_kev_below_nine_is_eligible_and_ranked(self):
        rows=[{'id':'CVE-2026-11111','score':8.1,'priorityProducts':[],'sources':[]},
              {'id':'CVE-2026-22222','score':9.9,'priorityProducts':[],'sources':[]}]
        enrich_risks(rows,{'CVE-2026-11111':{'dateAdded':'2026-11-24'}},{})
        self.assertTrue(eligible_risk(rows[0]))
        self.assertEqual(rank_risk(rows)[0]['id'],'CVE-2026-11111')
        self.assertEqual(rows[0]['sources'],['CISA KEV'])

    def test_medium_not_unconditionally_included(self):
        self.assertFalse(eligible_risk({'score':6.5,'priorityProducts':[]}))

    def test_kev_lookups_bounded(self):
        entries={}
        kev={f'CVE-2026-{i:05d}':{'dateAdded':'2026-11-24'} for i in range(10000,10004)}
        calls=[]
        def lookup(cid):
            calls.append(cid)
            return {'id':cid,'score':8.5,'priorityProducts':[]}
        stats=merge_kev_records(entries,kev,lookup,max_missing=2)
        self.assertEqual(stats['added'],2)
        self.assertEqual(stats['deferred'],2)
        self.assertEqual(len(calls),2)

if __name__=='__main__':unittest.main()
