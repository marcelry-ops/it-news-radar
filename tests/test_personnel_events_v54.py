import datetime as dt
import importlib.util
import json
from urllib.parse import unquote
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('news_v54', Path(__file__).resolve().parents[1] / 'update_news.py')
news = importlib.util.module_from_spec(spec)
spec.loader.exec_module(news)

def article(title, slug, offset=3, company='Nvidia', source='IT Reseller'):
    return {'id': slug, 'url': 'https://example.com/' + slug, 'title': title,
            'source': source, 'feedSource': source, 'feedHint': 'Personen',
            'excerpt': 'IT-Fuehrungswechsel bei ' + company,
            'published': (news.NOW - dt.timedelta(days=offset)).isoformat()}

class EventTests(unittest.TestCase):
    def setUp(self):
        self.leave1 = article('Jensen Huang tritt als Nvidia-CEO zurück, Colette Kress übernimmt', 'departure1', 12)
        self.leave2 = article('Nvidia-Chef Jensen Huang tritt zurück', 'departure2', 12, source='Inside IT')
        self.comeback = article('Nvidia holt Jensen Huang als CEO zurück', 'comeback', 3)

    def test_detect_same_person_company_departure(self):
        self.assertEqual(news.personnel_event_relation(self.leave1, self.leave2), 'same_event')

    def test_opposite_claims_not_deduplicated(self):
        self.assertEqual(news.personnel_event_relation(self.comeback, self.leave1), 'potential_conflict')
        kept = news.deduplicate([self.leave1, self.leave2, self.comeback])
        self.assertEqual(len(kept), 2)

    def test_diagnostics_marks_review_without_asserting_truth(self):
        raw = [self.leave1, self.leave2, self.comeback]
        chosen, counts = news.select(raw)
        self.assertEqual(counts['Personen'], 2)
        report = news.build_diagnostics(raw, chosen, [])
        d = report['personnelDiagnostics']
        self.assertEqual(d['eligible'], 2)
        self.assertEqual(d['selected'], 2)
        self.assertEqual(d['potentialConflictCount'], 1)
        self.assertTrue(d['potentialConflicts'][0]['reviewRequired'])
        self.assertTrue(d['eventDuplicates'])
        self.assertEqual(sum(row['status']=='selected' for row in report['articles']), 2)

    def test_two_people_same_company_are_separate(self):
        other = article('Nvidia-Chef Marco Berger tritt zurück', 'other', 12)
        self.assertIsNone(news.personnel_event_relation(self.leave1, other))
        self.assertEqual(len(news.deduplicate([self.leave1, other])), 2)

    def test_same_person_different_companies_are_separate(self):
        other = article('Cisco-Chef Jensen Huang tritt zurück', 'other2', 12, company='Cisco')
        self.assertIsNone(news.personnel_event_relation(self.leave1, other))

    def test_generic_leadership_change_not_forced_merge(self):
        one=article('Zscaler stellt Führungsspitze der Alpine-Region neu auf', 'one')
        two=article('Zscaler stellt Führungsteam in der Schweiz neu auf', 'two')
        self.assertIsNone(news.personnel_event_relation(one,two))

    def test_departures_a_month_apart_not_silently_merged(self):
        other=article('Nvidia-Chef Jensen Huang tritt zurück', 'old', 27)
        self.assertIsNone(news.personnel_event_relation(self.leave1,other))

    def test_news_sources_and_person_window_preserved(self):
        self.assertEqual(news.TARGETS['Personen'], 10)
        self.assertTrue(all('when:30d' in unquote(feed) for name, feed, hint in news.FEEDS if name.endswith(' / Personen')))
        self.assertEqual(len([1 for name,feed,hint in news.FEEDS if name.endswith(' / Personen')]),9)
        self.assertEqual(set(news.PERSON_SITES), {'IT Reseller','Netzwoche','Inside IT'})
        for site in ('itmagazine.ch','swissinfo.ch','nau.ch/news/digital','watson.ch/digital'):
            self.assertTrue(any(site in unquote(urllib_parse_feed) for _,urllib_parse_feed,_ in news.FEEDS))

    def test_no_duplicate_across_categories(self):
        generic=article('Nvidia-Chef Jensen Huang tritt zurück','generic',12,source='Google News / Firmen')
        generic['feedSource']='Google News / Firmen'
        chosen, counts=news.select([self.leave1,self.leave2,generic,self.comeback])
        self.assertEqual(len(chosen),2)
        self.assertTrue(all(row['category']=='Personen' for row in chosen))

if __name__=='__main__': unittest.main()
