"""Offline integration checks for the delivered update_news.py and update_cves.py."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.news = load_module(ROOT / 'update_news.py', 'radar_news_test')
        cls.temp = tempfile.TemporaryDirectory()
        cls.config = Path(cls.temp.name) / 'priority_products.json'
        cls.config.write_text(json.dumps({'products': [
            {'name': 'TestOS', 'patterns': [r'testos'], 'searchTerms': ['TestOS CVE']}
        ]}), encoding='utf-8')
        original = Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path).endswith('priority_products.json'):
                return original(cls.config, encoding='utf-8')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read_text):
            cls.cves = load_module(ROOT / 'update_cves.py', 'radar_cves_test')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_news_original_and_tracking_url_deduplicated(self):
        n = self.news
        now = n.NOW.isoformat()
        base = dict(title='Aktueller Sicherheitsvorfall bei einem Testunternehmen',
                    excerpt='Sicherheitsvorfall mit Datenleck', summary='Sicherheitsvorfall',
                    published=now, feedHint='Security', feedSource='heise online', source='heise online')
        a = dict(base, url='https://example.org/story/42?utm_source=rss', id='a')
        b = dict(base, url='https://example.org/story/42', id='b')
        got = n.deduplicate([a,b])
        self.assertEqual(1,len(got))
        self.assertEqual('https://example.org/story/42',got[0]['url'])

    def test_news_personnel_not_repeated_across_categories(self):
        n = self.news
        row = dict(id='1',title='Neuer CEO übernimmt Leitung eines Schweizer IT-Unternehmens',
                   excerpt='Der neue CEO übernimmt die Geschäftsleitung.',
                   summary='Neue Geschäftsleitung', source='Inside IT',
                   url='https://example.org/p/1', published=n.NOW.isoformat(),
                   feedHint='Personen', feedSource='Inside IT / Personen')
        items, counts = n.select([row])
        self.assertEqual(1, len(items))
        self.assertEqual('Personen', items[0]['category'])

    def test_cve_priority_only_structured_product(self):
        c = self.cves
        self.assertEqual([], c.priority_products({'description': 'TestOS is mentioned but not affected', 'products': []}))
        self.assertEqual(['TestOS'], c.priority_products({'description': '', 'products': ['Vendor / TestOS']}))

    def test_cve_known_exploited_below_nine_is_eligible(self):
        from radar_quality import enrich_risks, eligible_risk, rank_risk
        row = {'id':'CVE-2026-99999','score':8.1,'sources':['NVD'],'priorityProducts':[]}
        enrich_risks([row],{'CVE-2026-99999':{'dateAdded':'2026-11-20'}},{})
        self.assertTrue(eligible_risk(row))
        self.assertEqual('CVE-2026-99999',rank_risk([row])[0]['id'])

if __name__ == '__main__':
    unittest.main()
