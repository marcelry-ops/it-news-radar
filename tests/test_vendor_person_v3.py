"""Offline checks for selective 30-day personnel and vendor diagnostics."""
import datetime as dt
import importlib.util
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance


class V3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.news = module(ROOT/'update_news.py', 'news_v3_tests')

    def test_30_day_search_is_personnel_only(self):
        n = self.news
        qs = [urllib.parse.parse_qs(urllib.parse.urlparse(x[1]).query)['q'][0]
              for x in n.FEEDS if x[0].endswith(' / Personen')]
        self.assertTrue(qs)
        self.assertTrue(all('when:30d' in x for x in qs))
        self.assertIn('when:7d', urllib.parse.parse_qs(
            urllib.parse.urlparse(n.google_rss('Cloud')).query)['q'][0])

    def test_personnel_accepts_three_week_old_news_but_other_news_does_not(self):
        n = self.news
        date = (n.NOW - dt.timedelta(days=21)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        xml = (f'<rss><channel><item><title>Neue IT-Leiterin übernimmt die Geschäftsleitung eines Unternehmens</title>'
               f'<description>Die IT-Leiterin wurde in die Geschäftsleitung berufen.</description>'
               f'<link>https://example.org/leiterin</link><pubDate>{date}</pubDate></item></channel></rss>').encode()
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return xml
        with patch.object(n.urllib.request, 'urlopen', return_value=Response()):
            older_person = n.extract(('Inside IT / Personen', 'https://example.org/rss', 'Personen'))
            older_other = n.extract(('heise online', 'https://example.org/rss', None))
        self.assertEqual(1, len(older_person))
        self.assertEqual([], older_other)
        self.assertTrue(n.personnel_relevance(older_person[0]))

    def test_personnel_remains_restricted_to_three_publishers(self):
        n = self.news
        row = {'title': 'Neuer CEO übernimmt Geschäftsleitung eines IT-Unternehmens',
               'excerpt': 'Der CEO wurde ernannt.', 'feedSource': 'Google News / Security'}
        self.assertFalse(n.eligible(row, 'Personen'))
        row['feedSource'] = 'Netzwoche / Personen'
        self.assertTrue(n.eligible(row, 'Personen'))

    def test_vendor_discovery_reports_missing_domain_separately(self):
        with tempfile.TemporaryDirectory() as temp:
            c = Path(temp)/'priority_products.json'
            c.write_text('{"products":[{"name":"TestOS","patterns":["testos"],"searchTerms":["testos CVE"]}]}')
            original = Path.read_text
            def fake_read(path, *args, **kwargs):
                if str(path).endswith('priority_products.json'):
                    return original(c, encoding='utf-8')
                return original(path, *args, **kwargs)
            with patch.object(Path,'read_text', fake_read):
                mod = module(ROOT/'update_cves.py', 'cve_v3_tests')
            records, failures = mod.discover_official_cve_ids({'products':[{'name':'TestOS','advisoryDomain':''}]},
                                                               fetch=lambda _: (_ for _ in ()).throw(AssertionError('should not fetch')))
            self.assertEqual({},records)
            self.assertIn('keine verifizierte offizielle Advisory-Domain konfiguriert',failures[0])

if __name__ == '__main__': unittest.main()
