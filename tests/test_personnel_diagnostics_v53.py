import datetime as dt
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('news_v53', Path(__file__).resolve().parents[1] / 'update_news.py')
news = importlib.util.module_from_spec(spec)
spec.loader.exec_module(news)


def article(title, url, feed, source=None, excerpt='Schweizer IT-Branche: Wechsel in der Unternehmensleitung.'):
    return {'id': url, 'title': title, 'url': url, 'source': source or feed.split(' / ')[0],
            'feedSource': feed, 'feedHint': 'Personen' if feed.endswith(' / Personen') else 'IT Schweiz',
            'excerpt': excerpt, 'published': (news.NOW - dt.timedelta(days=3)).isoformat()}

class PersonnelV53Tests(unittest.TestCase):
    def test_reject_previously_excluded_concrete_ceo_departure(self):
        p = article('Nutanix-CEO Rajiv Ramaswami kündigt Abschied an', 'https://www.itreseller.ch/Artikel/106673', 'IT Reseller')
        self.assertTrue(news.eligible(p, 'Personen'))

    def test_accept_chief_transformation_officer(self):
        p = article('Infinigate ernennt Tom O’Reilly zum Chief Transformation Officer', 'https://www.itreseller.ch/Artikel/106670', 'IT Reseller')
        self.assertTrue(news.eligible(p, 'Personen'))

    def test_accept_leadership_reorganisation(self):
        p = article('Zscaler stellt Führungsspitze der Alpine-Region neu auf', 'https://www.itreseller.ch/Artikel/106658', 'IT Reseller')
        self.assertTrue(news.eligible(p, 'Personen'))

    def test_reject_generic_mention_of_ceos(self):
        p = article('Schweizer Chefs kennen Cyberrisiken, handeln aber selten', 'https://www.inside-it.ch/story', 'Inside IT')
        self.assertFalse(news.eligible(p, 'Personen'))

    def test_personnel_still_restricted_to_three_publishers(self):
        p = article('Nutanix-CEO Rajiv Ramaswami kündigt Abschied an', 'https://www.watson.ch/digital/news', 'Watson Digital')
        self.assertFalse(news.eligible(p, 'Personen'))

    def test_same_google_news_id_logged_once_selected(self):
        url = 'https://news.google.com/rss/articles/unique-one'
        a = article('Neuer CEO ernannt bei Schweizer IT-Unternehmen', url, 'IT Reseller / Personen')
        duplicate = dict(a)
        duplicate['feedSource'] = 'IT Reseller / Personen'
        chosen, counts = news.select([a, duplicate])
        report = news.build_diagnostics([a, duplicate], chosen, [])
        self.assertEqual(counts['Personen'], 1)
        self.assertEqual(report['selectedPerCategory']['Personen'], 1)
        self.assertEqual(sum('Personen' in x['selectedCategories'] for x in report['articles']), 1)
        self.assertEqual(sum(x['status'] == 'selected' for x in report['articles']), 1)
        self.assertEqual(report['articles'][1]['status'], 'duplicate_or_similar_story')
        self.assertEqual(report['personnelDiagnostics']['fetched'], 2)
        self.assertEqual(report['personnelDiagnostics']['eligible'], 1)
        self.assertEqual(report['personnelDiagnostics']['selected'], 1)

    def test_diagnostic_reason_for_rejected_headline(self):
        person = article('Schweizer Chefs kennen Cyberrisiken, handeln aber selten', 'https://www.inside-it.ch/chefs', 'Inside IT')
        report = news.build_diagnostics([person], [], [])
        self.assertEqual(report['personnelDiagnostics']['rejectedExamples'][0]['reason'], 'headline_not_personnel_change')

    def test_no_personnel_other_categories_duplicated(self):
        p = article('Nutanix-CEO Rajiv Ramaswami kündigt Abschied an', 'https://www.itreseller.ch/Artikel/106673', 'IT Reseller')
        generic = article(p['title'], 'https://example.com/nutanix', 'Google News / Firmen')
        chosen, counts = news.select([p, generic])
        self.assertEqual(counts['Personen'], 1)
        self.assertEqual(len(chosen), 1)

if __name__ == '__main__': unittest.main()
