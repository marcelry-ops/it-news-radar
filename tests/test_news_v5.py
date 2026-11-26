import importlib.util
import datetime as dt
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('radar_news', Path(__file__).with_name('update_news.py'))
news = importlib.util.module_from_spec(spec)
spec.loader.exec_module(news)

def item(title, source, url, excerpt='', date=None):
    return {'id': url, 'title': title, 'source': source, 'feedSource': source,
            'url': url, 'excerpt': excerpt, 'published': (date or news.NOW).isoformat(), 'feedHint': None}

class NewsV5Tests(unittest.TestCase):
    def test_all_four_publishers_registered(self):
        feeds = [n for n, _, _ in news.FEEDS]
        for publisher in news.STRICT_IT_PUBLISHERS:
            self.assertIn(publisher, feeds)

    def test_strict_filter_excludes_non_it(self):
        for title in ['Bundesrat diskutiert Zukunft der Landwirtschaft in Bern',
                      'Fussball: Schweizer Team mit neuem Trainer',
                      'Digitale Ausstellung im Museum eröffnet']:
            x = item(title, 'Watson Digital', 'https://watson.ch/digital/123', 'Neues aus der Schweiz')
            self.assertFalse(any(news.eligible(x, cat) for cat in news.TARGETS), title)

    def test_strict_filter_accepts_real_it(self):
        examples = [
            ('Neuer Microsoft Security Patch schliesst Sicherheitslücke', 'Nau Digital', 'Security'),
            ('Schweizer Unternehmen modernisiert Cloud-Infrastruktur', 'SWI swissinfo.ch', 'Cloud'),
            ('Microsoft 365 Teams erhält neue Funktionen', 'Watson Digital', 'Microsoft 365'),
            ('KI-Modell für Softwareentwicklung veröffentlicht', 'IT Magazine Schweiz', 'Trends'),
        ]
        for title, source, category in examples:
            x=item(title, source, 'https://example.ch/' + category)
            self.assertTrue(news.eligible(x, category), title)

    def test_personen_keeps_only_three_existing_publishers(self):
        x=item('Neuer CEO ernannt: Schweizer Softwarefirma meldet Führungswechsel', 'Nau Digital', 'https://nau.ch/a', 'Neuer CEO')
        self.assertFalse(news.eligible(x, 'Personen'))

    def test_tracking_parameter_dedup(self):
        a=item('Microsoft entdeckt schwere Sicherheitslücke in Windows', 'Watson Digital', 'https://www.watson.ch/digital/123?utm_source=abc&x=1')
        b=item('Völlig andere Nachricht zu Cloud-Anbietern', 'Nau Digital', 'https://watson.ch/digital/123?x=1&utm_medium=test')
        self.assertEqual(len(news.deduplicate([a,b])),1)

    def test_cross_publisher_same_story(self):
        a=item('Microsoft schliesst kritische Sicherheitslücke in Windows Server', 'Watson Digital','https://watson.ch/1')
        b=item('Microsoft schliesst kritische Sicherheitslücke in Windows Server', 'IT Magazine Schweiz','https://itmagazine.ch/2')
        self.assertEqual(len(news.deduplicate([a,b])),1)

    def test_general_google_news_path_also_strict(self):
        x=item('Bundesrat diskutiert die Schweizer Wirtschaft', 'watson', 'https://news.google.com/rss/articles/abc', 'Die Digitalisierung wird erwähnt.')
        x['feedSource'] = 'Google News / Markt'
        self.assertFalse(news.eligible(x, 'Markt'))

    def test_no_multi_category_duplicates(self):
        people=item('Neuer CEO ernannt bei Schweizer IT-Unternehmen', 'Inside IT','https://inside-it.ch/person', 'Geschäftsleitung übernimmt nach Wechsel')
        people['feedSource']='Inside IT / Personen'
        sec=item('Microsoft Windows erhält wichtigen Sicherheitspatch für kritische Sicherheitslücke', 'IT Magazine Schweiz', 'https://itmagazine.ch/security')
        other=item('Google veröffentlicht KI-Modell für Softwareentwicklung', 'Watson Digital', 'https://watson.ch/digital/ki')
        chosen,_=news.select([people,sec,other])
        urls=[news.canonical_url(x['url']) for x in chosen]
        self.assertEqual(len(urls),len(set(urls)))
        self.assertEqual(sum(x['url']==people['url'] for x in chosen),1)

    def test_no_false_positive_generic_it_context(self):
        x=item('Schweizer Markt entwickelt sich stark', 'SWI swissinfo.ch', 'https://swissinfo.ch/123', 'Die Digitalisierung wird diskutiert.')
        self.assertFalse(any(news.eligible(x, cat) for cat in news.TARGETS))

if __name__ == '__main__': unittest.main()
