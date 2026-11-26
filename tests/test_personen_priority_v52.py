import datetime as dt
import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('news_v52', Path(__file__).resolve().parents[1] / 'update_news.py')
news = importlib.util.module_from_spec(spec)
spec.loader.exec_module(news)

def article(title, url, feed, description='Ein Schweizer IT-Unternehmen bestätigt den Führungswechsel.', age=0):
    return {'title': title, 'url': url, 'id': url, 'excerpt': description,
            'published': (news.NOW-dt.timedelta(days=age)).isoformat(),
            'source': feed, 'feedSource': feed,
            'feedHint': 'Personen' if feed.endswith(' / Personen') else 'Firmen'}

class PriorityTests(unittest.TestCase):
    def test_generic_feed_longer_excerpt_does_not_hide_person(self):
        title='Neuer CEO ernannt bei Schweizer IT-Unternehmen'
        p=article(title,'https://inside-it.ch/wechsel?utm_source=news','Inside IT / Personen')
        generic=article(title,'https://inside-it.ch/wechsel','Google News / Firmen', 'Sehr ausführlicher ' * 30)
        selected,counts=news.select([generic,p])
        self.assertEqual(counts['Personen'],1)
        self.assertEqual(sum(x['category']=='Personen' for x in selected),1)
        self.assertEqual(sum(x['category']=='Firmen' for x in selected),0)
        self.assertEqual(selected[0]['url'],'https://inside-it.ch/wechsel')

    def test_similar_other_url_does_not_duplicate_person_in_other_categories(self):
        title='Neuer CEO ernannt bei Schweizer IT-Unternehmen'
        p=article(title,'https://inside-it.ch/wechsel','Inside IT / Personen')
        generic=article(title,'https://example.ch/anderer-artikel','Google News / Firmen','Ein IT-Unternehmen ernennt CEO')
        selected,counts=news.select([generic,p])
        self.assertEqual(counts['Personen'],1)
        self.assertEqual(len(selected),1)

    def test_personnel_older_than_seven_days_remains_eligible(self):
        p=article('Neuer CEO ernannt bei Schweizer IT-Unternehmen','https://inside-it.ch/wechsel','Inside IT / Personen',age=21)
        selected,counts=news.select([p])
        self.assertEqual(counts['Personen'],1)

    def test_unapproved_publisher_still_excluded(self):
        p=article('Neuer CEO ernannt bei Schweizer IT-Unternehmen','https://watson.ch/digital/wechsel','Watson Digital')
        self.assertEqual(news.select([p])[1]['Personen'],0)

if __name__=='__main__': unittest.main()
