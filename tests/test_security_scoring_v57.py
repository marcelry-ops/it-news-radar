"""Regression tests: Security headline bonuses must use incident recognition."""
import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('news_v57', Path(__file__).resolve().parents[1] / 'update_news.py')
news = importlib.util.module_from_spec(spec)
spec.loader.exec_module(news)


def article(title, excerpt='', source='IT Magazine Schweiz'):
    return {'title': title, 'excerpt': excerpt, 'feedHint': None,
            'source': source, 'feedSource': source, 'published': news.NOW.isoformat(),
            'id': f'https://example.ch/{len(title)}', 'url': f'https://example.ch/{len(title)}'}


class SecurityScoringV57Tests(unittest.TestCase):
    def test_singular_plural_and_equivalent_incidents_get_same_bonus(self):
        titles = [
            'Hackerangriff auf Testfirma',
            'Hackerangriffe auf Testfirma',
            'Cybervorfall bei Testfirma',
            'Datenabfluss bei Testfirma',
            'Datendiebstahl bei Testfirma',
            'Datenlecks bei Testfirma',
            'Cyberattacken auf Testfirma',
            'Sicherheitsvorfall bei Testfirma',
        ]
        base = news.score(article('Testfirma meldet Probleme'), 'Security')
        for title in titles:
            with self.subTest(title=title):
                candidate = article(title)
                self.assertTrue(news.explicit_it_relevance(candidate))
                self.assertTrue(news.eligible(candidate, 'Security'))
                self.assertEqual(news.score(candidate, 'Security') - base, 22)

    def test_security_bonus_only_when_headline_has_security_signal(self):
        base = news.score(article('Testfirma meldet Probleme'), 'Security')
        in_excerpt = article('Testfirma meldet Probleme', excerpt='Datenabfluss bestätigt')
        self.assertEqual(news.score(in_excerpt, 'Security'), base)
        in_headline = article('Testfirma meldet Datenabfluss')
        self.assertEqual(news.score(in_headline, 'Security'), base + 22)

    def test_non_incident_words_do_not_get_bonus(self):
        base = news.score(article('Testfirma meldet Probleme'), 'Security')
        for title in ('Angriff auf Torwart', 'Daten zur Saison', 'Sicherheit am Badesee', 'Abfluss im Kanal'):
            with self.subTest(title=title):
                self.assertEqual(news.score(article(title), 'Security'), base)

    def test_existing_security_term_remains_and_other_scores_unchanged(self):
        base = news.score(article('Testfirma meldet Probleme'), 'Security')
        self.assertEqual(news.score(article('Ransomware bei Testfirma'), 'Security'), base + 22)
        title = 'Hackerangriffe auf Testfirma'
        for category in ('Cloud', 'Trends', 'Markt', 'Firmen', 'Microsoft 365', 'IT Schweiz'):
            self.assertEqual(news.score(article(title), category), news.score(article('Testfirma meldet Probleme'), category))


if __name__ == '__main__':
    unittest.main()
