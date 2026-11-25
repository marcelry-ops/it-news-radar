import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from radar_monitor import assess
from radar_guard import guard_dataset
from nvd_incremental import read_snapshot, write_snapshot, modified_query_start
from radar_quality import risk_score

UTC=dt.timezone.utc

class AdditionalTests(unittest.TestCase):
    def test_monitor_detects_url_and_id_duplicates(self):
        now=dt.datetime(2026,11,25,10,tzinfo=UTC)
        news={'updatedAt':now.isoformat(),'items':[{'id':'a','url':'https://example.org/a?utm_source=rss','category':'Security'}, {'id':'b','url':'https://example.org/a','category':'Security'}],'targets':{'Security':5}}
        cves={'updatedAt':now.isoformat(),'items':[{'id':'CVE-2026-12345'}, {'id':'CVE-2026-12345'}]}
        result=assess(news,cves,now)
        self.assertEqual('error',result['status'])
        self.assertIn('duplicate_news_urls',result['errors'])
        self.assertIn('duplicate_cve_ids',result['errors'])

    def test_risk_score_is_bounded(self):
        row={'score':10,'epss':1,'priorityProducts':['X'],'knownExploited':True,'kevRansomware':'Known'}
        self.assertEqual(100, risk_score(row))
        self.assertEqual(0,risk_score({}))
        self.assertGreater(risk_score({'score':8,'knownExploited':True}),risk_score({'score':9.9}))

    def test_valid_snapshot_and_invalid_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'snapshot.json'
            now=dt.datetime(2026,11,25,9,tzinfo=UTC)
            items={'CVE-2026-11111':{'id':'CVE-2026-11111','published':'2026-11-25T00:00:00Z'}}
            write_snapshot(items,now,file)
            with patch.dict(os.environ,{'CVE_INCREMENTAL':'1'}):
                self.assertEqual(items,read_snapshot(now+dt.timedelta(hours=1),file)['entries'])
                self.assertIsNone(read_snapshot(now+dt.timedelta(days=8),file))
                self.assertLess(modified_query_start(read_snapshot(now,file)),now)
            with patch.dict(os.environ,{'CVE_INCREMENTAL':'0'}):
                self.assertIsNone(read_snapshot(now,file))

    def test_guard_blocks_severe_loss_and_retains_old_data(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'news.json'
            original={'items':[{'id':i} for i in range(40)]}
            file.write_text(json.dumps(original),encoding='utf-8')
            with self.assertRaises(RuntimeError):guard_dataset(file,{'items':[{'id':1}]})
            self.assertEqual(original,json.loads(file.read_text(encoding='utf-8')))
            guard_dataset(file,{'items':[{'id':i} for i in range(30)]})

if __name__=='__main__': unittest.main()
