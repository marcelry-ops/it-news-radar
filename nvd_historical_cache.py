"""Bounded, atomic, persistent cache for successful historical NVD query results.

Stores only validated search result rows, never EPSS, KEV, or translated content.
Expired or corrupt data is ignored; the caller performs the usual full search.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

UTC = dt.timezone.utc
FORMAT = 1
MAX_BYTES = 45_000_000


def cache_path():
    return Path(os.getenv('CVE_HISTORICAL_CACHE_PATH', '.radar-cache/historical-nvd.json'))


def fingerprint(terms, pages, per_term, budget):
    settings = [list(terms), int(pages), int(per_term), int(budget)]
    return hashlib.sha256(json.dumps(settings, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def read_history(now, fingerprint_value, *, path=None, max_age_hours=20):
    if os.getenv('CVE_HISTORICAL_CACHE', '1') != '1':
        return None
    path = Path(path) if path is not None else cache_path()
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or data.get('format') != FORMAT or data.get('fingerprint') != fingerprint_value:
            return None
        synced = dt.datetime.fromisoformat(data['syncedAt'].replace('Z', '+00:00'))
        age = now.astimezone(UTC) - synced.astimezone(UTC)
        if not dt.timedelta(0) <= age < dt.timedelta(hours=max_age_hours):
            return None
        rows = data.get('rows')
        if not isinstance(rows, list) or len(rows) > 10000:
            return None
        if any(not isinstance(row, dict) or not isinstance(row.get('id'), str) or
               not row['id'].startswith('CVE-') or 'score' not in row for row in rows):
            return None
        if not isinstance(data.get('deferred'), int) or data['deferred'] < 0:
            return None
        return data
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return None


def write_history(now, fingerprint_value, rows, deferred, *, path=None):
    if os.getenv('CVE_HISTORICAL_CACHE', '1') != '1':
        return
    path = Path(path) if path is not None else cache_path()
    data = {'format': FORMAT, 'syncedAt': now.astimezone(UTC).isoformat(),
            'fingerprint': fingerprint_value, 'deferred': deferred, 'rows': rows}
    content = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    if len(content.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Historischer NVD-Cache zu gross')
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(content, encoding='utf-8')
    temp.replace(path)
