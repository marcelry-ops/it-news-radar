"""Persistent NVD snapshot with safe, opt-in incremental refresh.

Requires a restored cache directory between CI runs. On invalid or old cache,
callers MUST execute the full publication-window query.
"""
import datetime as dt
import json
import os
from pathlib import Path

UTC=dt.timezone.utc
FORMAT_VERSION=1

def cache_path():
    return Path(os.getenv('CVE_NVD_CACHE_PATH','.radar-cache/nvd-snapshot.json'))

def read_snapshot(now, path=None, max_age_days=7):
    if os.getenv('CVE_INCREMENTAL','0')!='1': return None
    path=Path(path) if path is not None else cache_path()
    try:
        if path.stat().st_size > 45_000_000: return None
        payload=json.loads(path.read_text(encoding='utf-8'))
        if payload.get('format')!=FORMAT_VERSION or not payload.get('complete'): return None
        stamp=dt.datetime.fromisoformat(payload['syncedAt'].replace('Z','+00:00'))
        age=now-stamp.astimezone(UTC)
        if not dt.timedelta(0) <= age < dt.timedelta(days=max_age_days): return None
        entries=payload.get('entries')
        if not isinstance(entries,dict) or not entries: return None
        if len(entries)>100000: return None
        if any(k!=v.get('id') for k,v in entries.items() if isinstance(v,dict)): return None
        return payload
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        return None

def modified_query_start(snapshot):
    stamp=dt.datetime.fromisoformat(snapshot['syncedAt'].replace('Z','+00:00'))
    return stamp.astimezone(UTC)-dt.timedelta(hours=3)

def write_snapshot(entries, now, path=None):
    path=Path(path) if path is not None else cache_path()
    path.parent.mkdir(parents=True,exist_ok=True)
    payload={'format':FORMAT_VERSION,'complete':True,'syncedAt':now.isoformat(), 'entries':entries}
    temp=path.with_suffix('.tmp')
    temp.write_text(json.dumps(payload,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
    temp.replace(path)
