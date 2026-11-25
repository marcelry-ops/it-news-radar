"""Guard against replacing valid dashboards with clearly deficient data."""
import json
from pathlib import Path

def guard_dataset(path, payload, min_fraction=0.5):
    """Compare counts when a previous valid JSON exists; raise on severe drops."""
    path=Path(path)
    if not path.exists(): return
    try:
        previous=json.loads(path.read_text(encoding='utf-8'))
        old=previous.get('items',[])
        current=payload.get('items',[])
        if not isinstance(old,list) or not isinstance(current,list):
            raise RuntimeError('Ungueltige items-Struktur')
        if len(old)>=10 and len(current)<max(1,int(len(old)*min_fraction)):
            raise RuntimeError(f'Plausibilitaetskontrolle: {len(old)} -> {len(current)} Eintraege; bestehende Datei beibehalten')
    except (ValueError,OSError) as exc:
        raise RuntimeError('Bestehende JSON-Datei nicht lesbar') from exc
