"""Age of source evidence, independent of download time and network health."""
from collections import Counter
from datetime import date, datetime
import json
from .models import date_iso, utcnow


def evidence_day(pub):
    """Return a calendar day and its meaning; never substitute collection time."""
    meta = pub.get('metadata', {})
    if pub.get('published_at'):
        try:
            return datetime.fromisoformat(date_iso(pub['published_at'])).date(), 'publication'
        except (ValueError, TypeError, OverflowError):
            pass
    for key, meaning in (('publication_day', 'publication'), ('catalog_added_day', 'catalog_added')):
        raw = meta.get(key)
        if raw:
            try:
                return date.fromisoformat(raw), meaning
            except (ValueError, TypeError):
                pass
    return None, 'unknown'


def summarize(publications, max_age_days=30, as_of=None):
    now = datetime.fromisoformat(date_iso(as_of or utcnow()))
    counts = Counter(recent=0, stale=0, unknown=0, future=0)
    meanings = Counter()
    days = []
    for pub in publications:
        day, meaning = evidence_day(pub)
        meanings[meaning] += 1
        if day is None:
            counts['unknown'] += 1
            continue
        age = (now.date() - day).days
        if age < 0:
            counts['future'] += 1
        else:
            days.append(day)
            counts['recent' if age <= max_age_days else 'stale'] += 1
    total = sum(counts.values())
    state = ('empty' if not total else 'future_dates' if counts['future'] else
             'recent' if counts['recent'] else 'stale' if counts['stale'] else 'unknown')
    return {'status': state, 'as_of': now.isoformat(), 'max_age_days': max_age_days,
            'total': total, **counts, 'date_meanings': dict(meanings),
            'oldest_day': min(days).isoformat() if days else None,
            'newest_day': max(days).isoformat() if days else None,
            'newest_age_days': (now.date() - max(days)).days if days else None}


def audit(store, sources, demo=False, as_of=None):
    """Include manual and disabled sources, with their original provenance."""
    grouped = {}
    for row in store.publications(demo):
        grouped.setdefault(row['source_id'], []).append(json.loads(row['data']))
    configs = {s['id']: s for s in sources}
    results = []
    for sid in sorted(set(configs) | set(grouped)):
        source = configs.get(sid, {})
        pubs = grouped.get(sid, [])
        results.append({'source_id': sid, 'name': source.get('name', sid),
                        'configured': bool(source), 'enabled': source.get('enabled', False),
                        'mode': source.get('freshness_mode', 'monitoring' if source else 'manual'),
                        'last_collected_at': max((p['collected_at'] for p in pubs), default=None),
                        'freshness': summarize(pubs, source.get('freshness_days', 30), as_of)})
    return results
