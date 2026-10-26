"""Rule-based candidates; a match is never a verified incident."""
import re
from .models import normalized, digest, identifier_text

VERSION = 'rules-v1'
PATTERNS = {
    'access_sale_claim': r'прода[её](?:т|м|тся)|продаж[аиу]|selling|for sale',
    'data_leak_claim': r'утечк|слив\b|data leak|data breach|похищен\w* данн',
    'ransomware_claim': r'вымогат|шифроваль|ransomware|зашифрова',
    'availability_claim': r'ddos|ддос|атак\w* на отказ',
    'vulnerability_advisory': r'уязвим|vulnerabilit|\bCVE-\d{4}-\d{4,}\b',
    'attack_claim': r'кибератак|взлом|cyberattack|cyber.attack',
}
DOMAIN_RE = re.compile(r'(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-]|\.[a-z0-9])')


def event_type(text):
    text = identifier_text(text)
    if (re.search(r'bug[\s.-]*bounty|багбаунти|баг-баунти', text, re.I)
            and re.search(r'программ|program|площадк|платформ', text, re.I)
            and not re.search(r'зафиксир\w*.*эксплуатац|подтверждён\w*.*атак|confirmed attack', text, re.I)):
        return 'bug_bounty_announcement'
    for kind, pattern in PATTERNS.items():
        if re.search(pattern, text, re.I):
            if kind == 'access_sale_claim' and not re.search(r'доступ|access|vpn|rdp', text, re.I):
                continue
            return kind
    return 'unknown'


def alias_match(alias, text):
    return bool(re.search(r'(?<!\w)' + re.escape(normalized(alias)) + r'(?!\w)', normalized(text)))


def extract(pub, companies, products=None, entities=None):
    text = pub.title + '. ' + pub.text
    domains = sorted(set(m.group(0).lower() for m in DOMAIN_RE.finditer(text)))
    identifiers = identifier_text(text)
    cves = sorted(set(x.upper() for x in re.findall(r'\bCVE-\d{4}-\d{4,}\b', identifiers, re.I)))
    bdu_ids = sorted(set(x.upper() for x in re.findall(r'\bBDU:\d{4}-\d{4,}\b', identifiers, re.I)))
    entity_mentions = [{'id': e['id'], 'entity_type': e['entity_type']}
                       for e in entities or [] if bool(e.get('is_demo', False)) == pub.is_demo
                       and any(alias_match(a, text) for a in [e['name'], *e.get('aliases', [])])]
    signals = []
    for company in companies:
        if not company.get('monitor_target', True):
            continue
        aliases = [company['name'], *company.get('aliases', [])]
        for fragment in re.split(r'[\n!?;]+|(?<=[а-яА-Я])\.\s+', text):
            names = [a for a in aliases if alias_match(a, fragment)]
            seen_domains = [m.group(0).lower() for m in DOMAIN_RE.finditer(fragment)]
            hits = [d for d in company.get('domains', []) if any(
                seen == d.lower() or seen.endswith('.' + d.lower()) for seen in seen_domains)]
            if not names and not hits:
                continue
            kind = event_type(fragment)
            if kind in ('unknown', 'vulnerability_advisory', 'bug_bounty_announcement'):
                continue
            signals.append({
                'id': digest(pub.id + company['id'] + kind)[:24],
                'publication_id': pub.id, 'company_id': company['id'], 'event_type': kind,
                'excerpt': fragment.strip()[:600], 'matched_terms': names + hits,
                'extractor_version': VERSION, 'entity_status': 'needs_review',
                'verification_status': 'needs_review', 'analyst_confidence': 'low',
                'evidence_hash': pub.content_hash,
            })
    from .knowledge import extract_relations
    relations = extract_relations(pub, companies, products or [])
    return {'domains': domains, 'cves': cves, 'bdu_ids': bdu_ids, 'event_type': event_type(text),
            'signals': list({s['id']: s for s in signals}.values()), 'entity_mentions': entity_mentions, **relations}
