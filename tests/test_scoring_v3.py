from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors import ingest
from app.graph_scoring import calculate_graph
from app.models import Publication
from app.storage import CTIStore

NOW = '2026-10-24T12:00:00+00:00'


class ScoringPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        clock = patch('app.storage.utcnow', return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)
        self.store = CTIStore(Path(self.tmp.name) / 'test.sqlite3')
        self.store.load_companies([{'id': key, 'name': name, 'aliases': []}
                                   for key, name in [('alpha', 'Example Alpha'), ('beta', 'Example Beta')]])
        self.store.load_products([{'id': 'product', 'name': 'Example Product', 'aliases': []}])
        self.store.load_entities([{'id': 'incident', 'name': 'Example Incident', 'entity_type': 'Incident',
                                   'start_day': '2017-05-13', 'end_day': '2017-07-30'}])
        self.n = 0

    def publication(self, text):
        self.n += 1
        pub = Publication('test', 'https://example.org/' + str(self.n), 'Fictional evidence', text,
                          published_at=NOW, collected_at=NOW)
        ingest(self.store, [pub])
        return pub

    def claim(self, pub, kind, subject, obj, **attrs):
        uid = self.store.add_assertion({'kind': kind, 'subject': subject, 'object': obj,
                                       'publication_id': pub.id, 'excerpt': pub.text,
                                       'attributes': {'confidence': 'high', 'basis': 'victim_report', **attrs}})
        self.store.review_assertion(uid, 'confirmed', 'Analyst', 'Fictional reviewed evidence')
        return uid

    def fixture(self, victim='alpha', version=None):
        suffix = ' версии ' + version if version else ''
        use = self.publication('Example Alpha использует Example Product' + suffix + '.')
        self.use_id = self.claim(use, 'uses_product', 'alpha', 'product',
                                 **({'version': version} if version else {}))
        adv = self.publication('CVE-2026-99991 затрагивает Example Product версии 1.2.3.')
        advisory = self.claim(adv, 'affects_product', 'CVE-2026-99991', 'product',
                              basis='vendor_advisory', affected_versions=['1.2.3'])
        company = 'Example Alpha' if victim == 'alpha' else 'Example Beta'
        incident = self.publication('Example Incident затронул ' + company + '. Example Incident использовал '
                                    'Example Product. Example Incident: эксплуатировалась CVE-2026-99991.')
        ids = [self.claim(incident, 'incident_affects', 'incident', victim),
               self.claim(incident, 'incident_product', 'incident', 'product'),
               self.claim(incident, 'incident_exploited', 'incident', 'CVE-2026-99991'), advisory]
        return incident, ids

    def score(self, company='alpha'):
        return next(c for c in calculate_graph(self.store, as_of=NOW, include_historical=True)['companies']
                    if c['company_id'] == company)

    def test_confirmation_requires_metadata_and_rejected_attempt_is_atomic(self):
        pub = self.publication('Example Alpha использует Example Product.')
        uid = self.store.add_assertion({'kind': 'uses_product', 'subject': 'alpha', 'object': 'product',
                                        'publication_id': pub.id, 'excerpt': pub.text})
        for kwargs in ({}, {'confidence': 'high'}, {'confidence': 'high', 'basis': 'unspecified'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store.review_assertion(uid, 'confirmed', 'Analyst', 'Reviewed', **kwargs)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM assertion_reviews').fetchone()[0], 0)
        self.store.review_assertion(uid, 'confirmed', 'Analyst', 'Explicit source excerpt reviewed',
                                    confidence='medium', basis='research_report')
        claim = next(c for c in self.store.assertions() if c['id'] == uid)
        self.assertEqual(claim['attributes'], {'confidence': 'medium', 'basis': 'research_report'})
        with self.store.connect() as db:
            reviewed = json.loads(db.execute('SELECT data FROM assertion_reviews').fetchone()[0])
        self.assertEqual(reviewed['attributes'], claim['attributes'])

    def test_legacy_defaults_remain_visible_and_are_not_upgraded(self):
        self.fixture()
        with self.store.connect() as db:
            data = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (self.use_id,)).fetchone()[0])
            data['attributes'] = {}
            db.execute('UPDATE assertions SET data=? WHERE id=?', (json.dumps(data), self.use_id))
        edge = next(p for p in self.score()['paths'] if p['selected'] and p['dimension'] == 'technical')['edges'][0]
        self.assertEqual(edge['quality'], .42)
        self.assertEqual(edge['defaults_used'], ['confidence', 'basis'])
        self.assertIn('observation_date_unknown', edge['warnings'])
        self.assertEqual(edge['date_basis'], 'publication_proxy')

    def test_unknown_version_remains_limited_but_exact_incident_is_separate(self):
        self.fixture()
        row = self.score()
        self.assertAlmostEqual(row['technical']['score'], 13.5)
        self.assertEqual(row['historical_technical']['score'], 90)
        self.assertFalse(row['historical_technical']['current_vulnerability_established'])
        path = next(p for p in row['paths'] if p['selected'] and p['dimension'] == 'historical_technical')
        self.assertEqual({e['kind'] for e in path['edges']},
                          {'incident_affects', 'incident_product', 'incident_exploited', 'affects_product'})
        self.assertTrue(all(e['decay'] == 1 for e in path['edges']))

    def test_fixed_current_version_does_not_erase_a_past_incident(self):
        self.fixture(version='1.2.4')
        self.assertIsNone(self.score()['technical']['score'])
        self.assertEqual(self.score()['historical_technical']['score'], 90)

    def test_another_victim_cannot_supply_an_exact_incident_for_this_company(self):
        self.fixture(victim='beta')
        self.assertAlmostEqual(self.score()['technical']['score'], 13.5)
        self.assertIsNone(self.score()['historical_technical']['score'])
        self.assertEqual(self.score('beta')['historical_technical']['score'], 90)

    def test_each_required_link_can_invalidate_the_historical_result(self):
        _, ids = self.fixture()
        for uid in ids:
            with self.subTest(uid=uid):
                self.store.review_assertion(uid, 'refuted', 'Analyst', 'Evidence retracted')
                self.assertIsNone(self.score()['historical_technical']['score'])
                self.store.review_assertion(uid, 'confirmed', 'Analyst', 'Retraction withdrawn')

    def test_changed_incident_source_removes_historical_support(self):
        incident, _ = self.fixture()
        incident.text += ' Изменённый текст, требующий повторной проверки.'
        ingest(self.store, [incident])
        self.assertIsNone(self.score()['historical_technical']['score'])

    def test_incident_uses_end_of_period_and_new_publication_does_not_refresh_event(self):
        self.fixture()
        path = next(p for p in self.score()['paths'] if p['selected'] and p['dimension'] == 'interest')
        edge = path['edges'][0]
        self.assertEqual(edge['date'], '2017-07-30')
        self.assertEqual(edge['date_basis'], 'event_end')
        self.assertEqual(edge['published_day'], NOW[:10])
        self.assertEqual(edge['event_start_day'], '2017-05-13')
        self.assertGreater(edge['age_days'], 3000)

    def test_product_observation_is_not_replaced_with_publication_or_review_date(self):
        self.fixture()
        with self.store.connect() as db:
            data = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (self.use_id,)).fetchone()[0])
            data['attributes']['observed_day'] = '2020-01-01'
            db.execute('UPDATE assertions SET data=? WHERE id=?', (json.dumps(data), self.use_id))
        edge = next(p for p in self.score()['paths'] if p['selected'] and p['dimension'] == 'technical')['edges'][0]
        self.assertEqual(edge['date'], '2020-01-01')
        self.assertEqual(edge['date_basis'], 'observation')
        self.assertGreater(edge['age_days'], 2000)

    def test_future_review_cannot_confirm_a_historical_chain_in_an_earlier_slice(self):
        _, ids = self.fixture()
        with patch('app.storage.utcnow', return_value='2026-10-25T12:00:00+00:00'):
            self.store.review_assertion(ids[2], 'confirmed', 'Analyst', 'Later review')
        self.assertIsNone(self.score()['historical_technical']['score'])

    def test_new_signal_publication_cannot_refresh_a_linked_old_incident(self):
        pub = Publication('test', 'https://example.org/signal', 'Fictional historical signal',
                          'Example Alpha: продаётся доступ к системам компании.',
                          published_at=NOW, collected_at=NOW, metadata={'incident_id': 'incident'})
        ingest(self.store, [pub])
        signal = self.store.signals()[0]
        self.store.review(signal['id'], 'confirmed', 'confirmed', 'high', 'Analyst', 'Fictional signal')
        edge = next(p for p in self.score()['paths'] if p['selected'])['edges'][0]
        self.assertEqual(edge['date'], '2017-07-30')
        self.assertEqual(edge['date_basis'], 'event_end')

    def test_attacker_claim_and_legal_allegation_do_not_establish_the_historical_fact(self):
        _, ids = self.fixture()
        for basis in ('attacker_claim', 'legal_allegation'):
            with self.subTest(basis=basis):
                self.store.review_assertion(ids[2], 'confirmed', 'Analyst', 'Source statement checked', basis=basis)
                self.assertIsNone(self.score()['historical_technical']['score'])
                self.assertTrue(any('historical_fact_not_established' in p['excluded_reasons']
                                    for p in self.score()['paths']))

    def test_future_event_end_does_not_leak_into_the_reference_date(self):
        self.fixture()
        self.store.load_entities([{'id': 'incident', 'name': 'Example Incident', 'entity_type': 'Incident',
                                   'start_day': '2017-05-13', 'end_day': '2027-07-30'}])
        edge = next(p for p in self.score()['paths'] if p['selected'] and p['dimension'] == 'interest')['edges'][0]
        self.assertEqual(edge['date'], '2017-05-13')
        self.assertEqual(edge['date_basis'], 'event_start')
