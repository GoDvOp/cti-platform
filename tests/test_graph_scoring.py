import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors import ingest
from app.graph_scoring import calculate_graph, load_weights, projection_statements
from app.models import Publication
from app.reporting import export_report
from app.storage import CTIStore

NOW = '2026-10-24T12:00:00+00:00'


class GraphScoringTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'test.sqlite3')
        self.clock = patch('app.storage.utcnow', return_value=NOW)
        self.clock.start()
        self.score_clock = patch('app.graph_scoring.utcnow', return_value=NOW)
        self.score_clock.start()
        self.store.load_companies([
            {'id': 'alpha', 'name': 'Example Alpha', 'sector': 'test sector', 'aliases': []},
            {'id': 'beta', 'name': 'Example Beta', 'sector': 'test sector', 'aliases': []},
            {'id': 'gamma', 'name': 'Example Gamma', 'sector': 'test sector', 'aliases': []},
        ])
        self.store.load_products([{'id': 'product', 'name': 'Example Product', 'aliases': []}])
        self.store.load_entities([{'id': 'incident', 'name': 'Example Incident', 'entity_type': 'Incident'},
                                 {'id': 'actor', 'name': 'Example Actor', 'entity_type': 'ThreatActor'}])
        self.serial = 0

    def tearDown(self):
        self.clock.stop()
        self.score_clock.stop()
        self.tmp.cleanup()

    def pub(self, text, **kwargs):
        self.serial += 1
        pub = Publication(source_id=kwargs.pop('source_id', 'test'),
                          url=kwargs.pop('url', f'https://source.example/{self.serial}'),
                          title='Fictional evidence', text=text,
                          collected_at=NOW, published_at=kwargs.pop('published_at', NOW), **kwargs)
        ingest(self.store, [pub])
        return pub

    def claim(self, pub, kind, subject, obj, **attrs):
        data = {'kind': kind, 'subject': subject, 'object': obj, 'publication_id': pub.id,
                'excerpt': pub.text, 'attributes': {'confidence': 'high', 'basis': 'victim_report', **attrs}}
        identifier = self.store.add_assertion(data)
        self.store.review_assertion(identifier, 'confirmed', 'Test Analyst', 'Fictional fixture verified')
        return identifier

    def score(self, cid='alpha', **kwargs):
        result = calculate_graph(self.store, as_of=NOW, **kwargs)
        return next(r for r in result['companies'] if r['company_id'] == cid)

    def tech(self, version='1.2.3', advisory_date=NOW, confidence='high'):
        suffix = f' версии {version}' if version else ''
        use = self.pub('Example Alpha использует Example Product' + suffix + '.')
        attrs = {'version': version} if version else {}
        uid = self.claim(use, 'uses_product', 'alpha', 'product', confidence=confidence, **attrs)
        adv = self.pub('Уязвимость CVE-2026-99991 затрагивает Example Product версии 1.2.3.',
                       published_at=advisory_date)
        aid = self.claim(adv, 'affects_product', 'CVE-2026-99991', 'product',
                         affected_versions=['1.2.3'], basis='vendor_advisory')
        return uid, aid, use, adv

    def test_empty_graph_is_unknown_not_zero(self):
        row = self.score()
        self.assertIsNone(row['interest']['score'])
        self.assertIsNone(row['technical']['score'])
        self.assertEqual(row['interest']['component_coverage'], 0)

    def test_reviewed_signal_quality_and_decay_have_explicit_formula(self):
        pub = self.pub('Example Alpha: продаётся доступ к системам компании.')
        sig = self.store.signals()[0]
        self.store.review(sig['id'], 'confirmed', 'unresolved', 'medium', 'Analyst', 'Fixture')
        row = self.score()
        self.assertAlmostEqual(row['interest']['score'], 60 * .7 * .4)
        path = next(p for p in row['paths'] if p['selected'])
        self.assertEqual(path['edges'][0]['evidence_hash'], pub.content_hash)
        self.assertEqual(path['edges'][0]['age_days'], 0)
        self.assertEqual(row['technical']['score'], None)

    def test_unreviewed_and_refuted_signals_do_not_raise_interest(self):
        self.pub('Example Alpha: продаётся доступ к системам компании.')
        self.assertIsNone(self.score()['interest']['score'])
        sig = self.store.signals()[0]
        self.store.review(sig['id'], 'confirmed', 'refuted', 'high', 'Analyst', 'Refuted')
        self.assertIsNone(self.score()['interest']['score'])

    def test_fresh_followup_of_old_incident_is_not_new_targeting_signal(self):
        self.pub('Example Alpha сообщила о восстановлении после кибератаки прошлого года.',
                 metadata={'incident_id': 'incident', 'signal_scope': 'business_followup'})
        for signal in self.store.signals():
            self.store.review(signal['id'], 'confirmed', 'confirmed', 'high', 'Analyst',
                              'Подтверждено сообщение компании о последствиях прошлого инцидента')
        row = self.score()
        self.assertIsNone(row['interest']['score'])
        self.assertTrue(any('historical_context_not_current_signal' in p['excluded_reasons']
                            for p in row['paths']))

    def test_reposts_do_not_increase_signal_score(self):
        text = 'Example Alpha: продаётся доступ к системам компании.'
        self.pub(text)
        sig = self.store.signals()[0]
        self.store.review(sig['id'], 'confirmed', 'confirmed', 'high', 'Analyst', 'Fixture')
        before = self.score()['interest']['score']
        self.pub(text, source_id='copy')
        for sig in self.store.signals():
            self.store.review(sig['id'], 'confirmed', 'confirmed', 'high', 'Analyst', 'Fixture')
        after = self.score()
        self.assertEqual(before, after['interest']['score'])
        self.assertEqual(len([p for p in after['paths'] if p['selected']]), 1)

    def test_signal_and_incident_from_same_event_are_counted_once(self):
        pub = self.pub('Кибератака: Example Incident затронул Example Alpha.')
        self.claim(pub, 'incident_affects', 'incident', 'alpha')
        sig = self.store.signals()[0]
        self.store.review(sig['id'], 'confirmed', 'confirmed', 'high', 'Analyst', 'Fixture')
        row = self.score()
        self.assertEqual(row['interest']['score'], 60)
        self.assertTrue(any('same_event_already_counted' in p['excluded_reasons'] for p in row['paths']))

    def test_sector_context_does_not_recount_a_company_own_campaign(self):
        pub = self.pub('Example Incident затронул Example Alpha и Example Beta.')
        self.claim(pub, 'incident_affects', 'incident', 'alpha')
        self.claim(pub, 'incident_affects', 'incident', 'beta')
        row = self.score()
        self.assertEqual(row['interest']['observed_components'], ['incident_history'])
        gamma = self.score('gamma')
        self.assertAlmostEqual(gamma['interest']['score'], 18)
        self.assertEqual(gamma['interest']['observed_components'], ['sector_activity'])

    def test_version_match_unknown_and_mismatch_are_different(self):
        uid, _, use, _ = self.tech()
        self.assertAlmostEqual(self.score()['technical']['score'], 54)
        with self.store.connect() as db:
            data = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (uid,)).fetchone()[0])
            data['attributes'].pop('version')
            db.execute('UPDATE assertions SET data=? WHERE id=?', (json.dumps(data), uid))
        self.assertAlmostEqual(self.score()['technical']['score'], 13.5)
        with self.store.connect() as db:
            data['attributes']['version'] = '9.9.9'
            db.execute('UPDATE assertions SET data=? WHERE id=?', (json.dumps(data), uid))
        row = self.score()
        self.assertIsNone(row['technical']['score'])
        self.assertIn('version_outside_reported_range', row['paths'][0]['excluded_reasons'])

    def test_static_advisory_keeps_unknown_date_without_losing_validity(self):
        self.tech(advisory_date=None)
        row = self.score()
        self.assertAlmostEqual(row['technical']['score'], 54)
        advisory = next(p for p in row['paths'] if p['selected'])['edges'][1]
        self.assertIsNone(advisory['date'])
        self.assertEqual(advisory['temporal_policy'], 'static_reference')
        self.assertEqual(advisory['decay'], 1)

    def test_old_static_cve_does_not_make_recent_product_use_stale(self):
        self.tech(advisory_date='2017-03-07T12:00:00Z')
        row = self.score()
        self.assertAlmostEqual(row['technical']['score'], 54)
        self.assertEqual(row['technical']['status'], 'evidence_present')

    def test_incident_exploitation_adds_context_without_inventing_actor(self):
        self.tech()
        pub = self.pub('Example Incident: эксплуатировалась CVE-2026-99991.')
        self.claim(pub, 'incident_exploited', 'incident', 'CVE-2026-99991')
        row = self.score()
        self.assertAlmostEqual(row['technical']['score'], 54)
        path = next(p for p in row['paths'] if p['selected'])
        self.assertNotIn('exploitation_context', path['context'])
        self.assertIsNone(row['historical_technical']['score'])
        self.assertNotIn('actor_id', path['context'])

    def test_lower_confidence_and_older_evidence_reduce_score(self):
        uid, _, _, _ = self.tech()
        fresh = self.score()['technical']['score']
        with self.store.connect() as db:
            data = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (uid,)).fetchone()[0])
            data['attributes'].update(confidence='low', observed_day='2026-04-27')
            db.execute('UPDATE assertions SET data=? WHERE id=?', (json.dumps(data), uid))
        row = self.score()
        self.assertLess(row['technical']['score'], fresh)
        edge = next(p for p in row['paths'] if p['selected'])['edges'][0]
        self.assertEqual(edge['age_days'], 180)
        self.assertAlmostEqual(edge['decay'], .5)

    def test_repeated_cves_and_advisories_do_not_increase_technical_score(self):
        _, _, _, adv = self.tech()
        before = self.score()['technical']['score']
        copy = self.pub(adv.text, source_id='copy')
        self.claim(copy, 'affects_product', 'CVE-2026-99991', 'product',
                   affected_versions=['1.2.3'], basis='vendor_advisory')
        self.assertEqual(self.score()['technical']['score'], before)

    def test_cisa_context_modifies_one_path_instead_of_adding_another_score(self):
        self.tech()
        self.pub('CVE-2026-99991: Example Product; known exploited.', external_id='CVE-2026-99991',
                 metadata={'collection_method': 'cisa_kev_json', 'catalog_added_day': '2026-10-24'})
        row = self.score()
        self.assertAlmostEqual(row['technical']['score'], 86.4)
        self.assertEqual(len([p for p in row['paths'] if p['selected']]), 1)
        self.assertFalse(row['interest']['score'])

    def test_refuted_or_changed_evidence_removes_technical_path(self):
        uid, _, use, _ = self.tech()
        self.store.review_assertion(uid, 'refuted', 'Analyst', 'Use refuted')
        self.assertIsNone(self.score()['technical']['score'])
        use.text += ' Changed evidence.'
        ingest(self.store, [use])
        self.assertIsNone(self.score()['technical']['score'])

    def test_future_review_cannot_leak_into_earlier_calculation(self):
        self.tech()
        row = calculate_graph(self.store, as_of='2026-10-23T12:00:00+00:00')['companies'][0]
        self.assertIsNone(row['technical']['score'])
        self.assertTrue(any('evidence_or_review_after_as_of' in p['excluded_reasons'] for p in row['paths']))

    def test_configuration_is_validated_and_changes_fingerprint(self):
        config, sha = load_weights()
        path = self.root / 'weights.json'
        config['unknown_version_multiplier'] = .1
        path.write_text(json.dumps(config))
        self.assertNotEqual(load_weights(path)[1], sha)
        config['interest_caps']['direct_signal'] = 1000
        path.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            load_weights(path)

    def test_outputs_are_bounded_reproducible_and_explicitly_not_probabilities(self):
        self.tech()
        a = calculate_graph(self.store, as_of=NOW)
        b = calculate_graph(self.store, as_of=NOW)
        self.assertEqual(a, b)
        self.assertFalse(a['is_probability'])
        for company in a['companies']:
            for d in ('interest', 'technical'):
                self.assertTrue(company[d]['score'] is None or 0 <= company[d]['score'] <= 100)

    def test_projection_and_report_carry_same_model_and_trace(self):
        self.tech()
        queries = projection_statements(self.store)
        nodes = queries[-1]['parameters']['rows']
        alpha = next(r for r in nodes if r['id'] == 'alpha')['properties']
        self.assertAlmostEqual(alpha['technical_exposure_index'], 54)
        self.assertFalse(alpha['graph_score_is_probability'])
        self.assertTrue(json.loads(alpha['graph_score_explanation_json'])['paths'])
        export_report(self.store, self.root / 'report')
        payload = json.loads((self.root / 'report/graph_scores.json').read_text())
        self.assertEqual(payload['weights_sha256'], alpha['graph_score_config_sha256'])
        page = (self.root / 'report/report.html').read_text()
        self.assertIn('Оценка по весам связей графа', page)
        self.assertIn('не являются процентами', page)
        self.assertIn('54.000', page)
        self.assertTrue((self.root / 'report/graph_scores.csv').exists())

    def test_incident_exploitation_weight_is_projected_as_technical(self):
        pub = self.pub('Example Incident использовал CVE-2026-99991.')
        cid = self.claim(pub, 'incident_exploited', 'incident', 'CVE-2026-99991')
        queries = projection_statements(self.store, as_of=NOW)
        edges = next(q['parameters']['rows'] for q in queries if 'WHERE r.claim_id=row.claim_id' in q['statement'])
        props = next(row['properties'] for row in edges if row['claim_id'] == 'real:' + cid)
        self.assertEqual(props['weight_dimension'], 'technical')
        self.assertEqual(props['weight_temporal_policy'], 'static_reference')
