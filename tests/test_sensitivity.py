from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors import ingest
from app.graph_scoring import load_weights
from app.models import Publication
from app.sensitivity import analyze, export, scenarios, _fingerprint
from app.storage import CTIStore

NOW = '2026-10-24T12:00:00+00:00'


class SensitivityTests(unittest.TestCase):
    def test_demo_rerun_keeps_dates_and_counts_across_clock_change(self):
        from app.main import demo
        with tempfile.TemporaryDirectory() as tmp:
            store = CTIStore(Path(tmp) / 'demo.sqlite3')
            with patch('app.main.utcnow', return_value=NOW):
                self.assertEqual(demo(store)['inserted'], 12)
            original = {p['id']: json.loads(p['data'])['published_at'] for p in store.publications(True)}
            with patch('app.main.utcnow', return_value='2026-10-25T12:00:00+00:00'):
                self.assertEqual(demo(store)['unchanged'], 12)
            self.assertEqual(original, {p['id']: json.loads(p['data'])['published_at'] for p in store.publications(True)})

    def test_scenarios_preserve_budgets_and_document_clipping(self):
        weights, _ = load_weights()
        original = deepcopy(weights)
        variants = scenarios(weights)
        self.assertEqual(weights, original)
        self.assertEqual(len(variants), 45)
        for s in variants:
            load_weights(s['weights'])
            self.assertAlmostEqual(sum(s['weights']['interest_caps'].values()), 100)
            self.assertAlmostEqual(s['weights']['technical_base_multiplier'] + s['weights']['exploitation_bonus_multiplier'], 1)
        high = next(s for s in variants if s['id'] == 'confidence.high:plus')
        self.assertEqual(high['clipped'], ['confidence.high'])
        self.assertEqual(high['weights']['confidence']['high'], 1)
        cap = next(s for s in variants if s['id'] == 'interest_caps.incident_history:plus')
        self.assertIn('interest_caps', cap['normalized'])
        self.assertAlmostEqual(cap['weights']['interest_caps']['incident_history'], 100 * 24 / 104)
        self.assertNotAlmostEqual(cap['changes']['interest_caps.incident_history']['effective_change_percent'], 20)

    def test_invalid_delta_rejected(self):
        weights, _ = load_weights()
        for delta in (0, -.1, .6, float('nan'), True):
            with self.assertRaises(ValueError):
                scenarios(weights, delta)

    def test_analysis_is_read_only_and_null_does_not_become_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CTIStore(Path(tmp) / 'test.sqlite3')
            store.load_companies([{'id': 'alpha', 'name': 'Example Alpha', 'aliases': []}])
            pub = Publication('test', 'https://source.example/1', 'Fictional',
                              'Example Alpha: продаётся доступ к системам компании.',
                              published_at='2026-07-26T12:00:00Z', collected_at=NOW)
            ingest(store, [pub])
            with patch('app.storage.utcnow', return_value=NOW):
                sig = store.signals()[0]
                store.review(sig['id'], 'confirmed', 'confirmed', 'high', 'Analyst', 'Fictional fixture')
            before = _fingerprint(store)
            config, config_hash = load_weights()
            result = analyze(store, ['alpha'], as_of=NOW)
            self.assertEqual(before, _fingerprint(store))
            self.assertEqual(load_weights()[1], config_hash)
            self.assertEqual(result, analyze(store, ['alpha'], as_of=NOW))
            self.assertFalse(result['is_probability'])
            d = result['companies'][0]
            self.assertEqual(d['interest']['baseline'], 30)
            self.assertIsNone(d['technical']['baseline'])
            self.assertEqual(d['technical']['one_at_a_time']['null_count'], 43)
            half = next(s for s in result['scenarios'] if s['id'] == 'half_life_days.interest:plus')
            self.assertGreater(half['companies'][0]['interest']['score'], 30)
            exported = export(result, Path(tmp) / 'output')
            self.assertEqual(exported['scenario_count'], 45)
            self.assertTrue((Path(tmp) / 'output/sensitivity.html').exists())
            self.assertIn('не доверительный интервал', (Path(tmp) / 'output/sensitivity.html').read_text())

    def test_unknown_company_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'Не найдены компании'):
                analyze(CTIStore(Path(tmp) / 'test.sqlite3'), ['missing'], as_of=NOW)
