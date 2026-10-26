import json
from pathlib import Path
import tempfile
import unittest

from app.monitoring_case import seed, analyze, export_case, BUNDLE
from app.review_snapshot import read_snapshot, restore_snapshot, content_hash, tables
from app.storage import CTIStore, dumps
from app.knowledge import version_match

AS_OF = json.loads(BUNDLE.read_text())['AS_OF']


class MonitoringCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'case.sqlite3')
        seed(self.store)

    def use(self):
        return next(r for r in self.store.assertions() if r['kind'] == 'uses_product' and r['subject'] == 'ispras')

    def change_use(self, **attributes):
        row = self.use()
        row['attributes'].update(attributes)
        # Simulate an explicitly recorded later analyst inventory, not a guessed version.
        with self.store.connect() as db:
            value = {k: v for k, v in row.items() if k != 'publication'}
            db.execute('UPDATE assertions SET data=? WHERE id=?', (dumps(value), row['id']))

    def test_recent_observed_service_and_notice_create_conditional_queue(self):
        result = analyze(self.store, AS_OF)
        self.assertEqual(result['decision'], 'conditional_monitoring_candidate')
        self.assertTrue(result['monitoring_priority_increased'])
        self.assertIsNone(result['queue_entry']['installed_version'])
        self.assertIsNone(result['decision_gates']['affected_installed_version'])
        self.assertIsNone(result['decision_gates']['vulnerable_handler_reachability'])
        self.assertFalse(result['attack_established_by_this_chain'])
        self.assertFalse(result['named_external_target_supported'])
        self.assertEqual(result['source_groups'], ['gitlab_vendor', 'ispras'])
        self.assertEqual(len(result['evidence']), 3)
        undated = [r for r in result['evidence'] if r['source_id'].startswith('manual_ispras')]
        self.assertTrue(all(r['published_at'] is None for r in undated))
        self.assertNotIn('publication_day', undated[0]['metadata'])

    def test_fixed_version_is_excluded_using_vendor_branch_ranges(self):
        for version in ('18.11.13', '19.0.10', '19.1.9', '19.2.9', '19.3.6', '19.4.3', '19.5.1'):
            self.change_use(version=version)
            result = analyze(self.store, AS_OF)
            self.assertEqual(result['decision'], 'version_outside_reported_range', version)
            self.assertFalse(result['monitoring_priority_increased'])
        notice = next(r for r in self.store.assertions() if r['kind'] == 'affects_product')
        self.assertTrue(version_match('19.3.5', notice['attributes']))
        self.assertFalse(version_match('19.3.6', notice['attributes']))
        self.assertTrue(version_match('19.4.2', notice['attributes']))
        self.assertFalse(version_match('19.4.3', notice['attributes']))

    def test_old_observation_does_not_stay_in_current_queue(self):
        self.change_use(observed_day='2026-01-01')
        result = analyze(self.store, AS_OF)
        self.assertEqual(result['decision'], 'insufficient_current_evidence')
        self.assertIn('use_evidence_older_than_180_days', result['queue_entry']['missing'])
        self.assertFalse(result['monitoring_priority_increased'])

    def test_repeated_seed_preserves_data_and_manual_company_changes(self):
        company = next(r for r in self.store.companies() if r['id'] == 'ispras')
        company['analyst_note'] = 'Do not overwrite this manual addition'
        self.store.load_companies([company])
        before = content_hash(tables(self.store))
        repeated = seed(self.store)
        self.assertEqual(repeated['counts'], {})
        self.assertEqual(repeated['added_assertions'], [])
        self.assertEqual(len(repeated['preserved_assertions']), 2)
        self.assertEqual(content_hash(tables(self.store)), before)

    def test_retracted_use_or_vendor_scope_is_never_reconfirmed_by_seed(self):
        for kind in ('uses_product', 'affects_product'):
            store = CTIStore(self.root / ('retraction-' + kind + '.sqlite3'))
            seed(store)
            claim = next(r for r in store.assertions() if r['kind'] == kind)
            store.review_assertion(claim['id'], 'refuted', 'Human analyst', 'Retraction fixture')
            seed(store)
            current = next(r for r in store.assertions() if r['id'] == claim['id'])
            self.assertEqual(current['status'], 'refuted')
            result = analyze(store, AS_OF)
            self.assertEqual(result['decision'], 'insufficient_verified_basis')
            self.assertFalse(result['monitoring_priority_increased'])

    def test_exported_supplement_is_small_isolated_and_replays_same_decision(self):
        self.store.load_companies([{'id': 'unrelated', 'name': 'Unrelated organization', 'aliases': []}])
        result = analyze(self.store, AS_OF)
        folder = self.root / 'export'
        export_case(result, self.store, folder)
        snapshot = read_snapshot(folder / 'snapshot.json.gz')
        self.assertEqual(len(snapshot['tables']['companies']), 1)
        self.assertEqual(len(snapshot['tables']['publications']), 3)
        self.assertEqual(snapshot['frozen_at'], AS_OF)
        target = self.root / 'replayed.sqlite3'
        restore_snapshot(folder / 'snapshot.json.gz', target)
        replay = analyze(CTIStore(target), AS_OF)
        self.assertEqual(replay['decision'], result['decision'])
        self.assertEqual(replay['scores'], result['scores'])
        graph = json.loads((folder / 'graph_view.json').read_text())
        self.assertTrue(any(r['type'] == 'MONITORING_HYPOTHESIS' for r in graph['edges']))
        self.assertFalse(any('ATTACK' in r['type'] or r['type'] == 'AFFECTED_ORGANIZATION' for r in graph['edges']))
        self.assertTrue((folder / 'case.html').exists())
        self.assertTrue((folder / 'case.md').exists())

    def test_seed_does_not_restore_superseded_source_or_changed_publication(self):
        claim = self.use()
        with self.store.connect() as db:
            raw = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (claim['id'],)).fetchone()[0])
            raw['superseded'] = True
            raw['status'] = 'needs_review'
            db.execute('UPDATE assertions SET data=? WHERE id=?', (dumps(raw), claim['id']))
        before = content_hash(tables(self.store))
        seed(self.store)
        self.assertEqual(content_hash(tables(self.store)), before)
        self.assertEqual(analyze(self.store, AS_OF)['decision'], 'insufficient_verified_basis')
