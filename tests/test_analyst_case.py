import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.analyst_case import analyze, export_case
from app.collectors import ingest
from app.models import Publication
from app.storage import CTIStore

NOW = '2026-10-24T12:00:00+00:00'


class AnalystCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = patch('app.storage.utcnow', return_value=NOW);self.clock.start()
        self.store = CTIStore(self.root / 'db.sqlite3')
        self.store.load_companies([{'id': 'roszarubezhneft', 'name': 'Example Company', 'aliases': []}])
        self.store.load_products([{'id': 'trueconf-server', 'name': 'Example Product', 'aliases': []}])
        self.use = self.pub('Fictional deployment', 'Example Company использует Example Product в закрытом контуре.')
        self.claim = self.store.add_assertion({'kind': 'uses_product', 'subject': 'roszarubezhneft',
            'object': 'trueconf-server', 'publication_id': self.use.id, 'excerpt': self.use.text,
            'attributes': {'observed_day': '2026-10-01', 'network_exposure': 'closed_network',
                           'network_exposure_note': 'Fictional closed-network evidence.'}})
        self.store.review_assertion(self.claim, 'confirmed', 'Test analyst', 'Fictional fixture', confidence='medium', basis='research_report')
        self.pub('Fictional notice', 'Example Product has a security patch.', metadata={'security_notice':{
            'product_id': 'trueconf-server', 'affected_ranges': [{'lte': '2.0.0'}], 'fixed_versions': ['2.0.1']}})
        self.pub('Fictional update', 'Example Product fixes CVE-2026-12345.', metadata={'software_update':{
            'product_id': 'trueconf-server', 'reference_cves': ['CVE-2026-12345']}})
        self.pub('Зафиксированы попытки эксплуатации CVE-2026-12345', 'Fictional general telemetry; no named victim.')

    def tearDown(self):
        self.clock.stop();self.tmp.cleanup()

    def pub(self, title, text, **kwargs):
        p = Publication('test', 'https://example.org/' + str(len(self.store.publications())), title, text,
                        published_at=NOW, collected_at=NOW, **kwargs)
        ingest(self.store, [p])
        return p

    def test_closed_network_rejects_external_target_despite_shared_cve(self):
        result = analyze(self.store, NOW)
        self.assertEqual(result['decision'], 'internal_patch_review')
        self.assertFalse(result['named_external_target_supported'])
        self.assertIsNone(result['decision_gates']['affected_installed_version'])
        self.assertFalse(result['attack_established_by_this_chain'])
        self.assertEqual(len(result['queue_entry']['related_exploitation_reports']), 1)

    def test_case_export_has_source_hashes_and_no_invented_attack_arrow(self):
        result = analyze(self.store, NOW)
        out = self.root / 'case'
        export_case(result, self.store, out)
        graph = json.loads((out / 'graph_view.json').read_text())
        self.assertFalse(any(e['type'] == 'ATTRIBUTED_ATTACK_ON' for e in graph['edges']))
        self.assertTrue(any(e['type'] == 'MENTIONS_CVE' for e in graph['edges']))
        self.assertTrue(all(e['content_hash'] and e['url'] for e in result['evidence']))
        decision = json.loads((out / 'decision.json').read_text())
        self.assertEqual(decision['as_of'], NOW)
        self.assertEqual(decision['horizon_end'], '2026-11-23')

    def test_refuted_use_removes_case_basis(self):
        self.store.review_assertion(self.claim, 'refuted', 'Test analyst', 'Fictional retraction')
        with self.assertRaises(ValueError):analyze(self.store, NOW)

    def test_changed_evidence_invalidates_case_instead_of_silently_reusing_review(self):
        self.use.text += ' Changed source.'
        ingest(self.store, [self.use])
        with self.assertRaises(ValueError):analyze(self.store, NOW)
