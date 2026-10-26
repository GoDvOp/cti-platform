from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.collectors import ingest
from app.graph_audit import prepare, audit, fingerprint, read_live
from app.models import Publication
from app.storage import CTIStore


def projected_fixture(expected):
    """A controlled valid server response; tests inject projection faults into it."""
    nodes = {}
    for label, rows in expected['nodes'].items():
        for uid, props in rows.items():
            n = nodes.setdefault(uid, {'id': uid, 'labels': [], 'properties': {}})
            n['labels'].append(label); n['properties'].update(deepcopy(props))
    edges = []
    by_key = {}
    for key, props in expected['semantic'].items():
        edge = {'subject': key[0], 'relation': key[1], 'object': key[2], 'properties': deepcopy(props)}
        by_key[key] = edge; edges.append(edge)
    for key, props in expected.get('context', {}).items():
        edge = {'subject': key[0], 'relation': key[1], 'object': key[2], 'properties': deepcopy(props)}
        by_key[key] = edge; edges.append(edge)
    for key in expected['endpoints']:
        edges.append({'subject': key[0], 'relation': key[1], 'object': key[2], 'properties': {}})
    for key, view in expected['views'].items():
        edge = by_key.get(key)
        if edge is None:
            props = {} if view['existing'] else {'id': key[3], 'cti_managed': 'company-overview-v1'}
            edge = {'subject': key[0], 'relation': key[1], 'object': key[2], 'properties': props}
            edges.append(edge)
        edge['properties'].update(deepcopy(view['expected_properties']))
        for uid in (key[0], key[2]):
            if 'CompanyGraph' not in nodes[uid]['labels']:nodes[uid]['labels'].append('CompanyGraph')
    for uid, props in expected['company_scores'].items():nodes[uid]['properties'].update(deepcopy(props))
    for edge in edges:
        edge.update(subject_labels=list(nodes[edge['subject']]['labels']), object_labels=list(nodes[edge['object']]['labels']),
                    subject_demo=False, object_demo=False)
    return {'nodes': list(nodes.values()), 'relationships': edges}


class GraphAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CTIStore(Path(self.tmp.name) / 'working.sqlite3')
        self.store.load_companies([{'id': 'alpha', 'name': 'Example Alpha', 'aliases': [], 'sector': 'Example sector'}])
        self.store.load_products([{'id': 'sample', 'name': 'Example Product', 'aliases': []}])
        pub = Publication('test', 'https://example.org/test', 'Fictional fixture', 'Example Alpha использует Example Product.',
                          published_at='2026-10-23T12:00:00+00:00', collected_at='2026-10-23T13:00:00+00:00')
        ingest(self.store, [pub])
        claim_id = self.store.add_assertion({'publication_id': pub.id, 'kind': 'uses_product',
            'subject': 'alpha', 'object': 'sample', 'excerpt': pub.text, 'attributes': {'observed_day': '2026-10-23'}})
        self.store.review_assertion(claim_id, 'confirmed', 'Test analyst', 'Fictional fixture', confidence='medium', basis='research_report')
        self.expected = prepare(self.store, '2099-01-01T00:00:00+00:00')
        self.live = projected_fixture(self.expected)

    def tearDown(self):self.tmp.cleanup()

    def failures(self):
        result = audit(self.expected, self.live)
        return {c['name'] for c in result['checks'] if c['status'] == 'failed'}

    def test_valid_projection_passes_with_unknown_indices_absent(self):
        # Neo4j removes properties when SET receives null; absence must preserve unknown.
        for node in self.live['nodes']:
            node['properties'] = {k: v for k, v in node['properties'].items() if v is not None}
        self.assertEqual(self.failures(), set())

    def test_missing_evidence_node_fails_even_when_label_totals_look_plausible(self):
        publication = next(n for n in self.live['nodes'] if 'Publication' in n['labels'])
        publication['id'] = 'unrelated-publication'
        self.assertIn('expected_nodes_and_evidence', self.failures())

    def test_wrong_product_arrow_or_weight_is_detected(self):
        edge = next(e for e in self.live['relationships'] if e['properties'].get('claim_id'))
        edge['subject'], edge['object'] = edge['object'], edge['subject']
        self.assertIn('semantic_directions_provenance_and_weights', self.failures())
        edge['subject'], edge['object'] = edge['object'], edge['subject']
        edge['properties']['weight'] = 1.5
        self.assertIn('semantic_directions_provenance_and_weights', self.failures())

    def test_zero_cannot_replace_unknown_company_index(self):
        company = next(n for n in self.live['nodes'] if n['id'] == 'alpha')
        self.assertIsNone(company['properties']['technical_exposure_index'])
        company['properties']['technical_exposure_index'] = 0
        self.assertIn('company_indices_match_sqlite', self.failures())

    def test_duplicate_managed_edges_fail(self):
        edge = next(e for e in self.live['relationships'] if e['properties'].get('claim_id'))
        self.live['relationships'].append(deepcopy(edge))
        self.assertIn('no_duplicate_managed_evidence_edges', self.failures())

    def test_old_company_view_labels_and_demo_crossing_fail(self):
        node = next(n for n in self.live['nodes'] if 'Publication' in n['labels'])
        node['labels'].append('CompanyGraph')
        self.assertIn('company_view_labels', self.failures())
        self.live['relationships'][0]['object_demo'] = True
        self.assertIn('real_demo_separation', self.failures())

    def test_overview_qualification_and_source_endpoints_are_checked(self):
        edge = next(e for e in self.live['relationships'] if e['relation'] == 'INCLUDES_COMPANY')
        edge['properties']['status'] = 'invented'
        self.assertIn('company_view_exact_paths_and_qualifications', self.failures())
        edge = next(e for e in self.live['relationships'] if e['relation'] == 'SUBJECT')
        edge['object'] = 'wrong-endpoint'
        self.assertIn('assertion_source_and_endpoints', self.failures())

    def test_fingerprint_ignores_row_and_label_order_but_detects_changes(self):
        changed = deepcopy(self.live)
        changed['nodes'].reverse(); changed['relationships'].reverse()
        for node in changed['nodes']:node['labels'].reverse()
        for edge in changed['relationships']:edge['subject_labels'].reverse();edge['object_labels'].reverse()
        self.assertEqual(fingerprint(self.live), fingerprint(changed))
        changed['relationships'][0]['properties']['changed'] = True
        self.assertNotEqual(fingerprint(self.live), fingerprint(changed))

    def test_incomplete_server_response_is_not_a_successful_audit(self):
        with patch('app.graph_audit.connection', return_value=('url', 'auth')), \
                patch('app.graph_audit.execute_requests', return_value={'results': []}):
            with self.assertRaisesRegex(ValueError, 'неполный'):
                read_live()
