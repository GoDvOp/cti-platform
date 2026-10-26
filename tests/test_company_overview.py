import json
from pathlib import Path
import tempfile
import unittest

from app.company_overview import overview_rows, statements
from app.config import ROOT
from app.models import Publication
from app.collectors import ingest
from app.storage import CTIStore
from app.threats import seed_threats


class CompanyOverviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CTIStore(Path(self.tmp.name) / 'test.sqlite3')
        seed_threats(self.store, ROOT, 'company_attack_library.json')

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self, relation):
        return [r for r in overview_rows(self.store) if r['relation'] == relation]

    def test_actor_points_to_company_with_incident_and_legal_qualification(self):
        rows = self.rows('ATTRIBUTED_ATTACK_ON')
        self.assertEqual(len(rows), 3)
        self.assertEqual({r['subject'] for r in rows}, {'real:fin7'})
        self.assertEqual({r['object'] for r in rows}, {'chipotle', 'chilis', 'arbys'})
        self.assertTrue(all(r['properties']['incident_id'] == 'fin7-retail-2018' for r in rows))
        self.assertTrue(all('legal_allegation' in r['properties']['bases'] for r in rows))
        self.assertTrue(all(len(r['properties']['assertion_ids']) == 2 for r in rows))

    def test_sector_points_to_companies_and_campaign_is_not_counted_three_times(self):
        rows = self.rows('INCLUDES_COMPANY')
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r['subject_label'] == 'Sector' and r['object_label'] == 'Company' for r in rows))
        sector = self.rows('OBSERVED_ATTACK_IN_SECTOR')
        self.assertEqual(len(sector), 1)
        self.assertEqual(sector[0]['properties']['incident_count'], 1)
        self.assertEqual(sector[0]['properties']['company_count'], 3)
        self.assertIn('не частота', sector[0]['properties']['interpretation'])

    def test_refuted_attribution_removes_shortcuts_and_sector_aggregation(self):
        claim = next(a for a in self.store.assertions() if a['kind'] == 'attributed_to')
        self.store.review_assertion(claim['id'], 'refuted', 'Analyst', 'Attribution withdrawn')
        self.assertEqual(self.rows('ATTRIBUTED_ATTACK_ON'), [])
        self.assertEqual(self.rows('OBSERVED_ATTACK_IN_SECTOR'), [])

    def test_refuted_victim_removes_only_its_shortcut(self):
        claim = next(a for a in self.store.assertions() if a['kind'] == 'incident_affects' and a['object'] == 'chipotle')
        self.store.review_assertion(claim['id'], 'refuted', 'Analyst', 'Victim link withdrawn')
        self.assertEqual({r['object'] for r in self.rows('ATTRIBUTED_ATTACK_ON')}, {'chilis', 'arbys'})

    def test_changed_evidence_removes_attack_shortcuts(self):
        data = json.loads(self.store.assertions()[0]['publication']['data'])
        data['text'] += ' Changed evidence.'
        ingest(self.store, [Publication(**data)])
        self.assertEqual(self.rows('ATTRIBUTED_ATTACK_ON'), [])

    def test_actor_exploitation_requires_direct_evidence_not_incident_join(self):
        seed_threats(self.store, ROOT)
        rows = self.rows('REPORTED_EXPLOITS')
        self.assertEqual({(r['subject'], r['object']) for r in rows}, {('real:clop', 'real:CVE-2023-34362')})
        # UNC2582 is attributed only to the extortion phase. It must not acquire
        # exploitation links from the CVEs of the same Accellion campaign.
        self.assertFalse(any(r['subject'] == 'real:unc2582' for r in rows))
        self.assertFalse(any(r['subject_label'] == 'Company' and r['object_label'] == 'Vulnerability'
                             for r in overview_rows(self.store)))

    def test_claimed_responsibility_is_not_attribution_or_sector_targeting(self):
        from app.knowledge import claim_id
        old = next(a for a in self.store.assertions() if a['kind'] == 'attributed_to')
        with self.store.connect() as db:
            data = json.loads(db.execute('SELECT data FROM assertions WHERE id=?', (old['id'],)).fetchone()[0])
            data['kind'] = 'claimed_by'
            data['attributes']['basis'] = 'attacker_claim'
            data['id'] = claim_id(data['publication_id'], data['kind'], data['subject'], data['object'])
            db.execute('DELETE FROM assertion_reviews WHERE assertion_id=?', (old['id'],))
            db.execute('DELETE FROM assertions WHERE id=?', (old['id'],))
            db.execute('INSERT INTO assertions VALUES(?,?,?)', (data['id'], data['publication_id'], json.dumps(data)))
        self.assertEqual(self.rows('ATTRIBUTED_ATTACK_ON'), [])
        self.assertEqual(len(self.rows('CLAIMED_ATTACK_ON')), 3)
        self.assertEqual(self.rows('OBSERVED_ATTACK_IN_SECTOR'), [])

    def test_view_synchronization_cleans_only_owned_shortcuts(self):
        queries = statements(self.store)
        self.assertIn('company-overview-v1', queries[0]['statement'])
        self.assertTrue(any('REMOVE n:CompanyGraph' in q['statement'] for q in queries))
        self.assertNotIn('DETACH DELETE', ' '.join(q['statement'] for q in queries))
        self.assertEqual(statements(self.store, True), [])
        self.assertFalse(any('TARGETS_SECTOR' in q['statement'] for q in queries))
