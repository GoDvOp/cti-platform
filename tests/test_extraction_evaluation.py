from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from app.extraction_evaluation import prepare, assess, validate_labels, checksum, export_blind, metrics, blind_payload
from app.config import ROOT
from app.collectors import ingest
from app.models import Publication
from app.storage import CTIStore

NOW = '2026-10-24T12:00:00+00:00'


class ExtractionEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = CTIStore(self.root / 'db.sqlite3')
        self.store.load_companies([{'id': 'alpha', 'name': 'Компания Альфа', 'aliases': []}])
        self.store.load_products([{'id': 'product-a', 'name': 'Продукт А', 'aliases': []}])
        self.texts = {'use': 'Компания Альфа использует Продукт А.',
                      'deny': 'Компания Альфа не использует Продукт А.',
                      'cve': 'Уязвимость CVE-2026-12345 затрагивает Продукт А.'}
        self.pubs = {}
        for key, text in self.texts.items():
            pub = Publication('test', 'https://example.org/' + key, 'Fictional fixture', text,
                              collected_at=NOW, published_at=NOW)
            self.pubs[key] = pub
            ingest(self.store, [pub])
        with patch('app.extraction_evaluation.QUOTAS', {'test': 3}):
            self.corpus, self.predictions = prepare(self.store, NOW, {'records': []}, count=3)
        self.labels = {'format': 'cti-extraction-labels-v1', 'corpus_id': self.corpus['corpus_id'],
                       'reviewer': {'name': 'Fictional reviewer', 'role': 'project_author',
                                    'predictions_seen': False, 'ai_assisted': False}, 'records': []}
        for row in self.corpus['records']:
            key = row['publication']['url'].rsplit('/', 1)[1]
            relation = {'kind': 'uses_product', 'subject': 'alpha', 'object': 'product-a', 'excerpt': self.texts[key]}
            if key == 'cve':relation.update(kind='affects_product', subject='CVE-2026-12345')
            self.labels['records'].append({'sample_id': row['sample_id'], 'content_hash': row['content_hash'],
                'status': 'reviewed', 'products': ['product-a'],
                'vulnerabilities': ['CVE-2026-12345'] if key == 'cve' else [],
                'relations': [] if key == 'deny' else [relation], 'note': ''})

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_human_labels_never_produces_quality_numbers(self):
        result = assess(self.corpus, self.predictions)
        self.assertEqual(result['status'], 'awaiting_human_labels')
        self.assertIsNone(result['metrics'])
        self.assertEqual(result['reviewed'], 0)

    def test_exact_human_gold_scores_relations_and_mentions_separately(self):
        result = assess(self.corpus, self.predictions, self.labels)
        self.assertEqual(result['metrics']['relations']['tp'], 2)
        self.assertEqual(result['metrics']['relations']['f1'], 1)
        self.assertEqual(result['metrics']['products']['tp'], 3)
        self.assertEqual(result['metrics']['vulnerabilities']['tp'], 1)
        self.assertEqual(result['independence'], 'blind_project_author_review_not_external')
        self.assertFalse(result['prediction_quality_measured'])
        self.assertIsNone(result['per_relation_kind']['partners_with']['recall'])

    def test_false_positive_on_negative_document_is_counted(self):
        predictions = deepcopy(self.predictions)
        negative = next(r['sample_id'] for r in self.corpus['records'] if r['publication']['url'].endswith('/deny'))
        row = next(r for r in predictions['records'] if r['sample_id'] == negative)
        row['relations'].append({'kind': 'uses_product', 'subject': 'alpha', 'object': 'product-a'})
        predictions['run_id'] = checksum({k: v for k, v in predictions.items() if k != 'run_id'})
        result = assess(self.corpus, predictions, self.labels)
        self.assertEqual(result['metrics']['relations']['fp'], 1)
        self.assertAlmostEqual(result['metrics']['relations']['precision'], 2 / 3)

    def test_reversed_arrows_are_false_positive_and_false_negative(self):
        result = metrics({(1, ('partners_with', 'a', 'b'))}, {(1, ('partners_with', 'b', 'a'))})
        self.assertEqual((result['tp'], result['fp'], result['fn']), (0, 1, 1))

    def test_missing_or_pending_documents_are_not_empty_gold(self):
        for kind in ('missing', 'pending', 'duplicate'):
            labels = deepcopy(self.labels)
            if kind == 'missing':labels['records'].pop()
            if kind == 'pending':labels['records'][0]['status'] = 'pending'
            if kind == 'duplicate':labels['records'].append(labels['records'][0])
            with self.assertRaises(ValueError):assess(self.corpus, self.predictions, labels)

    def test_assisted_or_unblinded_annotations_cannot_claim_blind_human_review(self):
        for field in ('predictions_seen', 'ai_assisted'):
            labels = deepcopy(self.labels);labels['reviewer'][field] = True
            with self.assertRaises(ValueError):assess(self.corpus, self.predictions, labels)

    def test_changed_text_or_predictions_are_rejected(self):
        corpus = deepcopy(self.corpus);corpus['records'][0]['publication']['text'] += ' Changed.'
        with self.assertRaises(ValueError):assess(corpus, self.predictions, self.labels)
        predictions = deepcopy(self.predictions);predictions['records'][0]['products'] = []
        with self.assertRaises(ValueError):assess(self.corpus, predictions, self.labels)

    def test_gold_requires_existing_catalog_endpoints_and_verbatim_evidence(self):
        for field, value in (('object', 'missing'), ('excerpt', 'Not found in the source')):
            labels = deepcopy(self.labels)
            row = next(r for r in labels['records'] if r['relations'])
            row['relations'][0][field] = value
            with self.assertRaises(ValueError):validate_labels(self.corpus, labels)

    def test_all_exclusions_cannot_report_quality(self):
        labels = deepcopy(self.labels)
        for row in labels['records']:row.update(status='excluded', note='Fictional ambiguity')
        with self.assertRaises(ValueError):assess(self.corpus, self.predictions, labels)

    def test_blind_page_contains_no_algorithm_answers_or_structured_metadata(self):
        export_blind(self.corpus, self.root)
        page = (self.root / 'blind_review.html').read_text()
        public = json.loads(page.split('<script id="review-data" type="application/json">')[1].split('</script>')[0])
        self.assertNotIn('relations', public['records'][0])
        self.assertNotIn('products', public['records'][0])
        self.assertNotIn('metadata', public['records'][0])
        self.assertNotIn('extractor_sha256', public)
        self.assertEqual(len(public['records']), 3)

    def test_sampling_excludes_previous_records_before_prediction(self):
        p = self.pubs['use']
        prior = {'records': [{'publication_id': p.id, 'content_hash': p.content_hash, 'publication': p.asdict()}]}
        with patch('app.extraction_evaluation.QUOTAS', {'test': 2}):
            corpus, _ = prepare(self.store, NOW, prior, count=2)
        self.assertNotIn(p.id, {r['publication_id'] for r in corpus['records']})

    @unittest.skipUnless(shutil.which('node'), 'Optional JavaScript runtime check requires Node')
    def test_blind_form_renders_and_never_marks_unreviewed_texts_as_negative(self):
        harness = r'''
const assert=require('assert'), callbacks={};let downloads=0;
function el(id){const e={value:'',textContent:'',checked:false,disabled:false,hidden:false,style:{},children:[],
 append(...x){this.children.push(...x)},replaceChildren(){this.children=[]},setAttribute(){},removeAttribute(){},remove(){},click(){downloads++},
 addEventListener(type,cb){callbacks[id+':'+type]=cb}};Object.defineProperty(e,'options',{get(){return this.children}});return e;}
const elements={};global.document={getElementById(id){return elements[id]||(elements[id]=el(id))},createElement:el,createTextNode(text){return {textContent:text}},body:el('body')};
document.getElementById('review-data').textContent=__PAYLOAD__;
global.localStorage={getItem(){return null},setItem(){}};global.setTimeout=()=>{};
URL.createObjectURL=()=> 'blob:fixture';URL.revokeObjectURL=()=>{};
'''.replace('__PAYLOAD__', json.dumps(json.dumps(blind_payload(self.corpus), ensure_ascii=False)))
        checks = r'''
assert(labels.records.every(r=>r.status==='pending' && r.relations.length===0));
assert(document.getElementById('progress').textContent.includes('1 / 3'));
callbacks['next:click']();assert.strictEqual(index,1);assert(labels.records.every(r=>r.status==='pending'));
callbacks['previous:click']();assert.strictEqual(index,0);
callbacks['download:click']();assert.strictEqual(downloads,0);
document.getElementById('reviewer').value='Fictional reviewer';document.getElementById('role').value='project_author';document.getElementById('attest').checked=true;
callbacks['download:click']();assert.strictEqual(downloads,1);
assert(document.getElementById('message').textContent.includes('промежуточный'));
assert(labels.records.every(r=>r.status==='pending'));
callbacks['add:click']();assert.strictEqual(labels.records[0].relations[0].subject,'');
'''
        path = self.root / 'runtime.cjs'
        path.write_text(harness + '\n' + (ROOT / 'app/assets/extraction_review.js').read_text() + '\n' + checks)
        done = subprocess.run(['node', str(path)], text=True, capture_output=True, timeout=15)
        self.assertEqual(done.returncode, 0, done.stderr)
