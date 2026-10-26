import json
from pathlib import Path
import tempfile
import unittest
from app.evaluation import evaluate
from app.config import ROOT


class EvaluationTests(unittest.TestCase):
    def test_pilot_reports_real_errors_and_absent_classes(self):
        result=evaluate(ROOT/'evaluation/pilot_real.json')
        self.assertEqual(result['count'],30)
        self.assertEqual(result['correct'],21)
        self.assertEqual(result['status'],'development_pilot_not_independent_holdout')
        missing=next(m for m in result['per_class'] if m['class']=='access_sale_claim')
        self.assertEqual(missing['support'],0)
        self.assertIsNone(missing['recall'])
        self.assertTrue(any(not r['correct'] for r in result['records']))

    def test_changed_evaluation_evidence_is_rejected(self):
        data=json.loads((ROOT/'evaluation/pilot_real.json').read_text())
        data['records'][0]['publication']['text']+=' Changed evidence.'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'corpus.json';path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'Изменился размеченный текст'):
                evaluate(path)
