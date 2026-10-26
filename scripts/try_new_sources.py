"""Probe new public sources in isolation and save bounded HTML for parser diagnostics."""
from pathlib import Path
from contextlib import closing
import json
import sqlite3
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.collectors import collect_source
from app.storage import CTIStore
from app.models import utcnow

IDS={'standoff_programs','bizone_bounty_zvuk','bizone_news','pt_standoff_news','trueconf_php_notice'}
def main():
    output=ROOT/'data/diagnostics/new_sources';output.mkdir(parents=True,exist_ok=True)
    configs=[s for s in json.loads((ROOT/'config/sources.json').read_text()) if s['id'] in IDS and s.get('enabled',True)]
    result={'checked_at':utcnow(),'mode':'isolated_public_source_probe','results':[]}
    with tempfile.TemporaryDirectory(prefix='probe-',dir=output) as tmp:
        store=CTIStore(Path(tmp)/'probe.sqlite3')
        store.load_companies(json.loads((ROOT/'config/companies.json').read_text()))
        store.load_products(json.loads((ROOT/'config/products.json').read_text()))
        runtime={}
        for s in configs:
            print('Проверка '+s['id']+'...',flush=True)
            row=collect_source(store,dict(s,_capture_public_response=str(output/'html')),runtime)
            result['results'].append(row)
            (output/'results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
            print(json.dumps(row,ensure_ascii=False),flush=True)
        # Preserve provenance and parsed records for inspection, never fake a working collection.
        (output/'parsed.json').write_text(json.dumps(store.publications(),ensure_ascii=False,indent=2)+'\n')
    print('Результаты: '+str(output/'results.json'))
    return 0 if all(r['status'] in ('ok','partial') for r in result['results']) else 2
if __name__=='__main__':raise SystemExit(main())
