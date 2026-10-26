"""Transfer the checked public-source probe to the working DB without fetching again."""
import argparse
from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.storage import CTIStore
from app.probe_import import import_probe


def main():
    p=argparse.ArgumentParser(description='Импорт сохранённого публичного сбора с происхождением и временем')
    p.add_argument('--db',type=Path,default=ROOT/'data/cti.sqlite3')
    p.add_argument('--folder',type=Path,default=ROOT/'data/diagnostics/new_sources')
    args=p.parse_args()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup=ROOT/'data/backups'/('before-probe-import-'+stamp);backup.mkdir(parents=True)
    with closing(sqlite3.connect(args.db)) as source,closing(sqlite3.connect(backup/'cti.sqlite3')) as destination:
        source.backup(destination)
    store=CTIStore(args.db)
    result=import_probe(store,args.folder,json.loads((ROOT/'config/sources.json').read_text()))
    (args.folder/'import_result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
