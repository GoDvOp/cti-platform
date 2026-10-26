"""Import a user-run public probe, preserving collection timestamps and provenance."""
import hashlib
import json
from pathlib import Path
from .collectors import ingest, parse_source
from .models import Publication, utcnow, date_iso


def import_probe(store, folder, sources):
    folder=Path(folder)
    raw_receipt=(folder/'results.json').read_bytes()
    receipt=json.loads(raw_receipt)
    if receipt.get('mode')!='isolated_public_source_probe':
        raise ValueError('Ожидался результат изолированной проверки публичных источников')
    capture_id=hashlib.sha256(raw_receipt).hexdigest()
    captured={}
    for row in json.loads((folder/'parsed.json').read_text()):
        p=Publication(**json.loads(row['data']))
        if p.id!=row['id'] or p.content_hash!=row['content_hash']:
            raise ValueError('Хеш или ID сохранённой публикации не совпадает')
        captured[p.source_id,p.url]=p
    configs={s['id']:s for s in sources}
    pubs=[];accepted=[];capture_hashes={}
    for result in receipt['results']:
        sid=result['source_id'];source=configs.get(sid)
        if not source or not source.get('enabled',True) or result['status'] not in ('ok','partial'):
            continue
        stamp=result.get('freshness',{}).get('as_of')
        if not stamp or not date_iso(stamp):
            raise ValueError('Не найдено исходное время успешного сбора: '+sid)
        path=folder/'html'/(sid+'.html')
        payload=path.read_bytes()
        capture_hashes[sid]=hashlib.sha256(payload).hexdigest()
        parsed,errors=parse_source(payload,source)
        if errors:raise ValueError('Повторный разбор дал предупреждения: '+sid)
        expected={url for source_id,url in captured if source_id==sid}
        if {p.url for p in parsed}!=expected:
            raise ValueError('Набор URL после исправления парсера изменился: '+sid)
        for p in parsed:
            original=captured[sid,p.url]
            if original.metadata.get('content_scope')=='public_article_text' and source['kind']=='publisher_news':
                # Detail responses were fetched by the user with robots/host checks.
                p=original
            p.collected_at=original.collected_at
            p.metadata['capture_receipt_sha256']=capture_id
            p.metadata['capture_provenance']='user_run_public_probe_reparsed_offline'
            pubs.append(p)
        accepted.append(result)
    if not accepted:raise ValueError('Нет успешно собранных включённых источников для импорта')
    counts=ingest(store,pubs)
    previous={row['source_id']:json.loads(row['details']) for row in store.source_status()}
    for result in accepted:
        sid=result['source_id']
        if previous.get(sid,{}).get('capture_receipt_sha256')==capture_id:continue
        details={k:v for k,v in result.items() if k not in ('source_id','status')}
        details.update(capture_receipt_sha256=capture_id,capture_provenance='user_run_public_probe_reparsed_offline',
                       html_sha256=capture_hashes[sid],imported_at=utcnow(),timestamp_basis='receipt_freshness_as_of')
        stamp=result.get('freshness',{}).get('as_of')
        store.source_run(sid,result['status'],details,attempted_at=stamp)
    return {'counts':counts,'publications_imported':len(pubs),'sources':[r['source_id'] for r in accepted],
            'capture_receipt_sha256':capture_id,'html_sha256':capture_hashes,'imported_at':utcnow(),
            'note':'Импортированы реальные ответы пользовательского сбора; нового сетевого запроса при импорте не выполнялось.'}
