"""Import explicitly marked primary-source summaries and a documented network caveat."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.storage import CTIStore
from app.models import Publication
from app.collectors import ingest


def main():
    store=CTIStore(ROOT/'data/cti.sqlite3')
    current={c['id'] for c in store.companies()}
    store.load_companies([c for c in json.loads((ROOT/'config/companies.json').read_text()) if c['id'] not in current])
    summaries=[Publication(**json.loads(line)) for line in (ROOT/'examples/research_context/primary_summaries.jsonl').read_text().splitlines() if line.strip()]
    counts=ingest(store,summaries)
    old=next((a for a in store.assertions() if a['kind']=='uses_product' and a['subject']=='roszarubezhneft' and a['object']=='trueconf-server'),None)
    if old:
        data=json.loads(old['publication']['data'])
        sentence='Публикация сообщает о собственном ЦОД и работе в закрытом контуре без внешнего доступа.'
        if sentence not in data['text']:data['text']+=' '+sentence
        data.setdefault('metadata',{})['network_caveat_source']='https://trueconf.ru/blog/success-stories/roszarubezhneft-trueconf-server'
        publication=Publication(**data)
        ingest(store,[publication])
        attrs=dict(old['attributes'],network_exposure='closed_network',network_exposure_note=sentence)
        attrs.setdefault('confidence','medium')
        attrs.setdefault('basis','research_report')
        if old['attributes']!=attrs or old['evidence_hash']!=publication.content_hash or old['status']!='confirmed':
            uid=store.add_assertion({'kind':'uses_product','subject':old['subject'],'object':old['object'],
                'publication_id':publication.id,'excerpt':publication.text[:1000],'attributes':attrs})
            store.review_assertion(uid,'confirmed','assistant_primary_source_review',
                'Повторно проверен официальный кейс: TrueConf Server, публикация 16.08.2026, собственный ЦОД и закрытый контур без внешнего доступа. Это контраргумент внешней доступности, не текущая проверка конфигурации.')
    print(json.dumps({'summaries':counts,'companies':len(store.companies()),'manual_source_review':True,
        'note':'Эти пересказы первоисточников помечены отдельно от автоматического сетевого сбора; ограничения проверки сохранены в метаданных.'},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
