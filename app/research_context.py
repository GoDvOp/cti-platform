"""Public program context and conditional patch-review hypotheses, separate from threat indices."""
from datetime import datetime, date
import json
import re
from urllib.parse import urlsplit
from .freshness import evidence_day
from .knowledge import scope_id, assertion_day, version_match
from .models import digest, normalized, utcnow, date_iso, canonical_url


def _name(value):return normalized(value).replace('․', '.')


def build(store, as_of=None):
    at=datetime.fromisoformat(date_iso(as_of or utcnow()));today=at.date()
    companies={c['id']:c for c in store.companies() if not c.get('is_demo',False)}
    products={p['id']:p for p in store.products() if not p.get('is_demo',False)}
    publications=[]
    for pub in store.publications():
        if datetime.fromisoformat(pub['collected_at'])<=at:publications.append((pub,json.loads(pub['data'])))
    programs,edges,notices,queue={},{},[],[]
    update_cves={}
    def add(subject,label,relation,obj,target_label,properties,seed):
        uid='research:'+digest('|'.join([relation,subject,obj,seed]))[:24]
        edges[uid]={'id':uid,'subject':subject,'subject_label':label,'relation':relation,
                    'object':obj,'object_label':target_label,'properties':dict(properties,
                        cti_managed='research-context-v1',is_demo=False,weight_role='research_context_only')}
    for pub,data in publications:
        meta=data.get('metadata',{});program=meta.get('bug_bounty_program')
        provenance={'publication_id':pub['id'],'evidence_url':pub['url'],'evidence_hash':pub['content_hash']}
        if isinstance(program,dict) and all(isinstance(program.get(k),str) and program[k] for k in ('url','platform','name')):
            try:canonical_url(program['url'])
            except ValueError:continue
            # English/Russian routes describe the same program, not two observations.
            path=urlsplit(program['url']).path.removeprefix('/en-US').removeprefix('/ru-RU').rstrip('/')
            uid=scope_id('bounty:'+digest(urlsplit(program['url']).hostname+path)[:24])
            row={'id':uid,'properties':{'name':program['name'][:350],'url':program['url'],'platform':program['platform'],
                'observed_at':pub['collected_at'],'is_demo':False,'interpretation':'Публичная программа исследований; не признак атаки или уязвимости компании.'}}
            if uid not in programs or programs[uid]['properties']['observed_at']<pub['collected_at']:programs[uid]=row
            add(pub['id'],'Publication','DESCRIBES_PROGRAM',uid,'BugBountyProgram',dict(provenance,status='public_program_record'),pub['id'])
            key=_name(program.get('company_name') or program['name'])
            for cid,company in companies.items():
                if key not in {_name(a) for a in (company['name'],*company.get('aliases',[]))}:continue
                add(cid,'Company','HAS_PUBLIC_BUG_BOUNTY',uid,'BugBountyProgram',dict(provenance,
                    status='reported_program_participation',caption='Публичная программа bug bounty',
                    interpretation='Совпадение явного имени организации; участие в bug bounty не повышает индекс интереса атакующих.'),pub['id'])
        notice=meta.get('security_notice')
        update=meta.get('software_update')
        if isinstance(update,dict) and update.get('product_id') in products:
            references=set(update.get('reference_cves',[])) & set(json.loads(pub['extraction']).get('cves',[]))
            day,_=evidence_day(data)
            if references and day and day<=today:
                pid=update['product_id']
                update_cves.setdefault(pid,set()).update(references)
                add(pub['id'],'Publication','SECURITY_UPDATE_FOR',scope_id(pid),'Product',dict(provenance,
                    status='vendor_update_reference',caption='Описание обновления продукта',
                    reference_cves=sorted(references),fixed_versions=update.get('fixed_versions',[]),
                    verification_method=meta.get('verification_method','source_statement'),
                    interpretation=update.get('interpretation','Выпущенное обновление не доказывает состояние установок клиентов.')),pub['id'])
        if isinstance(notice,dict) and notice.get('product_id') in products:
            if notice.get('requires_verified_scope'):
                reviewed = [claim for claim in store.assertions() if claim['kind'] == 'affects_product'
                            and claim['object'] == notice['product_id'] and claim['publication_id'] == pub['id']
                            and claim['status'] == 'confirmed' and claim['evidence_hash'] == pub['content_hash']
                            and (not claim.get('reviewed_at') or datetime.fromisoformat(claim['reviewed_at']) <= at)]
                if not reviewed:
                    continue
            from .knowledge import validate_attributes
            bounds={k:notice[k] for k in ('affected_ranges','affected_versions','fixed_versions') if k in notice}
            try:validate_attributes('affects_product',bounds)
            except (ValueError,TypeError):continue
            if not bounds.get('affected_ranges') and not bounds.get('affected_versions'):continue
            pid=notice['product_id'];day,_=evidence_day(data)
            add(pub['id'],'Publication','SECURITY_NOTICE_FOR',scope_id(pid),'Product',dict(provenance,
                status='parsed_vendor_statement',caption='Уведомление об обновлении',publication_day=day.isoformat() if day else None,
                affected_ranges_json=json.dumps(notice.get('affected_ranges',[])),fixed_versions=notice.get('fixed_versions',[]),
                scope_source_urls=notice.get('scope_source_urls',[pub['url']]),
                interpretation='Область бюллетеня по словам разработчика; применимость к конкретной установке не подтверждена.'),pub['id'])
            notices.append((pub,data,notice,day))
    # Repeated automated/manual summaries of one URL do not multiply hypotheses.
    unique={}
    for item in notices:
        key=(item[0]['url'],item[2]['product_id'])
        def scope_rank(record):
            return (record[2].get('scope_updated_day') or (record[3].isoformat() if record[3] else ''),
                    record[2].get('extraction_status')=='project_primary_source_review',record[0]['collected_at'])
        if key not in unique or scope_rank(item)>scope_rank(unique[key]):unique[key]=item
    for use in store.assertions():
        if use['kind']!='uses_product' or use['status']!='confirmed' or use['subject'] not in companies:continue
        if any(use.get(k) and datetime.fromisoformat(use[k])>at for k in ('reviewed_at',)):continue
        if datetime.fromisoformat(use['publication']['collected_at'])>at:continue
        use_day=assertion_day(use);use_age=(today-date.fromisoformat(use_day)).days if use_day else None
        if use_age is not None and use_age<0:continue
        for pub,data,notice,day in unique.values():
            if notice['product_id']!=use['object']:continue
            age=(today-day).days if day else None
            if age is not None and age<0:continue
            attrs=use['attributes'];installed=attrs.get('version')
            applies=version_match(installed,notice) if installed else None
            # An exact version explicitly reported fixed is an exception to a
            # broad earlier bulletin; do not infer ranges from fix numbers.
            if installed and installed in notice.get('fixed_versions',[]):applies=False
            network=attrs.get('network_exposure','unknown')
            missing=[]
            if not installed:missing.append('installed_version_unknown')
            if network=='unknown':missing.append('network_exposure_unknown')
            if use_age is None:missing.append('use_date_unknown')
            elif use_age>180:missing.append('use_evidence_older_than_180_days')
            if age is None:missing.append('notice_date_unknown')
            elif age>30:missing.append('notice_older_than_30_days')
            if applies is False:status='version_outside_reported_range'
            elif use_age is None or use_age>180 or age is None or age>30:status='insufficient_current_evidence'
            elif network=='closed_network':status='internal_patch_review'
            else:status='conditional_monitoring_candidate'
            related=[]
            for report,content in publications:
                shared=update_cves.get(use['object'],set()) & set(json.loads(report['extraction']).get('cves',[]))
                title=content['title']
                if not shared or not re.search(r'(?:зафиксир\w*|наблюда\w*|observed).{0,90}(?:эксплуатац|exploit)',title,re.I):continue
                if re.search(r'\b(?:не|not|no)\s+(?:зафикс|наблюд|observ)',title,re.I):continue
                reported,_=evidence_day(content)
                if reported and 0<=(today-reported).days<=30:
                    related.append({'publication_id':report['id'],'url':report['url'],'cves':sorted(shared),
                        'qualification':'Источник сообщает о попытках эксплуатации CVE в общем; атака на эту компанию или продукт не установлена.'})
            row={'id':digest(use['id']+pub['url'])[:24],'company_id':use['subject'],'company':companies[use['subject']]['name'],
                'product_id':use['object'],'product':products[use['object']]['name'],'status':status,
                'use_assertion_id':use['id'],'use_url':use['publication']['url'],'use_age_days':use_age,
                'notice_id':pub['id'],'notice_url':pub['url'],'notice_age_days':age,'notice_title':data['title'],
                'installed_version':installed,'version_match':applies,'network_exposure':network,
                'counterevidence':attrs.get('network_exposure_note'),'missing':missing,'is_probability':False,
                'decision':'Проверить актуальность установки и обновление; атака и неустранённая уязвимость не установлены.',
                'horizon_days':30,'notice_review_status':notice.get('extraction_status','unreviewed'),
                'scope_source_urls':notice.get('scope_source_urls',[pub['url']])}
            row['related_exploitation_reports']=related
            queue.append(row)
            if status not in ('version_outside_reported_range','insufficient_current_evidence'):
                add(use['subject'],'Company','MONITORING_HYPOTHESIS',pub['id'],'Publication',
                    {'status':status,'caption':'Условная проверка обновления','use_assertion_id':scope_id(use['id']),
                     'use_evidence_url':row['use_url'],'notice_evidence_url':row['notice_url'],
                     'network_exposure':network,'counterevidence':row['counterevidence'],'missing':missing,
                     'related_report_ids':sorted({r['publication_id'] for r in related}),
                     'related_cves':sorted({v for r in related for v in r['cves']}),
                     'horizon_days':30,'is_probability':False,'interpretation':row['decision']},use['id'])
    order={'conditional_monitoring_candidate':0,'internal_patch_review':1,'insufficient_current_evidence':2,'version_outside_reported_range':3}
    queue.sort(key=lambda r:(order[r['status']],r['use_age_days'] if r['use_age_days'] is not None else 10**9,r['company_id'],r['notice_url']))
    return {'as_of':at.isoformat(),'method_version':'conditional-monitoring-v1.1','programs':list(programs.values()),'edges':list(edges.values()),'hypotheses':queue,
            'interpretation':'Очередь пассивной проверки условных гипотез. Bug bounty не создаёт угрозу; техническая применимость не устанавливает интерес злоумышленников.'}


def statements(store,as_of=None):
    result=build(store,as_of)
    queries=[{'statement':'MATCH ()-[r]->() WHERE r.cti_managed="research-context-v1" AND r.is_demo=false DELETE r'},
             {'statement':'UNWIND $rows AS row MERGE (n:BugBountyProgram {id:row.id}) SET n += row.properties',
              'parameters':{'rows':result['programs']}}]
    groups={}
    for row in result['edges']:groups.setdefault((row['subject_label'],row['relation'],row['object_label']),[]).append(row)
    for (subject,relation,obj),rows in groups.items():
        queries.append({'statement':f'UNWIND $rows AS row MATCH (s:{subject} {{id:row.subject}}),(o:{obj} {{id:row.object}}) '
            f'MERGE (s)-[r:{relation} {{id:row.id}}]->(o) SET r += row.properties', 'parameters':{'rows':rows}})
    return queries


def export(result,output):
    import html
    from pathlib import Path
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    (output/'monitoring.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    esc=lambda v:html.escape(str(v))
    labels={'conditional_monitoring_candidate':'Условная гипотеза: проверить применимость',
            'internal_patch_review':'Проверка обновления в закрытом контуре',
            'insufficient_current_evidence':'Не хватает актуальных данных',
            'version_outside_reported_range':'Версия вне указанного диапазона'}
    rows=[]
    for r in result['hypotheses']:
        row='<tr><td>'+esc(r['company'])+'</td><td>'+esc(r['product'])+'</td><td>'+esc(labels[r['status']])+'</td>'
        row+='<td>'+esc(r['use_age_days'])+'</td><td>'+esc(r['notice_age_days'])+'</td><td>'+esc(r['installed_version'] or 'неизвестна')+'</td>'
        row+='<td>'+esc(r['counterevidence'] or 'Внешняя доступность и текущая конфигурация неизвестны.')+'</td>'
        row+='<td><a href="'+esc(r['use_url'])+'">Использование</a> · <a href="'+esc(r['notice_url'])+'">Бюллетень</a></td></tr>'
        rows.append(row)
    programs=''.join('<li><a href="'+esc(p['properties']['url'])+'">'+esc(p['properties']['name'])+'</a> — '+esc(p['properties']['platform'])+'</li>' for p in result['programs'])
    page='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Условные гипотезы мониторинга</title><style>body{font:16px/1.55 system-ui;color:#1b2c43;margin:30px auto;padding:0 20px;max-width:1250px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #ccd5df;padding:10px;vertical-align:top;text-align:left}.wrap{overflow:auto}a{color:#165e9e}</style><h1>Условные гипотезы мониторинга</h1>'''
    page+='<p>Срез '+esc(result['as_of'])+'. '+esc(result['interpretation'])+'</p>'
    page+='<p>Горизонт проверки — 30 дней; порог актуальности использования ПО — 180 дней. Нет частоты исходов, калибровки и измеренной вероятности атаки. Это правила отбора для аналитика. Заявления источников и версия установки требуют проверки.</p>'
    page+='<div class="wrap"><table><tr><th>Компания</th><th>Продукт</th><th>Решение</th><th>Возраст использования, дни</th><th>Возраст бюллетеня, дни</th><th>Версия</th><th>Ограничения и контраргументы</th><th>Основания</th></tr>'+''.join(rows)+'</table></div>'
    page+='<h2>Публичные программы bug bounty</h2><p>Участие в программе, число отчётов и размер вознаграждения не повышают индексы угроз. Это контекст исследований.</p><ul>'+programs+'</ul>'
    page+='<p><a href="monitoring.json">Полные пути и ограничения JSON</a></p>'
    (output/'monitoring.html').write_text(page,encoding='utf-8')
    return {'directory':str(output.resolve()),'hypotheses':len(result['hypotheses']),'programs':len(result['programs']),
            'conditional_candidates':sum(r['status']=='conditional_monitoring_candidate' for r in result['hypotheses'])}


def record(store,output,history):
    """Freeze first, then build the queue and export exactly that evidence state."""
    from contextlib import closing
    from pathlib import Path
    import sqlite3
    import tempfile
    from .storage import CTIStore
    from .review_snapshot import export_snapshot
    history=Path(history);history.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='record-copy-',dir=history) as tmp:
        path=Path(tmp)/'frozen.sqlite3'
        with store.connect() as original,closing(sqlite3.connect(path)) as copied:original.backup(copied)
        frozen=CTIStore(path)
        result=build(frozen)
        stamp=result['as_of'].replace('-','').replace(':','').replace('+0000','Z')
        directory=history/stamp;directory.mkdir(exist_ok=False)
        metadata=export_snapshot(frozen,directory/'snapshot.json.gz',result['as_of'])
        (directory/'queue.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        (directory/'manifest.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n')
        saved=export(result,output)
        saved['recorded_snapshot']=str(directory.resolve())
        return saved
