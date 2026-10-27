/* Imported observations remain separate from company risk indices. */
(() => {
  'use strict';
  let data=null,fieldNumber=0;
  const target=$('shodan-list'),note=$('shodan-note');
  async function get(path){const r=await fetch(path);const d=await r.json();if(!r.ok)throw Error(d.error||'Не удалось прочитать наблюдения');return d;}
  function field(parent,title,input){const box=el('div'),label=el('label',title);input.id='shodan-field-'+(++fieldNumber);label.htmlFor=input.id;box.append(label,input);parent.append(box);return input;}
  function reviewForm(o,companies){
    const details=el('details');details.append(el('summary','Проверить принадлежность сервиса'));
    const form=el('form',undefined,'shodan-review'),review=o.association_review||{};
    const company=el('select');const blank=el('option','Выберите компанию');blank.value='';company.append(blank);
    for(const c of companies.filter(c=>Boolean(c.is_demo)===o.is_demo)){const option=el('option',c.name);option.value=c.id;company.append(option);}
    company.value=review.company_id||'';company.required=true;field(form,'Компания',company);
    const status=el('select');for(const [value,label]of[['needs_review','Требует проверки'],['confirmed','Принадлежность подтверждена'],['refuted','Связь отклонена']]){const opt=el('option',label);opt.value=value;status.append(opt);}status.value=review.status||'needs_review';field(form,'Решение по принадлежности',status);
    const who=el('input');who.required=true;who.maxLength=200;who.value=review.reviewer||'';field(form,'Кто проверил',who);
    const explanation=el('textarea');explanation.required=true;explanation.maxLength=2000;explanation.value=review.note||'';field(form,'Какие сведения подтверждают или опровергают связь',explanation);
    const url=el('input');url.type='url';url.required=true;url.value=review.evidence_url||'';field(form,'Публичная ссылка на основание',url);
    const submit=el('button','Сохранить проверку','secondary-button');submit.type='submit';form.append(submit);
    form.onsubmit=async event=>{event.preventDefault();submit.disabled=true;try{await post('/api/shodan/review',{id:o.id,company_id:company.value,status:status.value,reviewer:who.value,note:explanation.value,evidence_url:url.value});notice('Проверка сохранена. Индексы компании не изменены.');await loadObservations();await load();}catch(e){notice(e.message,true);}finally{submit.disabled=false;}};
    details.append(form);return details;
  }
  function render(){
    target.replaceChildren();if(!data)return;
    note.textContent=data.example_only?'Вымышленный пример формата. Запрос к Shodan не выполнялся; данные не сохранены в рабочую базу.':data.offline?'Офлайн-панель работает с временной копией. Импорт и подтверждение доступны после обычного запуска стенда.':'Сохранённых наблюдений: '+data.observations.length+'. Загрузка повторного снимка не обновляет дату наблюдения.';
    if(!data.observations.length){target.append(el('div','Наблюдений пока нет. Импортируйте сохранённый JSON Shodan или откройте вымышленный пример.','empty-state'));return;}
    for(const o of data.observations){
      const card=el('article',undefined,'shodan-card');card.dataset.observation=o.id||'example';
      card.append(badge(o.is_demo?'Вымышленный пример':'Наблюдение стороннего источника',o.is_demo?'':'internal'),el('h3',o.ip+':'+o.port+' / '+o.transport));
      const dl=el('dl');for(const [title,value]of[['Продукт',o.product||'неизвестен'],['Версия по баннеру',o.reported_version||'неизвестна'],['Дата наблюдения',date(o.observed_at,true)],['Первый импорт',date(o.imported_at,true)],['Имена хоста',(o.hostnames||[]).join(', ')||'не указаны'],['Организация в Shodan',o.reported_org||'не указана']])dl.append(el('dt',title),el('dd',value));card.append(dl);
      if(o.freshness==='stale')card.append(el('p','Наблюдение старше 30 дней; текущее состояние требует уточнения.','small-note'));
      if(o.freshness==='future')card.append(el('p','Дата наблюдения находится в будущем. Не используйте запись как актуальное основание.','small-note'));
      if(o.timestamp_utc_assumed)card.append(el('p','В исходной дате нет часового пояса; при импорте явно принято UTC.','small-note'));
      if(o.vulnerabilities.length){card.append(el('h4','CVE, указанные источником'));const list=el('ul',undefined,'shodan-vulns');for(const v of o.vulnerabilities)list.append(el('li',v.id+' — '+(v.verified_by_shodan===true?'проверено Shodan':v.verified_by_shodan===false?'предположено Shodan':'статус проверки не указан')));card.append(list);}
      const review=o.association_review;
      if(review){const company=(data.companies||[]).find(c=>c.id===review.company_id);card.append(el('p','Связь с '+(company?company.name:review.company_id)+': '+({confirmed:'принадлежность подтверждена',refuted:'отклонена',needs_review:'требует проверки'}[review.status])),el('p',review.note,'small-note'),link('Основание проверки ↗',review.evidence_url));}
      else card.append(el('p','Принадлежность компании не подтверждена. Поля org и ASN не устанавливают владельца сервиса.','small-note'));
      if(o.company_candidates&&o.company_candidates.length)card.append(el('p','Совпадения имён для проверки: '+o.company_candidates.map(c=>c.name+' ('+c.matching_hostnames.join(', ')+')').join('; '),'small-note'));
      card.append(el('p','Эта запись не подтверждает атаку или нынешнюю уязвимость компании и не меняет её индексы.','small-note'));
      if(o.source_url)card.append(link('Сохранённая запись в Shodan ↗',o.source_url));
      if(!data.example_only&&!data.offline&&!o.is_demo)card.append(reviewForm(o,data.companies||[]));
      const raw=el('details');raw.append(el('summary','Сохранённые поля наблюдения'),el('pre',JSON.stringify(o,null,2)));card.append(raw);target.append(card);
    }
  }
  async function loadObservations(){try{data=await get('/api/shodan');render();}catch(e){notice(e.message,true);}}
  document.querySelector('[data-view="shodan"]').addEventListener('click',loadObservations);
  $('reload').addEventListener('click',()=>{if(currentView==='shodan')loadObservations();});
  $('shodan-example').onclick=async()=>{try{data=await get('/api/shodan/example');render();}catch(e){notice(e.message,true);}};
  $('shodan-file').addEventListener('change',async event=>{const file=event.target.files[0];if(!file)return;try{if(file.size>2000000)throw Error('Импорт не более 2 МБ');const text=await file.text();let body;try{body=JSON.parse(text);}catch(_){body=text.split(/\r?\n/).filter(s=>s.trim()).map(s=>JSON.parse(s));}const result=await post('/api/shodan/import',body);notice('Импортировано наблюдений: '+result.observations+'. Индексы компаний не изменены.');await loadObservations();await load();}catch(e){notice('Импорт Shodan не выполнен: '+e.message,true);}finally{event.target.value='';}});
})();
