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
    company.value=review.company_id||((o.company_candidates||[]).length===1?o.company_candidates[0].id:'');company.required=true;field(form,'Компания',company);
    const status=el('select');for(const [value,label]of[['needs_review','Требует проверки'],['confirmed','Принадлежность подтверждена'],['refuted','Связь отклонена']]){const opt=el('option',label);opt.value=value;status.append(opt);}status.value=review.status||'needs_review';field(form,'Решение по принадлежности',status);
    const who=el('input');who.required=true;who.maxLength=200;who.value=review.reviewer||'';field(form,'Кто проверил',who);
    const explanation=el('textarea');explanation.required=true;explanation.maxLength=2000;explanation.value=review.note||'';field(form,'Какие сведения подтверждают или опровергают связь',explanation);
    const url=el('input');url.type='url';url.required=true;url.value=review.evidence_url||'';field(form,'Публичная ссылка на основание',url);
    const submit=el('button','Сохранить проверку','secondary-button');submit.type='submit';form.append(submit);
    form.onsubmit=async event=>{event.preventDefault();submit.disabled=true;try{await post('/api/shodan/review',{id:o.id,company_id:company.value,status:status.value,reviewer:who.value,note:explanation.value,evidence_url:url.value});notice('Проверка сохранена. Индексы компании не изменены.');await loadObservations();await load();}catch(e){notice(e.message,true);}finally{submit.disabled=false;}};
    details.append(form);return details;
  }
  function renderMonitor(){
    const box=$('shodan-monitor');box.replaceChildren();
    if(!data||data.example_only){box.hidden=true;return;}box.hidden=false;
    box.append(el('h3','Автоматическое наблюдение по доменам'));
    const monitor=data.monitor||{},state=(data.runtime||{}).shodan_monitor;
    box.append(el('p','Поиск не чаще раза в сутки: до 100 результатов на домен. Не более 10 поисковых запросов за 24 часа. Подтверждённые IP обновляются отдельно раз в сутки. Поиск расходует кредиты Shodan.','small-note'));
    const labels={not_configured:'Ключ не подключён к сборщику',invalid_key:'Неверный формат ключа',no_targets:'Домены ещё не выбраны',cooldown:'Ожидание разрешённого времени запроса',budget_exhausted:'Достигнут лимит поисковых запросов',waiting:'Ожидание очередного обновления',ok:'Последний запрос выполнен',error:'Последний запрос завершился ошибкой'};
    if(data.offline){box.append(el('p','Настройка доступна после обычного запуска платформы.'));return;}
    if(!(data.runtime||{}).running)box.append(el('p','Сборщик сейчас недоступен. Сохранённые настройки применятся после его запуска.','small-note'));
    if(state)box.append(el('p',(labels[state.status]||state.status)+(state.error_code?' · '+state.error_code:'')+(state.message?' · '+state.message:'')));
    box.append(el('p','Поисковых запросов за 24 часа: '+(monitor.search_requests_24h||0)+' / '+(monitor.search_limit_24h||10),'small-note'));
    for(const t of monitor.targets||[]){
      const row=el('div',undefined,'shodan-target'),last=t.last_run;
      row.append(el('strong',t.company_name+' · '+t.domain),el('p',!t.catalog_valid?'Домен удалён из каталога; опрос остановлен.':t.enabled?'Наблюдение включено':'Наблюдение приостановлено','small-note'));
      if(last){row.append(el('p','Последняя попытка: '+date(last.attempted_at,true)+' · '+(labels[last.status]||last.status)+(last.error_code?' · '+last.error_code:'')+'; следующий запрос не ранее '+date(last.next_allowed_at,true),'small-note'));
        if(last.status==='ok')row.append(el('p','Найдено в Shodan: '+last.total+'; получено: '+last.returned+'; сохранено совпадений: '+last.observations+'.'+(last.partial?' Показана только первая страница; поиск неполный.':''),'small-note'));
        if(last.error_code==='forbidden'||last.error_code==='unauthorized')row.append(el('p','Проверьте ключ и доступ аккаунта к Search API.','small-note'));
      }
      const toggle=el('button',t.enabled?'Приостановить':'Возобновить','secondary-button');toggle.disabled=!t.catalog_valid&&!t.enabled;
      toggle.onclick=async()=>{toggle.disabled=true;try{await post('/api/shodan/monitor',{company_id:t.company_id,domain:t.domain,enabled:!t.enabled});await loadObservations();}catch(e){notice(e.message,true);toggle.disabled=false;}};row.append(toggle);box.append(row);
    }
    const form=el('form',undefined,'shodan-review'),company=el('select'),domain=el('select');
    const companies=(data.companies||[]).filter(c=>!c.is_demo&&(c.domains||[]).length);
    for(const c of companies){const option=el('option',c.name);option.value=c.id;company.append(option);}
    function domains(){domain.replaceChildren();const c=companies.find(c=>c.id===company.value);for(const d of c?c.domains:[]){const option=el('option',d);option.value=d;domain.append(option);}}
    company.onchange=domains;domains();field(form,'Компания',company);field(form,'Домен из каталога',domain);
    const submit=el('button','Включить наблюдение','secondary-button');submit.type='submit';submit.disabled=!companies.length;form.append(submit);
    form.onsubmit=async event=>{event.preventDefault();submit.disabled=true;try{await post('/api/shodan/monitor',{company_id:company.value,domain:domain.value,enabled:true});notice('Наблюдение включено. Запрос выполнится в ближайшем доступном цикле сборщика.');await loadObservations();}catch(e){notice(e.message,true);submit.disabled=false;}};
    box.append(form,el('p','Ключ хранится в SHODAN_API_KEY локального .env. После его изменения выполните ./start-cti.sh для пересоздания сборщика.','small-note'));
  }
  function render(){
    target.replaceChildren();if(!data)return;renderMonitor();
    note.textContent=data.example_only?'Вымышленный пример формата. Запрос к Shodan не выполнялся; данные не сохранены в рабочую базу.':data.offline?'Офлайн-панель работает с временной копией. Импорт и подтверждение доступны после обычного запуска стенда.':'Сохранённых наблюдений: '+data.observations.length+'. Загрузка повторного снимка не обновляет дату наблюдения.';
    if(!data.observations.length){target.append(el('div','Наблюдений пока нет. Включите наблюдение по домену, импортируйте JSON Shodan или откройте вымышленный пример.','empty-state'));return;}
    for(const o of data.observations){
      const card=el('article',undefined,'shodan-card');card.dataset.observation=o.id||'example';
      card.append(badge(o.is_demo?'Вымышленный пример':'Наблюдение стороннего источника',o.is_demo?'':'internal'),el('h3',o.ip+':'+o.port+' / '+o.transport));
      const dl=el('dl');for(const [title,value]of[['Продукт',o.product||'неизвестен'],['Версия по баннеру',o.reported_version||'неизвестна'],['Дата наблюдения',date(o.observed_at,true)],['Первый импорт',date(o.imported_at,true)],['Имена хоста',(o.hostnames||[]).join(', ')||'не указаны'],['Организация в Shodan',o.reported_org||'не указана']])dl.append(el('dt',title),el('dd',value));card.append(dl);
      if((o.discovered_for||[]).length)card.append(el('p','Найдено при поиске по доменам: '+o.discovered_for.map(t=>t.domain).join(', '),'small-note'));
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
