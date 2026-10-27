/* Optional real-browser QA; install Playwright outside the runtime application. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.CTI_PLAYWRIGHT_MODULE || 'playwright');
const base = process.argv[2] || 'http://127.0.0.1:8765';
const output = process.argv[3] || '/tmp/cti-workbench-browser';
(async () => {
  fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:1000}});
  const page = await context.newPage();
  const errors = [], checks = [];
  page.on('pageerror', error => errors.push(error.message));
  async function check(name, operation) {await operation();checks.push({name,status:'passed'});console.log(name+': passed');}
  try {
    await page.goto(base);
    await page.waitForSelector('[data-company="ispras"]');
    await check('positive_case_first_in_queue', async()=>{
      assert.equal(await page.locator('.company-item').first().getAttribute('data-company'),'ispras');
      assert.match(await page.locator('#company-detail').innerText(),/Версия установки: неизвестна/);
      assert.match(await page.locator('#company-detail').innerText(),/Граница вывода/);
      assert.match(await page.locator('#company-detail').innerText(),/Публикация: дата неизвестна/);
      assert.match(await page.locator('#company-detail').innerText(),/Наблюдение страницы:/);
    });
    await check('desktop_layout_has_no_horizontal_overflow', async()=>{
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await page.screenshot({path:path.join(output,'desktop.png'),fullPage:false});
    });
    await check('company_search_and_empty_state',async()=>{
      await page.locator('[data-tab="all"]').click();
      await page.locator('#search').fill('ИСП РАН');
      assert.equal(await page.locator('.company-item').count(),1);
      await page.locator('#search').fill('nonexistent-fixture-company');
      assert.equal(await page.locator('.company-item').count(),0);
      assert.match(await page.locator('#company-detail').innerText(),/Выберите другой/);
      await page.locator('#search').fill('');
      await page.locator('[data-tab="attention"]').click();
    });
    await check('source_and_case_navigation',async()=>{
      await page.locator('[data-view="sources"]').click();
      assert.ok(await page.locator('.source-card').count()>0);
      assert.equal(await page.locator('#sources-view').isVisible(),true);
      await page.locator('[data-view="cases"]').click();
      assert.equal(await page.locator('.case-card').count(),4);
      const response=await page.request.get(base+'/cases/ispras-gitlab-2026/case.html');
      assert.equal(response.status(),200);
      await page.locator('[data-view="queue"]').click();
    });
    await check('historical_example_shows_both_real_indices_and_stays_outside_queue',async()=>{
      await page.locator('[data-tab="example"]').click();
      assert.equal(await page.locator('.company-item').count(),1);
      assert.equal(await page.locator('.company-item').getAttribute('data-company'),'equifax');
      assert.match(await page.locator('.example-notice').innerText(),/Исторический пример/);
      assert.match(await page.locator('.example-notice').innerText(),/не прогноз атаки/);
      assert.equal(await page.locator('.score strong').count(),2);
      assert.deepEqual(await page.locator('.score strong').allTextContents(),['6,87','90']);
      for(const label of await page.locator('.score small:first-of-type').allTextContents())assert.match(label,/15.09.2017/);
      assert.match(await page.locator('.example-notice').innerText(),/собраны и проверены позднее/);
      assert.match(await page.locator('#company-detail').innerText(),/Применены значения по умолчанию/);
      const exampleData=await (await page.request.get(base+'/api/dashboard')).json();
      const exampleCard=exampleData.companies.find(c=>c.id==='equifax');
      assert.equal(exampleCard.historical_technical.score,90);
      assert.equal(exampleCard.historical_technical.current_vulnerability_established,false);
      assert.ok(exampleCard.technical.score<0.001);
      assert.equal(await page.locator('details.paths[open]').count(),1);
      await page.screenshot({path:path.join(output,'historical-example.png'),fullPage:true});
      const direct=await context.newPage();
      await direct.goto(base+'/#equifax');
      await direct.waitForSelector('.example-notice');
      assert.equal(await direct.locator('[data-tab="example"]').getAttribute('class'),'selected');
      await direct.close();
      await page.locator('[data-tab="attention"]').click();
      assert.equal(await page.locator('[data-company="equifax"]').count(),0);
    });
    await check('graph_opens_selected_company',async()=>{
      const graph=await context.newPage();
      graph.on('pageerror',e=>errors.push(e.message));
      await graph.goto(base+'/graph?company=ispras');
      await graph.waitForFunction(()=>document.getElementById('detail-title').textContent.includes('ИСП РАН'));
      await graph.close();
    });
    await check('mobile_layout_and_navigation',async()=>{
      await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await page.screenshot({path:path.join(output,'mobile.png'),fullPage:false});
      await page.locator('[data-view="sources"]').click();
      assert.equal(await page.locator('#sources-view').isVisible(),true);
      await page.locator('[data-view="queue"]').click();
    });
    await check('untrusted_evidence_stays_text_and_unsafe_link_is_not_active',async()=>{
      const original=await (await page.request.get(base+'/api/dashboard')).json();
      const victim=original.companies.find(c=>c.id==='ispras');
      victim.evidence[0].title='<img src=x onerror="window.__ctiInjected=true">';
      victim.evidence[0].url='javascript:window.__ctiInjected=true';
      const isolated=await browser.newContext({viewport:{width:1440,height:1000}});
      await isolated.route('**/api/dashboard',route=>route.fulfill({json:original}));
      const test=await isolated.newPage();await test.goto(base);await test.waitForSelector('.company-item');
      assert.equal(await test.locator('#company-detail img').count(),0);
      assert.equal(await test.locator('a[href^="javascript:"]').count(),0);
      assert.equal(await test.evaluate(()=>window.__ctiInjected===true),false);
      await isolated.close();
    });
    // This block writes fictional fixtures; use only the isolated acceptance DB.
    if(process.env.CTI_TEST_SHODAN==='1') {
      const observations=async()=>await(await page.request.get(base+'/api/shodan')).json();
      const company=async()=>{const d=await(await page.request.get(base+'/api/dashboard')).json();return d.companies.find(c=>c.id==='shodan-test-client');};
      const initialCompany=await company();assert.ok(initialCompany,'Seed fictional shodan-test-client in the isolated DB');
      await page.setViewportSize({width:1440,height:1000});
      await check('shodan_example_is_marked_and_does_not_write',async()=>{
        await page.locator('[data-view="shodan"]').click();
        await page.waitForFunction(()=>document.getElementById('shodan-note').textContent.includes('Сохранённых'));
        const before=(await observations()).observations.length;
        await page.locator('#shodan-example').click();
        await page.waitForFunction(()=>document.getElementById('shodan-note').textContent.includes('Вымышленный пример'));
        assert.match(await page.locator('.shodan-card').innerText(),/Вымышленный пример/);
        assert.equal(await page.locator('.shodan-review').count(),0);
        assert.equal((await observations()).observations.length,before);
      });
      const fixture={ip_str:'203.0.113.10',data:[{port:443,transport:'tcp',timestamp:'2026-10-24T10:00:00Z',product:'<img src=x onerror="window.__shodanInjected=true">',version:'1.0',hostnames:['git.client.example'],vulns:{'CVE-2099-20001':{verified:false}}}]};
      await check('shodan_upload_is_unattributed_safe_text',async()=>{
        await page.locator('#shodan-file').setInputFiles({name:'fictional-service.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(fixture))});
        await page.waitForSelector('.shodan-review',{state:'attached'});
        assert.equal((await observations()).observations.length,1);
        assert.equal((await observations()).observations[0].association_review,null);
        assert.match(await page.locator('.shodan-card').innerText(),/Совпадения имён для проверки/);
        assert.equal(await page.locator('.shodan-card img').count(),0);
        assert.equal(await page.evaluate(()=>window.__shodanInjected===true),false);
      });
      await check('shodan_manual_association_reaches_company_card_without_score_change',async()=>{
        await page.locator('.shodan-card details').first().locator('summary').click();
        const form=page.locator('.shodan-review');
        await form.getByLabel('Компания',{exact:true}).selectOption('shodan-test-client');
        await form.getByLabel('Решение по принадлежности',{exact:true}).selectOption('confirmed');
        await form.getByLabel('Кто проверил',{exact:true}).fill('Browser acceptance');
        await form.getByLabel('Какие сведения подтверждают или опровергают связь',{exact:true}).fill('Fictional fixture association in isolated acceptance DB');
        await form.getByLabel('Публичная ссылка на основание',{exact:true}).fill('https://client.example/about');
        await form.getByRole('button',{name:'Сохранить проверку'}).click();
        await page.waitForFunction(()=>document.querySelector('.shodan-card').textContent.includes('принадлежность подтверждена'));
        const c=await company();assert.equal(c.technical_observations.length,1);
        assert.deepEqual(c.interest,initialCompany.interest);assert.deepEqual(c.technical,initialCompany.technical);
        await page.locator('[data-view="queue"]').click();await page.locator('[data-tab="history"]').click();
        await page.locator('[data-company="shodan-test-client"]').click();
        assert.match(await page.locator('#company-detail').innerText(),/Версия по баннеру/);
        await page.locator('[data-view="shodan"]').click();
        await page.evaluate(()=>scrollTo(0,0));
        await page.screenshot({path:path.join(output,'shodan-desktop.png'),fullPage:true});
      });
      await check('shodan_mobile_layout_has_no_horizontal_overflow',async()=>{
        await page.setViewportSize({width:390,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
        await page.screenshot({path:path.join(output,'shodan-mobile.png'),fullPage:true});
      });
      await check('shodan_repeated_upload_and_revocation_preserve_observation',async()=>{
        await page.locator('#shodan-file').setInputFiles({name:'repeated.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(fixture))});
        await page.waitForFunction(()=>document.getElementById('message').textContent.includes('Импортировано наблюдений'));
        assert.equal((await observations()).observations.length,1);
        assert.equal((await observations()).observations[0].association_review.status,'confirmed');
        await page.locator('.shodan-card details').first().locator('summary').click();
        await page.locator('.shodan-review').getByLabel('Решение по принадлежности',{exact:true}).selectOption('refuted');
        await page.locator('.shodan-review').getByRole('button',{name:'Сохранить проверку'}).click();
        await page.waitForFunction(()=>document.querySelector('.shodan-card').textContent.includes(': отклонена'));
        assert.equal((await observations()).observations[0].association_review.status,'refuted');
        assert.deepEqual((await company()).technical_observations,[]);
      });
    }
    if(process.env.CTI_TEST_CONTROLS==='1') {
      await check('desktop_pause_resume_and_refresh_controls',async()=>{
        await page.setViewportSize({width:1440,height:1000});
        const initial=await (await page.request.get(base+'/api/dashboard')).json();
        assert.equal(initial.runtime.running,true);
        assert.equal(initial.runtime.paused,false);
        try {
          await page.locator('#pause').click();
          const deadline=Date.now()+30000;
          while(Date.now()<deadline){const r=await (await page.request.get(base+'/api/dashboard')).json();if(r.runtime.phase==='paused')break;await page.waitForTimeout(200);}
          assert.equal((await (await page.request.get(base+'/api/dashboard')).json()).runtime.phase,'paused');
          await page.locator('#pause').click();
          const resumeDeadline=Date.now()+30000;
          while(Date.now()<resumeDeadline){const r=await (await page.request.get(base+'/api/dashboard')).json();if(r.runtime.phase!=='paused')break;await page.waitForTimeout(200);}
          assert.equal((await (await page.request.get(base+'/api/dashboard')).json()).runtime.paused,false);
          await page.locator('#refresh').click();
          await page.waitForFunction(()=>document.getElementById('message').textContent.includes('Обновление запрошено'));
        } finally {
          const latest=await (await page.request.get(base+'/api/dashboard')).json();
          if(latest.runtime.paused){const t=await page.locator('meta[name="cti-token"]').getAttribute('content');await page.request.post(base+'/api/control',{headers:{'X-CTI-Token':t},data:{action:'resume'}});}
        }
      });
    }
    assert.deepEqual(errors,[]);
    fs.writeFileSync(path.join(output,'checks.json'),JSON.stringify({status:'passed',browser:await browser.version(),checks,page_errors:errors,controls:process.env.CTI_TEST_CONTROLS==='1'?'desktop_verified_and_resumed':'verified_separately_in_isolated_docker'},null,2)+'\n');
  } finally {await context.close();await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
