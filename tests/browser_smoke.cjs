const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert/strict');

(async () => {
  const server = spawn(process.env.PYTHON || 'python3', [path.join(__dirname, 'serve_browser_fixture.py')], {stdio:['ignore','pipe','pipe']});
  let browser;
  let errorLog = '';
  server.stderr.on('data', chunk => errorLog += chunk.toString());
  try {
    const endpoints = await new Promise((resolve, reject) => {
      let data='';
      const timer=setTimeout(()=>reject(new Error('Fixture startup timed out: '+errorLog)),15000);
      server.stdout.on('data',chunk=>{
        data+=chunk;
        const line=data.split('\n')[0];
        if(data.includes('\n')) {clearTimeout(timer);resolve(JSON.parse(line));}
      });
      server.on('exit',code=>{clearTimeout(timer);reject(new Error('Fixture exit '+code+': '+errorLog));});
    });
    browser=await chromium.launch({headless:true, ...(process.env.BROWSER_EXECUTABLE ? {executablePath:process.env.BROWSER_EXECUTABLE} : {})});
    for(const viewport of [{width:1440,height:1000},{width:390,height:844}]) {
      const context=await browser.newContext({viewport});
      // No network leaves the local test app; external map/fonts aren't part of this check.
      await context.route('**/*',route=>route.request().url().startsWith(endpoints.app+'/')?route.continue():route.abort());
      const page=await context.newPage();
      const errors=[]; const dialogs=[]; const auth=[];
      page.on('pageerror',e=>errors.push(e.message));
      page.on('dialog',async d=>{dialogs.push(d.message());await d.dismiss();});
      page.on('request',req=>{if(/\/api\/(scan|status|results|cancel)/.test(req.url())) auth.push(req.headers()['x-api-key']);});
      await page.goto(endpoints.app);
      await page.waitForFunction(()=>document.querySelectorAll('.module-item').length===18);
      await page.waitForFunction(()=>document.getElementById('scanAvailability').textContent.includes('API anahtar'));
      await page.waitForFunction(()=>document.querySelectorAll('#newsGrid a').length===1);
      assert.equal(await page.locator('#newsGrid a[href^="javascript:"]').count(),0);
      assert.equal(await page.locator('#newsGrid h3 img').count(),0);
      assert.equal(await page.locator('#targetUrl').evaluate(el=>getComputedStyle(el).height),'56px');
      await page.locator('#targetUrl').fill(endpoints.target+'/xss/unsafe');
      await page.route('**/api/config', route=>route.fulfill({json:{auth_required:true,scan_available:false}}));
      await page.locator('#targetUrl').press('Enter');
      await page.waitForFunction(()=>document.getElementById('scanAvailability').textContent.includes('sunucu yöneticisi'));
      assert.equal(await page.locator('#btnScan').isDisabled(),true);
      assert.equal(auth.length,0, 'Enter must not bypass a missing server key');
      await page.unroute('**/api/config');
      await page.locator('#targetUrl').press('Enter');
      await page.waitForFunction(()=>document.activeElement.id==='apiKey');
      assert.equal(auth.length,0, 'Missing key must be caught before starting a scan');
      await page.locator('#apiKey').fill('  browser-fixture-key  ');
      await page.locator('#btnModules').click();
      await page.locator('#toggleAllModules').click();
      await page.locator('[data-module="xss"]').click();
      assert.equal(await page.locator('#moduleCount').textContent(),'1 / 18 seçili');
      assert.equal(await page.locator('[data-module="xss"] input').isChecked(),true);
      await page.locator('#closeModules').click();
      await page.locator('#targetUrl').fill(endpoints.target+'/xss/unsafe');
      await page.locator('#btnScan').click();
      await page.waitForFunction(()=>getComputedStyle(document.getElementById('resultsSection')).display!=='none',{},{timeout:15000});
      assert.match(await page.locator('#findingsList').textContent(),/Olası Yansıtılan XSS/);
      await page.locator('.finding-header').first().click();
      assert.equal(await page.locator('.finding-card.open').count(),1);
      assert.match(await page.locator('#scanNotes').textContent(),/1 \/ 1/);
      assert(auth.length>=3 && auth.every(key=>key==='browser-fixture-key'));
      assert.equal(await page.evaluate(()=>Object.keys(localStorage).length+Object.keys(sessionStorage).length),0);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true);
      if(process.env.SCREENSHOT_DIR) {
        fs.mkdirSync(process.env.SCREENSHOT_DIR,{recursive:true});
        await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,`results-${viewport.width}.png`),fullPage:true});
      }
      // A failed module must show missing score and an explanation.
      await page.locator('#newScan').click();
      await page.waitForFunction(()=>document.querySelectorAll('.module-item').length===18);
      await page.waitForFunction(()=>document.getElementById('authDetails').open);
      await page.locator('#apiKey').fill('browser-fixture-key');
      await page.locator('#btnModules').click(); await page.locator('#toggleAllModules').click();
      await page.locator('[data-module="headers"]').click(); await page.locator('#closeModules').click();
      await page.locator('#targetUrl').fill(endpoints.target+'/protected');
      await page.locator('#btnScan').click();
      await page.waitForFunction(()=>getComputedStyle(document.getElementById('resultsSection')).display!=='none',{},{timeout:15000});
      assert.match(await page.locator('#findingsList').textContent(),/Güvenlik skoru hesaplanmadı/);
      assert.match(await page.locator('#summaryGrid').textContent(),/—/);
      assert.match(await page.locator('#scanNotes').textContent(),/0 \/ 1/);
      assert.equal(dialogs.length,0); assert.deepEqual(errors,[]);
      await context.close();
      console.log(`Browser ${viewport.width}px passed: auth, modules, actual scan, escaping, results, failed scan, layout.`);
    }
  } finally {
    if(browser) await browser.close();
    server.kill('SIGTERM');
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
