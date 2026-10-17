// Exercise the actual result renderer without external CDN or browser dependencies.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'security_scanner.html'), 'utf8');
for (const [, attributes, source] of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
  if (!attributes.includes('src=')) new vm.Script(source);
}
const js = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
new vm.Script(js);
const source = js.slice(js.indexOf('    function showResults(result)'), js.indexOf('    /* ───', js.indexOf('    function showResults(result)')));
const nodes = new Map();
const context = vm.createContext({
  document: { getElementById(id) { if (!nodes.has(id)) nodes.set(id, {style: {}, innerHTML: '', textContent: ''}); return nodes.get(id); } },
  scannedUrl: 'https://fixture.invalid',
  escapeHTML: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
});
vm.runInContext(source, context);
for (const status of ['error', 'cancelled', 'timeout']) {
  context.showResults({status, score: null, findings: [], counts: {}});
  assert.match(nodes.get('summaryGrid').innerHTML, /—/);
  assert.match(nodes.get('findingsList').innerHTML, /Güvenlik skoru hesaplanmadı/);
  assert.doesNotMatch(nodes.get('findingsList').innerHTML, /Açık bulunamadı/);
}
context.showResults({status: 'error', score: null, findings: [{title: '<script>', severity: 'HIGH', detail: 'partial', fix: 'fix'}], counts: {HIGH: 1}});
assert.match(nodes.get('findingsList').innerHTML, /Güvenlik skoru hesaplanmadı/);
assert.match(nodes.get('findingsList').innerHTML, /&lt;script&gt;/);
context.showResults({status: 'completed', score: 100, findings: [], counts: {}});
assert.match(nodes.get('findingsList').innerHTML, /Açık bulunamadı/);
assert.match(nodes.get('summaryGrid').innerHTML, />100<\/span>/);
const moduleSource = js.match(/const modules = (\[[\s\S]*?\]);/)[1];
const modules = vm.runInNewContext(moduleSource);
assert.equal(modules.length, 18);
assert.equal(new Set(modules.map(m => m.id)).size, 18);
for (const id of ['cookies', 'methods', 'clickjack', 'ratelimit', 'tech', 'ports']) assert(modules.some(m => m.id === id));
console.log('UI checks passed: script syntax, completed/failed/cancelled/timeout results, partial findings, and 18 modules.');

assert.doesNotMatch(html, /\son(?:click|keydown|error)=/);
assert.doesNotMatch(js, /Math\.random/);
const safeUrlSource = js.slice(js.indexOf('    function safeWebURL'), js.indexOf('    function scanFetch'));
vm.runInContext(safeUrlSource, context);
context.URL = URL;
for (const url of ['javascript:alert(1)', 'data:text/html,x', '//evil.invalid', 'https://a:b@fixture.invalid']) {
  assert.equal(context.safeWebURL(url), '');
}
assert.equal(context.safeWebURL('https://fixture.invalid/a'), 'https://fixture.invalid/a');
assert.match(js, /headers.set\('X-API-Key', key\)/);
assert.doesNotMatch(js, /localStorage|sessionStorage/);
console.log('UI security checks passed: safe URLs, memory-only API key, no inline handlers or fabricated counters.');
