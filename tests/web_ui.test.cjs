const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

const template = fs.readFileSync(path.join(__dirname, '../osint_tool/web/templates/index.html'), 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1];

function setup(fetch) {
    const elements = new Map();
    const timers = new Map();
    let nextTimer = 1;
    function element(id) {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, {
                value: '', innerHTML: '', textContent: '', disabled: false, style: {}, listeners: {},
                classList: {add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c)},
                addEventListener(event, handler) { this.listeners[event] = handler; },
            });
        }
        return elements.get(id);
    }
    const context = vm.createContext({
        URL, AbortController, fetch,
        document: {getElementById: element, querySelectorAll: () => [], querySelector: () => null},
        setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, {callback, delay}); return id; },
        clearTimeout(id) { timers.delete(id); },
    });
    vm.runInContext(script, context);
    return {
        context, element, timers,
        run: code => vm.runInContext(code, context),
        fire(delay) {
            const entry = [...timers].find(([, timer]) => timer.delay === delay);
            assert.ok(entry, `Missing ${delay}ms timer`);
            timers.delete(entry[0]);
            return entry[1].callback();
        },
    };
}

const response = (data, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => data});
const flush = () => new Promise(resolve => setImmediate(resolve));

test('external result links are escaped and unsafe schemes are not linked', () => {
    const ui = setup();
    const rendered = ui.context.renderData({links: [null, {url: 'javascript:alert(1)'},
        {url: 'https://example.com/?q="quoted"', valid: false, count: 0}], details: {valid: false, count: 0}});
    assert.doesNotMatch(rendered, /href="javascript:/);
    assert.match(rendered, /href="https:\/\/example.com\/\?q=&quot;quoted&quot;"/);
    assert.match(rendered, /valid: false/);
    assert.match(rendered, /count: 0/);
    assert.equal(ui.context.safeUrl('java\nscript:alert(1)'), false);
    assert.equal(ui.context.safeUrl('data:text/html,test'), false);
    assert.equal(ui.context.safeUrl('viber://chat?number=%2B12025550123'), true);
    assert.equal(ui.context.esc(0), '0');
});

test('module errors and hostile titles are rendered as text', () => {
    const ui = setup();
    ui.context.renderResults({summary: {total_modules: 1, total_results: 1, total_found: 0, total_errors: 1},
        modules: [{module: '<img src=x>', summary: {found: 0, total_checks: 1, duration_seconds: 0},
            errors: ['Source <unavailable>'], results: [{title: '<script>bad()</script>', source: 'test',
                severity: '" onclick="bad()', category: 'test', url: 'javascript:bad()', data: {}}]}]}, 'scan');
    const html = ui.element('moduleCards').innerHTML;
    assert.match(html, /Source &lt;unavailable&gt;/);
    assert.match(html, /&lt;script&gt;bad\(\)&lt;\/script&gt;/);
    assert.doesNotMatch(html, /href="javascript:|onclick="bad\(\)/);
});

test('a rejected scan shows the server error and restores the button', async () => {
    const ui = setup(async () => response({error: 'Keine gültige Eingabe'}, 400));
    ui.element('searchInput').value = 'example';
    await ui.context.startScan();
    assert.equal(ui.element('searchBtn').disabled, false);
    assert.equal(ui.run('scanRunning'), false);
    assert.equal(ui.element('progressMsg').textContent, 'Keine gültige Eingabe');
    assert.equal(ui.timers.size, 0);
});

test('duplicate starts and overlapping polls are prevented; 404 stops polling', async () => {
    let resolveStart;
    let resolveStatus;
    const calls = [];
    const ui = setup(url => {
        calls.push(url);
        if (url === '/api/scan') return new Promise(resolve => { resolveStart = resolve; });
        return new Promise(resolve => { resolveStatus = resolve; });
    });
    ui.element('searchInput').value = 'example';
    const first = ui.context.startScan();
    await ui.context.startScan();
    assert.deepEqual(calls, ['/api/scan']);
    assert.equal(ui.element('searchBtn').disabled, true);
    resolveStart(response({scan_id: 'one'}));
    await first;
    assert.equal(calls.length, 2);
    assert.equal([...ui.timers.values()].filter(t => t.delay === 400).length, 0);
    resolveStatus(response({status: 'running', progress: 25}));
    await flush();
    const next = ui.fire(400);
    assert.equal(calls.length, 3);
    resolveStatus(response({error: 'Scan nicht gefunden'}, 404));
    await next;
    assert.equal(ui.element('progressMsg').textContent, 'Scan nicht gefunden');
    assert.equal(ui.element('searchBtn').disabled, false);
    assert.equal(ui.timers.size, 0);
});

test('polling stops after three consecutive connection failures', async () => {
    let calls = 0;
    const ui = setup(async () => { calls++; throw new Error('Offline'); });
    ui.run('currentScanId = "one"; scanRunning = true');
    await ui.context.pollStatus('one');
    await ui.fire(1000);
    await ui.fire(1000);
    assert.equal(calls, 3);
    assert.equal(ui.run('scanRunning'), false);
    assert.equal(ui.element('progressMsg').textContent, 'Offline');
    assert.equal(ui.timers.size, 0);
});

test('a transient failure is retried and a completed scan displays results', async () => {
    let calls = 0;
    const ui = setup(async () => {
        if (++calls === 1) throw new Error('Offline');
        return response({status: 'done', progress: 100, results: {
            summary: {total_modules: 0, total_results: 0, total_found: 0, total_errors: 0}, modules: [],
        }});
    });
    ui.run('currentScanId = "one"; scanRunning = true');
    await ui.context.pollStatus('one');
    await ui.fire(1000);
    assert.equal(ui.run('scanRunning'), false);
    assert.equal(ui.element('resultsSection').classList.contains('visible'), true);
    assert.match(ui.element('exportBar').innerHTML, /\/api\/scan\/one\/export\/html/);
    ui.fire(600);
    assert.equal(ui.element('progressSection').classList.contains('visible'), false);
});

test('late status responses cannot overwrite a newer scan', async () => {
    let resolve;
    const ui = setup(() => new Promise(r => { resolve = r; }));
    ui.run('currentScanId = "old"; scanRunning = true');
    const pending = ui.context.pollStatus('old');
    ui.run('currentScanId = "new"');
    resolve(response({status: 'error', message: 'Old failure'}));
    await pending;
    assert.equal(ui.element('progressMsg').textContent, '');
    assert.equal(ui.run('scanRunning'), true);
});

test('request timeouts abort fetch and produce a usable error', async () => {
    const ui = setup((url, {signal}) => new Promise((resolve, reject) => {
        signal.addEventListener('abort', () => reject(Object.assign(new Error(), {name: 'AbortError'})));
    }));
    const request = ui.context.requestJSON('/test');
    ui.fire(15000);
    await assert.rejects(request, /Zeitüberschreitung/);
    assert.equal(ui.timers.size, 0);
});

test('stale auto-detection cannot restore a badge after input was cleared', async () => {
    let resolve;
    const ui = setup(() => new Promise(r => { resolve = r; }));
    const input = ui.element('searchInput');
    input.value = 'example.com';
    input.listeners.input();
    const pending = ui.fire(300);
    input.value = '';
    input.listeners.input();
    resolve(response({type: 'domain'}));
    await pending;
    assert.equal(ui.element('detectedBadge').innerHTML, '');
});
