// Screenshots of the running demo (for slides).
// Default: at 1366x768 and 1920x1080, the graph once the DDoS campaign has appeared, the attacked
// host's stage timeline, and the exfiltration drawer.
// --ppt: 1920x1080 only, the PPT set 01-05 (dashboard, host timeline, exfil drawer, model card,
// facts-strip crop at 2x), each taken only after what it shows has been asserted on the page.
// Usage: PORT=18001 scripts/demo.sh &  then  node tests/demo-shots.mjs http://127.0.0.1:18001 OUT_DIR [--ppt]
import { chromium } from 'playwright';

const [url, dir, mode] = process.argv.slice(2);
const HOST = '192.168.1.66';
const fail = (msg) => { console.error(`SHOTS FAIL: ${msg}`); process.exit(1); };

async function openAtDdos(b, w, h, scale = 1) {
  const p = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: scale });
  await p.goto(url);
  await p.waitForFunction(() => window.__cy && window.__cy.edges('[cls="THREAT_DDOS_VOLUME"]').length > 0, null, { timeout: 400000 });
  await p.waitForTimeout(1500);
  return p;
}

async function clickGraph(p, sel, mid) {
  const box = await p.locator('[data-testid="campaign-graph"]').boundingBox();
  const q = await p.evaluate(([s, m]) => { const e = window.__cy.$(s)[0]; const r = m ? e.renderedMidpoint() : e.renderedPosition(); return { x: r.x, y: r.y }; }, [sel, mid]);
  await p.mouse.click(box.x + q.x, box.y + q.y);
}

const b = await chromium.launch();
try {
  if (mode === '--ppt') {
    // facts strip first, while the replay is running (flows/s > 0) and the log already verifies
    // several alerts; cropped from the sensor name to the chain badge
    const s = await b.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 });
    await s.goto(url);
    await s.waitForFunction(() => {
      const t = document.querySelector('header')?.innerText || '';
      const m = t.match(/scored \/ s\s*([\d,.]+)/i);
      const v = t.match(/verified · (\d+) records/);
      return v && +v[1] >= 5 && m && parseFloat(m[1].replace(/,/g, '')) > 0;
    }, null, { timeout: 400000, polling: 500 });
    const hb = await s.locator('header').boundingBox();
    const facts = await s.locator('header .divide-x').boundingBox();
    const badge = await s.locator('header span:has-text("Alert log verified")').boundingBox();
    const shift = badge.x - (facts.x + facts.width + 24); // bring the badge next to the facts
    await s.evaluate((dx) => { document.querySelector('header .ml-auto').style.transform = `translateX(-${dx}px)`; }, shift);
    await s.screenshot({ path: `${dir}/05-facts-strip.png`, clip: { x: hb.x, y: hb.y, width: badge.x - shift + badge.width + 4, height: hb.height } });
    await s.close();

    const p = await openAtDdos(b, 1920, 1080);
    const n = await p.evaluate(async () => (await (await fetch('/api/v1/campaigns')).json()).campaigns.length);
    if (n < 4) fail(`only ${n} campaigns on screen`);
    // the chain badge refreshes debounced: wait until it counts every alert
    await p.waitForFunction(async () => {
      const k = (await (await fetch('/api/v1/alerts?limit=1000')).json()).alerts.length;
      return document.querySelector('header').innerText.includes(`verified · ${k} records`);
    }, null, { timeout: 15000, polling: 500 });
    const head = await p.locator('header').innerText();
    if (!/Bytes sent onto monitored link\s*0\b/i.test(head)) fail(`facts strip: ${head}`);
    await p.screenshot({ path: `${dir}/01-dashboard.png` });

    await clickGraph(p, `node[ip="${HOST}"]`, false);
    await p.waitForSelector('[data-testid="host-timeline"] ol', { timeout: 10000 });
    const tl = await p.locator('[data-testid="host-timeline"]').innerText();
    for (const t of ['Discovery', 'Command and Control', 'Exfiltration']) if (!tl.includes(t)) fail(`timeline lacks ${t}`);
    await p.screenshot({ path: `${dir}/02-host-timeline.png` });

    await p.getByLabel('Close timeline').click();
    await clickGraph(p, 'edge[cls="THREAT_EXFILTRATION"]', true);
    await p.waitForSelector('[data-testid="alert-drawer"] [data-testid="chain-verified"]', { timeout: 10000 });
    await p.waitForTimeout(500);
    await p.screenshot({ path: `${dir}/03-exfil-drawer.png` });

    await p.getByLabel('Close alert').click();
    await p.getByTestId('model-card-button').click();
    await p.waitForSelector('[data-testid="model-card"]');
    await p.waitForTimeout(300);
    await p.screenshot({ path: `${dir}/04-model-card.png` });
  } else {
    for (const [w, h] of [[1366, 768], [1920, 1080]]) {
      const p = await openAtDdos(b, w, h);
      await p.screenshot({ path: `${dir}/demo-${w}-graph.png` });
      await clickGraph(p, `node[ip="${HOST}"]`, false);
      await p.waitForSelector('[data-testid="host-timeline"] ol', { timeout: 10000 });
      await p.screenshot({ path: `${dir}/demo-${w}-timeline.png` });
      await clickGraph(p, 'edge[cls="THREAT_EXFILTRATION"]', true);
      await p.waitForSelector('[data-testid="alert-drawer"]');
      await p.waitForTimeout(500);
      await p.screenshot({ path: `${dir}/demo-${w}-drawer.png` });
      await p.close();
    }
  }
} finally {
  await b.close();
}
console.log('shots written to', dir);
