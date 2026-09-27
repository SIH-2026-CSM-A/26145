// Deck stills (1920x1080) of the running demo, each taken only after what it shows has been
// asserted on the page. Needs a replay of demo/demo.pcap with a long hold, so the final picture
// stays up while stills 2-5 are taken:
//   SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 \
//     uv run sih26145 serve demo/demo.pcap --speed 5 --loop --pause 600 --port 18001 &
//   node tests/demo-shots.mjs http://127.0.0.1:18001 OUT_DIR
// Writes s6-01 .. s6-06 (s6-07, the verify-log terminal, is scripts/render_verify_log.py).
import { chromium } from 'playwright';

const [url, dir] = process.argv.slice(2);
const HOST = '192.168.1.66';
const fail = (msg) => { console.error(`SHOTS FAIL: ${msg}`); process.exit(1); };
const api = async (path) => (await fetch(`${url}/api/v1${path}`)).json();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// clicks the middle of a map line with a real mouse
async function clickEdge(p, cls) {
  const m = await p.evaluate((c) => {
    const e = document.querySelector(`[data-testid="campaign-map"] [data-cls="${c}"] path`);
    const t = e.getScreenCTM(), q = e.getPointAtLength(e.getTotalLength() / 2);
    return { x: t.a * q.x + t.c * q.y + t.e, y: t.b * q.x + t.d * q.y + t.f };
  }, cls);
  await p.mouse.click(m.x, m.y);
}

const b = await chromium.launch();
try {
  // join at the start of a loop, so every alert arrives live (sparks, pulses, counters)
  process.stdout.write('waiting for a loop to start ');
  for (let k = 0; (await api('/campaigns')).count > 0 || (await api('/metrics')).pipeline_state !== 'running'; k++) {
    if (k > 900) fail('no loop start within 15 min'); await sleep(1000);
  }
  console.log('ok');
  const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
  await p.goto(url);
  const s = await b.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 });
  await s.goto(url);

  // 6: KPI strip at 2x, while the replay runs (live rate) and the log verifies several records
  await s.waitForFunction(() => {
    const t = document.querySelector('[data-testid="kpi-chain"]')?.innerText || '';
    return (+(t.match(/(\d+)\s*records/) || [])[1] >= 5) && parseFloat(document.querySelector('[data-testid="kpi-fps"] .kpi')?.textContent) > 0;
  }, null, { timeout: 400000, polling: 500 }).catch(() => fail('KPI strip never showed a live rate with >= 5 verified records'));
  await s.waitForTimeout(1200);
  await s.locator('[data-testid="kpi-strip"]').screenshot({ path: `${dir}/s6-06-kpi-strip.png` });
  await s.close();

  // 1: the flood's spark lands on tile (a): all four campaigns are in
  await p.waitForFunction(() => +document.querySelector('[data-testid="tile-a"]').dataset.pulses > 0, null, { timeout: 400000, polling: 100 })
    .catch(() => fail('tile (a) never pulsed'));
  await p.waitForTimeout(250);
  const n = (await api('/campaigns')).count;
  if (n !== 4) fail(`${n} campaigns, expected 4`);
  const ribbon = await p.locator('[data-testid="campaign-list"] > li').count();
  if (ribbon !== 4) fail(`ribbon shows ${ribbon} campaigns`);
  if (!/Bytes sent back\s*0/.test(await p.getByTestId('bytes-back').innerText())) fail('no "Bytes sent back 0"');
  for (const t of ['a', 'b', 'c', 'd', 'e', 'f']) if (!(await p.getByTestId(`tile-${t}-latest`).count())) fail(`tile ${t} has no latest alert`);
  await p.screenshot({ path: `${dir}/s6-01-hero-tiles-kpi.png` });
  console.log('s6-01 at pipeline state', (await api('/metrics')).pipeline_state);

  // 2: the campaign map, all four campaigns, no label overlap
  await p.locator('#map').evaluate((e) => e.scrollIntoView());
  await p.waitForTimeout(1500);
  const map = await p.evaluate(() => {
    const r = [...document.querySelectorAll('[data-testid="campaign-map"] [data-label]')].map((e) => e.getBoundingClientRect());
    let hit = 0;
    for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) {
      const A = r[i], B = r[j]; if (A.left < B.right && B.left < A.right && A.top < B.bottom && B.top < A.bottom) hit++;
    }
    return { clusters: document.querySelectorAll('[data-testid="campaign-map"] [data-campaign]').length, hit };
  });
  if (map.clusters !== 4 || map.hit) fail(`map: ${JSON.stringify(map)}`);
  await p.screenshot({ path: `${dir}/s6-02-campaign-map.png` });

  // 3: the host's stage timeline
  await p.locator(`[data-ip="${HOST}"][data-host]`).click();
  await p.waitForSelector('[data-testid="host-timeline"] [data-stage]');
  await p.waitForTimeout(3500); // cards animate in order
  const stages = await p.locator('[data-testid="host-timeline"] [data-stage]').evaluateAll((e) => [...new Set(e.map((x) => x.dataset.stage))]);
  if (stages.join('|') !== 'Discovery|Command and Control|Exfiltration') fail(`stages: ${stages}`);
  await p.locator('#map').evaluate((e) => e.scrollIntoView());
  await p.screenshot({ path: `${dir}/s6-03-stage-timeline-${HOST}.png` });
  await p.getByLabel('Close timeline').click();
  await p.waitForTimeout(1200);

  // 4: the exfiltration case file, chain verified just now, every line inside the frame
  await clickEdge(p, 'THREAT_EXFILTRATION');
  await p.waitForSelector('[data-testid="alert-drawer"]');
  await p.getByTestId('verify-button').click();
  await p.waitForFunction(() => /verified just now/.test(document.querySelector('[data-testid="chain-verified"]')?.textContent || ''), null, { timeout: 10000 })
    .catch(() => fail('chain did not verify'));
  await p.waitForTimeout(1200);
  const fits = await p.evaluate(() => { const d = document.querySelector('[data-testid="alert-drawer"] .overflow-y-auto'); return d.scrollHeight <= d.clientHeight + 1; });
  if (!fits) fail('case file does not fit the frame');
  await p.screenshot({ path: `${dir}/s6-04-exfil-case-file.png` });
  await p.getByLabel('Close alert').click();

  // 5: the model card
  await p.locator('#root').evaluate(() => window.scrollTo(0, 0));
  await p.getByTestId('model-card-button').click();
  await p.waitForSelector('[data-testid="model-card"]');
  await p.waitForTimeout(900);
  await p.screenshot({ path: `${dir}/s6-05-model-card.png` });
} finally {
  await b.close();
}
console.log('stills written to', dir);
