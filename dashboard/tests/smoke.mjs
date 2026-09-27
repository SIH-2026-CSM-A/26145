// Headless smoke test of the served dashboard, opened before the (paced) replay raises alerts:
// the hero renders, a threat tile pulses when an alert lands, the campaign map draws with no two
// labels overlapping, clicking a line opens the case file, Verify recomputes the chain, the 2D
// fallback (?nogl) renders, and no request leaves the origin.
// Usage: node tests/smoke.mjs http://127.0.0.1:8765 [screenshot-dir]
import { chromium } from 'playwright';

const url = process.argv[2] || 'http://127.0.0.1:8000';
const shots = process.argv[3];
const fail = (msg) => { console.error(`SMOKE FAIL: ${msg}`); process.exit(1); };

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  const errors = [], offsite = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('request', (r) => { if (!r.url().startsWith(url) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) offsite.push(r.url()); });
  await page.goto(url, { waitUntil: 'domcontentloaded' });

  await page.waitForSelector('[data-testid="hero-webgl"], [data-testid="hero-2d"]', { timeout: 15000 }).catch(() => fail('hero did not render'));
  console.log(`hero: ${await page.locator('[data-testid="hero-webgl"]').count() ? 'webgl' : '2d'}`);
  await page.waitForSelector('[data-testid="bytes-back"]');

  await page.waitForFunction(() => [...document.querySelectorAll('[data-testid^="tile-"][data-pulses]')].some((t) => +t.dataset.pulses > 0),
    null, { timeout: 120000, polling: 250 }).catch(() => fail('no threat tile pulsed on an alert within 120 s'));
  const pulsed = await page.evaluate(() => [...document.querySelectorAll('[data-pulses]')].filter((t) => +t.dataset.pulses > 0).map((t) => t.dataset.testid));
  console.log(`pulsed: ${pulsed.join(', ')}`);
  if (shots) await page.screenshot({ path: `${shots}/live-1920x1080.png` });

  await page.locator('#map').scrollIntoViewIfNeeded();
  await page.waitForSelector('[data-testid="campaign-map"] [data-edge]', { state: 'attached', timeout: 60000 }).catch(() => fail('campaign map drew no lines'));
  await page.waitForTimeout(1200); // edges draw in
  const overlaps = await page.evaluate(() => {
    const r = [...document.querySelectorAll('[data-testid="campaign-map"] [data-label]')].map((e) => [e.textContent, e.getBoundingClientRect()]);
    const out = [];
    for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) {
      const [a, A] = r[i], [b, B] = r[j];
      if (A.left < B.right && B.left < A.right && A.top < B.bottom && B.top < A.bottom) out.push(`${a} / ${b}`);
    }
    return { n: r.length, out };
  });
  console.log(`map: ${overlaps.n} labels`);
  if (overlaps.out.length) fail(`map labels overlap: ${overlaps.out.join(' | ')}`);
  if (shots) await page.screenshot({ path: `${shots}/map-1920x1080.png` });

  // a real mouse click on the middle of the first line
  const mid = await page.evaluate(() => {
    const p = document.querySelector('[data-testid="campaign-map"] [data-edge] path');
    const m = p.getScreenCTM(), q = p.getPointAtLength(p.getTotalLength() / 2);
    return { x: m.a * q.x + m.c * q.y + m.e, y: m.b * q.x + m.d * q.y + m.f };
  });
  await page.mouse.click(mid.x, mid.y);
  await page.waitForSelector('[data-testid="alert-drawer"]', { timeout: 5000 }).catch(() => fail('case file did not open'));
  console.log(`case file: ${await page.locator('[data-testid="alert-drawer"] h2').innerText()}`);
  await page.getByTestId('verify-button').click();
  await page.waitForFunction(() => /verified just now/.test(document.querySelector('[data-testid="chain-verified"]')?.textContent || ''),
    null, { timeout: 10000 }).catch(() => fail('Verify did not recompute the chain'));
  if (shots) await page.screenshot({ path: `${shots}/casefile-1920x1080.png` });

  const flat = await browser.newPage({ viewport: { width: 1366, height: 768 } });
  flat.on('pageerror', (e) => errors.push(`?nogl: ${e}`));
  await flat.goto(`${url}/?nogl`);
  await flat.waitForSelector('[data-testid="hero-2d"] canvas', { timeout: 10000 }).catch(() => fail('2D fallback did not render'));
  if (shots) { await flat.waitForTimeout(1500); await flat.screenshot({ path: `${shots}/nogl-1366x768.png` }); }

  if (errors.length) fail(`page errors: ${errors.join(' | ')}`);
  if (offsite.length) fail(`requests left the origin: ${offsite.join(', ')}`);
  console.log('SMOKE PASS');
} finally {
  await browser.close();
}
