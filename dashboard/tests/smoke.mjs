// Headless smoke test of the served dashboard: page loads, the campaign graph renders nodes,
// clicking an alert edge opens the drawer. Usage: node tests/smoke.mjs http://127.0.0.1:8765 [screenshot-dir]
import { chromium } from 'playwright';

const url = process.argv[2] || 'http://127.0.0.1:8000';
const shots = process.argv[3];
const fail = (msg) => { console.error(`SMOKE FAIL: ${msg}`); process.exit(1); };

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1366, height: 768 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  const offsite = [];
  page.on('request', (r) => { if (!r.url().startsWith(url) && !r.url().startsWith('data:')) offsite.push(r.url()); });
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('[data-testid="campaign-graph"]', { timeout: 15000 });
  await page.waitForFunction(() => window.__cy && window.__cy.edges().length > 0, null, { timeout: 60000 })
    .catch(() => fail('graph rendered no alert edges within 60 s'));
  const n = await page.evaluate(() => ({ nodes: window.__cy.nodes().length, edges: window.__cy.edges().length }));
  console.log(`graph: ${n.nodes} nodes, ${n.edges} edges`);
  await page.waitForTimeout(500);
  if (shots) await page.screenshot({ path: `${shots}/dashboard-1366x768.png` });

  // a real mouse click on the middle of the first edge
  const mid = await page.evaluate(() => { const p = window.__cy.edges()[0].renderedMidpoint(); return { x: p.x, y: p.y }; });
  const box = await page.locator('[data-testid="campaign-graph"]').boundingBox();
  await page.mouse.click(box.x + mid.x, box.y + mid.y);
  await page.waitForSelector('[data-testid="alert-drawer"]', { timeout: 5000 }).catch(() => fail('alert drawer did not open'));
  const title = await page.locator('[data-testid="alert-drawer"] h2').innerText();
  console.log(`drawer: ${title}`);
  await page.waitForSelector('[data-testid="chain-verified"]', { timeout: 10000 }).catch(() => fail('chain not verified in drawer'));
  if (shots) {
    await page.screenshot({ path: `${shots}/drawer-1366x768.png` });
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.waitForTimeout(500);
    await page.screenshot({ path: `${shots}/drawer-1920x1080.png` });
  }
  if (errors.length) fail(`page errors: ${errors.join(' | ')}`);
  if (offsite.length) fail(`requests left the origin: ${offsite.join(', ')}`);
  console.log('SMOKE PASS');
} finally {
  await browser.close();
}
