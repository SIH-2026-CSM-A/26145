// Screenshots of the running demo at 1366x768 and 1920x1080 (for slides): the graph once the
// DDoS campaign has appeared, the attacked host's stage timeline, and the exfiltration drawer.
// Usage: PORT=18001 scripts/demo.sh &  then  node tests/demo-shots.mjs http://127.0.0.1:18001 OUT_DIR
import { chromium } from 'playwright';

const [url, dir] = process.argv.slice(2);
const HOST = '192.168.1.66';
const b = await chromium.launch();
try {
  for (const [w, h] of [[1366, 768], [1920, 1080]]) {
    const p = await b.newPage({ viewport: { width: w, height: h } });
    await p.goto(url);
    await p.waitForFunction(() => window.__cy && window.__cy.edges('[cls="THREAT_DDOS_VOLUME"]').length > 0, null, { timeout: 300000 });
    await p.waitForTimeout(1500);
    await p.screenshot({ path: `${dir}/demo-${w}-graph.png` });
    const box = await p.locator('[data-testid="campaign-graph"]').boundingBox();
    const at = (sel, mid) => p.evaluate(([s, m]) => { const e = window.__cy.$(s)[0]; const q = m ? e.renderedMidpoint() : e.renderedPosition(); return { x: q.x, y: q.y }; }, [sel, mid]);
    const n = await at(`node[ip="${HOST}"]`, false);
    await p.mouse.click(box.x + n.x, box.y + n.y);
    await p.waitForSelector('[data-testid="host-timeline"] ol', { timeout: 10000 });
    await p.screenshot({ path: `${dir}/demo-${w}-timeline.png` });
    const e = await at('edge[cls="THREAT_EXFILTRATION"]', true);
    await p.mouse.click(box.x + e.x, box.y + e.y);
    await p.waitForSelector('[data-testid="alert-drawer"]');
    await p.waitForTimeout(500);
    await p.screenshot({ path: `${dir}/demo-${w}-drawer.png` });
    await p.close();
  }
} finally {
  await b.close();
}
console.log('shots written to', dir);
