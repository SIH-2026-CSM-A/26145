// Records the live part of the film: one real replay of demo/demo.pcap at 5x through the real
// pipeline, captured frame by frame with Chrome's screencast (1920x1080). It logs when each alert
// arrives and when its spark lands on its tile, then performs the scripted clicks (map + timeline,
// exfiltration case file + Verify, model card, the university C2 alerts), holding each state for as
// long as its narration in out/plan.json. Writes out/live.mp4 (30 fps CFR) and out/live-events.json.
// Usage: node film-record.mjs [PORT]
import { chromium } from '../../dashboard/node_modules/playwright/index.mjs';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const HERE = import.meta.dirname, OUT = resolve(HERE, 'out'), REPO = resolve(HERE, '../..');
const port = process.argv[2] || '18003', url = `http://127.0.0.1:${port}`, HOST = '192.168.1.66';
const plan = Object.fromEntries(JSON.parse(readFileSync(`${OUT}/plan.json`, 'utf8')).map((s) => [s.id, s]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Date.now() / 1000;
const marks = {};
const mark = (k) => { marks[k] = now(); console.log(`${k} ${(marks[k] - t0).toFixed(1)}`); };

// --pause only holds the final picture (the scripted part runs after the flood); it does not change
// what the pipeline sees
const server = spawn('uv', ['run', 'sih26145', 'serve', 'demo/demo.pcap', '--speed', '5', '--loop', '--pause', '900',
  '--host', '127.0.0.1', '--port', port], { cwd: REPO, stdio: 'ignore',
  env: { ...process.env, SIH26145_INTERNAL_CIDRS: '147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12' } });
process.on('exit', () => server.kill());
for (let k = 0; ; k++) { try { if ((await fetch(`${url}/api/v1/health`)).ok) break; } catch {} if (k > 120) throw new Error('server did not start'); await sleep(250); }

const dir = `${OUT}/live-frames`; rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
const b = await chromium.launch({ args: ['--hide-scrollbars'] });
const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
const frames = [];
const cdp = await p.context().newCDPSession(p);
cdp.on('Page.screencastFrame', async (f) => {
  const i = frames.length; frames.push(now());
  writeFileSync(`${dir}/${String(i).padStart(6, '0')}.jpg`, Buffer.from(f.data, 'base64'));
  await cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {});
});
await p.goto(url);
await cdp.send('Page.startScreencast', { format: 'jpeg', quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
const t0 = now();
mark('page');
// the page's own alert stream and tile pulses, on the same wall clock
await p.evaluate(() => {
  window.__ev = [];
  const es = new EventSource('/api/v1/stream/alerts');
  es.addEventListener('alert', (e) => { const a = JSON.parse(e.data); window.__ev.push({ t: Date.now() / 1000, kind: 'alert', cls: a.threat_class, src: a.flow?.src_ip, dst: a.flow?.dst_ip, id: a.alert_id }); });
  new MutationObserver((ms) => ms.forEach((m) => window.__ev.push({ t: Date.now() / 1000, kind: 'land', tile: m.target.dataset.testid, n: +m.target.dataset.pulses })))
    .observe(document.querySelector('[data-testid="threat-tiles"]'), { attributes: true, subtree: true, attributeFilter: ['data-pulses'] });
});

// wait for the flood's spark to land: all four campaigns are in
await p.waitForFunction(() => +document.querySelector('[data-testid="tile-a"]').dataset.pulses > 0, null, { timeout: 400000, polling: 100 });
mark('flood_landed');
await sleep((plan.flood.dur + 0.5) * 1000);

// 3e: the map, then the host's stage timeline
const hold = (id, extra = 1.2) => sleep((plan[id].dur + extra) * 1000);
mark('map');
await p.evaluate(() => document.getElementById('map').scrollIntoView({ behavior: 'smooth' }));
await sleep(3300);
await p.locator(`[data-ip="${HOST}"][data-host]`).click();
mark('map_click');
await sleep((plan.map.dur - 3.3 + 1.2) * 1000);
await p.getByLabel('Close timeline').click();
await sleep(1800);

// 4: the exfiltration case file; Verify when its line is spoken
const edge = await p.evaluate(() => {
  const e = document.querySelector('[data-testid="campaign-map"] [data-cls="THREAT_EXFILTRATION"] path');
  const t = e.getScreenCTM(), q = e.getPointAtLength(e.getTotalLength() / 2);
  return { x: t.a * q.x + t.c * q.y + t.e, y: t.b * q.x + t.d * q.y + t.f };
});
mark('case');
await sleep(500);
await p.mouse.click(edge.x, edge.y);
const verifyAt = plan.case.cues.at(-1).at + 0.9;
await sleep((verifyAt - 0.5) * 1000);
await p.getByTestId('verify-button').click();
mark('verify');
await sleep((plan.case.dur - verifyAt + 1.2) * 1000);
await p.getByLabel('Close alert').click();
await p.evaluate(() => window.scrollTo(0, 0));
await sleep(1500);

// 6a: the model card; outline the held-out result when its line is spoken
mark('card');
await sleep(300);
await p.getByTestId('model-card-button').click();
await sleep((plan.card.cues[1].at + 0.2 - 0.3) * 1000);
await p.evaluate(() => {
  const c = [...document.querySelectorAll('[data-testid="model-card"] .eyebrow')].find((e) => e.textContent === 'Held-out result')?.closest('.rounded-xl');
  if (c) { c.style.transition = 'box-shadow .4s'; c.style.boxShadow = '0 0 0 3px #fbbf24, 0 0 40px -6px #fbbf24'; }
});
await hold('card', 0.5 - plan.card.cues[1].at);
await p.getByLabel('Close model card').click();
await sleep(600);

// 6b: the map with the three C2 alerts on university hosts outlined
mark('fp');
await p.evaluate(() => document.getElementById('map').scrollIntoView({ behavior: 'smooth' }));
await sleep((plan.fp.cues[0].at + 0.3) * 1000);
await p.evaluate(() => {
  const NS = 'http://www.w3.org/2000/svg';
  for (const g of document.querySelectorAll('[data-testid="campaign-map"] [data-campaign]')) {
    const title = g.querySelector('[data-label="title"]')?.textContent || '';
    if (!title.startsWith('147.32.')) continue;
    // around the nodes and their labels (not the glow), with a margin
    const bs = [...g.querySelectorAll('[data-ip]')].map((e) => e.getBBox());
    const x0 = Math.min(...bs.map((b) => b.x)) - 28, y0 = Math.min(...bs.map((b) => b.y)) - 28;
    const x1 = Math.max(...bs.map((b) => b.x + b.width)) + 28, y1 = Math.max(...bs.map((b) => b.y + b.height)) + 28;
    const r = document.createElementNS(NS, 'rect');
    Object.entries({ x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 28, fill: 'none', stroke: '#fbbf24', 'stroke-width': 4, 'stroke-dasharray': '14 10' })
      .forEach(([k, v]) => r.setAttribute(k, v));
    g.appendChild(r);
  }
});
await hold('fp', 0.8 - plan.fp.cues[0].at);
mark('end');

await cdp.send('Page.stopScreencast');
const ev = await p.evaluate(() => window.__ev);
await b.close();
server.kill();

// constant 30 fps from the screencast's variable-rate frames
const list = frames.map((t, i) => `file '${dir}/${String(i).padStart(6, '0')}.jpg'\nduration ${((frames[i + 1] ?? t + 1 / 30) - t).toFixed(4)}`);
writeFileSync(`${OUT}/live-frames.txt`, `${list.join('\n')}\nfile '${dir}/${String(frames.length - 1).padStart(6, '0')}.jpg'\n`);
const r = spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', `${OUT}/live-frames.txt`, '-vf', 'fps=30',
  '-c:v', 'libx264', '-crf', '16', '-preset', 'medium', '-pix_fmt', 'yuv420p', `${OUT}/live.mp4`], { stdio: 'inherit' });
if (r.status) throw new Error('ffmpeg failed');
const rel = (t) => +(t - frames[0]).toFixed(3);
writeFileSync(`${OUT}/live-events.json`, JSON.stringify({
  frames: frames.length, seconds: rel(frames.at(-1)), fps: +(frames.length / (frames.at(-1) - frames[0])).toFixed(1),
  marks: Object.fromEntries(Object.entries(marks).map(([k, v]) => [k, rel(v)])),
  events: ev.map((e) => ({ ...e, t: rel(e.t) })),
}, null, 1));
console.log(`live.mp4: ${frames.length} frames over ${rel(frames.at(-1))} s`);
rmSync(dir, { recursive: true, force: true });
