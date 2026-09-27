// Records the captioned demo walkthrough (1920x1080 mp4) against a local replay of demo/demo.pcap
// at 2x real time through the real pipeline. Every caption waits for what it describes to be on the
// page (or in the API the page reads); a beat whose precondition never appears is skipped and
// reported, never captioned. Needs dashboard/dist (npm run build) and ffmpeg with libx264.
// Usage (from dashboard/): node tests/demo-video.mjs OUT.mp4 [PORT]
import { chromium } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const out = resolve(process.argv[2] || 'sih26145-demo.mp4');
const port = process.argv[3] || '18001';
const url = `http://127.0.0.1:${port}`;
const HOST = '192.168.1.66';
const REPO = resolve(import.meta.dirname, '../..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skipped = [];

// ---- the replay: --pause only holds the final picture longer, so the walkthrough after the flood
// is not cut by the loop reset; it does not change what the pipeline sees
const server = spawn('uv', ['run', 'sih26145', 'serve', 'demo/demo.pcap', '--speed', '2', '--loop', '--pause', '240',
  '--host', '127.0.0.1', '--port', port], {
  cwd: REPO, env: { ...process.env, SIH26145_INTERNAL_CIDRS: '147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12' },
});
const loopStart = new Promise((res) => {
  const seen = (d) => { if (/loop 1\b/.test(String(d))) res(Date.now()); };
  server.stdout.on('data', seen);
  server.stderr.on('data', seen);
});
process.on('exit', () => server.kill());

const CSS = `
.h-screen { height: calc(100vh - 120px) !important; }
#__cap { position: fixed; left: 0; right: 0; bottom: 0; height: 120px; z-index: 50; display: flex; align-items: center;
  justify-content: center; padding: 0 64px; background: #020617; border-top: 2px solid #334155; color: #f8fafc;
  font: 600 33px/1.25 system-ui, sans-serif; text-align: center; }
#__card { position: fixed; inset: 0; z-index: 60; background: #020617; color: #f8fafc; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 22px; font-family: system-ui, sans-serif; text-align: center; padding: 0 120px; }
#__card h1 { font-size: 110px; font-weight: 800; letter-spacing: 0.08em; margin: 0; color: #7dd3fc; }
#__card .big { font-size: 44px; font-weight: 600; }
#__card .small { font-size: 32px; color: #cbd5e1; max-width: 1500px; line-height: 1.35; }
.__spot { outline: 4px solid #fbbf24 !important; outline-offset: 3px; border-radius: 8px; }`;

const b = await chromium.launch();
const tmp = mkdtempSync(join(tmpdir(), 'sih-video-'));
let recordT0;
try {
  const t0 = await Promise.race([loopStart, sleep(60000).then(() => { throw new Error('replay did not start'); })]);
  await sleep(Math.max(0, t0 + 30000 - Date.now())); // join 30 s into the 60 s quiet period
  const ctx = await b.newContext({ viewport: { width: 1920, height: 1080 }, recordVideo: { dir: tmp, size: { width: 1920, height: 1080 } } });
  await ctx.addInitScript((css) => {
    document.addEventListener('DOMContentLoaded', () => {
      const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s);
      const c = document.createElement('div'); c.id = '__cap'; document.body.appendChild(c);
    });
  }, CSS);
  recordT0 = Date.now();
  const p = await ctx.newPage();
  await p.goto(url, { waitUntil: 'domcontentloaded' });
  await p.waitForSelector('#__cap');
  const trim = (Date.now() - recordT0) / 1000;

  const cap = (t) => p.evaluate((t) => { document.getElementById('__cap').textContent = t; }, t);
  const say = async (t, s) => { await cap(t); await sleep(s * 1000); };
  const card = (html) => p.evaluate((h) => {
    let c = document.getElementById('__card');
    if (!h) { c?.remove(); return; }
    if (!c) { c = document.createElement('div'); c.id = '__card'; document.body.appendChild(c); }
    c.innerHTML = h;
  }, html);
  // outline what a caption talks about; nth picks one match (negative counts from the end)
  const spot = (sel, on = true, nth = null) => p.evaluate(([s, o, n]) => {
    const all = [...document.querySelectorAll(s)];
    (n === null ? all : [all.at(n)]).forEach((e) => e?.classList.toggle('__spot', o));
  }, [sel, on, nth]);
  const api = (path) => p.evaluate(async (u) => (await fetch(`/api/v1${u}`)).json(), path);
  // the host's edge of a class, once it is drawn: its campaign id, or null on timeout
  const hostEdge = (cls, ms) => p.waitForFunction(([c, h]) => {
    const e = window.__cy?.edges(`[cls="${c}"]`).filter((x) => x.source().data('ip') === h || x.target().data('ip') === h)[0];
    return e ? e.data('campaign') : null;
  }, [cls, HOST], { timeout: ms, polling: 250 }).then((h) => h.jsonValue()).catch(() => null);
  const clickGraph = async (sel, mid) => {
    const box = await p.locator('[data-testid="campaign-graph"]').boundingBox();
    const q = await p.evaluate(([s, m]) => { const e = window.__cy.$(s)[0]; const r = m ? e.renderedMidpoint() : e.renderedPosition(); return { x: r.x, y: r.y }; }, [sel, mid]);
    await p.mouse.click(box.x + q.x, box.y + q.y);
  };

  // 1. title card
  await card(`<h1>SAAKSHI</h1><div class="big">SIH26145 · Team F.R.I.E.N.D.S</div>
    <div class="small">A committed capture (real CTU-13 university traffic plus generated attack packets),
    replayed at 2× real time through the real detection pipeline. Nothing on screen is mocked.</div>`);
  await sleep(3500);
  await card(null);

  // 2. the quiet link
  await say('Replayed at 2× real time: real university traffic is crossing the link. Nothing suspicious yet.', 7);
  await spot('header .divide-x');
  await say('These figures come from the running pipeline: flows scored per second, throughput, and queue drops (every drop is counted).', 7);
  await say('Its capacity, measured on one laptop core: about 860 flows per second (docs/BENCHMARK.md). The demo runs far below that.', 7);
  await spot('header .divide-x', false);
  await spot('header .divide-x > div:last-child');
  await say('Bytes sent onto the monitored link: 0. The sensor sits behind a one-way data diode and has no transmit path.', 8);
  await spot('header .divide-x > div:last-child', false);

  // 3. the attack chain on one host, as it happens
  const campaign = await hostEdge('THREAT_RECON_PORTSCAN', 120000);
  if (!campaign) throw new Error('no scan from the demo host');
  const scanned = await p.evaluate((h) => window.__cy.edges('[cls="THREAT_RECON_PORTSCAN"]').filter((e) => e.source().data('ip') === h)[0].target().data('ip'), HOST);
  await say(`${HOST} scans many ports on ${scanned} (Discovery). Its alert opens a campaign.`, 6);
  const steps = [
    ['THREAT_C2_BEACON', 'C2 beacon: regular check-ins to an outside server'],
    ['THREAT_ENCRYPTED_ANOMALY', 'Rare TLS client: an unusual encrypted client repeatedly contacting one server'],
    ['THREAT_DNS_DGA', 'DGA: lookups of many random-looking domain names'],
    ['THREAT_DNS_TUNNEL', 'DNS tunnel: data hidden inside DNS lookups'],
    ['THREAT_EXFILTRATION', 'Exfiltration: a large upload leaving the network'],
  ];
  let first = true;
  for (const [cls, text] of steps) {
    if (!first) await cap('Alerts that share a rare host, server, name or fingerprint are grouped into one campaign.');
    const c = await hostEdge(cls, 150000);
    if (!c) { skipped.push(`beat 3: no ${cls} on ${HOST}`); continue; }
    await say(`${text}. ${c === campaign ? `It joins ${HOST}'s campaign.` : 'It forms a separate campaign.'}`, 7);
    first = false;
  }

  // 4. the host's stage timeline
  await clickGraph(`node[ip="${HOST}"]`, false);
  await p.waitForSelector('[data-testid="host-timeline"] ol', { timeout: 10000 });
  const tactics = await p.locator('[data-testid="host-timeline"] ol li .text-sm').allInnerTexts();
  await say(`Click the host: the stages seen on ${HOST}, in order: ${[...new Set(tactics)].join(' → ')}.`, 7);
  await say('This is observed history, not a prediction of the next step.', 5);
  await p.getByLabel('Close timeline').click();

  // 5. the exfiltration evidence
  await clickGraph('edge[cls="THREAT_EXFILTRATION"]', true);
  await p.waitForSelector('[data-testid="alert-drawer"]');
  await spot('[data-testid="alert-drawer"] table');
  await say('Click the upload: the evidence. Each feature\'s value is shown next to its normal level or threshold.', 7);
  await say('The chip on each row says what this link could supply for that feature, as declared in the feature contract.', 7);
  await spot('[data-testid="alert-drawer"] table', false);
  const obs = await p.locator('[data-testid="alert-drawer"] section:has-text("What this link could see") div.text-slate-100').innerText();
  await spot('[data-testid="alert-drawer"] section.rounded-lg', true, 0);
  await say(`What this link could see for this flow: "${obs}". The sensor measures it per flow and never assumes it.`, 7);
  await spot('[data-testid="alert-drawer"] section.rounded-lg', false, 0);
  if (await p.locator('[data-testid="chain-verified"]').isVisible()) {
    await spot('[data-testid="alert-drawer"] section.rounded-lg', true, -1);
    await say('Every stored alert is linked into a SHA-256 hash chain. The server recomputed it just now: chain verified.', 7);
    await spot('[data-testid="alert-drawer"] section.rounded-lg', false, -1);
  } else skipped.push('beat 5: chain-verified badge not visible');
  await p.getByLabel('Close alert').click();

  // 6. the flood, as its own campaign
  const ddos = await p.waitForFunction(() => window.__cy?.edges('[cls="THREAT_DDOS_VOLUME"]')[0]?.data('campaign') || null, null, { timeout: 120000 })
    .then((h) => h.jsonValue()).catch(() => null);
  if (ddos) {
    const target = await p.evaluate(() => window.__cy.edges('[cls="THREAT_DDOS_VOLUME"]')[0].target().data('ip'));
    await spot('[data-testid="campaign-list"] li', true, 0);
    await say(`The SYN flood on ${target} is ${ddos === campaign ? `in ${HOST}'s campaign` : 'its own campaign: it shares no rare host, server, name or fingerprint with the others'}.`, 7);
    await spot('[data-testid="campaign-list"] li', false, 0);
    const notMerged = await p.locator('[data-testid="campaign-list"] :text("not merged")').first();
    if (await notMerged.count()) {
      await spot('[data-testid="campaign-list"] .text-amber-300\\/90');
      await say(`The correlator records why it kept campaigns apart: "${(await notMerged.innerText()).replace(/^⊘\s*/, '')}".`, 8);
      await spot('[data-testid="campaign-list"] .text-amber-300\\/90', false);
    } else skipped.push('beat 6: no "not merged" note on screen');
  } else skipped.push('beat 6: no DDoS alert');

  // 7. the model card
  await p.getByTestId('model-card-button').click();
  await p.waitForSelector('[data-testid="model-card"]');
  await say('Model card. Validated by leaving one CTU-13 scenario out: every score comes from a model that never saw that capture.', 8);
  await say('Its threshold is set for 1 ML-only false positive per 10,000 benign flows. ML-only alerts are capped at MEDIUM.', 7);
  await say('It never sees DNS names, TLS fingerprints or payload. DGA, DNS tunnel and encrypted-session alerts come from the rules.', 8);
  await p.getByLabel('Close model card').click();

  // 8. the false positives, shown as they are
  const { alerts } = await api('/alerts?limit=1000');
  // either end: one of them is an inbound flow to a university host
  const uni = (a) => [a.flow?.src_ip, a.flow?.dst_ip].find((ip) => ip?.startsWith('147.32.'));
  const fp = alerts.filter((a) => a.threat_class === 'THREAT_C2_BEACON' && uni(a));
  if (fp.length) {
    const hosts = [...new Set(fp.map(uni))];
    const item = p.locator('[data-testid="campaign-list"] button', { hasText: hosts[0] }).first();
    await item.click();
    await say(`The ${fp.length} C2 alerts on real university hosts (${hosts.join(', ')}) are false positives. They are shown as they are.`, 8);
    await say('C2 is the noisiest rule on real traffic: 97.3 alerts per 10,000 flows on held-out CTU-13 s12 (docs/RULES.md).', 7);
    await item.click();
  } else skipped.push('beat 8: no C2 alert on a 147.32.x host');

  // 9. end card
  await cap('');
  await card(`<div class="big">github.com/SIH-2026-CSM-A/26145</div>
    <div class="small">All numbers are measured. See docs/BENCHMARK.md, docs/MODELS.md and docs/RULES.md.</div>
    <div class="small">SAAKSHI · SIH26145 · Team F.R.I.E.N.D.S</div>`);
  await sleep(5000);

  const video = p.video();
  await ctx.close();
  const webm = await video.path();
  const r = spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', trim.toFixed(2), '-i', webm, '-c:v', 'libx264', '-crf', '18',
    '-preset', 'slow', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-an', out], { stdio: 'inherit' });
  if (r.status !== 0) throw new Error('ffmpeg failed');
  console.log(`video: ${out}`);
  console.log(skipped.length ? `skipped beats:\n  ${skipped.join('\n  ')}` : 'all beats shown');
} finally {
  await b.close();
  server.kill();
  rmSync(tmp, { recursive: true, force: true });
}
