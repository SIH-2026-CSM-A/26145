// Renders the film's HTML scenes frame by frame (seek, screenshot) at 30 fps, 1920x1080, into
// out/scenes/<id>.mp4. Each scene gets its narration cue times from out/plan.json.
// Usage: node render-scenes.mjs [id ...]            (default: every scene segment)
//        node render-scenes.mjs --preview id s1,s2  (PNG stills at those seconds, into out/preview)
import { chromium } from '../../dashboard/node_modules/playwright/index.mjs';
import { mkdirSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const HERE = import.meta.dirname, OUT = resolve(HERE, 'out'), FPS = 30;
const plan = JSON.parse(readFileSync(`${OUT}/plan.json`, 'utf8'));
const args = process.argv.slice(2);
const preview = args[0] === '--preview';
const ids = preview ? [args[1]] : args.length ? args : plan.filter((s) => s.kind === 'scene').map((s) => s.id);
const data = existsSync(`${OUT}/tamper.json`) ? JSON.parse(readFileSync(`${OUT}/tamper.json`, 'utf8')) : null;

const b = await chromium.launch({ args: ['--allow-file-access-from-files'] });
try {
  for (const id of ids) {
    const seg = plan.find((s) => s.id === id);
    const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
    const errs = []; p.on('pageerror', (e) => errs.push(String(e)));
    await p.goto(`file://${HERE}/scenes/${id}.html`);
    await p.evaluate(() => document.fonts.ready);
    await p.evaluate((cfg) => window.setup(cfg), { cues: seg.cues, dur: seg.dur, data });
    if (errs.length) throw new Error(`${id}: ${errs.join(' | ')}`);
    if (preview) {
      mkdirSync(`${OUT}/preview`, { recursive: true });
      for (const s of args[2].split(',').map(Number)) {
        await p.evaluate((ms) => window.seek(ms), s * 1000);
        await p.screenshot({ path: `${OUT}/preview/${id}-${s}.png` });
      }
    } else {
      const dir = `${OUT}/scenes/${id}`; rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
      const n = Math.round(seg.dur * FPS);
      for (let f = 0; f < n; f++) {
        await p.evaluate((ms) => window.seek(ms), (f * 1000) / FPS);
        await p.screenshot({ path: `${dir}/${String(f).padStart(5, '0')}.jpg`, type: 'jpeg', quality: 95 });
      }
      const r = spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', String(FPS), '-i', `${dir}/%05d.jpg`, '-c:v', 'libx264',
        '-crf', '16', '-preset', 'medium', '-pix_fmt', 'yuv420p', `${OUT}/scenes/${id}.mp4`], { stdio: 'inherit' });
      if (r.status) throw new Error(`ffmpeg failed on ${id}`);
      rmSync(dir, { recursive: true, force: true });
      console.log(`${id}: ${n} frames, ${seg.dur} s`);
    }
    await p.close();
  }
} finally { await b.close(); }
