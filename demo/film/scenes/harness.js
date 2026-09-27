// Scene harness: the renderer calls setup(cfg) once, then seek(ms) per frame. cfg.cues are the
// narration line start times (seconds) from plan.py; build(tl, cue, cfg) adds the scene's tweens.
window.setup = (cfg) => {
  const tl = anime.createTimeline({ autoplay: false, defaults: { ease: 'outCubic' } });
  const cue = (i, dt = 0) => (cfg.cues[i].at + dt) * 1000; // ms of narration line i (+dt s)
  window.build(tl, cue, cfg);
  tl.seek(0);
  window.seek = (ms) => { tl.seek(ms); window.frame?.(ms / 1000, cfg); };
  window.seek(0);
  return true;
};
