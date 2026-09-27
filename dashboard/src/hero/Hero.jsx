import React, { forwardRef, lazy, Suspense, useCallback, useEffect, useImperativeHandle, useMemo, useRef } from 'react';
import { useReducedMotion } from 'motion/react';
import { Lock } from 'lucide-react';
import { FLOWS_PER_DOT, makeHosts, makeSim } from './sim';
import Scene2D from './Scene2D';

const Scene3D = lazy(() => import('./Scene3D'));
const hasWebGL = !new URLSearchParams(location.search).has('nogl') && (() => { // ?nogl forces the fallback
  try { const c = document.createElement('canvas'); return !!(c.getContext('webgl2') || c.getContext('webgl')); } catch { return false; }
})();

const Label = ({ title, sub }) => (
  <div className="text-center whitespace-nowrap pointer-events-none select-none">
    <div className="text-base font-semibold text-fg [text-shadow:0_0_12px_rgb(4_8_20)]">{title}</div>
    <div className="text-xs text-dim">{sub}</div>
  </div>
);

// The hero: the production network on the left, the diode, the enclave on the right. Dots move
// left to right at a rate proportional to the flows/s the pipeline measures. An alert's flow is
// a coloured spark; on reaching the enclave it calls back with its page position.
const Hero = forwardRef(function Hero({ metrics }, ref) {
  const reduced = useReducedMotion();
  const hosts = useMemo(() => makeHosts(), []);
  const sim = useMemo(() => makeSim(hosts), [hosts]);
  const rate = useRef(0), enclaveAt = useRef({ x: 0, y: 0 }), box = useRef(null), primed = useRef(false);
  const running = metrics?.pipeline_state === 'running';
  const fps = running ? metrics.flows_per_sec || 0 : 0;

  useEffect(() => {
    rate.current = fps;
    if (fps > 0 && !primed.current) { // start with the link already in motion, never an empty stage
      primed.current = true;
      for (let i = 0; i < 60; i++) sim.step(0.05, fps);
    }
  }, [fps, sim]);

  useImperativeHandle(ref, () => ({
    launch(color, onArrive) {
      const done = () => {
        const r = box.current.getBoundingClientRect();
        onArrive({ x: r.left + enclaveAt.current.x, y: r.top + enclaveAt.current.y });
      };
      if (reduced) done(); else sim.spawn({ color, onArrive: done });
    },
  }), [sim, reduced]);

  // labels are plain DOM; the active scene projects each anchor and moves it (no re-render per frame)
  const labelEls = useRef({});
  const place = useCallback((k, x, y) => { const e = labelEls.current[k]; if (e) e.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`; }, []);
  const labels = useMemo(() => [
    { key: 'net', at: [-4.3, 2.25, 0], node: <Label title="Production network" sub="the monitored link" /> },
    { key: 'diode', at: [0, 2.3, 0], node: <Label title="Data diode" sub="light travels one way" /> },
    { key: 'enc', at: [4.2, 2.25, 0], node: <Label title="SAAKSHI enclave" sub="listens, never transmits" /> },
    { key: 'back', at: [0, -1.95, 0.3], node: (
      <div className="flex items-center gap-2 rounded-full bg-ink/90 px-3 py-1 ring-1 ring-safe/40 whitespace-nowrap"
           title="True by construction: tests/ingest/test_no_transmit.py fails if the capture or ingest path gains a socket, a send or a writable open."
           data-testid="bytes-back">
        <Lock className="h-4 w-4 text-safe" />
        <span className="text-sm text-dim">Return path: none · Bytes sent back</span>
        <span className="font-mono text-base font-bold text-safe">0</span>
      </div>) },
  ], []);
  const props = { sim, hosts, rate, still: !!reduced, enclaveAt, labels, place };
  return (
    <section className="glass relative overflow-hidden" data-testid="hero">
      <div className="absolute left-5 top-4 z-10">
        <div className="eyebrow">The one-way link, live</div>
      </div>
      <div className="absolute bottom-4 right-5 z-10 flex items-center gap-2 rounded-full bg-ink/70 px-3 py-1 ring-1 ring-line/25 text-sm text-dim"
           title={`Each dot stands for about ${FLOWS_PER_DOT} flows scored by the pipeline. Rate from /api/v1/metrics.`}>
        <span className="h-2 w-2 rounded-full bg-brand shadow-[0_0_8px_rgb(94_230_255)]" />
        1 dot ≈ {FLOWS_PER_DOT} flows
        <span className="text-faint">·</span>
        <span className="font-mono text-fg">{running ? `${fps.toFixed(0)} flows/s` : metrics?.pipeline_state === 'finished' ? 'replay finished' : 'waiting for traffic'}</span>
      </div>
      <div ref={box} className="absolute inset-0">
        {hasWebGL ? <Suspense fallback={null}><Scene3D {...props} /></Suspense> : <Scene2D {...props} />}
        {labels.map((l) => <div key={l.key} ref={(e) => { labelEls.current[l.key] = e; }} className="absolute left-0 top-0 z-10" style={{ transform: 'translate(-9999px, 0)' }}>{l.node}</div>)}
      </div>
    </section>
  );
});
export default Hero;
