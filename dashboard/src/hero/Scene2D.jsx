import React, { useEffect, useRef } from 'react';

const CYAN = '94,230,255';

// Fallback when WebGL is missing: the same particle model and the same stage (network, diode,
// enclave, return lane), drawn flat on a 2D canvas. Scene x in [-6, 6] maps across the width,
// scene y in [-2.8, 2.8] down the height; z gives a small vertical parallax.
export default function Scene2D({ sim, hosts, rate, still, enclaveAt, labels, place }) {
  const cv = useRef(null);
  useEffect(() => {
    const c = cv.current, g = c.getContext('2d');
    let raf, last = performance.now(), spin = 0, stage = null;
    // everything that does not move, rendered once per canvas size
    const drawStage = (w, h, dpr, X, Y, k) => {
      const oc = document.createElement('canvas'); oc.width = Math.round(w * dpr); oc.height = Math.round(h * dpr);
      const g = oc.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0);

      // floor grid
      g.strokeStyle = 'rgba(42,74,138,0.35)'; g.lineWidth = 1;
      for (let x = -6; x <= 6; x += 1) { g.beginPath(); g.moveTo(X(x), Y(-2.4)); g.lineTo(X(x * 1.6), h); g.stroke(); }
      // network
      g.strokeStyle = 'rgba(156,196,255,0.25)';
      for (const [a, b] of links) { g.beginPath(); g.moveTo(X(a[0]), Y(a[1], a[2])); g.lineTo(X(b[0]), Y(b[1], b[2])); g.stroke(); }
      g.fillStyle = '#9cc4ff';
      for (const p of hosts) { g.beginPath(); g.arc(X(p[0]), Y(p[1], p[2]), 4, 0, 7); g.fill(); }
      // diode: two bars, a glass pane, three chevrons
      g.fillStyle = `rgba(${CYAN},0.08)`; g.fillRect(X(-0.14), Y(1.75), 0.28 * k, 3.3 * k);
      g.shadowColor = `rgb(${CYAN})`; g.shadowBlur = 14; g.strokeStyle = `rgb(${CYAN})`; g.lineWidth = 3;
      for (const x of [-0.14, 0.14]) { g.beginPath(); g.moveTo(X(x), Y(1.75)); g.lineTo(X(x), Y(-1.55)); g.stroke(); }
      g.lineWidth = 2.5;
      for (const x of [-0.3, 0.05, 0.4]) { g.beginPath(); g.moveTo(X(x - 0.16), Y(0.46)); g.lineTo(X(x + 0.16), Y(0.1)); g.lineTo(X(x - 0.16), Y(-0.26)); g.stroke(); }
      g.shadowBlur = 0; g.strokeStyle = `rgba(${CYAN},0.3)`; g.lineWidth = 1.5;
      g.strokeRect(X(3.0), Y(1.6), 2.4 * k, 3 * k);
      g.setLineDash([7, 6]); g.strokeStyle = 'rgba(122,134,158,0.7)';
      g.beginPath(); g.moveTo(X(3.2), Y(-1.95)); g.lineTo(X(-3.3), Y(-1.95)); g.stroke(); g.setLineDash([]);
      return { c: oc, w, h };
    };
    const tmp = [0, 0, 0];
    const links = hosts.flatMap((h, i) => (i % 3 === 0 ? [[h, hosts[(i + 5) % hosts.length]]] : []));
    const frame = (now) => {
      const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
      if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      const k = Math.min(w / 12, h / 5.6); // uniform scale, stage centred
      const X = (x) => w / 2 + x * k, Y = (y, z = 0) => h / 2 - y * k + z * k * 0.12;
      const dt = still ? 0 : Math.min((now - last) / 1000, 0.05);
      sim.step(dt, rate.current); last = now; spin += dt * 0.5;
      enclaveAt.current = { x: X(4.2), y: Y(0.1) };
      for (const l of labels) place(l.key, X(l.at[0]), Y(l.at[1]));
      if (!stage || stage.w !== w || stage.h !== h) stage = drawStage(w, h, dpr, X, Y, k);
      g.clearRect(0, 0, w, h);
      g.drawImage(stage.c, 0, 0, w, h);
      // enclave: sealed box, a turning polyhedron outline, a core
      g.strokeStyle = `rgba(${CYAN},0.9)`; g.lineWidth = 1.5;
      const pts = [0, 1, 2, 3, 4, 5].map((i) => [X(4.2) + Math.cos(spin + (i * Math.PI) / 3) * 0.9 * k, Y(0.1) + Math.sin(spin + (i * Math.PI) / 3) * 0.9 * k]);
      g.beginPath(); pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y))); g.closePath(); g.stroke();
      g.beginPath(); [0, 2, 4, 0].forEach((i, j) => (j ? g.lineTo(...pts[i]) : g.moveTo(...pts[i]))); g.stroke();
      g.beginPath(); [1, 3, 5, 1].forEach((i, j) => (j ? g.lineTo(...pts[i]) : g.moveTo(...pts[i]))); g.stroke();
      g.fillStyle = `rgba(${CYAN},0.35)`; g.beginPath(); g.arc(X(4.2), Y(0.1), 0.38 * k, 0, 7); g.fill();
      // dots and sparks, additive glow
      g.globalCompositeOperation = 'lighter';
      for (const q of sim.particles) {
        if (!q.live) continue;
        sim.pos(q, tmp);
        const x = X(tmp[0]), y = Y(tmp[1], tmp[2]);
        if (q.big) { g.shadowColor = q.color; g.shadowBlur = 22; g.fillStyle = q.color; g.beginPath(); g.arc(x, y, 7, 0, 7); g.fill(); g.shadowBlur = 0; }
        else { g.fillStyle = `rgba(${CYAN},${0.45 + 0.55 * Math.sin(Math.PI * q.t)})`; g.beginPath(); g.arc(x, y, 3, 0, 7); g.fill(); }
      }
      g.globalCompositeOperation = 'source-over';
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [sim, hosts, rate, still, enclaveAt, labels, place]);
  return <div className="absolute inset-0" data-testid="hero-2d"><canvas ref={cv} className="absolute inset-0 h-full w-full" /></div>;
}
