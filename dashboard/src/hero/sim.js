// Particle model shared by the WebGL scene and the 2D fallback. Scene units: the production
// network sits around x = -4.2, the diode gate at x = 0, the enclave at x = +4.2. Particles only
// ever move left to right: there is no code path that moves one back.
export const FLOWS_PER_DOT = 5;
export const MAX = 600;
const TRAVEL = 2.4; // seconds from host to enclave

export function makeHosts(n = 16, seed = 7) {
  let s = seed;
  const rnd = () => ((s = (s * 16807) % 2147483647) / 2147483647);
  return Array.from({ length: n }, (_, i) => {
    const a = (i / n) * Math.PI * 2 + rnd() * 0.4, r = 0.55 + rnd() * 1.05;
    return [-4.3 + Math.cos(a) * r * 0.75, 0.15 + Math.sin(a) * r * 1.05, (rnd() - 0.5) * 1.6];
  });
}

export function makeSim(hosts) {
  const p = Array.from({ length: MAX }, () => ({ live: false, t: 0, from: 0, gy: 0, gz: 0, color: null, big: false, onArrive: null }));
  let debt = 0, cursor = 0;
  const spawn = (opts = {}) => {
    const q = p[cursor]; cursor = (cursor + 1) % MAX;
    Object.assign(q, { live: true, t: 0, from: (Math.random() * hosts.length) | 0, gy: (Math.random() - 0.5) * 1.5,
      gz: (Math.random() - 0.5) * 0.5, color: opts.color || null, big: !!opts.color, onArrive: opts.onArrive || null });
  };
  // position along host -> gate -> enclave (two quadratic legs)
  const pos = (q, out) => {
    const h = hosts[q.from];
    if (q.t < 0.5) {
      const u = q.t / 0.5, m = [(h[0] + 0) / 2, (h[1] + q.gy) / 2 + 0.35, (h[2] + q.gz) / 2];
      for (let k = 0; k < 3; k++) out[k] = (1 - u) ** 2 * h[k] + 2 * (1 - u) * u * m[k] + u * u * [0, q.gy, q.gz][k];
    } else {
      const u = (q.t - 0.5) / 0.5, e = [4.2, 0.1, 0], m = [2.1, q.gy * 0.5 + 0.3, q.gz * 0.5];
      for (let k = 0; k < 3; k++) out[k] = (1 - u) ** 2 * [0, q.gy, q.gz][k] + 2 * (1 - u) * u * m[k] + u * u * e[k];
    }
    return out;
  };
  return {
    particles: p, pos, spawn,
    step(dt, flowsPerSec) {
      debt += (flowsPerSec / FLOWS_PER_DOT) * dt;
      while (debt >= 1) { spawn(); debt -= 1; }
      for (const q of p) {
        if (!q.live) continue;
        q.t += dt / (q.big ? TRAVEL * 0.6 : TRAVEL);
        if (q.t >= 1) { q.live = false; if (q.onArrive) { q.onArrive(); q.onArrive = null; } }
      }
    },
  };
}
