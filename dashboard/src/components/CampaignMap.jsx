import React, { useEffect, useMemo, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { CLASS_INFO, classInfo } from '../lib/labels';

// Campaigns as glowing clusters: the campaign's host(s) in the middle, the other ends on a ring,
// one coloured spoke per (other end, class). Deterministic layout (oldest campaign first, so live
// updates never reshuffle). Labels sit outside the ring along each spoke's angle and ring slots
// avoid straight up/down, so no two labels share a line; the smoke test checks for overlaps.
const GAP = 70, TITLE = 110, PAD = 40; // TITLE clears the two-line labels of the upper ring slots

export function buildMap(alerts, campaigns, box, max = 12) {
  const shown = [...campaigns.slice(0, max)].sort((a, b) => (a.first_seen < b.first_seen ? -1 : 1));
  const byCamp = new Map(shown.map((c) => [c.campaign_id, { c, hosts: new Set(c.hosts), ends: new Map(), edges: new Map() }]));
  for (const a of [...alerts].reverse()) { // oldest first: ring order = order of first sighting
    const g = byCamp.get(a.campaign_id);
    const { src_ip: s, dst_ip: d } = a.flow || {};
    if (!g || !s || !d) continue;
    for (const ip of [s, d]) if (!g.hosts.has(ip) && !g.ends.has(ip)) g.ends.set(ip, new Set());
    const other = g.hosts.has(s) ? d : s;
    if (g.ends.has(other)) g.ends.get(other).add(a.threat_class);
    const k = `${s}|${d}|${a.threat_class}`;
    const e = g.edges.get(k) || { id: `${a.campaign_id}|${k}`, s, d, cls: a.threat_class, alertIds: [] };
    e.alertIds.push(a.alert_id);
    g.edges.set(k, e);
  }
  // size each cluster, then place clusters left to right in rows
  const clusters = [...byCamp.values()].map((g) => {
    const n = g.ends.size, R = n ? Math.max(95, 24 * n) : 0;
    return { ...g, n, R, w: 2 * R + 300, h: 2 * R + TITLE + 60 };
  });
  // rows: pick the row count that lets the whole map be drawn largest in the box
  const pack = (rowW) => {
    let x = PAD, y = PAD, rowH = 0;
    for (const c of clusters) {
      if (x + c.w > rowW + PAD && x > PAD) { x = PAD; y += rowH + GAP; rowH = 0; }
      c.cx = x + c.w / 2; c.cy = y + TITLE + c.R + 20;
      x += c.w + GAP; rowH = Math.max(rowH, c.h);
    }
    return [Math.max(...clusters.map((c) => c.cx + c.w / 2), 400) + PAD, y + rowH + PAD];
  };
  const total = clusters.reduce((t, c) => t + c.w + GAP, 0), widest = Math.max(0, ...clusters.map((c) => c.w));
  const fits = (rw) => { const [w, h] = pack(rw); return Math.min(box.w / w, box.h / h); };
  const best = clusters.map((_, r) => Math.max(widest, total / (r + 1))).reduce((b, rw) => (fits(rw) > fits(b) ? rw : b), total);
  const [w0, h0] = pack(best);
  const width = Math.max(w0, box.w / 1.25), height = Math.max(h0, box.h / 1.25); // never draw larger than 1.25x
  for (const c of clusters) {
    const pos = new Map();
    const hosts = [...c.hosts];
    hosts.forEach((ip, j) => pos.set(ip, { x: c.cx + (j - (hosts.length - 1) / 2) * 70, y: c.cy, a: Math.PI / 2 }));
    [...c.ends.keys()].forEach((ip, k) => {
      const a = -Math.PI / 2 + (2 * Math.PI * (k + 0.5)) / c.n;
      pos.set(ip, { x: c.cx + c.R * Math.cos(a), y: c.cy + c.R * Math.sin(a), a });
    });
    c.pos = pos;
    const counts = {};
    for (const e of c.edges.values()) counts[e.cls] = (counts[e.cls] || 0) + e.alertIds.length;
    c.color = classInfo(Object.entries(counts).sort((p, q) => q[1] - p[1])[0]?.[0]).color;
  }
  return { clusters, width, height, ox: (width - w0) / 2, oy: (height - h0) / 2 };
}

export default function CampaignMap({ alerts, campaigns, selected, focus, onPickEdge, onPickHost, onPickCampaign }) {
  const reduced = useReducedMotion();
  const el = useRef(null);
  const [box, setBox] = useState({ w: 1600, h: 800 });
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setBox({ w: e.contentRect.width || 1600, h: e.contentRect.height || 800 }));
    ro.observe(el.current);
    return () => ro.disconnect();
  }, []);
  const shown = useMemo(() => {
    if (!focus) return campaigns;
    const ids = new Set(alerts.filter((a) => a.flow?.src_ip === focus || a.flow?.dst_ip === focus).map((a) => a.campaign_id));
    const f = campaigns.filter((c) => ids.has(c.campaign_id));
    return f.length ? f : campaigns;
  }, [alerts, campaigns, focus]);
  const { clusters, width, height, ox, oy } = useMemo(() => buildMap(alerts, shown, box), [alerts, shown, box]);
  const draw = reduced ? { initial: false } : { initial: { pathLength: 0, opacity: 0 }, animate: { pathLength: 1, opacity: 1 }, transition: { duration: 0.9, ease: 'easeOut' } };
  return (
    <div ref={el} className="absolute inset-0" data-testid="campaign-map">
      <svg viewBox={`${-ox} ${-oy} ${width} ${height}`} className="h-full w-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          {clusters.map((c) => (
            <radialGradient key={c.c.campaign_id} id={`glow-${c.c.campaign_id}`}>
              <stop offset="0" stopColor={c.color} stopOpacity="0.28" /><stop offset="0.6" stopColor={c.color} stopOpacity="0.08" /><stop offset="1" stopColor={c.color} stopOpacity="0" />
            </radialGradient>
          ))}
          {Object.entries(CLASS_INFO).map(([k, v]) => (
            <marker key={k} id={`arr-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill={v.color} />
            </marker>
          ))}
        </defs>
        {clusters.map((c) => {
          const id = c.c.campaign_id, sel = selected === id;
          return (
            <g key={id} data-campaign={id}>
              <circle cx={c.cx} cy={c.cy} r={c.R + 90} fill={`url(#glow-${id})`} />
              {sel && <circle cx={c.cx} cy={c.cy} r={c.R + 60} fill="none" stroke="#5ee6ff" strokeOpacity="0.6" strokeDasharray="4 6" />}
              <g className="cursor-pointer" onClick={() => onPickCampaign?.(id)} data-label="title">
                <text x={c.cx} y={c.cy - c.R - 98} textAnchor="middle" className="fill-fg font-sans" fontSize="20" fontWeight="600">
                  {c.c.hosts.join(', ') || 'campaign'}
                </text>
                <text x={c.cx} y={c.cy - c.R - 74} textAnchor="middle" className="fill-dim font-sans" fontSize="15">
                  {c.c.alerts} alert{c.c.alerts === 1 ? '' : 's'}{c.c.tactics.length ? ` · ${c.c.tactics.join(' → ')}` : ''}
                </text>
              </g>
              {[...c.edges.values()].map((e, i) => {
                const p = c.pos.get(e.s), q = c.pos.get(e.d), col = classInfo(e.cls).color;
                if (!p || !q) return null;
                // parallel spokes to the same end bow apart; stop short of the node
                const dup = [...c.edges.values()].filter((f) => (f.s === e.s && f.d === e.d) || (f.s === e.d && f.d === e.s));
                const bow = dup.length > 1 ? (dup.indexOf(e) - (dup.length - 1) / 2) * 46 : 0;
                const dx = q.x - p.x, dy = q.y - p.y, L = Math.hypot(dx, dy) || 1, nx = -dy / L, ny = dx / L;
                const rs = c.hosts.has(e.s) ? 22 : 12, rd = c.hosts.has(e.d) ? 22 : 12;
                // parallel spokes also land apart, so their arrowheads never overlap
                const sx = p.x + (dx / L) * rs, sy = p.y + (dy / L) * rs;
                const tx = q.x - (dx / L) * (rd + 4) + nx * bow * 0.3, ty = q.y - (dy / L) * (rd + 4) + ny * bow * 0.3;
                const d = `M${sx},${sy} Q${(sx + tx) / 2 + nx * bow},${(sy + ty) / 2 + ny * bow} ${tx},${ty}`;
                return (
                  <g key={e.id} className="cursor-pointer" data-cls={e.cls} data-edge={e.id} onClick={() => onPickEdge(e.alertIds.at(-1))}>
                    <path d={d} stroke="transparent" strokeWidth="18" fill="none" />
                    <motion.path d={d} stroke={col} strokeOpacity="0.25" strokeWidth="10" fill="none" strokeLinecap="round" {...draw} />
                    <motion.path d={d} stroke={col} strokeWidth="3.5" fill="none" markerEnd={`url(#arr-${e.cls})`} {...draw} />
                  </g>
                );
              })}
              {[...c.ends.entries()].map(([ip, classes]) => {
                const p = c.pos.get(ip), cos = Math.cos(p.a), sin = Math.sin(p.a);
                const anchor = cos > 0.35 ? 'start' : cos < -0.35 ? 'end' : 'middle';
                const lx = p.x + cos * 22, ly = p.y + sin * 22 + (sin > 0.35 ? 12 : sin < -0.35 ? -20 : -4);
                return (
                  <g key={ip} className="cursor-pointer" data-ip={ip} onClick={() => onPickHost(ip)}>
                    <rect x={p.x - 9} y={p.y - 9} width="18" height="18" rx="3" transform={`rotate(45 ${p.x} ${p.y})`} fill="#1b2744" stroke="#8fa3c8" strokeWidth="1.5" />
                    <text x={lx} y={ly} textAnchor={anchor} data-label="end">
                      <tspan x={lx} className="fill-fg font-mono" fontSize="15">{ip}</tspan>
                      <tspan x={lx} dy="19" fontSize="14" className="font-sans" fontWeight="600">
                        {[...classes].map((k, i) => <tspan key={k} fill={classInfo(k).color}>{i ? ' · ' : ''}{classInfo(k).short}</tspan>)}
                      </tspan>
                    </text>
                  </g>
                );
              })}
              {[...c.hosts].map((ip) => {
                const p = c.pos.get(ip);
                return (
                  <g key={ip} className="cursor-pointer" data-ip={ip} data-host onClick={() => onPickHost(ip)}>
                    <circle cx={p.x} cy={p.y} r="30" fill={c.color} opacity="0.18" />
                    <circle cx={p.x} cy={p.y} r="18" fill="#0b1630" stroke={c.color} strokeWidth="3" />
                    <circle cx={p.x} cy={p.y} r="6" fill={c.color} />
                  </g>
                );
              })}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
