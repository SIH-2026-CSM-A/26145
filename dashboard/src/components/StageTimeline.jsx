import React, { useEffect, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { X } from 'lucide-react';
import { classInfo, fmtTime } from '../lib/labels';
import { getJSON } from '../lib/api';

const LANES = ['TA0007', 'TA0011', 'TA0010', 'TA0040']; // Discovery, C2, Exfiltration, Impact (kill-chain order)
const CARD = 210, GAP = 12, LANE_H = 92, LEFT = 190;

// Swim lanes, one per ATT&CK tactic seen on the host; a card per (tactic, class) at the time it
// was first seen, pushed right only when it would overlap its lane neighbour. History only.
export default function StageTimeline({ host, campaigns, onClose }) {
  const [stages, setStages] = useState(null);
  const reduced = useReducedMotion();
  useEffect(() => {
    if (!host) return;
    setStages(null);
    getJSON(`/hosts/${encodeURIComponent(host)}/timeline`, { stages: [] }).then((r) => setStages(r.stages));
  }, [host, campaigns]);
  if (!host) return null;

  const lanes = stages ? [...new Set(stages.map((s) => s.tactic_id))].sort((a, b) => LANES.indexOf(a) - LANES.indexOf(b)) : [];
  const t = (s) => Date.parse(s.first_seen);
  const t0 = stages?.length ? Math.min(...stages.map(t)) : 0, t1 = stages?.length ? Math.max(...stages.map(t)) : 1;
  const span = Math.max(t1 - t0, 1), W = 900;
  const edge = {};
  const cards = (stages || []).map((s, i) => {
    const lane = lanes.indexOf(s.tactic_id);
    const x = Math.max(LEFT + ((t(s) - t0) / span) * W, (edge[lane] ?? -Infinity) + GAP);
    edge[lane] = x + CARD;
    return { s, i, x, y: 40 + lane * LANE_H };
  });
  const width = Math.max(...cards.map((c) => c.x + CARD), LEFT + W) + 24;

  return (
    <motion.section initial={{ y: 40, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="glass shrink-0 px-6 py-5" data-testid="host-timeline">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-lg font-semibold text-fg">Stages observed on <span className="font-mono text-brand">{host}</span></div>
          <div className="text-sm text-dim">MITRE ATT&CK tactics in the order they were seen. <span className="text-fg">Observed history. Nothing here predicts the next step.</span></div>
        </div>
        <button onClick={onClose} className="rounded-full p-1.5 text-dim hover:bg-deep hover:text-fg" aria-label="Close timeline"><X className="h-5 w-5" /></button>
      </div>
      {stages === null && <div className="mt-3 text-dim">Loading…</div>}
      {stages?.length === 0 && <div className="mt-3 text-dim">No alert names this address as the internal host. It appears on the map as the other end of a connection.</div>}
      {stages?.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <div className="relative" style={{ width, height: 40 + lanes.length * LANE_H }}>
            <div className="absolute left-0 right-0 top-2 flex justify-between font-mono text-xs text-faint" style={{ left: LEFT, width: W + CARD }}>
              <span>{fmtTime(stages[0].first_seen)}</span><span>event time (UTC) →</span><span>{fmtTime(new Date(t1).toISOString())}</span>
            </div>
            {lanes.map((l, k) => {
              const s = stages.find((x) => x.tactic_id === l);
              return (
                <div key={l} className="absolute left-0 right-0 flex items-center border-t border-line/10" style={{ top: 40 + k * LANE_H, height: LANE_H }}>
                  <div className="w-[180px] pl-1"><div className="text-[15px] font-semibold text-fg">{s.tactic}</div><div className="font-mono text-xs text-faint">{l}</div></div>
                </div>
              );
            })}
            {cards.map(({ s, i, x, y }) => {
              const c = classInfo(s.threat_class).color;
              return (
                <motion.div key={`${s.tactic_id}-${s.threat_class}`} data-stage={s.tactic}
                            initial={reduced ? false : { opacity: 0, x: -24, scale: 0.9 }} animate={{ opacity: 1, x: 0, scale: 1 }}
                            transition={{ delay: reduced ? 0 : 0.25 + i * 0.35, duration: 0.45, ease: 'easeOut' }}
                            className="absolute rounded-xl px-3 py-2 ring-1" style={{ left: x, top: y + 10, width: CARD, background: `${c}18`, '--tw-ring-color': `${c}88`, boxShadow: `0 0 20px -6px ${c}` }}>
                  <div className="text-[15px] font-semibold" style={{ color: c }}>{classInfo(s.threat_class).short}</div>
                  <div className="font-mono text-xs text-dim">{fmtTime(s.first_seen)}{s.last_seen !== s.first_seen ? `–${fmtTime(s.last_seen)}` : ''} · {s.alerts}×</div>
                </motion.div>
              );
            })}
          </div>
        </div>
      )}
    </motion.section>
  );
}
