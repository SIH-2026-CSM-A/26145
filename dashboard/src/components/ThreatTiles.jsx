import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { classInfo, evidenceLine, fmtTime, TILES } from '../lib/labels';
import Counter from '../ui/Counter';

// The six PS threat classes. Counts come from /api/v1/stats/classes (the whole log); `pulse`
// maps a tile id to a counter bumped when an alert's spark lands on it.
export default function ThreatTiles({ stats, pulse, tileRefs, alerts }) {
  const reduced = useReducedMotion();
  return (
    <div className="grid h-full min-h-0 grid-cols-2 grid-rows-3 gap-3 overflow-hidden" data-testid="threat-tiles">
      {TILES.map((t) => {
        const color = classInfo(t.classes[0]).color;
        const rows = t.classes.map((c) => stats?.[c]).filter(Boolean);
        const count = rows.reduce((s, r) => s + r.count, 0);
        const k = pulse[t.id] || 0;
        const latest = alerts.find((a) => t.classes.includes(a.threat_class)); // alerts are newest first
        // fast lane: a provisional alert is drawn outlined until a flow-lane alert confirms it
        const confirmed = new Set(alerts.map((a) => a.confirms).filter(Boolean));
        const waiting = latest?.provisional && !confirmed.has(latest.alert_id);
        const first = latest?.confirms && alerts.find((a) => a.alert_id === latest.confirms);
        const pending = alerts.filter((a) => a.provisional && t.classes.includes(a.threat_class) && !confirmed.has(a.alert_id)).length;
        const split = t.classes.length > 1 && rows.length ? t.classes.map((c) => `${classInfo(c).short} ${stats?.[c]?.count || 0}`).join(' · ') : null;
        return (
          <div key={t.id} ref={(el) => { tileRefs.current[t.id] = el; }} data-testid={`tile-${t.id}`} data-pulses={k}
               className="glass relative min-h-0 overflow-hidden px-5 py-3.5" style={{ borderColor: `${color}${count ? '55' : '22'}` }}>
            <div className="absolute inset-x-0 top-0 h-[3px]" style={{ background: color, opacity: count ? 1 : 0.35 }} />
            {k > 0 && !reduced && (
              <motion.div key={k} className="pointer-events-none absolute inset-0 rounded-2xl" initial={{ opacity: 0.9 }} animate={{ opacity: 0 }}
                          transition={{ duration: 1.6, ease: 'easeOut' }} style={{ boxShadow: `inset 0 0 0 2px ${color}, inset 0 0 60px ${color}66` }} />
            )}
            <div className="flex h-full min-h-0 flex-col">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-mono text-sm font-bold" style={{ color }}>({t.id}) <span className="font-sans font-medium text-faint">{t.ps}</span></div>
                  <div className="mt-0.5 text-lg font-semibold leading-snug text-fg">{t.title}</div>
                </div>
                <div className="shrink-0 text-right">
                  {count ? <Counter value={count} className="kpi text-5xl" style={{ color, textShadow: `0 0 24px ${color}88` }} />
                         : pending ? <span className="kpi text-5xl" data-testid={`tile-${t.id}-provisional`} style={{ color: 'transparent', WebkitTextStroke: `1.5px ${color}` }}>{pending}</span>
                         : <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-base font-medium text-dim"><span className="h-2.5 w-2.5 animate-pulse rounded-full" style={{ background: color }} />watching</span>}
                </div>
              </div>
              {latest && (
                <div className={`mt-2 min-h-0 rounded-lg px-3 py-1.5 ${waiting ? 'border border-dashed bg-transparent' : 'bg-ink/50 ring-1 ring-line/10'}`}
                     style={waiting ? { borderColor: color } : undefined} data-testid={`tile-${t.id}-latest`} data-provisional={waiting ? 'true' : 'false'}>
                  <div className="truncate text-xs text-faint">
                    {waiting ? <span style={{ color }}>provisional · fast lane, 1 s · not yet confirmed</span>
                             : <>latest <span className="font-mono">{fmtTime(latest.timestamp)}</span>{first ? ` · confirmed; fast lane flagged it at ${fmtTime(first.timestamp)}` : ''}{split ? ` · ${split}` : ''}</>}
                  </div>
                  <div className="line-clamp-2 font-mono text-sm leading-snug text-fg">{evidenceLine(latest)}</div>
                </div>
              )}
              <div className="mt-auto truncate pt-1.5 text-sm text-dim">looks at: <span className="text-fg/90">{t.looks}</span></div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
