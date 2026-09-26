import React from 'react';
import { X } from 'lucide-react';
import { classInfo, fmtTime } from '../lib/labels';

export default function HostTimeline({ host, stages, onClose }) {
  if (!host) return null;
  return (
    <section className="absolute left-3 right-3 bottom-3 bg-slate-900/95 ring-1 ring-slate-700 rounded-xl p-3 shadow-2xl" data-testid="host-timeline">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-100">
          Stages observed on <span className="font-mono text-sky-300">{host}</span>
          <span className="ml-2 text-[11px] font-normal text-slate-400">MITRE ATT&CK tactics, in the order they were seen. History only: nothing here predicts a next step.</span>
        </h3>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-800 text-slate-400" aria-label="Close timeline"><X className="w-4 h-4" /></button>
      </div>
      {stages === null && <div className="text-sm text-slate-400">Loading…</div>}
      {stages && stages.length === 0 && (
        <div className="text-sm text-slate-400">No alert names this address as the internal host. It appears in the graph as the other end of a connection.</div>
      )}
      {stages && stages.length > 0 && (
        <ol className="flex items-stretch gap-2 overflow-x-auto pb-1">
          {stages.map((s, i) => (
            <React.Fragment key={`${s.tactic_id}-${s.threat_class}`}>
              {i > 0 && <li aria-hidden className="self-center text-slate-500">→</li>}
              <li className="min-w-[170px] rounded-lg p-2 ring-1" style={{ background: `${classInfo(s.threat_class).color}14`, borderColor: classInfo(s.threat_class).color, '--tw-ring-color': `${classInfo(s.threat_class).color}66` }}>
                <div className="text-[10px] uppercase tracking-wider text-slate-400">{s.tactic_id}</div>
                <div className="text-sm font-semibold text-slate-100">{s.tactic}</div>
                <div className="text-xs" style={{ color: classInfo(s.threat_class).color }}>{classInfo(s.threat_class).short}</div>
                <div className="text-[11px] text-slate-400 font-mono">{fmtTime(s.first_seen)}{s.last_seen !== s.first_seen ? `–${fmtTime(s.last_seen)}` : ''} · {s.alerts}×</div>
              </li>
            </React.Fragment>
          ))}
        </ol>
      )}
    </section>
  );
}
