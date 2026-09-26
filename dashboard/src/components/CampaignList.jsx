import React from 'react';
import { classInfo, fmtTime, SEVERITY_STYLE } from '../lib/labels';

export default function CampaignList({ campaigns, selected, onSelect, shownCount }) {
  return (
    <aside className="flex-1 flex flex-col min-h-0 bg-slate-900/60 border-r border-slate-800">
      <div className="px-3 py-2 border-b border-slate-800 flex items-baseline justify-between">
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">Campaigns</h2>
        <span className="text-[11px] text-slate-500">
          {campaigns.length === 0 ? 'none yet' : shownCount < campaigns.length ? `newest ${shownCount} of ${campaigns.length} in graph` : `${campaigns.length}`}
        </span>
      </div>
      <ul className="flex-1 overflow-y-auto divide-y divide-slate-800/70" data-testid="campaign-list">
        {campaigns.length === 0 && (
          <li className="p-4 text-sm text-slate-400">The link is quiet. Alerts that share a host, server, name or fingerprint are grouped here as they arrive.</li>
        )}
        {campaigns.map((c) => (
          <li key={c.campaign_id}>
            <button onClick={() => onSelect(c.campaign_id)}
                    className={`w-full text-left px-3 py-2.5 hover:bg-slate-800/60 ${selected === c.campaign_id ? 'bg-sky-500/10 ring-1 ring-inset ring-sky-500/40' : ''}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm text-slate-100 truncate">{c.hosts.join(', ') || '—'}</span>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ring-1 ${SEVERITY_STYLE[c.max_severity] || ''}`}>{c.max_severity}</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {c.threat_classes.map((t) => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: `${classInfo(t).color}26`, color: classInfo(t).color }}>
                    {classInfo(t).short}
                  </span>
                ))}
              </div>
              <div className="mt-1 text-[11px] text-slate-400">
                {c.alerts} alert{c.alerts === 1 ? '' : 's'} · {fmtTime(c.first_seen)}–{fmtTime(c.last_seen)}
                {c.tactics.length > 1 && <> · {c.tactics.join(' → ')}</>}
              </div>
              {c.not_merged.slice(0, 2).map((n) => (
                <div key={n.campaign_id + n.reason} className="mt-1 text-[11px] text-amber-300/90">⊘ {n.reason.replace('not merged: ', 'not merged with another campaign: ')}</div>
              ))}
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
