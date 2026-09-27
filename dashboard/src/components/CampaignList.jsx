import React from 'react';
import { motion } from 'motion/react';
import { classInfo } from '../lib/labels';

const SEV = { CRITICAL: '#f43f5e', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#34d399' };

export default function CampaignList({ campaigns, selected, onSelect }) {
  return (
    <aside className="glass flex h-[150px] shrink-0 items-stretch gap-4 overflow-hidden px-5 py-4">
      <div className="flex w-[120px] shrink-0 flex-col justify-between">
        <span className="eyebrow">Campaigns</span>
        <span className="kpi text-4xl text-fg">{campaigns.length}</span>
        <span className="text-xs text-dim">related alerts, grouped</span>
      </div>
      <ul className="flex min-w-0 flex-1 gap-3 overflow-x-auto" data-testid="campaign-list">
        {campaigns.length === 0 && <li className="self-center text-dim">The link is quiet. Alerts that share a rare host, server, name or fingerprint are grouped here as they arrive.</li>}
        {campaigns.map((c) => (
          <motion.li key={c.campaign_id} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} className="min-w-[260px] flex-1">
            <button onClick={() => onSelect(c.campaign_id)}
                    className={`h-full w-full rounded-xl px-3 py-2.5 text-left ring-1 transition ${selected === c.campaign_id ? 'bg-brand/10 ring-brand/50' : 'bg-deep/50 ring-line/10 hover:ring-line/30'}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-[15px] text-fg">{c.hosts.join(', ') || '—'}</span>
                <span className="text-xs font-bold" style={{ color: SEV[c.max_severity] }}>{c.max_severity}</span>
              </div>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {c.threat_classes.map((t) => (
                  <span key={t} className="h-2.5 w-7 rounded-full" title={classInfo(t).short} style={{ background: classInfo(t).color, boxShadow: `0 0 8px ${classInfo(t).color}88` }} />
                ))}
              </div>
              <div className="mt-1.5 line-clamp-2 text-xs text-dim">{c.alerts} alert{c.alerts === 1 ? '' : 's'} · {c.tactics.join(' → ') || 'unclassified'}</div>
              {c.not_merged.slice(0, 1).map((n) => (
                <div key={n.campaign_id + n.reason} className="mt-1 truncate text-xs text-amber-300">⊘ {n.reason.replace('not merged: ', 'not merged with another campaign: ')}</div>
              ))}
            </button>
          </motion.li>
        ))}
      </ul>
    </aside>
  );
}
