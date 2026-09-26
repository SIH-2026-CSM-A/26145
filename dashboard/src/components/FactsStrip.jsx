import React from 'react';
import { Radio, ShieldCheck, ShieldAlert, BookOpen } from 'lucide-react';

function Fact({ label, value, unit, title, strong }) {
  return (
    <div className="flex flex-col px-3 py-1.5 min-w-0" title={title}>
      <span className="text-[10px] uppercase tracking-wider text-slate-400 whitespace-nowrap">{label}</span>
      <span className={`font-mono tabular-nums whitespace-nowrap ${strong ? 'text-emerald-300 text-lg font-bold' : 'text-slate-100 text-base font-semibold'}`}>
        {value}
        {unit && <span className="text-xs text-slate-400 font-normal ml-1">{unit}</span>}
      </span>
    </div>
  );
}

const num = (v, d = 1) => (v === null || v === undefined ? '—' : Number(v).toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d }));

export default function FactsStrip({ metrics, live, chain, onModelCard }) {
  const m = metrics || {};
  const vis = m.link_reverse_visibility_w;
  const src = m.source;
  const running = m.pipeline_state === 'running';
  return (
    <header className="bg-slate-900 border-b border-slate-800">
      <div className="flex items-center gap-3 px-4 py-2 flex-wrap">
        <div className="flex items-center gap-2 mr-2">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 ring-1 ring-sky-400/40 flex items-center justify-center">
            <Radio className="w-4 h-4 text-sky-300" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold text-slate-100">Passive threat sensor</div>
            <div className="text-[11px] text-slate-400">
              {src ? <>Replaying <span className="font-mono">{src.capture}</span>{src.speed ? ` at ${src.speed}× real time` : ' unthrottled'}{src.loop ? ` · loop ${src.loop}` : ''}</> : 'No capture attached'}
              <span className={`ml-2 inline-flex items-center gap-1 ${live ? 'text-emerald-300' : 'text-amber-300'}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${live ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                {live ? (running ? 'live' : m.pipeline_state || 'connected') : 'reconnecting'}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center divide-x divide-slate-800 bg-slate-950/60 rounded-lg ring-1 ring-slate-800 flex-wrap">
          <Fact label="Flows scored / s" value={num(m.flows_per_sec)} title="Flows scored per second over the last few seconds (measured by the running pipeline)" />
          <Fact label="Throughput" value={num(m.mbps, 2)} unit="Mbps" title="Wire bits ingested per second" />
          <Fact label="Queue drops" value={m.drops ?? '—'} title="Flows dropped at a full queue. Every drop is counted, none hidden." />
          <Fact label="Reverse visible" value={vis === null || vis === undefined ? '—' : `${Math.round(vis * 100)}%`}
                title="Share of recent flows whose reply direction was also on the link (measured per flow)" />
          <Fact label="Bytes sent onto monitored link" value="0" strong
                title="By construction: the sensor has no transmit path. tests/ingest/test_no_transmit.py fails if capture or ingest code gains a socket send or a writable open." />
        </div>

        <div className="ml-auto flex items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md ring-1 ${chain?.ok ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30' : chain ? 'bg-red-500/15 text-red-300 ring-red-500/40' : 'bg-slate-800 text-slate-400 ring-slate-700'}`}
                title="The alert log is a SHA-256 hash chain; this recomputes it on the server">
            {chain?.ok ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
            {chain ? (chain.ok ? `Alert log verified · ${chain.n} records` : `Log broken at #${chain.first_bad_index}`) : 'Log not checked'}
          </span>
          <button onClick={onModelCard} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 ring-1 ring-slate-700" data-testid="model-card-button">
            <BookOpen className="w-3.5 h-3.5" /> Model card
          </button>
        </div>
      </div>
    </header>
  );
}
