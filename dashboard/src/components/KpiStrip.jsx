import React from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import Counter from '../ui/Counter';
import Sparkline from '../ui/Sparkline';

const fix = (d) => (v) => v.toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });

function Kpi({ label, children, note, title, testid }) {
  return (
    <div className="glass flex min-w-0 flex-col justify-between px-5 py-4" title={title} data-testid={testid}>
      <div className="eyebrow">{label}</div>
      <div className="mt-2 flex items-end justify-between gap-3">{children}</div>
      {note && <div className="mt-1.5 text-xs text-faint">{note}</div>}
    </div>
  );
}

// Live figures from /api/v1/metrics (polled) and /chain/verify. history = recent flows/s samples.
export default function KpiStrip({ metrics, history, chain }) {
  const m = metrics || {};
  const vis = m.link_reverse_visibility_w;
  return (
    <div className="grid grid-cols-[1.5fr_1fr_1fr_1fr_1.3fr] gap-4" data-testid="kpi-strip">
      <Kpi label="Flows scored / s" note="demo replay rate · tested capacity ~860 flows/s per core (docs/BENCHMARK.md)"
           title="Flows scored per second by the running demo replay (last few seconds). Capacity is measured separately: docs/BENCHMARK.md, CTU-13 s12, one core." testid="kpi-fps">
        <Counter value={m.flows_per_sec} format={fix(1)} className="kpi text-5xl text-fg" />
        <Sparkline data={history} />
      </Kpi>
      <Kpi label="Throughput" note="demo replay rate · capacity ~223 Mbps per core" title="Wire bits ingested per second by the running demo replay. Capacity from docs/BENCHMARK.md (CTU-13 s12, one core).">
        <span><Counter value={m.mbps} format={fix(2)} className="kpi text-5xl text-fg" /><span className="ml-2 text-lg text-dim">Mbps</span></span>
      </Kpi>
      <Kpi label="Queue drops" note="every drop is counted" title="Flows dropped at a full queue. Every drop is counted, none hidden.">
        <Counter value={m.drops} className={`kpi text-5xl ${m.drops > 0 ? 'text-amber-300' : 'text-fg'}`} />
      </Kpi>
      <Kpi label="Reply direction visible" note="measured per flow, never assumed"
           title="Share of recent flows whose reply direction was also on the link (measured per flow)">
        <span><Counter value={vis === null || vis === undefined ? null : vis * 100} className="kpi text-5xl text-fg" /><span className="ml-1 text-2xl text-dim">%</span></span>
      </Kpi>
      <Kpi label="Alert log" note="SHA-256 hash chain, recomputed by the server" testid="kpi-chain"
           title="The alert log is a SHA-256 hash chain; /api/v1/chain/verify recomputes it">
        {chain?.ok !== false
          ? <span className="flex items-center gap-3"><ShieldCheck className="h-10 w-10 text-safe" />
              <span><span className="kpi block text-3xl text-safe">verified</span><span className="text-sm text-dim"><Counter value={chain?.n} /> records</span></span></span>
          : <span className="flex items-center gap-3"><ShieldAlert className="h-10 w-10 text-rose-400" />
              <span className="kpi text-3xl text-rose-300">broken at #{chain.first_bad_index}</span></span>}
      </Kpi>
    </div>
  );
}
