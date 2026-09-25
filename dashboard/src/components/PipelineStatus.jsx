import React from 'react';

const fmt = (v, digits = 0) => (v == null ? '—' : Number(v).toFixed(digits));

function Stat({ label, value, hint, testId }) {
  return (
    <div className="flex flex-col" data-testid={testId}>
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</span>
      <span className="text-sm font-mono font-semibold text-slate-900">{value}</span>
      {hint && <span className="text-[10px] text-slate-400 font-mono">{hint}</span>}
    </div>
  );
}

// Live pipeline health from /api/v1/metrics; a dash means "not measured", never a guessed zero.
export default function PipelineStatus({ metrics }) {
  const lat = metrics.alert_latency_ms;
  const vis = metrics.link_reverse_visibility_w;
  return (
    <div className="bg-white border border-slate-200 rounded-xl px-5 py-3 shadow-sm grid grid-cols-2 md:grid-cols-5 gap-4">
      <Stat testId="pipeline-state" label="Pipeline" value={metrics.pipeline_state ?? 'not running'} />
      <Stat testId="queue" label="Queue" value={metrics.queue_depth == null ? '—' : `${metrics.queue_depth} / ${metrics.queue_max}`} />
      <Stat testId="drops" label="Dropped flows" value={fmt(metrics.drops)} hint="queue full" />
      <Stat testId="latency" label="Alert latency p50 / p95 / p99"
            value={lat ? `${fmt(lat.p50, 1)} / ${fmt(lat.p95, 1)} / ${fmt(lat.p99, 1)} ms` : '—'} hint="flush → published" />
      <Stat testId="visibility" label="Reverse visibility" value={vis == null ? '—' : `${(vis * 100).toFixed(0)}%`}
            hint="flows with both halves" />
    </div>
  );
}
