import React, { useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { animate, stagger } from 'animejs';
import { X, Eye, Cpu, Link2, ShieldCheck, ShieldAlert, RotateCw } from 'lucide-react';
import { classInfo, FEATURE_PLAIN, fmtTime, fmtValue, OBSERVABILITY } from '../lib/labels';
import { getJSON } from '../lib/api';

const SEV = { CRITICAL: '#f43f5e', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#34d399' };
const CHIP = {
  computable: ['#34d399', 'Fully derivable from what this link shows'],
  'needs both': ['#5ee6ff', 'Needs both directions; both were captured on this flow, so it was computed'],
  degraded: ['#facc15', 'Derivable with a stated loss (see the feature contract)'],
  substituted: ['#a78bfa', 'Stands in for a feature this flow could not provide'],
  unavailable: ['#f43f5e', 'Could not be computed on this flow; never estimated'],
};

function chipKind(feature, contract, substitutedBy) {
  if (substitutedBy.has(feature)) return 'substituted';
  const st = contract?.features?.[feature]?.state;
  return { computable: 'computable', degraded: 'degraded', unavailable: 'unavailable', reverse_dependent: 'needs both' }[st] || null;
}
// the exfil ratio's own tooltip names its substitute (feature_contract.toml `substitutes`)
const TIP = { outbound_inbound_byte_ratio: 'uses bytes in both directions; if the reply is not captured, the substitute is egress spike + rare server' };
const Chip = ({ kind, feature }) => kind && (
  <span title={(kind === 'needs both' && TIP[feature]) || CHIP[kind][1]} className="chip whitespace-nowrap" style={{ color: CHIP[kind][0], background: `${CHIP[kind][0]}14`, '--tw-ring-color': `${CHIP[kind][0]}55` }}>{kind}</span>
);

function Ring({ value, color }) {
  const r = 26, c = 2 * Math.PI * r;
  return (
    <div className="relative h-16 w-16 shrink-0" title="Detector confidence" aria-label={`confidence ${Math.round(value * 100)}%`}>
      <svg viewBox="0 0 64 64" className="h-16 w-16 -rotate-90">
        <circle cx="32" cy="32" r={r} fill="none" stroke="rgb(96 140 220 / 0.18)" strokeWidth="6" />
        <motion.circle cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={c}
                       initial={{ strokeDashoffset: c }} animate={{ strokeDashoffset: c * (1 - value) }} transition={{ duration: 1, ease: 'easeOut' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className="kpi text-base text-fg">{Math.round(value * 100)}%</span>
      </div>
    </div>
  );
}

// value against the rule's threshold (or learned normal) on one scale; no "above/below" claim,
// because some rules fire below their threshold (e.g. low timing irregularity)
function EvidenceBar({ e, color, chip, reason }) {
  const num = typeof e.value === 'number' && typeof e.baseline === 'number'; // a bar needs something to compare with
  const scale = num ? Math.max(Math.abs(e.value), Math.abs(e.baseline)) * 1.15 || 1 : 1;
  const ref = e.baseline_source === 'rule_threshold' ? 'threshold' : e.baseline_source ? 'normal' : null;
  return (
    <div className="py-2" title={reason}>
      <div className="flex items-baseline justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[15px] text-fg">{FEATURE_PLAIN[e.feature] || e.feature}</div>
          <div className="truncate font-mono text-xs text-faint">{e.feature}</div>
        </div>
        <Chip kind={chip} feature={e.feature} />
      </div>
      {num ? (
        <div className="mt-2">
          <div className="relative h-3 rounded-full bg-deep ring-1 ring-line/15">
            <motion.div className="absolute inset-y-0 left-0 rounded-full" style={{ background: `linear-gradient(90deg, ${color}66, ${color})`, boxShadow: `0 0 12px ${color}88` }}
                        initial={{ width: 0 }} animate={{ width: `${(Math.abs(e.value) / scale) * 100}%` }} transition={{ duration: 0.8, ease: 'easeOut' }} />
            <div className="absolute -top-1 -bottom-1 w-0.5 bg-fg" style={{ left: `${(Math.abs(e.baseline) / scale) * 100}%` }} />
          </div>
          <div className="mt-1 flex justify-between font-mono text-sm">
            <span style={{ color }}>{fmtValue(e.value)}</span>
            <span className="text-dim">{ref || 'reference'} {fmtValue(e.baseline)}</span>
          </div>
        </div>
      ) : (
        <div className="mt-1 flex justify-between gap-3 font-mono text-sm"><span className="break-all" style={{ color }}>{fmtValue(e.value)}</span>
          {e.baseline === null && <span className="shrink-0 text-faint">no baseline</span>}</div>
      )}
    </div>
  );
}

// two arrows: request (host -> other end) and reply; the reply is greyed when it was not captured
function LinkView({ alert }) {
  const f = alert.flow || {}, st = alert.observability_state;
  const fwd = st !== 'reverse_only', rev = st === 'bidirectional' || st === 'reverse_only';
  const arrow = (on, y, dir, label) => (
    <g opacity={on ? 1 : 0.35}>
      <line x1={dir > 0 ? 118 : 322} y1={y} x2={dir > 0 ? 318 : 122} y2={y} stroke={on ? '#5ee6ff' : '#68768f'} strokeWidth="3" strokeDasharray={on ? '' : '6 6'} markerEnd={on ? 'url(#lv-on)' : 'url(#lv-off)'} />
      <text x="220" y={y - 9} textAnchor="middle" fontSize="14" className={on ? 'fill-fg' : 'fill-faint'}>{label}{on ? '' : ' · not captured'}</text>
    </g>
  );
  return (
    <svg viewBox="0 0 440 118" className="w-full" data-testid="link-view">
      <defs>
        {[['lv-on', '#5ee6ff'], ['lv-off', '#68768f']].map(([id, c]) => (
          <marker key={id} id={id} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill={c} /></marker>
        ))}
      </defs>
      {[[8, f.src_ip, 'sender'], [332, f.dst_ip, 'receiver']].map(([x, ip, role]) => (
        <g key={role}>
          <rect x={x} y="22" width="100" height="74" rx="12" fill="#0b1630" stroke="rgb(96 140 220 / 0.35)" />
          <text x={x + 50} y="54" textAnchor="middle" fontSize="13" className="fill-fg font-mono">{ip}</text>
          <text x={x + 50} y="74" textAnchor="middle" fontSize="13" className="fill-dim">{role}</text>
        </g>
      ))}
      {arrow(fwd, 44, 1, 'request')}
      {arrow(rev, 90, -1, 'reply')}
    </svg>
  );
}

function ChainBlocks({ alert, chain }) {
  const [blocks, setBlocks] = useState(null);
  const [check, setCheck] = useState(null); // null | 'running' | result
  const row = useRef(null), reduced = useReducedMotion();
  useEffect(() => {
    setBlocks(null); setCheck(null);
    getJSON(`/chain/blocks?alert_id=${encodeURIComponent(alert.alert_id)}&around=2`).then((r) => setBlocks(r?.blocks || []));
  }, [alert.alert_id]);
  const verify = async () => {
    setCheck('running');
    const res = await getJSON('/chain/verify');
    const ticks = row.current?.querySelectorAll('[data-tick]') || [];
    if (!reduced && ticks.length) {
      await animate(ticks, { opacity: [0, 1], scale: [0.2, 1], delay: stagger(180), duration: 420, ease: 'outBack' }).then?.();
    }
    setCheck(res || { ok: false, reason: 'no answer' });
  };
  const ok = check && check !== 'running' ? check.ok : chain?.ok;
  return (
    <section className="rounded-2xl bg-deep/70 px-4 py-3 ring-1 ring-line/15" data-testid="chain-section">
      <div className="flex items-center justify-between gap-3">
        <div className="eyebrow flex items-center gap-2"><Link2 className="h-4 w-4" /> Tamper-evident record</div>
        <button onClick={verify} disabled={check === 'running'} data-testid="verify-button"
                className="inline-flex items-center gap-2 rounded-full bg-safe/10 px-3.5 py-1 text-sm font-medium text-safe ring-1 ring-safe/40 hover:bg-safe/20 disabled:opacity-60">
          <RotateCw className={`h-4 w-4 ${check === 'running' ? 'animate-spin' : ''}`} /> Verify chain
        </button>
      </div>
      <div ref={row} className="mt-3 flex items-center gap-1 overflow-x-auto pb-1">
        {(blocks || []).map((b, i) => {
          const me = b.alert_id === alert.alert_id, col = classInfo(b.threat_class).color;
          return (
            <React.Fragment key={b.seq}>
              {i > 0 && <div className="h-0.5 w-4 shrink-0 bg-line/40" />}
              <div className={`relative shrink-0 rounded-xl px-3 py-2 ring-1 ${me ? 'bg-panel' : 'bg-ink/60'}`}
                   style={{ '--tw-ring-color': me ? col : 'rgb(96 140 220 / 0.2)', boxShadow: me ? `0 0 18px -2px ${col}` : 'none' }} data-me={me || undefined}>
                <div className="flex items-center gap-1.5 text-xs text-dim"><span className="h-2 w-2 rounded-full" style={{ background: col }} />#{b.seq}</div>
                <div className="font-mono text-xs text-fg">{b.record_hash.slice(0, 8)}</div>
                <div className="font-mono text-xs text-faint">← {b.prev_hash.slice(0, 6)}</div>
                <ShieldCheck data-tick className="absolute -right-1.5 -top-1.5 h-5 w-5 rounded-full bg-ink text-safe" style={{ opacity: check && check !== 'running' && check.ok ? 1 : 0 }} />
              </div>
            </React.Fragment>
          );
        })}
      </div>
      <div className="mt-2 flex items-center gap-2 text-sm">
        {ok
          ? <span className="inline-flex items-center gap-1.5 text-safe" data-testid="chain-verified"><ShieldCheck className="h-4 w-4" />
              chain verified{check && check !== 'running' ? ` just now · ${check.n} records recomputed` : chain ? ` · ${chain.n} records` : ''}</span>
          : <span className="inline-flex items-center gap-1.5 text-rose-300"><ShieldAlert className="h-4 w-4" />{check && check !== 'running' ? `broken at #${check.first_bad_index}` : 'not checked yet'}</span>}
      </div>
      <div className="mt-1 break-all font-mono text-xs text-faint">record_hash {alert.record_hash}</div>
    </section>
  );
}

export default function CaseFile({ alert, contract, chain, onClose }) {
  if (!alert) return null;
  const info = classInfo(alert.threat_class), f = alert.flow || {};
  const obs = OBSERVABILITY[alert.observability_state];
  const substitutedBy = new Set((alert.substitutions || []).flatMap((s) => s.substituted_by || []));
  const ruleRows = (alert.evidence || []).filter((e) => e.baseline_source !== 'lgbm_pred_contrib');
  const mlRows = (alert.evidence || []).filter((e) => e.baseline_source === 'lgbm_pred_contrib');
  const corr = alert.detection?.correlation;
  return (
    <motion.aside key={alert.alert_id} initial={{ x: 60, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ duration: 0.35, ease: 'easeOut' }}
                  className="glass fixed bottom-4 right-4 top-4 z-30 flex w-[560px] max-w-[calc(100vw-2rem)] flex-col !bg-panel/95" data-testid="alert-drawer">
      <div className="absolute inset-x-0 top-0 h-1 rounded-t-2xl" style={{ background: info.color }} />
      <div className="flex items-start gap-4 px-6 pb-3 pt-4">
        <Ring value={alert.confidence} color={info.color} />
        <div className="min-w-0 flex-1">
          <div className="eyebrow">Case file</div>
          <h2 className="mt-1 text-2xl font-semibold leading-tight text-fg">{info.plain}</h2>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="chip font-bold" style={{ color: SEV[alert.severity], background: `${SEV[alert.severity]}1a`, '--tw-ring-color': `${SEV[alert.severity]}66` }}>{alert.severity}</span>
            <span className="font-mono text-sm text-dim">{alert.threat_class}</span>
          </div>
        </div>
        <button onClick={onClose} className="rounded-full p-1.5 text-dim hover:bg-deep hover:text-fg" aria-label="Close alert"><X className="h-6 w-6" /></button>
      </div>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-6 pb-5">
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-sm text-dim">
          <div><span className="text-faint">from </span><span className="text-fg">{f.src_ip}</span>{f.src_port !== undefined ? `:${f.src_port}` : ''}</div>
          <div><span className="text-faint">to </span><span className="text-fg">{f.dst_ip}</span>:{f.dst_port} {f.protocol}</div>
          <div className="col-span-2"><span className="text-faint">event time </span>{alert.timestamp?.replace('T', ' ').slice(0, 19)} UTC · {alert.detector?.name}</div>
        </div>

        <section>
          <div className="eyebrow mb-1">Evidence</div>
          <div className="divide-y divide-line/10">
            {ruleRows.map((e) => <EvidenceBar key={e.feature} e={e} color={info.color} chip={chipKind(e.feature, contract, substitutedBy)} reason={contract?.features?.[e.feature]?.reason} />)}
            {ruleRows.length === 0 && <div className="py-2 text-dim">No rule evidence: raised by the model alone.</div>}
          </div>
        </section>

        <section className="rounded-2xl bg-deep/70 px-4 py-3 ring-1 ring-line/15">
          <div className="eyebrow mb-1 flex items-center gap-2"><Eye className="h-4 w-4" /> What this link could see</div>
          <LinkView alert={alert} />
          <div className="mt-1 text-[15px] text-fg">{obs ? obs.label : 'not recorded'}<span className="text-dim"> · {obs?.note}</span></div>
          {(alert.substitutions || []).map((s) => (
            <div key={s.unavailable_on_this_flow} className="mt-2 text-sm text-dim">
              <span className="font-mono text-fg">{s.unavailable_on_this_flow}</span> <Chip kind="unavailable" /> {s.reason}. Used instead:{' '}
              <span className="font-mono">{(s.substituted_by || []).join(', ')}</span>
            </div>
          ))}
        </section>

        {mlRows.length > 0 && (
          <section>
            <div className="eyebrow mb-1 flex items-center gap-2"><Cpu className="h-4 w-4" /> ML top features (LightGBM contributions)</div>
            {mlRows.map((e) => {
              const top = Math.max(...mlRows.map((r) => Math.abs(r.contribution))) || 1, up = e.contribution >= 0;
              return (
                <div key={e.feature} className="grid grid-cols-[1fr_140px_56px] items-center gap-3 py-1 font-mono text-sm">
                  <span className="truncate text-dim">{e.feature} = {fmtValue(e.value)}</span>
                  <div className="relative h-2 rounded-full bg-deep"><div className={`absolute inset-y-0 rounded-full ${up ? 'left-1/2 bg-rose-400' : 'right-1/2 bg-emerald-400'}`} style={{ width: `${(Math.abs(e.contribution) / top) * 50}%` }} /></div>
                  <span className={`text-right ${up ? 'text-rose-300' : 'text-emerald-300'}`}>{up ? '+' : ''}{Number(e.contribution).toFixed(2)}</span>
                </div>
              );
            })}
            {alert.detection?.ml_scores?.length > 0 && <div className="mt-1 text-xs text-faint">score {alert.detection.ml_scores.join(', ')} · {alert.model_version}</div>}
          </section>
        )}

        {corr && (
          <section className="text-sm">
            <div className="eyebrow mb-1">Campaign</div>
            <div className="text-fg">Stage: {corr.tactic} <span className="font-mono text-dim">({alert.host_stage})</span></div>
            <div className="text-dim">{corr.joined_on.length ? <>joined on {corr.joined_on.join(', ')}</> : 'first alert of this campaign'}</div>
            {corr.not_merged.map((n) => <div key={n.campaign_id} className="text-amber-300">⊘ {n.reason}</div>)}
          </section>
        )}

        <ChainBlocks alert={alert} chain={chain} />
        <div className="text-xs text-faint">window {fmtTime(f.window_start)}–{fmtTime(f.window_end)} · contract {alert.contract_version} · {alert.model_version}</div>
      </div>
    </motion.aside>
  );
}
