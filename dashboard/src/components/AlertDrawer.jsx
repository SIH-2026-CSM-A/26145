import React from 'react';
import { X, ShieldCheck, ShieldAlert, Eye, Cpu } from 'lucide-react';
import { classInfo, fmtTime, fmtValue, OBSERVABILITY, SEVERITY_STYLE } from '../lib/labels';

const CHIP = {
  computable: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  degraded: 'bg-yellow-500/10 text-yellow-200 ring-yellow-500/30',
  substituted: 'bg-sky-500/10 text-sky-300 ring-sky-500/30',
  unavailable: 'bg-red-500/10 text-red-300 ring-red-500/30',
};
const CHIP_TITLE = {
  computable: 'Fully derivable from what this link shows',
  degraded: 'Derivable with a stated loss (see the feature contract)',
  substituted: 'Stands in for a feature this flow could not provide',
  unavailable: 'Could not be computed on this flow; never estimated',
};

function contractChip(feature, contract, substitutedBy) {
  if (substitutedBy.has(feature)) return 'substituted';
  const st = contract?.features?.[feature]?.state;
  if (st === 'degraded') return 'degraded';
  if (st === 'unavailable') return 'unavailable';
  return st ? 'computable' : null; // reverse_dependent that was computed = both halves were seen
}

function Chip({ kind }) {
  if (!kind) return null;
  return <span title={CHIP_TITLE[kind]} className={`text-[10px] px-1.5 py-0.5 rounded ring-1 whitespace-nowrap ${CHIP[kind]}`}>{kind}</span>;
}

export default function AlertDrawer({ alert, contract, chain, onClose }) {
  if (!alert) return null;
  const info = classInfo(alert.threat_class);
  const obs = OBSERVABILITY[alert.observability_state];
  const substitutedBy = new Set((alert.substitutions || []).flatMap((s) => s.substituted_by || []));
  const ruleRows = (alert.evidence || []).filter((e) => e.baseline_source !== 'lgbm_pred_contrib');
  const mlRows = (alert.evidence || []).filter((e) => e.baseline_source === 'lgbm_pred_contrib');
  const corr = alert.detection?.correlation;
  const f = alert.flow || {};
  return (
    <aside className="absolute top-0 right-0 bottom-0 w-full sm:w-[440px] bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col z-20" data-testid="alert-drawer">
      <div className="px-4 py-3 border-b border-slate-800 flex items-start gap-3">
        <span className="mt-1 w-3 h-3 rounded-full shrink-0" style={{ background: info.color }} />
        <div className="min-w-0 flex-1">
          <h2 className="text-base font-bold text-slate-50 leading-snug">{info.plain}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
            <span className={`font-bold px-1.5 py-0.5 rounded ring-1 ${SEVERITY_STYLE[alert.severity] || ''}`}>{alert.severity}</span>
            <span className="text-slate-400 font-mono">{alert.threat_class}</span>
            <span className="text-slate-400">confidence {(alert.confidence * 100).toFixed(0)}%</span>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-slate-800 text-slate-400" aria-label="Close alert"><X className="w-5 h-5" /></button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4 text-sm">
        <section className="grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-xs text-slate-300">
          <div><span className="text-slate-500">from </span>{f.src_ip}{f.src_port !== undefined ? `:${f.src_port}` : ''}</div>
          <div><span className="text-slate-500">to </span>{f.dst_ip}:{f.dst_port} {f.protocol}</div>
          <div className="col-span-2"><span className="text-slate-500">event time </span>{alert.timestamp?.replace('T', ' ').slice(0, 19)} UTC</div>
          <div className="col-span-2"><span className="text-slate-500">detector </span>{alert.detector?.name} ({alert.detector?.type}) · {(alert.detection?.rule_matches || []).join(', ') || 'model'}</div>
        </section>

        <section className="rounded-lg bg-slate-950/60 ring-1 ring-slate-800 p-3">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-xs uppercase tracking-wider mb-1"><Eye className="w-3.5 h-3.5" /> What this link could see</div>
          <div className="text-slate-100">{obs ? obs.label : 'not recorded'}</div>
          {obs && <div className="text-xs text-slate-400">{obs.note}</div>}
          {(alert.substitutions || []).map((s) => (
            <div key={s.unavailable_on_this_flow} className="mt-2 text-xs">
              <div className="flex items-center gap-2"><span className="font-mono text-slate-300">{s.unavailable_on_this_flow}</span><Chip kind="unavailable" /></div>
              <div className="text-slate-400">{s.reason}. Used instead: <span className="font-mono">{(s.substituted_by || []).join(', ')}</span></div>
            </div>
          ))}
        </section>

        <section>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">Evidence</h3>
          <table className="w-full text-xs">
            <thead className="text-slate-500"><tr><th className="text-left font-normal pb-1">feature</th><th className="text-right font-normal pb-1">value</th><th className="text-right font-normal pb-1">normal / threshold</th><th /></tr></thead>
            <tbody className="font-mono">
              {ruleRows.map((e, i) => (
                <tr key={i} className="border-t border-slate-800">
                  <td className="py-1 pr-2 text-slate-300 break-all">{e.feature}</td>
                  <td className="py-1 text-right text-slate-100">{fmtValue(e.value)}</td>
                  <td className="py-1 text-right text-slate-400" title={e.baseline_source || ''}>{fmtValue(e.baseline)}</td>
                  <td className="py-1 pl-2 text-right"><Chip kind={contractChip(e.feature, contract, substitutedBy)} /></td>
                </tr>
              ))}
              {ruleRows.length === 0 && <tr><td colSpan={4} className="text-slate-500 py-1">No rule evidence: raised by the model alone.</td></tr>}
            </tbody>
          </table>
        </section>

        {mlRows.length > 0 && (
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5 flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5" /> ML top features (LightGBM contributions)</h3>
            <table className="w-full text-xs font-mono">
              <tbody>
                {mlRows.map((e, i) => (
                  <tr key={i} className="border-t border-slate-800">
                    <td className="py-1 text-slate-300 break-all">{e.feature}</td>
                    <td className="py-1 text-right text-slate-100">{fmtValue(e.value)}</td>
                    <td className={`py-1 text-right ${e.contribution >= 0 ? 'text-rose-300' : 'text-emerald-300'}`}>{e.contribution >= 0 ? '+' : ''}{Number(e.contribution).toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {alert.detection?.ml_scores?.length > 0 && <div className="text-[11px] text-slate-500 mt-1">score {alert.detection.ml_scores.join(', ')} · {alert.model_version}</div>}
          </section>
        )}

        {corr && (
          <section className="text-xs text-slate-300">
            <h3 className="font-semibold uppercase tracking-wider text-slate-300 mb-1">Campaign</h3>
            <div className="font-mono">{alert.campaign_id} · stage {corr.tactic} ({alert.host_stage})</div>
            <div className="text-slate-400">{corr.joined_on.length ? <>joined on {corr.joined_on.join(', ')}</> : 'first alert of this campaign'}</div>
            {corr.not_merged.map((n) => <div key={n.campaign_id} className="text-amber-300/90">⊘ {n.reason}</div>)}
          </section>
        )}

        <section className="rounded-lg bg-slate-950/60 ring-1 ring-slate-800 p-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="font-semibold uppercase tracking-wider text-slate-300">Tamper-evident record</span>
            {chain?.ok
              ? <span className="inline-flex items-center gap-1 text-emerald-300" data-testid="chain-verified"><ShieldCheck className="w-3.5 h-3.5" /> chain verified</span>
              : <span className="inline-flex items-center gap-1 text-red-300"><ShieldAlert className="w-3.5 h-3.5" /> {chain ? 'chain broken' : 'not checked'}</span>}
          </div>
          <div className="mt-1 font-mono text-[11px] text-slate-400 break-all">record_hash {alert.record_hash || '—'}</div>
          <div className="text-[11px] text-slate-500">contract {alert.contract_version} · {alert.model_version} · flow {alert.flow_id}</div>
        </section>
        <div className="text-[11px] text-slate-500">window {fmtTime(f.window_start)}–{fmtTime(f.window_end)} · {alert.alert_id}</div>
      </div>
    </aside>
  );
}
