import React from 'react';
import { ShieldAlert, Cpu, Network, Activity, ArrowRight } from 'lucide-react';

const SEVERITY_BADGES = {
  CRITICAL: 'bg-rose-50 border-rose-200 text-rose-700',
  HIGH: 'bg-orange-50 border-orange-200 text-orange-700',
  MEDIUM: 'bg-amber-50 border-amber-200 text-amber-700',
  LOW: 'bg-blue-50 border-blue-200 text-blue-700',
};

export default function DetectionInsightPanel({ alert, onOpenModal }) {
  if (!alert) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm h-full flex flex-col justify-center items-center text-center">
        <ShieldAlert className="w-10 h-10 text-slate-300 mb-2" />
        <h4 className="text-sm font-bold text-slate-700">No Threat Selected</h4>
        <p className="text-xs text-slate-500 max-w-xs mt-1">
          Select any alert from the live feed or historical event log to inspect detailed detection evidence.
        </p>
      </div>
    );
  }

  const severityBadgeClass = SEVERITY_BADGES[alert.severity] || 'bg-slate-100 text-slate-700 border-slate-200';
  const confidencePct = (alert.confidence * 100).toFixed(1);
  const ruleMatches = alert.evidence?.rule_matches || [];
  const mlScores = alert.evidence?.ml_scores || [];
  const metrics = alert.evidence?.metrics || {};

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-extrabold text-slate-900 font-sans">{alert.threat_class}</h3>
            <span className={`px-2 py-0.5 rounded border text-[10px] font-bold font-mono ${severityBadgeClass}`}>
              {alert.severity}
            </span>
          </div>
          <p className="text-xs text-slate-500 font-mono mt-0.5">ID: {alert.alert_id}</p>
        </div>
        <div className="text-right">
          <span className="text-xs text-slate-500 block font-medium">Confidence</span>
          <span className="text-lg font-bold text-blue-600 font-mono">{confidencePct}%</span>
        </div>
      </div>

      {/* 5-Tuple Flow Box */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800 mb-2">
          <Network className="w-3.5 h-3.5 text-blue-600" />
          <span>Flow Endpoint Details</span>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-700">
          <div><span className="text-slate-500">Source:</span> <span className="text-blue-700 font-semibold">{alert.flow?.src_ip}</span></div>
          <div><span className="text-slate-500">Target:</span> <span className="text-emerald-700 font-semibold">{alert.flow?.dst_ip}:{alert.flow?.dst_port}</span></div>
          <div><span className="text-slate-500">Protocol:</span> <span className="text-slate-800">{alert.flow?.protocol}</span></div>
          <div><span className="text-slate-500">Detector:</span> <span className="text-purple-700 font-semibold">{alert.detector?.name}</span></div>
        </div>
      </div>

      {/* Detection Evidence Summary */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
          <Cpu className="w-3.5 h-3.5 text-emerald-600" />
          <span>Triggered Detection Evidence</span>
        </div>

        {ruleMatches.length > 0 && (
          <div>
            <span className="text-[11px] text-slate-500 block mb-1 font-medium">Deterministic Rule Triggers:</span>
            <div className="flex flex-wrap gap-1">
              {ruleMatches.map((rule, idx) => (
                <span key={idx} className="bg-rose-50 border border-rose-200 text-rose-700 text-[10px] font-mono px-2 py-0.5 rounded font-semibold">
                  {rule}
                </span>
              ))}
            </div>
          </div>
        )}

        {mlScores.length > 0 && (
          <div>
            <span className="text-[11px] text-slate-500 block mb-1 font-medium">Classical ML Anomaly Evaluation:</span>
            <div className="flex flex-wrap gap-1">
              {mlScores.map((score, idx) => (
                <span key={idx} className="bg-blue-50 border border-blue-200 text-blue-700 text-[10px] font-mono px-2 py-0.5 rounded font-semibold">
                  {score.model}: {score.score?.toFixed(3)}
                </span>
              ))}
            </div>
          </div>
        )}

        {Object.keys(metrics).length > 0 && (
          <div className="pt-2 border-t border-slate-200">
            <span className="text-[11px] text-slate-500 block mb-1 font-medium">Synthesized Feature Metrics:</span>
            <div className="grid grid-cols-2 gap-1 text-[11px] font-mono text-slate-700">
              {Object.entries(metrics).map(([k, v]) => (
                <div key={k} className="truncate">
                  <span className="text-slate-500">{k}:</span> {typeof v === 'number' ? v.toFixed(2) : String(v)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="flex items-center justify-between pt-1">
        <span className="text-[11px] text-slate-500 font-mono">
          Time: {new Date(alert.timestamp).toLocaleTimeString()}
        </span>
        <button
          onClick={() => onOpenModal(alert)}
          className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition flex items-center gap-1.5 shadow-sm"
        >
          <span>Full Raw Evidence</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
