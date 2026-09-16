import React from 'react';
import { X, ShieldAlert, Cpu, Network, FileCode, Layers } from 'lucide-react';

export default function EvidenceModal({ alert, onClose }) {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6 text-slate-900">
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-200">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-50 border border-rose-200">
              <ShieldAlert className="w-6 h-6 text-rose-600" />
            </div>
            <div>
              <h2 className="text-lg font-extrabold text-slate-900 font-sans">{alert.threat_class}</h2>
              <p className="text-xs text-slate-500 font-mono">Canonical Alert ID: {alert.alert_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg bg-slate-100 hover:bg-slate-200 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content Grid */}
        <div className="space-y-5">
          {/* Top Metric Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <span className="text-slate-500 block mb-1">Severity</span>
              <span className="font-bold text-rose-600">{alert.severity}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <span className="text-slate-500 block mb-1">Confidence</span>
              <span className="font-bold text-blue-600">{(alert.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <span className="text-slate-500 block mb-1">Detector Name</span>
              <span className="font-bold text-emerald-600">{alert.detector?.name || 'Rule Engine'}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <span className="text-slate-500 block mb-1">Detector Type</span>
              <span className="font-bold text-purple-600">{alert.detector?.type || 'HYBRID'}</span>
            </div>
          </div>

          {/* 5-Tuple Flow Details */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-2 font-sans">
              <Network className="w-4 h-4 text-blue-600" /> 5-Tuple Flow Endpoint Details
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-xs text-slate-700">
              <div><span className="text-slate-500">Source IP:</span> <span className="text-blue-700 font-semibold">{alert.flow?.src_ip}</span></div>
              <div><span className="text-slate-500">Dest IP:</span> <span className="text-emerald-700 font-semibold">{alert.flow?.dst_ip}</span></div>
              <div><span className="text-slate-500">Dest Port:</span> <span className="text-slate-900 font-semibold">{alert.flow?.dst_port}</span></div>
              <div><span className="text-slate-500">Protocol:</span> <span className="text-slate-900">{alert.flow?.protocol}</span></div>
              <div><span className="text-slate-500">Window Start:</span> <span className="text-slate-600">{alert.flow?.window_start}</span></div>
              <div><span className="text-slate-500">Window End:</span> <span className="text-slate-600">{alert.flow?.window_end}</span></div>
            </div>
          </div>

          {/* Evidence & ML Details */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-2 font-sans">
              <Cpu className="w-4 h-4 text-emerald-600" /> Rule Matches & ML Anomaly Evidence
            </h3>
            <div className="space-y-3">
              {alert.evidence?.rule_matches?.length > 0 && (
                <div>
                  <span className="text-[11px] text-slate-500 block mb-1.5 font-mono">Deterministic Rule Triggers:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {alert.evidence.rule_matches.map((rule, idx) => (
                      <span key={idx} className="bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono px-2.5 py-1 rounded-lg font-semibold">
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {alert.evidence?.ml_scores?.length > 0 && (
                <div>
                  <span className="text-[11px] text-slate-500 block mb-1.5 font-mono">Classical ML Model Scores:</span>
                  <div className="flex flex-wrap gap-2">
                    {alert.evidence.ml_scores.map((score, idx) => (
                      <span key={idx} className="bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono px-2.5 py-1 rounded-lg font-semibold">
                        {score.model}: {score.score?.toFixed(4)} ({score.prediction})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Feature Summary */}
          {alert.feature_summary && (
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
              <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-2 font-sans">
                <Layers className="w-4 h-4 text-amber-600" /> Flow Feature Metrics Summary
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs text-slate-700">
                <div><span className="text-slate-500">Packets:</span> {alert.feature_summary.total_packets}</div>
                <div><span className="text-slate-500">Bytes:</span> {alert.feature_summary.total_bytes}</div>
                <div><span className="text-slate-500">PPS:</span> {alert.feature_summary.pps?.toFixed(1)}</div>
                <div><span className="text-slate-500">BPS:</span> {alert.feature_summary.bps?.toFixed(1)}</div>
              </div>
            </div>
          )}

          {/* Complete Raw JSON View */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-2 font-sans">
              <FileCode className="w-4 h-4 text-purple-600" /> Standardized Alert JSON Schema (sih26145.alert.v1)
            </h3>
            <pre className="text-[11px] font-mono bg-slate-900 p-4 rounded-xl border border-slate-800 text-slate-100 overflow-x-auto max-h-48 shadow-inner">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}