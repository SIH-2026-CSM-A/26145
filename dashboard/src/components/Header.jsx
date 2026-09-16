import React from 'react';
import { ShieldCheck, Radio, Eye, Activity } from 'lucide-react';

export default function Header({ isConnected, health }) {
  const isHealthy = health && health.status === 'OK';

  return (
    <header className="bg-white border-b border-slate-200 px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
      <div className="flex items-center space-x-3">
        <div className="bg-blue-50 p-2.5 rounded-xl border border-blue-200 shadow-xs">
          <ShieldCheck className="w-7 h-7 text-blue-600" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-extrabold tracking-tight text-slate-900 font-sans">
              SIH26145 ThreatLens SOC
            </h1>
            <span className="text-[11px] px-2.5 py-0.5 rounded-md font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
              NTRO v1.0
            </span>
          </div>
          <p className="text-xs text-slate-500 font-medium">AI-Based Cyber Threat Detection in Unidirectional IP Traffic</p>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        {/* PASSIVE READ-ONLY SECURITY MODEL BADGE */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-semibold tracking-wide shadow-xs">
          <Eye className="w-4 h-4 text-emerald-600 animate-pulse" />
          <span>PASSIVE / READ-ONLY MONITORING</span>
        </div>

        {/* HEALTH & SSE CONNECTION STATUS BADGES */}
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold ${
            isHealthy
              ? 'bg-slate-100 border-slate-200 text-slate-700'
              : 'bg-rose-50 border-rose-200 text-rose-700'
          }`}>
            <Activity className={`w-3.5 h-3.5 ${isHealthy ? 'text-emerald-600' : 'text-rose-600'}`} />
            <span>{isHealthy ? 'REST API ONLINE' : 'REST API OFFLINE'}</span>
          </div>

          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold ${
            isConnected
              ? 'bg-blue-50 border-blue-200 text-blue-700'
              : 'bg-amber-50 border-amber-200 text-amber-700'
          }`}>
            <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-blue-600 animate-pulse' : 'text-amber-600'}`} />
            <span>{isConnected ? 'SSE STREAM ACTIVE' : 'SSE DISCONNECTED'}</span>
          </div>
        </div>
      </div>
    </header>
  );
}