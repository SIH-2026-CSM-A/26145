import React from 'react';

export default function MetricCard({ title, value, unit, icon: Icon, colorClass, subtext }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-slate-300 transition relative overflow-hidden flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-bold uppercase tracking-wider text-slate-500 font-sans">{title}</p>
          <div className="flex items-baseline gap-1.5 mt-2">
            <span className="text-2xl font-extrabold text-slate-900 font-sans tracking-tight">{value}</span>
            {unit && <span className="text-xs font-semibold text-slate-500 font-mono">{unit}</span>}
          </div>
        </div>
        {Icon && (
          <div className={`p-3 rounded-xl border ${colorClass} shadow-xs`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      {subtext && (
        <div className="mt-3 pt-2 border-t border-slate-100">
          <p className="text-[11px] text-slate-500 font-mono flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            {subtext}
          </p>
        </div>
      )}
    </div>
  );
}