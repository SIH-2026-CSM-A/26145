import React from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

export default function TrafficChart({ data }) {
  const hasData = data && data.length > 0;

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900 font-sans">Live Traffic Throughput Timeline</h3>
          <p className="text-xs text-slate-500 font-medium">Real-time Packets/Sec (PPS) & Byte Throughput (KB/s)</p>
        </div>
        <span className="text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
          3s Polling Rate
        </span>
      </div>

      <div className="h-64 w-full">
        {!hasData ? (
          <div className="h-full w-full flex items-center justify-center border border-dashed border-slate-200 rounded-lg text-slate-400 text-xs font-mono">
            Waiting for backend metrics stream...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563eb" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="bpsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
              <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '0.75rem', color: '#0f172a', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                itemStyle={{ fontSize: '12px' }}
              />
              <Area type="monotone" dataKey="pps" name="Packets/Sec (PPS)" stroke="#2563eb" fillOpacity={1} fill="url(#ppsGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="bps" name="Byte Rate (KB/s)" stroke="#10b981" fillOpacity={1} fill="url(#bpsGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}