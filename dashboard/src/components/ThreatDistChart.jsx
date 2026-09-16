import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, CartesianGrid } from 'recharts';

// Canonical Threat Classes in preferred visual display order (top to bottom)
const CANONICAL_THREAT_CLASSES = [
  {
    name: 'Data Exfiltration',
    keys: ['THREAT_EXFILTRATION', 'THREAT_ICMP_EXFILTRATION'],
    psCategory: '6. Data Exfiltration',
    color: '#ca8a04',
  },
  {
    name: 'C2 Beaconing',
    keys: ['THREAT_C2_BEACON'],
    psCategory: '2. C2 Beaconing',
    color: '#9333ea',
  },
  {
    name: 'Encrypted Anomaly',
    keys: ['THREAT_ENCRYPTED_ANOMALY'],
    psCategory: '4. Encrypted Session',
    color: '#2563eb',
  },
  {
    name: 'DGA',
    keys: ['THREAT_DNS_DGA'],
    psCategory: '3. DGA / DNS Tunnelling',
    color: '#db2777',
  },
  {
    name: 'DNS Tunnelling',
    keys: ['THREAT_DNS_TUNNEL'],
    psCategory: '3. DGA / DNS Tunnelling',
    color: '#ea580c',
  },
  {
    name: 'DDoS Volumetric',
    keys: ['THREAT_DDOS_VOLUME'],
    psCategory: '1. DDoS Anomalies',
    color: '#dc2626',
  },
  {
    name: 'Reconnaissance',
    keys: ['THREAT_RECON_PORTSCAN'],
    psCategory: '5. Reconnaissance',
    color: '#0891b2',
  },
  {
    name: 'Unsupervised Anomaly',
    keys: ['THREAT_UNSUPERVISED_ANOMALY'],
    psCategory: 'Unsupervised ML Anomaly',
    color: '#059669',
  },
];

export default function ThreatDistChart({ alertCounts }) {
  // Map alert counts into the preferred canonical order
  const data = CANONICAL_THREAT_CLASSES.map((cls) => {
    const count = cls.keys.reduce((sum, k) => sum + (alertCounts[k] || 0), 0);
    return {
      name: cls.name,
      count,
      psCategory: cls.psCategory,
      color: cls.color,
      fullName: cls.keys.join(', '),
    };
  });

  // Preserve dynamic handling for any unanticipated threat classes from backend
  Object.keys(alertCounts).forEach((k) => {
    const isMatched = CANONICAL_THREAT_CLASSES.some((cls) => cls.keys.includes(k));
    if (!isMatched) {
      data.push({
        name: k.replace('THREAT_', ''),
        count: alertCounts[k] || 0,
        psCategory: 'Custom Threat Class',
        color: '#64748b',
        fullName: k,
      });
    }
  });

  const hasData = data.some((item) => item.count > 0);

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900 font-sans">Threat Class Distribution</h3>
        </div>
        <span className="text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
          {data.length} Active Threat Classes
        </span>
      </div>

      <div className="h-64 w-full">
        {!hasData ? (
          <div className="h-full w-full flex items-center justify-center border border-dashed border-slate-200 rounded-lg text-slate-400 text-xs font-mono">
            No historical threat detections available.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart layout="vertical" data={data} margin={{ top: 5, right: 25, left: 10, bottom: 25 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
              <XAxis
                type="number"
                stroke="#64748b"
                tick={{ fontSize: 10, fill: '#64748b' }}
                allowDecimals={false}
                axisLine={{ stroke: '#cbd5e1' }}
                tickLine={false}
              />
              <YAxis
                type="category"
                dataKey="name"
                interval={0}
                stroke="#64748b"
                tick={{ fontSize: 10, fill: '#334155', fontWeight: 500 }}
                width={145}
                tickLine={false}
                axisLine={{ stroke: '#cbd5e1' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  borderColor: '#cbd5e1',
                  borderRadius: '0.75rem',
                  color: '#0f172a',
                  boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)',
                }}
                formatter={(val, name, item) => [`${val} alerts (${item.payload.psCategory})`, item.payload.name]}
              />
              <Bar dataKey="count" barSize={12} radius={[0, 4, 4, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
