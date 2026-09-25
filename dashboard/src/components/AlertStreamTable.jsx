import React, { useState } from 'react';
import { Search, ChevronRight, ShieldAlert, Filter } from 'lucide-react';

const SEVERITY_BADGES = {
  CRITICAL: 'bg-rose-50 text-rose-700 border-rose-200',
  HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
  MEDIUM: 'bg-amber-50 text-amber-700 border-amber-200',
  LOW: 'bg-blue-50 text-blue-700 border-blue-200',
};

export default function AlertStreamTable({ alerts, onSelectAlert, activeAlertId }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSev = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    const matchesSearch =
      !searchQuery ||
      alert.threat_class.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.flow?.src_ip?.includes(searchQuery) ||
      alert.flow?.dst_ip?.includes(searchQuery);
    return matchesSev && matchesSearch;
  });

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-slate-900 font-sans flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            Live Threat Event Log Feed
          </h3>
          <p className="text-xs text-slate-500 font-medium">
            Real-time SSE event stream & historical SQLite alert records (<code className="text-blue-600 font-mono font-semibold">sih26145.alert.v2</code>)
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filter IP or threat class..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-50 border border-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-800 focus:outline-none focus:border-blue-500 font-mono w-48 sm:w-56"
            />
          </div>

          {/* Severity Filters */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs font-mono">
            <Filter className="w-3 h-3 text-slate-500 ml-1.5 mr-0.5" />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2 py-0.5 rounded font-semibold transition ${
                  filterSeverity === sev ? 'bg-blue-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Alert Feed Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-200">
        <table className="w-full text-left text-xs text-slate-700">
          <thead className="bg-slate-100 text-slate-600 font-mono uppercase tracking-wider text-[11px] border-b border-slate-200">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Threat Category</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Destination IP</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 font-mono">
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center py-10 text-slate-400 italic font-sans">
                  No threat events detected matching active search filters.
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert, idx) => {
                const isSelected = activeAlertId === alert.alert_id;
                return (
                  <tr
                    key={alert.alert_id || idx}
                    className={`transition cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50/80 border-l-4 border-l-blue-600 font-medium'
                        : 'hover:bg-slate-50/80'
                    }`}
                    onClick={() => onSelectAlert(alert)}
                  >
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_BADGES[alert.severity] || 'bg-slate-100 text-slate-700'}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-900 whitespace-nowrap">
                      {alert.threat_class}
                    </td>
                    <td className="px-4 py-3 text-blue-700 whitespace-nowrap font-semibold">{alert.flow?.src_ip}</td>
                    <td className="px-4 py-3 text-emerald-700 whitespace-nowrap font-semibold">{alert.flow?.dst_ip}:{alert.flow?.dst_port}</td>
                    <td className="px-4 py-3 font-bold text-slate-900 whitespace-nowrap">
                      {(alert.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        className="text-blue-600 hover:text-blue-800 flex items-center justify-end gap-1 ml-auto text-[11px] font-semibold"
                      >
                        Inspect <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}