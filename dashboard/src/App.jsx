import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import MetricCard from './components/MetricCard';
import TrafficChart from './components/TrafficChart';
import ThreatDistChart from './components/ThreatDistChart';
import DetectionInsightPanel from './components/DetectionInsightPanel';
import AlertStreamTable from './components/AlertStreamTable';
import EvidenceModal from './components/EvidenceModal';
import { fetchHealth, fetchMetrics, fetchAlerts } from './services/api';
import { subscribeToAlertStream } from './services/sse';
import { Activity, ShieldAlert, Zap, Layers, AlertTriangle, AlertOctagon } from 'lucide-react';

export default function App() {
  const [health, setHealth] = useState({ status: 'OFFLINE', monitoring: 'DISCONNECTED', active: false });
  const [metrics, setMetrics] = useState({ active_flows: 0, packets_per_sec: 0, bytes_per_sec: 0, total_alerts: 0 });
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [modalAlert, setModalAlert] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

  // Poll backend health & metrics every 3s
  useEffect(() => {
    async function loadData() {
      const h = await fetchHealth();
      setHealth(h);
      const m = await fetchMetrics();
      setMetrics(m);

      // Append point to throughput timeline
      const nowStr = new Date().toLocaleTimeString();
      setTrafficHistory((prev) => {
        const next = [...prev, { time: nowStr, pps: m.packets_per_sec || 0, bps: (m.bytes_per_sec || 0) / 1024 }];
        return next.slice(-20);
      });
    }

    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial historical alerts
  useEffect(() => {
    fetchAlerts(null, null, 100).then((res) => {
      if (res && res.alerts) {
        setAlerts(res.alerts);
        if (res.alerts.length > 0) {
          setSelectedAlert(res.alerts[0]);
        }
      }
    });
  }, []);

  // Subscribe to live SSE Alert Stream
  useEffect(() => {
    const unsubscribe = subscribeToAlertStream(
      (newAlert) => {
        setIsConnected(true);
        setAlerts((prev) => [newAlert, ...prev]);
        setSelectedAlert((prev) => prev || newAlert);
        setMetrics((prev) => ({ ...prev, total_alerts: prev.total_alerts + 1 }));
      },
      () => {
        setIsConnected(false);
      }
    );
    setIsConnected(true);
    return () => unsubscribe();
  }, []);

  // Compute threat category distribution
  const alertCounts = alerts.reduce((acc, alert) => {
    const tc = alert.threat_class || 'UNKNOWN';
    acc[tc] = (acc[tc] || 0) + 1;
    return acc;
  }, {});

  // High/Critical severity alert count
  const highSevCount = alerts.filter((a) => a.severity === 'HIGH' || a.severity === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      <Header isConnected={isConnected} health={health} />

      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Connection Warning Banner if Backend Offline */}
        {health.status !== 'OK' && (
          <div className="bg-rose-50 border border-rose-200 text-rose-800 p-4 rounded-xl flex items-center gap-3 shadow-sm">
            <AlertOctagon className="w-5 h-5 text-rose-600 shrink-0" />
            <div className="text-xs">
              <span className="font-bold block">FastAPI Backend Unavailable</span>
              Ensure the SIH26145 backend server is running on <code className="font-mono text-rose-700 font-semibold bg-rose-100 px-1 py-0.5 rounded">http://localhost:8000</code>.
            </div>
          </div>
        )}

        {!isConnected && health.status === 'OK' && (
          <div className="bg-amber-50 border border-amber-200 text-amber-800 p-3.5 rounded-xl flex items-center gap-3 shadow-sm">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
            <div className="text-xs">
              <span className="font-bold block">Live Stream Reconnecting</span>
              Attempting to establish connection with SSE live threat feed...
            </div>
          </div>
        )}

        {/* Top Summary Metric Overview Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <MetricCard
            title="Active Flows"
            value={metrics.active_flows}
            unit="tracked"
            icon={Layers}
            colorClass="bg-blue-50 border-blue-200 text-blue-600"
            subtext="LRU State Engine"
          />
          <MetricCard
            title="Packet Rate"
            value={metrics.packets_per_sec ? metrics.packets_per_sec.toFixed(1) : "0.0"}
            unit="PPS"
            icon={Zap}
            colorClass="bg-emerald-50 border-emerald-200 text-emerald-600"
            subtext="Ingestion Telemetry"
          />
          <MetricCard
            title="Byte Throughput"
            value={metrics.bytes_per_sec ? (metrics.bytes_per_sec / 1024).toFixed(1) : "0.0"}
            unit="KB/s"
            icon={Activity}
            colorClass="bg-purple-50 border-purple-200 text-purple-600"
            subtext="Unidirectional Tap"
          />
          <MetricCard
            title="Total Detections"
            value={alerts.length}
            unit="alerts"
            icon={ShieldAlert}
            colorClass="bg-indigo-50 border-indigo-200 text-indigo-600"
            subtext="SQLite & SSE Stream"
          />
          <MetricCard
            title="High / Critical"
            value={highSevCount}
            unit="alerts"
            icon={AlertTriangle}
            colorClass="bg-rose-50 border-rose-200 text-rose-600"
            subtext="High Severity Ratio"
          />
        </div>

        {/* Primary Dashboard Grid Row: Timeline, Distribution, & Insight Panel */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <TrafficChart data={trafficHistory} />
              <ThreatDistChart alertCounts={alertCounts} />
            </div>
          </div>

          <div className="lg:col-span-1">
            <DetectionInsightPanel alert={selectedAlert} onOpenModal={setModalAlert} />
          </div>
        </div>

        {/* Live SSE & Historical Threat Feed Table */}
        <AlertStreamTable
          alerts={alerts}
          onSelectAlert={setSelectedAlert}
          activeAlertId={selectedAlert?.alert_id}
        />
      </main>

      {/* Raw Evidence Inspection Modal */}
      {modalAlert && (
        <EvidenceModal alert={modalAlert} onClose={() => setModalAlert(null)} />
      )}
    </div>
  );
}