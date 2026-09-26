import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import FactsStrip from './components/FactsStrip';
import CampaignGraph, { buildElements } from './components/CampaignGraph';
import CampaignList from './components/CampaignList';
import AlertDrawer from './components/AlertDrawer';
import HostTimeline from './components/HostTimeline';
import ModelCard from './components/ModelCard';
import { getJSON, subscribe } from './lib/api';
import { CLASS_INFO, classInfo, fmtTime, SEVERITY_STYLE } from './lib/labels';

const MAX_ALERTS = 3000;
const GRAPH_CAMPAIGNS = 12;

function useDebounced(fn, ms) {
  const t = useRef(null);
  return useCallback(() => {
    clearTimeout(t.current);
    t.current = setTimeout(fn, ms);
  }, [fn, ms]);
}

export default function App() {
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [contract, setContract] = useState(null);
  const [chain, setChain] = useState(null);
  const [live, setLive] = useState(false);
  const [openAlert, setOpenAlert] = useState(null);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [host, setHost] = useState(null);
  const [stages, setStages] = useState(null);
  const [showCard, setShowCard] = useState(false);

  const loadCampaigns = useCallback(() => getJSON('/campaigns', { campaigns: [] }).then((r) => setCampaigns(r.campaigns)), []);
  const loadChain = useCallback(() => getJSON('/chain/verify').then(setChain), []);
  const refreshCampaigns = useDebounced(loadCampaigns, 800);
  const refreshChain = useDebounced(loadChain, 2500);

  useEffect(() => {
    getJSON('/alerts?limit=1000', { alerts: [] }).then((r) => setAlerts(r.alerts));
    loadCampaigns();
    loadChain();
    getJSON('/contract').then(setContract);
    const poll = () => getJSON('/metrics').then((m) => m && setMetrics(m));
    poll();
    const id = setInterval(poll, 2000);
    const stop = subscribe({
      onAlert: (a) => {
        setAlerts((prev) => [a, ...prev].slice(0, MAX_ALERTS));
        refreshCampaigns();
        refreshChain();
      },
      onReset: () => {
        setAlerts([]); setCampaigns([]); setOpenAlert(null); setSelectedCampaign(null); setHost(null);
        loadChain();
      },
      onOpen: () => setLive(true),
      onError: () => setLive(false),
    });
    return () => { clearInterval(id); stop(); };
  }, [loadCampaigns, loadChain, refreshCampaigns, refreshChain]);

  useEffect(() => {
    if (!host) return;
    setStages(null);
    getJSON(`/hosts/${encodeURIComponent(host)}/timeline`, { stages: [] }).then((r) => setStages(r.stages));
  }, [host, campaigns]);

  const byId = useMemo(() => new Map(alerts.map((a) => [a.alert_id, a])), [alerts]);
  const elements = useMemo(() => buildElements(alerts, campaigns, GRAPH_CAMPAIGNS), [alerts, campaigns]);
  const latest = alerts.slice(0, 8);

  return (
    <div className="h-screen flex flex-col bg-slate-950 text-slate-100">
      <FactsStrip metrics={metrics} live={live} chain={chain} onModelCard={() => setShowCard(true)} />
      <div className="flex-1 min-h-0 grid grid-cols-[minmax(260px,300px)_1fr]">
        <div className="flex flex-col min-h-0">
          <CampaignList campaigns={campaigns} selected={selectedCampaign} shownCount={Math.min(campaigns.length, GRAPH_CAMPAIGNS)}
                        onSelect={(c) => setSelectedCampaign((cur) => (cur === c ? null : c))} />
          <section className="border-t border-r border-slate-800 bg-slate-900/60 h-[34%] min-h-[150px] flex flex-col">
            <h2 className="px-3 py-2 text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-slate-800">Latest alerts</h2>
            <ul className="flex-1 overflow-y-auto" data-testid="latest-alerts">
              {latest.length === 0 && <li className="px-3 py-2 text-xs text-slate-500">None yet.</li>}
              {latest.map((a) => (
                <li key={a.alert_id}>
                  <button onClick={() => setOpenAlert(a)} className="w-full text-left px-3 py-1.5 hover:bg-slate-800/60 flex items-center gap-2 text-xs">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: classInfo(a.threat_class).color }} />
                    <span className="font-mono text-slate-400">{fmtTime(a.timestamp)}</span>
                    <span className="text-slate-100 truncate flex-1">{classInfo(a.threat_class).short} · <span className="font-mono">{a.flow?.src_ip}</span></span>
                    <span className={`text-[9px] font-bold px-1 rounded ring-1 ${SEVERITY_STYLE[a.severity] || ''}`}>{a.severity}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </div>

        <main className="relative min-h-0 overflow-hidden bg-[radial-gradient(ellipse_at_center,_#0f172a_0%,_#020617_75%)]">
          <CampaignGraph elements={elements} selectedCampaign={selectedCampaign}
                         onPickEdge={(d) => setOpenAlert(byId.get(d.alertIds[d.alertIds.length - 1]) || null)}
                         onPickHost={(d) => setHost(d.ip)} />
          {elements.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="text-center">
                <div className="text-lg text-slate-300">Watching the link. Nothing suspicious yet.</div>
                <div className="text-sm text-slate-500">Hosts and the servers they talk to appear here when an alert names them.</div>
              </div>
            </div>
          )}
          <div className="absolute top-2 left-2 bg-slate-900/85 ring-1 ring-slate-800 rounded-lg px-2.5 py-1.5 text-[10px] pointer-events-none" data-testid="legend">
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
              {Object.entries(CLASS_INFO).map(([k, v]) => (
                <div key={k} className="flex items-center gap-1.5"><span className="w-3 h-0.5 rounded" style={{ background: v.color }} /><span className="text-slate-300">{v.short}</span></div>
              ))}
            </div>
            <div className="pt-1 text-slate-500">● internal host · ◆ other end · click either</div>
          </div>
          <HostTimeline host={host} stages={stages} onClose={() => setHost(null)} />
          <AlertDrawer alert={openAlert} contract={contract} chain={chain} onClose={() => setOpenAlert(null)} />
        </main>
      </div>
      {showCard && <ModelCard onClose={() => setShowCard(false)} />}
    </div>
  );
}
