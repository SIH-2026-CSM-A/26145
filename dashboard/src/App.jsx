import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import TopBar from './components/TopBar';
import Hero from './hero/Hero';
import ThreatTiles from './components/ThreatTiles';
import KpiStrip from './components/KpiStrip';
import CampaignMap from './components/CampaignMap';
import CampaignList from './components/CampaignList';
import CaseFile from './components/CaseFile';
import StageTimeline from './components/StageTimeline';
import ModelCard from './components/ModelCard';
import Sparks from './components/Sparks';
import { getJSON, subscribe } from './lib/api';
import { CLASS_INFO, classInfo, tileOf } from './lib/labels';

const MAX_ALERTS = 3000;
const HISTORY = 60; // flows/s samples kept for the sparkline (1 s poll)

function useDebounced(fn, ms) {
  const t = useRef(null);
  return useCallback(() => { clearTimeout(t.current); t.current = setTimeout(fn, ms); }, [fn, ms]);
}

export default function App() {
  const [metrics, setMetrics] = useState(null);
  const [history, setHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [stats, setStats] = useState({});
  const [pulse, setPulse] = useState({});
  const [contract, setContract] = useState(null);
  const [chain, setChain] = useState(null);
  const [live, setLive] = useState(false);
  const [openAlert, setOpenAlert] = useState(null);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [host, setHost] = useState(null);
  const [showCard, setShowCard] = useState(false);
  const hero = useRef(null), sparks = useRef(null), tileRefs = useRef({});

  const loadCampaigns = useCallback(() => getJSON('/campaigns', { campaigns: [] }).then((r) => setCampaigns(r.campaigns)), []);
  const loadChain = useCallback(() => getJSON('/chain/verify').then(setChain), []);
  const loadStats = useCallback(() => getJSON('/stats/classes', { classes: {} }).then((r) => setStats(r.classes)), []);
  const refreshCampaigns = useDebounced(loadCampaigns, 800);
  const refreshChain = useDebounced(loadChain, 2500);

  // an alert's flow crosses the link as a spark; the tile counts it when the spark lands
  const land = useCallback((a) => {
    const t = tileOf(a.threat_class);
    loadStats();
    if (t) setPulse((p) => ({ ...p, [t.id]: (p[t.id] || 0) + 1 }));
  }, [loadStats]);
  const launch = useCallback((a) => {
    const t = tileOf(a.threat_class), color = classInfo(a.threat_class).color;
    if (!hero.current || !t) return land(a);
    hero.current.launch(color, (from) => {
      const r = tileRefs.current[t.id]?.getBoundingClientRect();
      if (!r || !sparks.current) return land(a);
      sparks.current.fly(from, { x: r.left + r.width - 48, y: r.top + 32 }, color, () => land(a));
    });
  }, [land]);

  useEffect(() => {
    getJSON('/alerts?limit=1000', { alerts: [] }).then((r) => setAlerts(r.alerts));
    loadCampaigns(); loadChain(); loadStats();
    getJSON('/contract').then(setContract);
    const poll = () => getJSON('/metrics').then((m) => {
      if (!m) return;
      setMetrics(m);
      if (m.pipeline_state === 'running') setHistory((h) => [...h, m.flows_per_sec || 0].slice(-HISTORY));
    });
    poll();
    const id = setInterval(poll, 1000);
    const stop = subscribe({
      onAlert: (a) => { setAlerts((prev) => [a, ...prev].slice(0, MAX_ALERTS)); refreshCampaigns(); refreshChain(); launch(a); },
      onReset: () => {
        setAlerts([]); setCampaigns([]); setStats({}); setPulse({}); setHistory([]);
        setOpenAlert(null); setSelectedCampaign(null); setHost(null); loadChain();
      },
      onOpen: () => setLive(true),
      onError: () => setLive(false),
    });
    return () => { clearInterval(id); stop(); };
  }, [loadCampaigns, loadChain, loadStats, refreshCampaigns, refreshChain, launch]);

  const byId = useMemo(() => new Map(alerts.map((a) => [a.alert_id, a])), [alerts]);
  const mlCount = stats.THREAT_ML_MALICIOUS_FLOW?.count || 0;

  const pickCampaign = (c) => setSelectedCampaign((cur) => (cur === c ? null : c));
  return (
    <div>
      <div className="flex h-screen min-h-[1000px] flex-col" data-testid="screen-live">
        <TopBar metrics={metrics} live={live} onModelCard={() => setShowCard(true)} />
        <main className="flex min-h-0 flex-1 flex-col gap-4 px-6 pb-6">
          <div className="grid min-h-0 flex-1 grid-cols-[1.5fr_1fr] gap-4">
            <Hero ref={hero} metrics={metrics} />
            <ThreatTiles stats={stats} pulse={pulse} tileRefs={tileRefs} alerts={alerts} />
          </div>
          <KpiStrip metrics={metrics} history={history} chain={chain} />
          <CampaignList campaigns={campaigns} selected={selectedCampaign}
                        onSelect={(c) => { pickCampaign(c); document.getElementById('map')?.scrollIntoView({ behavior: 'smooth' }); }} />
        </main>
      </div>
      <div id="map" className="flex h-screen min-h-[1000px] flex-col gap-4 px-6 py-6" data-testid="screen-map">
        <section className="glass relative flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex flex-wrap items-center gap-2 px-6 pt-5">
            <span className="eyebrow mr-3">Campaign map</span>
            {Object.entries(CLASS_INFO).map(([k, v]) => (
              <span key={k} className="chip" style={{ color: v.color, background: `${v.color}14`, '--tw-ring-color': `${v.color}40` }}>
                <span className="h-2 w-2 rounded-full" style={{ background: v.color }} />{v.short}
              </span>
            ))}
            <span className="ml-auto text-sm text-dim">Click a host for its stages · click a line for the case file</span>
          </div>
          <div className="relative min-h-0 flex-1">
            {campaigns.length ? (
              <CampaignMap alerts={alerts} campaigns={campaigns} selected={selectedCampaign} focus={host}
                           onPickEdge={(id) => setOpenAlert(byId.get(id) || null)} onPickHost={setHost} onPickCampaign={pickCampaign} />
            ) : (
              <div className="flex h-full items-center justify-center text-center">
                <div><div className="text-xl text-fg">Watching the link. Nothing suspicious yet.</div>
                  <div className="mt-1 text-dim">Alerts that share a rare host, server, name or fingerprint are grouped here as campaigns.</div></div>
              </div>
            )}
          </div>
          {mlCount > 0 && <div className="px-6 pb-3 text-sm text-faint">ML-only flags (not drawn): {mlCount}</div>}
        </section>
        <StageTimeline host={host} campaigns={campaigns} onClose={() => setHost(null)} />
      </div>
      <CaseFile alert={openAlert} contract={contract} chain={chain} onClose={() => setOpenAlert(null)} />
      {showCard && <ModelCard onClose={() => setShowCard(false)} />}
      <Sparks ref={sparks} />
    </div>
  );
}
