import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import { classInfo } from '../lib/labels';

// Hosts and destinations are nodes, alerts are edges (one per campaign/src/dst/class, with a
// count), campaigns are compound parents. A destination seen by two campaigns is drawn once
// in each: the campaign boxes stay separate, as the correlator decided.
export function buildElements(alerts, campaigns, maxCampaigns = 12) {
  const shown = campaigns.slice(0, maxCampaigns);
  const keep = new Set(shown.map((c) => c.campaign_id));
  const hostsOf = Object.fromEntries(shown.map((c) => [c.campaign_id, new Set(c.hosts)]));
  const nodes = new Map();
  const edges = new Map();
  for (const c of shown) {
    const stages = c.tactics.length;
    nodes.set(`c:${c.campaign_id}`, {
      data: { id: `c:${c.campaign_id}`, label: `${c.hosts.join(', ') || 'campaign'} · ${c.alerts} alert${c.alerts === 1 ? '' : 's'}${stages > 1 ? ` · ${stages} stages` : ''}`, kind: 'campaign', campaign: c.campaign_id },
    });
  }
  for (const a of alerts) {
    const cid = a.campaign_id;
    if (!keep.has(cid)) continue;
    const { src_ip: s, dst_ip: d } = a.flow || {};
    if (!s || !d) continue;
    for (const ip of [s, d]) {
      const id = `${cid}|${ip}`;
      if (!nodes.has(id)) {
        const isHost = hostsOf[cid].has(ip);
        nodes.set(id, { data: { id, label: ip, ip, parent: `c:${cid}`, kind: isHost ? 'host' : 'remote', campaign: cid } });
      }
    }
    const eid = `${cid}|${s}|${d}|${a.threat_class}`;
    const e = edges.get(eid) || { data: { id: eid, source: `${cid}|${s}`, target: `${cid}|${d}`, cls: a.threat_class, color: classInfo(a.threat_class).color, count: 0, alertIds: [], campaign: cid } };
    e.data.count += 1;
    e.data.alertIds.push(a.alert_id);
    e.data.label = `${classInfo(a.threat_class).short}${e.data.count > 1 ? ` ×${e.data.count}` : ''}`;
    edges.set(eid, e);
  }
  return [...nodes.values(), ...edges.values()];
}

const STYLE = [
  { selector: 'node[kind="campaign"]', style: {
    'background-color': '#0f172a', 'background-opacity': 0.55, 'border-color': '#334155', 'border-width': 1.5,
    shape: 'round-rectangle', label: 'data(label)', 'text-valign': 'top', 'text-halign': 'center', color: '#cbd5e1',
    'font-size': 15, 'font-weight': 600, 'text-margin-y': -6, padding: 22, 'min-zoomed-font-size': 6 } },
  { selector: 'node[kind="campaign"].selected', style: { 'border-color': '#38bdf8', 'border-width': 2.5 } },
  { selector: 'node[kind="host"]', style: {
    'background-color': '#0ea5e9', 'border-color': '#bae6fd', 'border-width': 2, width: 40, height: 40,
    label: 'data(label)', color: '#e2e8f0', 'font-size': 15, 'text-valign': 'bottom', 'text-margin-y': 5,
    'text-outline-color': '#020617', 'text-outline-width': 2 } },
  { selector: 'node[kind="remote"]', style: {
    'background-color': '#475569', 'border-color': '#94a3b8', 'border-width': 1, width: 28, height: 28, shape: 'diamond',
    label: 'data(label)', color: '#cbd5e1', 'font-size': 13, 'text-valign': 'bottom', 'text-margin-y': 4,
    'text-outline-color': '#020617', 'text-outline-width': 2 } },
  { selector: 'node.picked', style: { 'border-color': '#fde047', 'border-width': 3 } },
  { selector: 'edge', style: {
    width: 3.5, 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle',
    'curve-style': 'bezier', label: 'data(label)', 'font-size': 13, 'font-weight': 600, color: '#f1f5f9', 'text-rotation': 'autorotate',
    'text-background-color': '#020617', 'text-background-opacity': 0.85, 'text-background-padding': 2 } },
  { selector: 'edge.picked', style: { width: 5 } },
];

export default function CampaignGraph({ elements, selectedCampaign, onPickEdge, onPickHost }) {
  const box = useRef(null);
  const cy = useRef(null);
  const handlers = useRef({ onPickEdge, onPickHost });
  handlers.current = { onPickEdge, onPickHost };

  useEffect(() => {
    cy.current = cytoscape({ container: box.current, style: STYLE, wheelSensitivity: 0.2, minZoom: 0.2, maxZoom: 3 });
    cy.current.on('tap', 'edge', (e) => {
      cy.current.elements().removeClass('picked');
      e.target.addClass('picked');
      handlers.current.onPickEdge(e.target.data());
    });
    cy.current.on('tap', 'node[kind!="campaign"]', (e) => {
      cy.current.elements().removeClass('picked');
      e.target.addClass('picked');
      handlers.current.onPickHost(e.target.data());
    });
    window.__cy = cy.current; // for the Playwright smoke test
    return () => cy.current.destroy();
  }, []);

  useEffect(() => {
    const g = cy.current;
    const want = new Map(elements.map((el) => [el.data.id, el]));
    let added = false;
    g.batch(() => {
      g.elements().forEach((el) => { if (!want.has(el.id())) el.remove(); });
      for (const [id, el] of want) {
        const cur = g.getElementById(id);
        if (cur.nonempty()) cur.data(el.data);
        else { g.add(el); added = true; }
      }
    });
    if (added) {
      g.layout({ name: 'cose', animate: false, randomize: false, nodeDimensionsIncludeLabels: true,
                 idealEdgeLength: () => 150, nodeRepulsion: () => 12000, componentSpacing: 30, padding: 20 }).run();
      g.fit(undefined, 30);
    }
  }, [elements]);

  useEffect(() => {
    const g = cy.current;
    g.nodes('[kind="campaign"]').removeClass('selected');
    if (!selectedCampaign) return;
    const n = g.getElementById(`c:${selectedCampaign}`);
    if (n.nonempty()) {
      n.addClass('selected');
      g.animate({ fit: { eles: n.union(n.descendants()), padding: 60 } }, { duration: 300 });
    }
  }, [selectedCampaign]);

  return <div ref={box} className="absolute inset-0" data-testid="campaign-graph" />;
}
