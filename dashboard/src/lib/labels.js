// Plain words for a non-technical viewer; the technical id is shown next to it.
export const CLASS_INFO = {
  THREAT_RECON_PORTSCAN: { short: 'Scan', plain: 'Scanning many ports or machines (reconnaissance)', color: '#38bdf8' },
  THREAT_C2_BEACON: { short: 'C2 beacon', plain: 'Regular check-ins to an outside server (command and control)', color: '#a78bfa' },
  THREAT_DNS_DGA: { short: 'DGA', plain: 'Lookups of many random-looking domain names (malware searching for its server)', color: '#fbbf24' },
  THREAT_DNS_TUNNEL: { short: 'DNS tunnel', plain: 'Data hidden inside DNS lookups (DNS tunnelling)', color: '#fb923c' },
  THREAT_ENCRYPTED_ANOMALY: { short: 'Rare TLS client', plain: 'An unusual encrypted client repeatedly contacting one server', color: '#2dd4bf' },
  THREAT_EXFILTRATION: { short: 'Exfiltration', plain: 'A large upload leaving the network (data exfiltration)', color: '#f472b6' },
  THREAT_DDOS_VOLUME: { short: 'DDoS', plain: 'A traffic flood aimed at one server (denial of service)', color: '#f43f5e' },
  THREAT_ML_MALICIOUS_FLOW: { short: 'ML flag', plain: 'A connection the ML model scores as botnet-like', color: '#94a3b8' },
};
export const classInfo = (c) => CLASS_INFO[c] || { short: c, plain: c, color: '#94a3b8' };

// The six PS 26145 threat classes, in the PS's order, in plain words. `looks` names what the
// detector reads (README threat table). (c) covers two alert classes.
export const TILES = [
  { id: 'a', classes: ['THREAT_DDOS_VOLUME'], title: 'Floods aimed at one server', ps: 'Volumetric / protocol DDoS', looks: 'source count + spread + SYN share' },
  { id: 'b', classes: ['THREAT_C2_BEACON'], title: 'Malware checking in on a timer', ps: 'C2 beaconing', looks: 'how regular the check-ins are' },
  { id: 'c', classes: ['THREAT_DNS_DGA', 'THREAT_DNS_TUNNEL'], title: 'Random domains and DNS tunnels', ps: 'DGA and DNS tunnelling', looks: 'name randomness + query volume' },
  { id: 'd', classes: ['THREAT_ENCRYPTED_ANOMALY'], title: 'Malware inside encrypted sessions', ps: 'TLS metadata, no decryption', looks: 'how rare the TLS fingerprint is' },
  { id: 'e', classes: ['THREAT_RECON_PORTSCAN'], title: 'Scanning for open doors', ps: 'Recon and port scanning', looks: 'ports + hosts touched, SYN-only share' },
  { id: 'f', classes: ['THREAT_EXFILTRATION'], title: 'Data leaving the network', ps: 'Data exfiltration', looks: 'upload vs normal + destination rarity' },
];
export const tileOf = (cls) => TILES.find((t) => t.classes.includes(cls));

export const OBSERVABILITY = {
  bidirectional: { label: 'Both directions seen', note: 'Request and reply were both on the link.' },
  forward_only: { label: 'Forward direction only', note: 'Only the sender side was captured on this link.' },
  reverse_only: { label: 'Reverse direction only', note: 'Only the replies were captured on this link.' },
};

export const SEVERITY_STYLE = {
  CRITICAL: 'bg-red-500/20 text-red-300 ring-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-300 ring-orange-500/40',
  MEDIUM: 'bg-yellow-500/15 text-yellow-200 ring-yellow-500/40',
  LOW: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
};

export const fmtTime = (iso) => (iso ? new Date(iso).toISOString().slice(11, 19) : '—');

export function fmtValue(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return v.toLocaleString('en-US');
    return Math.abs(v) >= 100 ? v.toLocaleString('en-US', { maximumFractionDigits: 1 }) : v.toFixed(3);
  }
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  return String(v);
}

// Plain names for evidence features; the contract id is shown next to it.
export const FEATURE_PLAIN = {
  dst_distinct_srcs_w: 'Distinct sources hitting this server',
  dst_src_ip_entropy_w: 'How spread out the sources are',
  dst_syn_only_ratio_w: 'Share of connections that never complete',
  outbound_inbound_byte_ratio: 'Bytes sent out per byte received',
  egress_bytes: 'Bytes uploaded',
  src_dns_queries_w: 'DNS lookups by this host',
  pair_iat_cv: 'Timing irregularity of check-ins (low = clockwork)',
  pair_iat_n: 'Check-ins observed',
  pair_iat_mean: 'Seconds between check-ins',
  src_periodic_dsts_w: 'Servers this host polls on a timer',
  src_high_entropy_qnames_w: 'Random-looking names looked up',
  src_distinct_qnames_w: 'Distinct names looked up',
  src_nxdomain_rate_w: 'Share of lookups for names that do not exist',
  tls_ja4: 'TLS client fingerprint (JA4)',
  ja4_prevalence: 'Times this fingerprint was seen, enclave-wide',
  pair_history_count: 'Past connections between this pair',
  pair_flows_w: 'Connections between this pair (window)',
  total_bytes: 'Bytes in the session',
  duration: 'Session length (s)',
  src_distinct_dsts_w: 'Machines this host contacted',
  src_distinct_dst_ports_w: 'Ports this host tried',
  src_syn_only_ratio_w: 'Share of its connections left half-open',
  src_egress_bytes_z: 'Upload vs this host\'s normal (z-score)',
  dst_distinct_srcs_longterm: 'Hosts that ever contacted this destination',
  off_hours: 'Outside working hours',
  dst_reflector_flows_w: 'Unsolicited replies from reflector ports',
  dst_reflector_bytes_w: 'Bytes of those replies',
  dst_bytes_vs_baseline: 'Bytes to this server vs its usual',
  dst_flows_vs_baseline: 'Connections to this server vs its usual',
};

// Short names for the one-line evidence on a threat tile.
export const FEATURE_SHORT = {
  dst_distinct_srcs_w: 'sources', dst_src_ip_entropy_w: 'source entropy', dst_syn_only_ratio_w: 'SYN-only share',
  outbound_inbound_byte_ratio: 'out/in bytes', egress_bytes: 'bytes out', src_dns_queries_w: 'DNS lookups',
  pair_iat_cv: 'timing CV', pair_iat_mean: 's between check-ins', src_high_entropy_qnames_w: 'random names',
  src_nxdomain_rate_w: 'NXDOMAIN share', ja4_prevalence: 'fingerprint sightings', pair_flows_w: 'sessions',
  src_distinct_dsts_w: 'hosts touched', src_distinct_dst_ports_w: 'ports tried', src_syn_only_ratio_w: 'half-open share',
  src_egress_bytes_z: 'upload z-score', dst_reflector_flows_w: 'reflector flows', dst_reflector_bytes_w: 'reflector bytes',
  dst_reflector_mean_pkt_w: 'mean reflected packet', dst_bytes_vs_baseline: '× usual bytes', dst_flows_vs_baseline: '× usual flows', dst_flows_w: 'flows',
  fl_dst_syn_srcs_1s: 'SYN sources in 1 s', fl_dst_refl_srcs_1s: 'reflectors in 1 s', fl_src_syn_targets_1s: 'SYN targets in 1 s',
};

const compact = (v) => (typeof v !== 'number' ? String(v)
  : Math.abs(v) >= 100 ? Math.round(v).toLocaleString('en-US') : Number(v.toPrecision(2)).toString());

// "src → dst · 280 out/in bytes (threshold 50)" from the alert's own evidence: the first row at or past
// its reference value (else the first with one, else the first row); entity only when there is none.
export function evidenceLine(a) {
  const f = a.flow || {};
  const who = `${f.src_ip} → ${f.dst_ip}`;
  const rows = a.evidence || [];
  const ref = rows.filter((r) => typeof r.value === 'number' && typeof r.baseline === 'number');
  const e = ref.find((r) => r.value >= r.baseline) || ref[0] || rows[0]; // first row at or past its reference
  if (!e) return who;
  const refText = typeof e.baseline === 'number' ? ` (${e.baseline_source === 'rule_threshold' ? 'threshold' : 'normal'} ${compact(e.baseline)})` : '';
  return `${who} · ${compact(e.value)} ${FEATURE_SHORT[e.feature] || e.feature}${refText}`;
}
