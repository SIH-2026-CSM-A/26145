// Plain words for a non-technical viewer; the technical id is shown next to it.
export const CLASS_INFO = {
  THREAT_RECON_PORTSCAN: { short: 'Scan', plain: 'Scanning many ports or machines (reconnaissance)', color: '#38bdf8' },
  THREAT_C2_BEACON: { short: 'C2 beacon', plain: 'Regular check-ins to an outside server (command and control)', color: '#a78bfa' },
  THREAT_DNS_DGA: { short: 'DGA', plain: 'Lookups of many random-looking domain names (malware searching for its server)', color: '#fbbf24' },
  THREAT_DNS_TUNNEL: { short: 'DNS tunnel', plain: 'Data hidden inside DNS lookups (DNS tunnelling)', color: '#fb923c' },
  THREAT_ENCRYPTED_ANOMALY: { short: 'Rare TLS client', plain: 'An unusual encrypted client repeatedly contacting one server', color: '#2dd4bf' },
  THREAT_EXFILTRATION: { short: 'Exfiltration', plain: 'A large upload leaving the network (data exfiltration)', color: '#f472b6' },
  THREAT_DDOS_VOLUME: { short: 'DDoS', plain: 'A traffic flood aimed at one server (denial of service)', color: '#ef4444' },
  THREAT_ML_MALICIOUS_FLOW: { short: 'ML flag', plain: 'A connection the ML model scores as botnet-like', color: '#94a3b8' },
};
export const classInfo = (c) => CLASS_INFO[c] || { short: c, plain: c, color: '#94a3b8' };

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
